# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
import threading
from collections import defaultdict

import tenacity
from futurist import periodics
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from sqlalchemy.orm import exc as db_exceptions

from octavia.db import repositories as repo, models
from octavia_f5.utils import cert_manager
from octavia_f5.controller.worker.f5agent_driver import tenant_update, tenant_delete
from octavia_f5.db import api as db_apis
from octavia_f5.restclient.as3restclient import BigipAS3RestClient
from octavia_f5.utils import esd_repo, driver_utils
from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions as driver_exceptions
from octavia_lib.common import constants as lib_consts

CONF = cfg.CONF
CONF.import_group('f5_agent', 'octavia_f5.common.config')
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


def _status(_id,
            provisioning_status=lib_consts.ACTIVE,
            operating_status=lib_consts.ONLINE):
    return {
        lib_consts.ID: _id,
        lib_consts.PROVISIONING_STATUS: provisioning_status,
        lib_consts.OPERATING_STATUS: operating_status
    }


class ControllerWorker(object):
    """Worker class to update load balancers."""

    def __init__(self):
        self._loadbalancer_repo = repo.LoadBalancerRepository()
        self._octavia_driver_lib = driver_lib.DriverLibrary(
            status_socket=CONF.driver_agent.status_socket_path,
            stats_socket=CONF.driver_agent.stats_socket_path
        )
        self._esd = esd_repo.EsdRepository()
        self._amphora_repo = repo.AmphoraRepository()
        self._amphora_health_repo = repo.AmphoraHealthRepository()
        self._health_mon_repo = repo.HealthMonitorRepository()
        self._lb_repo = repo.LoadBalancerRepository()
        self._listener_repo = repo.ListenerRepository()
        self._member_repo = repo.MemberRepository()
        self._pool_repo = repo.PoolRepository()
        self._l7policy_repo = repo.L7PolicyRepository()
        self._l7rule_repo = repo.L7RuleRepository()
        self._flavor_repo = repo.FlavorRepository()
        self._vip_repo = repo.VipRepository()
        self.bigip = BigipAS3RestClient(
            bigip_url=CONF.f5_agent.bigip_url,
            enable_verify=CONF.f5_agent.bigip_verify,
            enable_token=CONF.f5_agent.bigip_token,
            esd=self._esd)
        self.network_driver = driver_utils.get_network_driver()
        self.cert_manager = cert_manager.CertManagerWrapper()
        worker = periodics.PeriodicWorker(
            [(self.pending_sync, None, None)]
        )
        t = threading.Thread(target=worker.start)
        t.daemon = True
        t.start()

        super(ControllerWorker, self).__init__()

    @periodics.periodic(120, run_immediately=True)
    @lockutils.synchronized('tenant_refresh')
    def pending_sync(self):
        lbs = self._loadbalancer_repo.get_all(
            db_apis.get_session(),
            provisioning_status=lib_consts.PENDING_UPDATE,
            show_deleted=False)[0]
        lbs.extend(self._loadbalancer_repo.get_all(
            db_apis.get_session(),
            provisioning_status=lib_consts.PENDING_CREATE,
            show_deleted=False)[0])
        lbs.extend(self._loadbalancer_repo.get_all(
            db_apis.get_session(),
            provisioning_status=lib_consts.PENDING_DELETE,
            show_deleted=False)[0])

        for network_id in set([lb.vip.network_id for lb in lbs]):
            LOG.info("Found pending tennant network %s, syncing...", network_id)
            self._refresh(network_id)

    def _set_status_deleted(self, object_id, object_type):
        status = {
            object_type: [{
                lib_consts.ID: object_id,
                lib_consts.PROVISIONING_STATUS: lib_consts.DELETED
            }]
        }
        self._update_status_to_octavia(status)

    def _set_status_error(self, object_id, object_type):
        status = {
            object_type: [{
                lib_consts.ID: object_id,
                lib_consts.PROVISIONING_STATUS: lib_consts.ERROR
            }]
        }
        self._update_status_to_octavia(status)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _update_status_to_octavia(self, status):
        try:
            self._octavia_driver_lib.update_loadbalancer_status(status)
        except driver_exceptions.UpdateStatusError as e:
            msg = ("Error while updating status to octavia: "
                   "%s") % e.fault_string
            LOG.error(msg)
            raise driver_exceptions.UpdateStatusError(msg)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _get_all_loadbalancer(self, network_id):
        LOG.debug("Get load balancers from DB for network id: %s ",
                  network_id)
        vips = self._vip_repo.get_all(
            db_apis.get_session(),
            network_id=network_id)
        loadbalancers = []
        for vip in vips[0]:
            loadbalancers.append(self._loadbalancer_repo.get(
                db_apis.get_session(),
                show_deleted=False,
                id=vip.load_balancer_id))
        return [lb for lb in loadbalancers if lb]

    def _refresh(self, network_id):
        loadbalancers = self._get_all_loadbalancer(network_id)
        segmentation_id = self.network_driver.get_segmentation_id(network_id)
        ret = tenant_update(self.bigip, self.cert_manager, network_id, loadbalancers, segmentation_id)

        if ret.status_code < 400:
            status = defaultdict(list)
            for loadbalancer in loadbalancers:
                status[lib_consts.LOADBALANCERS].append(
                    _status(loadbalancer.id))

                for listener in loadbalancer.listeners:
                    status[lib_consts.LISTENERS].append(
                        _status(listener.id))

                    for l7policy in listener.l7policies:
                        status[lib_consts.L7POLICIES].append(
                            _status(l7policy.id))

                        for l7rule in l7policy.l7rules:
                            status[lib_consts.L7RULES].append(
                                _status(l7rule.id))

                for pool in loadbalancer.pools:
                    status[lib_consts.POOLS].append(
                        _status(pool.id))

                    for member in pool.members:
                        status[lib_consts.MEMBERS].append(
                            _status(member.id))

                    if pool.health_monitor:
                        status[lib_consts.HEALTHMONITORS].append(
                            _status(pool.health_monitor.id))

            self._update_status_to_octavia(status)
            return True
        return False

        """
                if ret.headers.get('Content-Type') == 'application/json':
                    # Iterate through errors and update status
                    for error in ret.json().get('errors', []):
                        _, net, lb, item, remark = error.split('/', 4)
                        LOG.error("Error with %s: %s", lb, remark)
                        if item.startswith('pool'):
                            SET_TO_ERROR(status[lib_consts.POOLS], item[5:])
                else:
                    # set all lb's to error
                    status['loadbalancers'].extend([
                        {'id': lb.id, lib_consts.PROVISIONING_STATUS: lib_consts.ERROR}
                        for lb in loadbalancers])
        """

    """
    Loadbalancer
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    @lockutils.synchronized('tenant_refresh')
    def create_load_balancer(self, load_balancer_id, flavor=None):
        lb = self._lb_repo.get(db_apis.get_session(), id=load_balancer_id)
        """ We are retrying to fetch load-balancer since API could be still 
            busy inserting the LB into the database """
        if not lb:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'load_balancer', load_balancer_id)
            raise db_exceptions.NoResultFound

        self._refresh(lb.vip.network_id)

    @lockutils.synchronized('tenant_refresh')
    def update_load_balancer(self, load_balancer_id, load_balancer_updates):
        lb = self._lb_repo.get(db_apis.get_session(), id=load_balancer_id)
        self._refresh(lb.vip.network_id)

    @lockutils.synchronized('tenant_refresh')
    def delete_load_balancer(self, load_balancer_id, cascade=False):
        lb = self._lb_repo.get(db_apis.get_session(),
                               id=load_balancer_id)
        existing_lbs = [loadbalancer for loadbalancer in self._get_all_loadbalancer(lb.vip.network_id)
                        if loadbalancer.id != lb.id]

        if not existing_lbs:
            # Delete whole tenant
            ret = tenant_delete(self.bigip, lb.vip.network_id)
        else:
            # Don't delete whole tenant
            segmentation_id = self.network_driver.get_segmentation_id(lb.vip.network_id)
            ret = tenant_update(self.bigip, self.cert_manager, lb.vip.network_id, existing_lbs, segmentation_id)

        if ret.status_code < 400:
            self._set_status_deleted(lb.id, lib_consts.LOADBALANCERS)

    """
    Listener
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    @lockutils.synchronized('tenant_refresh')
    def create_listener(self, listener_id):
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)
        if not listener:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'listener', listener_id)
            raise db_exceptions.NoResultFound

        if not self._refresh(listener.load_balancer.vip.network_id):
            self._set_status_error(listener.id, lib_consts.LISTENERS)

    @lockutils.synchronized('tenant_refresh')
    def update_listener(self, listener_id, listener_updates):
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)
        if not self._refresh(listener.load_balancer.vip.network_id):
            self._set_status_error(listener.id, lib_consts.LISTENERS)

    @lockutils.synchronized('tenant_refresh')
    def delete_listener(self, listener_id):
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)

        if self._refresh(listener.load_balancer.vip.network_id):
            self._set_status_deleted(listener.id, lib_consts.LISTENERS)

    """
    Pool
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    @lockutils.synchronized('tenant_refresh')
    def create_pool(self, pool_id):
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        if not pool:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'pool', pool_id)
            raise db_exceptions.NoResultFound

        if not self._refresh(pool.load_balancer.vip.network_id):
            self._set_status_error(pool.id, lib_consts.POOLS)

    @lockutils.synchronized('tenant_refresh')
    def update_pool(self, pool_id, pool_updates):
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        if not self._refresh(pool.load_balancer.vip.network_id):
            self._set_status_error(pool.id, lib_consts.POOLS)

    @lockutils.synchronized('tenant_refresh')
    def delete_pool(self, pool_id):
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        if self._refresh(pool.load_balancer.vip.network_id):
            self._set_status_deleted(pool.id, lib_consts.POOLS)

    """
    Member
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    @lockutils.synchronized('tenant_refresh')
    def create_member(self, member_id):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        if not member:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'member', member_id)
            raise db_exceptions.NoResultFound

        if not self._refresh(member.pool.load_balancer.vip.network_id):
            self._set_status_error(member.id, lib_consts.MEMBERS)

    @lockutils.synchronized('tenant_refresh')
    def batch_update_members(self, old_member_ids, new_member_ids,
                             updated_members):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=old_member_ids[0])
        if not self._refresh(member.pool.load_balancer.vip.network_id):
            self._set_status_error(member.id, lib_consts.MEMBERS)

    @lockutils.synchronized('tenant_refresh')
    def update_member(self, member_id, member_updates):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        if not self._refresh(member.pool.load_balancer.vip.network_id):
            self._set_status_error(member.id, lib_consts.MEMBERS)

    @lockutils.synchronized('tenant_refresh')
    def delete_member(self, member_id):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        if self._refresh(member.pool.load_balancer.vip.network_id):
            self._set_status_deleted(member.id, lib_consts.MEMBERS)

    """
    Member
    """
    @lockutils.synchronized('tenant_refresh')
    def create_health_monitor(self, health_monitor_id):
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        if not health_mon:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'health_monitor', health_monitor_id)
            raise db_exceptions.NoResultFound

        pool = health_mon.pool
        load_balancer = pool.load_balancer
        if not self._refresh(load_balancer.vip.network_id):
            self._set_status_error(health_mon.id, lib_consts.HEALTHMONITORS)

    @lockutils.synchronized('tenant_refresh')
    def update_health_monitor(self, health_monitor_id, health_monitor_updates):
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        pool = health_mon.pool
        load_balancer = pool.load_balancer
        if not self._refresh(load_balancer.vip.network_id):
            self._set_status_error(health_mon.id, lib_consts.HEALTHMONITORS)

    @lockutils.synchronized('tenant_refresh')
    def delete_health_monitor(self, health_monitor_id):
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        pool = health_mon.pool
        load_balancer = pool.load_balancer
        if self._refresh(load_balancer.vip.network_id):
            self._set_status_deleted(health_mon.id, lib_consts.HEALTHMONITORS)

    """
    l7policy
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    @lockutils.synchronized('tenant_refresh')
    def create_l7policy(self, l7policy_id):
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        if not l7policy:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'l7policy', l7policy_id)
            raise db_exceptions.NoResultFound

        if not self._refresh(l7policy.listener.load_balancer.vip.network_id):
            self._set_status_error(l7policy.id, lib_consts.L7POLICIES)

    @lockutils.synchronized('tenant_refresh')
    def update_l7policy(self, l7policy_id, l7policy_updates):
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        if not self._refresh(l7policy.listener.load_balancer.vip.network_id):
            self._set_status_error(l7policy.id, lib_consts.L7POLICIES)

    @lockutils.synchronized('tenant_refresh')
    def delete_l7policy(self, l7policy_id):
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        if self._refresh(l7policy.listener.load_balancer.vip.network_id):
            self._set_status_deleted(l7policy.id, lib_consts.L7POLICIES)

    """
    l7rule
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    @lockutils.synchronized('tenant_refresh')
    def create_l7rule(self, l7rule_id):
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        if not l7rule:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'l7rule', l7rule_id)
            raise db_exceptions.NoResultFound

        if not self._refresh(l7rule.l7policy.listener.load_balancer.vip.network_id):
            self._set_status_error(l7rule.id, lib_consts.L7RULES)

    @lockutils.synchronized('tenant_refresh')
    def update_l7rule(self, l7rule_id, l7rule_updates):
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        if not self._refresh(l7rule.l7policy.listener.load_balancer.vip.network_id):
            self._set_status_error(l7rule.id, lib_consts.L7RULES)

    @lockutils.synchronized('tenant_refresh')
    def delete_l7rule(self, l7rule_id):
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        if self._refresh(l7rule.l7policy.listener.load_balancer.vip.network_id):
            self._set_status_deleted(l7rule.id, lib_consts.L7RULES)

    """
    Amphora
    """

    def create_amphora(self):
        pass

    def delete_amphora(self, amphora_id):
        pass

    def failover_amphora(self, amphora_id):
        pass

    def failover_loadbalancer(self, load_balancer_id):
        pass

    def amphora_cert_rotation(self, amphora_id):
        pass

    def update_amphora_agent_config(self, amphora_id):
        pass
