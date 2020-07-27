# Copyright 2019, 2020 SAP SE
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

import collections
import threading

import prometheus_client as prometheus
import tenacity
from futurist import periodics
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy.orm import exc as db_exceptions

from octavia.common import exceptions as o_exceptions, data_models
from octavia.db import repositories as repo
from octavia.network import base
from octavia_f5.common import constants
from octavia_f5.controller.worker import status_manager, sync_manager
from octavia_f5.db import api as db_apis
from octavia_f5.db import repositories as f5_repos
from octavia_f5.utils import exceptions, driver_utils
from octavia_lib.common import constants as lib_consts

CONF = cfg.CONF
CONF.import_group('f5_agent', 'octavia_f5.common.config')
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


class ControllerWorker(object):
    """Worker class to update load balancers."""

    def __init__(self):
        self._repositories = repo.Repositories()
        self._loadbalancer_repo = f5_repos.LoadBalancerRepository()
        self._amphora_repo = repo.AmphoraRepository()
        self._health_mon_repo = repo.HealthMonitorRepository()
        self._lb_repo = repo.LoadBalancerRepository()
        self._listener_repo = f5_repos.ListenerRepository()
        self._member_repo = repo.MemberRepository()
        self._pool_repo = f5_repos.PoolRepository()
        self._l7policy_repo = f5_repos.L7PolicyRepository()
        self._l7rule_repo = repo.L7RuleRepository()
        self._vip_repo = repo.VipRepository()
        self._quota_repo = repo.QuotasRepository()

        self.sync = sync_manager.SyncManager()
        self.status = status_manager.StatusManager()
        self.network_driver = driver_utils.get_network_driver()
        worker = periodics.PeriodicWorker(
            [(self.pending_sync, None, None),
             (self.full_sync_reappearing_devices, None, None)]
        )
        t = threading.Thread(target=worker.start)
        t.daemon = True
        t.start()

        if cfg.CONF.f5_agent.prometheus:
            prometheus_port = CONF.f5_agent.prometheus_port
            LOG.info('Starting Prometheus HTTP server on port {}'.format(prometheus_port))
            prometheus.start_http_server(prometheus_port)

        super(ControllerWorker, self).__init__()

    @periodics.periodic(120, run_immediately=True)
    def pending_sync(self):
        """
        Reconciliation loop that
        - synchronizes load balancers that are in a PENDING state
        - deletes load balancers that are PENDING_DELETE
        - executes a full sync on F5 devices that were offline but are now back online
        """

        # synchronize load balancers that are in a PENDING state
        self.sync_loadbalancers()

        # delete load balancers that are PENDING_DELETE
        session = db_apis.get_session()
        lbs_to_delete = self._loadbalancer_repo.get_all_from_host(
            session, provisioning_status=lib_consts.PENDING_DELETE)
        for lb in lbs_to_delete:
            LOG.info("Found pending deletion of lb %s", lb.id)
            self.delete_load_balancer(lb.id)

    @periodics.periodic(240, run_immediately=True)
    @lockutils.synchronized('tenant_refresh')
    def full_sync_reappearing_devices(self):
        session = db_apis.get_session(autocommit=False)

        # Get all pending devices
        booting_devices = self._amphora_repo.get_all(
            session, status=constants.AMPHORA_BOOTING,
            compute_flavor=CONF.host, load_balancer_id=None)

        for device in booting_devices[0]:
            if CONF.f5_agent.migration and device.role != constants.ROLE_BACKUP:
                LOG.warning("[Migration Mode] Skipping full sync of active device %s", device.cached_zone)
                continue

            LOG.info("Device reappeared: %s. Doing a full sync.", device.cached_zone)

            # get all load balancers (of this host)
            lbs = self._loadbalancer_repo.get_all_from_host(session, show_deleted=False)

            # deduplicate
            networks = collections.defaultdict(list)
            for lb in lbs:
                if lb not in networks[lb.vip.network_id]:
                    networks[lb.vip.network_id].append(lb)

            # push configuration
            for network_id, loadbalancers in networks.items():
                try:
                    self.sync.tenant_update(network_id, loadbalancers, device.cached_zone)
                except base.NetworkException as e:
                    LOG.error("Neutron exception while syncing reappared device %s: %s", device.cached_zone, e)
                except exceptions.AS3Exception as e:
                    LOG.error("AS3 exception while syncing reappared device %s: %s", device.cached_zone, e)

            # Set device ready
            self._amphora_repo.update(session, device.id, status=constants.AMPHORA_READY)
            session.commit()

    @lockutils.synchronized('tenant_refresh')
    def sync_loadbalancers(self):
        """Sync loadbalancers that are in a PENDING state
        """

        # Find pending loadbalancer not yet finally assigned to this host
        lbs = []
        pending_create_lbs = self._loadbalancer_repo.get_all(
            db_apis.get_session(),
            provisioning_status=lib_consts.PENDING_CREATE,
            show_deleted=False)[0]
        for lb in pending_create_lbs:
            # bind to loadbalancer if scheduled to this host
            if CONF.host == self.network_driver.get_scheduled_host(lb.vip.port_id):
                self.ensure_host_set(lb)
                lbs.append(lb)

        # Find pending loadbalancer
        lbs.extend(self._loadbalancer_repo.get_all_from_host(
            db_apis.get_session(),
            provisioning_status=lib_consts.PENDING_UPDATE))
        for lb in lbs:
            self.ensure_amphora_exists(lb.id)

        # Find pending listener
        listeners = self._listener_repo.get_pending_from_host(db_apis.get_session())
        lbs.extend([listener.load_balancer for listener in listeners])

        # Find pending pools
        pools = self._pool_repo.get_pending_from_host(db_apis.get_session())
        lbs.extend([pool.load_balancer for pool in pools])

        # Find pending l7policies
        l7policies = self._l7policy_repo.get_pending_from_host(db_apis.get_session())
        lbs.extend([l7policy.listener.load_balancer for l7policy in l7policies])

        # Deduplicate
        pending_networks = collections.defaultdict(list)
        for lb in lbs:
            if lb not in pending_networks[lb.vip.network_id]:
                pending_networks[lb.vip.network_id].append(lb)

        for network_id, loadbalancers in pending_networks.items():
            LOG.info("Found pending tenant network %s, syncing...", network_id)
            try:
                if self._refresh(network_id).ok:
                    self.status.update_status(loadbalancers)
                    for lb in loadbalancers:
                        self._reset_in_use_quota(lb.project_id)
            except exceptions.AS3Exception as e:
                LOG.error("AS3 exception while syncing tenant %s: %s", network_id, e)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _get_all_loadbalancer(self, network_id):
        LOG.debug("Get load balancers from DB for network id: %s ", network_id)
        return self._loadbalancer_repo.get_all_by_network(
            db_apis.get_session(), network_id=network_id, show_deleted=False)

    def _refresh(self, network_id, status=None):
        loadbalancers = self._get_all_loadbalancer(network_id)
        try:
            return self.sync.tenant_update(network_id, loadbalancers, status=self.status)
        except exceptions.RetryException as e:
            LOG.warning("Device is busy, retrying with next sync: %s", e)
            raise e
        except o_exceptions.CertificateRetrievalException as e:
            LOG.warning("Could not retrieve certificate for tenant %s: %s", network_id, e)
            raise e

    def _decrement_quota(self, data_model, project_id):
        lock_session = db_apis.get_session(autocommit=False)
        try:
            self._repositories.decrement_quota(lock_session, data_model, project_id)
            lock_session.commit()
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to decrement %s quota for '
                          'project: %s the project may have excess '
                          'quota in use.', data_model, project_id)
                lock_session.rollback()

    def _reset_in_use_quota(self, project_id):
        """ reset in_use quota to None, so it will be recalculated the next time
        :param project_id: project id
        """
        reset_dict = {
            'in_use_load_balancer': None,
            'in_use_listener': None,
            'in_use_pool': None,
            'in_use_health_monitor': None,
            'in_use_member': None,
        }

        lock_session = db_apis.get_session(autocommit=False)
        try:
            self._quota_repo.update(lock_session, project_id=project_id, quota=reset_dict)
            lock_session.commit()
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to reset quota for '
                          'project: %(proj)s the project may have excess '
                          'quota in use.', {'proj': project_id})
                lock_session.rollback()

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
        # We are retrying to fetch load-balancer since API could
        # be still busy inserting the LB into the database.
        if not lb:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'load_balancer', load_balancer_id)
            raise db_exceptions.NoResultFound

        self.ensure_amphora_exists(lb.id)
        self.ensure_host_set(lb)
        if self._refresh(lb.vip.network_id).ok:
            self.status.set_active(lb)

    @lockutils.synchronized('tenant_refresh')
    def update_load_balancer(self, load_balancer_id, load_balancer_updates):
        lb = self._lb_repo.get(db_apis.get_session(), id=load_balancer_id)
        if self._refresh(lb.vip.network_id).ok:
            self.status.set_active(lb)

    @lockutils.synchronized('tenant_refresh')
    def delete_load_balancer(self, load_balancer_id, cascade=False):
        lb = self._lb_repo.get(db_apis.get_session(), id=load_balancer_id)
        existing_lbs = [loadbalancer for loadbalancer in self._get_all_loadbalancer(lb.vip.network_id)
                        if loadbalancer.id != lb.id]

        if not existing_lbs:
            # Delete whole tenant
            ret = self.sync.tenant_delete(lb.vip.network_id)
        else:
            # Don't delete whole tenant
            ret = self.sync.tenant_update(lb.vip.network_id, existing_lbs)

        if ret.ok:
            self.status.set_deleted(lb)
            self._decrement_quota(data_models.LoadBalancer, lb.project_id)

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

        if self._refresh(listener.load_balancer.vip.network_id, self.status).ok:
            self.status.set_active(listener)

    @lockutils.synchronized('tenant_refresh')
    def update_listener(self, listener_id, listener_updates):
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)
        if self._refresh(listener.load_balancer.vip.network_id, self.status).ok:
            self.status.set_active(listener)

    @lockutils.synchronized('tenant_refresh')
    def delete_listener(self, listener_id):
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)

        if self._refresh(listener.load_balancer.vip.network_id).ok:
            self.status.set_deleted(listener)
            self._decrement_quota(data_models.Listener, listener.project_id)

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

        if self._refresh(pool.load_balancer.vip.network_id).ok:
            self.status.set_active(pool)

    @lockutils.synchronized('tenant_refresh')
    def update_pool(self, pool_id, pool_updates):
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        if self._refresh(pool.load_balancer.vip.network_id).ok:
            self.status.set_active(pool)

    @lockutils.synchronized('tenant_refresh')
    def delete_pool(self, pool_id):
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        if pool and self._refresh(pool.load_balancer.vip.network_id).ok:
            self.status.set_deleted(pool)

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

        self.ensure_amphora_exists(member.pool.load_balancer.id)

        if not member.backup:
            try:
                if self.sync.member_create(member).ok:
                    self.status.set_active(member)
                    return
            except exceptions.AS3Exception:
                pass
        elif self._refresh(member.pool.load_balancer.vip.network_id).ok:
            self.status.set_active(member)

    @lockutils.synchronized('tenant_refresh')
    def batch_update_members(self, old_member_ids, new_member_ids,
                             updated_members):
        old_members = [self._member_repo.get(db_apis.get_session(), id=mid)
                       for mid in old_member_ids]
        new_members = [self._member_repo.get(db_apis.get_session(), id=mid)
                       for mid in new_member_ids]
        updated_members = [
            (self._member_repo.get(db_apis.get_session(), id=m.get('id')), m)
            for m in updated_members]
        if old_members:
            pool = old_members[0].pool
        elif new_members:
            pool = new_members[0].pool
        elif updated_members:
            pool = updated_members[0][0].pool
        else:
            return
        load_balancer = pool.load_balancer
        network_id = load_balancer.vip.network_id
        if self._refresh(network_id).ok:
            self.status.update_status([load_balancer])

    @lockutils.synchronized('tenant_refresh')
    def update_member(self, member_id, member_updates):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        if self._refresh(member.pool.load_balancer.vip.network_id).ok:
            self.status.set_active(member)

    @lockutils.synchronized('tenant_refresh')
    def delete_member(self, member_id):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        if self._refresh(member.pool.load_balancer.vip.network_id).ok:
            self.status.set_deleted(member)
            self._decrement_quota(data_models.Member, member.project_id)

    """
    Health Monitor
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
        if self._refresh(load_balancer.vip.network_id).ok:
            self.status.set_active(health_mon)

    @lockutils.synchronized('tenant_refresh')
    def update_health_monitor(self, health_monitor_id, health_monitor_updates):
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        pool = health_mon.pool
        load_balancer = pool.load_balancer
        if self._refresh(load_balancer.vip.network_id).ok:
            self.status.set_active(health_mon)

    @lockutils.synchronized('tenant_refresh')
    def delete_health_monitor(self, health_monitor_id):
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        pool = health_mon.pool
        load_balancer = pool.load_balancer
        if self._refresh(load_balancer.vip.network_id).ok:
            self.status.set_deleted(health_mon)
            self._decrement_quota(data_models.HealthMonitor, load_balancer.project_id)

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

        if self._refresh(l7policy.listener.load_balancer.vip.network_id).ok:
            self.status.set_active(l7policy)

    @lockutils.synchronized('tenant_refresh')
    def update_l7policy(self, l7policy_id, l7policy_updates):
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        if self._refresh(l7policy.listener.load_balancer.vip.network_id).ok:
            self.status.set_active(l7policy)

    @lockutils.synchronized('tenant_refresh')
    def delete_l7policy(self, l7policy_id):
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        if self._refresh(l7policy.listener.load_balancer.vip.network_id).ok:
            self.status.set_deleted(l7policy)

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

        if self._refresh(l7rule.l7policy.listener.load_balancer.vip.network_id).ok:
            self.status.set_active(l7rule)

    @lockutils.synchronized('tenant_refresh')
    def update_l7rule(self, l7rule_id, l7rule_updates):
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        if self._refresh(l7rule.l7policy.listener.load_balancer.vip.network_id).ok:
            self.status.set_active(l7rule)

    @lockutils.synchronized('tenant_refresh')
    def delete_l7rule(self, l7rule_id):
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        if self._refresh(l7rule.l7policy.listener.load_balancer.vip.network_id).ok:
            self.status.set_deleted(l7rule)

    """
    Amphora
    """

    def ensure_amphora_exists(self, load_balancer_id):
        """
        Octavia health manager makes some assumptions about the existence of amphorae.
        That's why even the F5 provider driver has to care about amphora DB entries.
        Otherwise status updates won't work correctly.

        This function creates an amphora entry in the database, if it doesn't already exist.
        """
        device_entry = self._amphora_repo.get(
            db_apis.get_session(),
            load_balancer_id=load_balancer_id)

        # create amphora mapping if missing
        if not device_entry:
            self._amphora_repo.create(
                db_apis.get_session(),
                id=load_balancer_id,
                load_balancer_id=load_balancer_id,
                compute_flavor=CONF.host,
                status=lib_consts.ACTIVE)
            return

        # update host if not updated yet
        if device_entry.compute_flavor != CONF.host:
            self._amphora_repo.update(
                db_apis.get_session(),
                id=device_entry.id,
                compute_flavor=CONF.host)

    def create_amphora(self):
        pass

    def delete_amphora(self, amphora_id):
        self._amphora_repo.delete(
            db_apis.get_session(),
            id=amphora_id)

    def failover_amphora(self, amphora_id):
        pass

    def failover_loadbalancer(self, load_balancer_id):
        pass

    def amphora_cert_rotation(self, amphora_id):
        pass

    def update_amphora_agent_config(self, amphora_id):
        pass

    def ensure_host_set(self, loadbalancer):
        """Assigns the current host to loadbalancer by writing
        it into server_group_id column of loadbalancer table."""
        if CONF.host[:36] != loadbalancer.server_group_id:
            self._loadbalancer_repo.update(db_apis.get_session(),
                                           id=loadbalancer.id,
                                           server_group_id=CONF.host[:36])
