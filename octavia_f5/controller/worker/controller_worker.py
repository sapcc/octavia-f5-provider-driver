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

import json
import threading
import time
from itertools import chain
from queue import Empty

import prometheus_client as prometheus
import tenacity
from futurist import periodics
from octavia_lib.common import constants as lib_consts
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_log import log as logging
from oslo_utils import excutils, uuidutils
from requests import HTTPError
from sqlalchemy.orm import exc as db_exceptions

from octavia.db import repositories as repo
from octavia_f5.common import constants
from octavia_f5.controller.worker import status_manager, sync_manager, l2_sync_manager
from octavia_f5.controller.worker.set_queue import SetQueue
from octavia_f5.db import api as db_apis
from octavia_f5.db import repositories as f5_repos
from octavia_f5.utils import exceptions, driver_utils

CONF = cfg.CONF
CONF.import_group('f5_agent', 'octavia_f5.common.config')
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


class ControllerWorker(object):
    """Worker class to update load balancers."""

    _metric_as3worker_queue = prometheus.metrics.Gauge(
        'octavia_as3_worker_queue', 'Number of items in AS3 worker queue', ['octavia_host'])

    def __init__(self):
        self._repositories = repo.Repositories()
        self._loadbalancer_repo = f5_repos.LoadBalancerRepository()
        self._amphora_repo = repo.AmphoraRepository()
        self._health_mon_repo = repo.HealthMonitorRepository()
        self._listener_repo = f5_repos.ListenerRepository()
        self._member_repo = repo.MemberRepository()
        self._pool_repo = f5_repos.PoolRepository()
        self._l7policy_repo = f5_repos.L7PolicyRepository()
        self._l7rule_repo = repo.L7RuleRepository()
        self._vip_repo = repo.VipRepository()
        self._quota_repo = f5_repos.QuotasRepository()
        self._az_repo = repo.AvailabilityZoneRepository()
        self._azp_repo = repo.AvailabilityZoneProfileRepository()
        self.queue = SetQueue()

        # instantiate managers/drivers
        self.status = status_manager.StatusManager()
        self.sync = sync_manager.SyncManager(self.status, self._loadbalancer_repo)
        self.l2sync = l2_sync_manager.L2SyncManager()
        self.network_driver = driver_utils.get_network_driver()

        # start thread for reconciliation loop, full sync loop, orphan cleanup loop
        worker = periodics.PeriodicWorker(
            [(self.pending_sync, None, None),
             (self.full_sync_reappearing_devices, None, None),
             (self.cleanup_orphaned_tenants, None, None),
             (self.full_sync_l2, None, None)]
        )
        t = threading.Thread(target=worker.start)
        t.daemon = True
        t.start()

        # start thread for AS3 provisioning loop
        LOG.info("Starting as3worker")
        as3worker = threading.Thread(target=self.as3worker)
        as3worker.setDaemon(True)
        as3worker.start()

        # start prometheus server
        if cfg.CONF.f5_agent.prometheus:
            prometheus_port = CONF.f5_agent.prometheus_port
            LOG.info('Starting Prometheus HTTP server on port {}'.format(prometheus_port))
            prometheus.start_http_server(prometheus_port)

        # 'register' this worker to its availability zone
        if CONF.f5_agent.availability_zone:
            self.register_in_availability_zone(CONF.f5_agent.availability_zone)

        super(ControllerWorker, self).__init__()

    def as3worker(self):
        """ AS3 Worker thread, pops tenant to refresh from thread-safe set queue"""

        @lockutils.synchronized("f5sync", fair=True)
        def f5sync(network_id, device, *args):
            self._metric_as3worker_queue.labels(octavia_host=CONF.host).set(self.queue.qsize())
            loadbalancers = self._get_all_loadbalancer(network_id)
            LOG.debug("AS3Worker after pop (queue_size=%d): Refresh tenant '%s' with loadbalancer %s",
                      self.queue.qsize(), network_id, [lb.id for lb in loadbalancers])
            selfips = list(chain.from_iterable(
                self.network_driver.ensure_selfips(loadbalancers, CONF.host, cleanup_orphans=True)))
            if all(lb.provisioning_status == lib_consts.PENDING_DELETE for lb in loadbalancers):
                self.sync.tenant_delete(network_id, device).raise_for_status()
                # Cleanup l2 configuration and remove selfip ports
                self.l2sync.remove_l2_flow(network_id, device)
                self.network_driver.cleanup_selfips(selfips)
            else:
                if all(lb.provisioning_status in [lib_consts.PENDING_CREATE, lib_consts.PENDING_DELETE]
                       for lb in loadbalancers):
                    # Network is new - ensure complete l2 flow
                    self.l2sync.ensure_l2_flow(selfips, network_id, device)
                elif any(lb.provisioning_status in [lib_consts.PENDING_CREATE, lib_consts.PENDING_DELETE]
                         for lb in loadbalancers):
                    # Network already exists, just ensure correct selfips and subnet routes
                    self.l2sync.sync_l2_selfips_and_subnet_routes_flow(selfips, network_id, device)
                self.sync.tenant_update(network_id, device, selfips).raise_for_status()

            # update status of just-synced LBs
            self.status.update_status(loadbalancers)
            for project_id in set(lb.project_id for lb in loadbalancers):
                self._reset_in_use_quota(project_id)

        # run sync loop
        while True:
            try:
                network_id, device = self.queue.get()
                f5sync(network_id, device)
            except Empty:
                # Queue empty, pass
                pass
            except (exceptions.RetryException, tenacity.RetryError) as e:
                LOG.warning("Worker run failed (device may be busy), retrying with next sync: %s", e)
                time.sleep(15)
            except Exception as e:
                LOG.exception(e)
                # restart

    @periodics.periodic(60*60*24, run_immediately=CONF.f5_agent.sync_immediately)
    def cleanup_orphaned_tenants(self):
        LOG.info("Running (24h) tenant cleanup")
        session = db_apis.get_session(autocommit=False)

        for device in self.sync.devices():
            try:
                # Fetch all Tenants
                tenants = self.sync.get_tenants(device)

                # Get all loadbalancers of this host
                for tenant_name, applications in tenants.items():
                    # Convert tenant_name to network_id
                    network_id = tenant_name.replace(constants.PREFIX_NETWORK, '').replace('_', '-')

                    # Fetch active loadbalancers for this network
                    octavia_lb_ids = [lb.id for lb in self._loadbalancer_repo.get_all_by_network(
                        session, network_id, show_deleted=False)]
                    if not octavia_lb_ids:
                        LOG.info("Found orphaned tenant '%s' for device '%s'", tenant_name, device)
                        self.queue.put((network_id, device))
            except HTTPError:
                # Ignore as3 errors
                pass

    @periodics.periodic(60*4, run_immediately=CONF.f5_agent.sync_immediately)
    def full_sync_reappearing_devices(self):
        session = db_apis.get_session(autocommit=False)

        # Get all pending devices
        booting_devices = self._amphora_repo.get_all(
            session, status=lib_consts.AMPHORA_BOOTING,
            compute_flavor=CONF.host, load_balancer_id=None)

        for device in booting_devices[0]:
            if CONF.f5_agent.migration and device.role != constants.ROLE_BACKUP:
                LOG.warning("[Migration Mode] Skipping full sync of active device %s", device.cached_zone)
                continue

            LOG.info("Device reappeared: %s. Doing a full sync.", device.cached_zone)

            # get all load balancers (of this host)
            lbs = self._loadbalancer_repo.get_all_from_host(session, show_deleted=False)

            # deduplicate
            for network_id in set(lb.vip.network_id for lb in lbs):
                self.queue.put((network_id, device.cached_zone))

            # Set device ready
            self._amphora_repo.update(session, device.id, status=lib_consts.AMPHORA_READY)
            session.commit()

    @periodics.periodic(60*60*24, run_immediately=CONF.f5_agent.sync_immediately)
    def full_sync_l2(self):
        session = db_apis.get_session()

        # get all load balancers (of this host)
        loadbalancers = self._loadbalancer_repo.get_all_from_host(
            session, show_deleted=False)
        self.l2sync.full_sync(loadbalancers)

    @periodics.periodic(60*2, run_immediately=CONF.f5_agent.sync_immediately)
    def pending_sync(self):
        """
        Reconciliation loop that
        - synchronizes load balancers that are in a PENDING state
        - deletes load balancers that are PENDING_DELETE
        - executes a full sync on F5 devices that were offline but are now back online
        """

        # delete load balancers that are PENDING_DELETE
        session = db_apis.get_session()
        lbs_to_delete = self._loadbalancer_repo.get_all_from_host(
            session, provisioning_status=lib_consts.PENDING_DELETE)
        for lb in lbs_to_delete:
            LOG.info("Found pending deletion of lb %s", lb.id)
            self.delete_load_balancer(lb.id)

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

        # Make the Octavia health manager happy by creating DB amphora entries
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

        # Deduplicate into networks
        # because each network is synced separately
        pending_networks = set(lb.vip.network_id for lb in lbs)
        for network_id in pending_networks:
            self.queue.put_nowait((network_id, None))

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _get_all_loadbalancer(self, network_id):
        LOG.debug("Get load balancers from DB for this host for network id: %s ", network_id)
        return self._loadbalancer_repo.get_all_by_network(
            db_apis.get_session(), network_id=network_id, show_deleted=False)

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
            'in_use_l7policy': None,
            'in_use_l7rule': None,
        }

        try:
            self._quota_repo.update(db_apis.get_session(),
                                    project_id=project_id, **reset_dict)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error('Failed to reset quota for '
                          'project: %(proj)s the project may have excess '
                          'quota in use.', {'proj': project_id})

    """
    Loadbalancer
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_load_balancer(self, load_balancer_id, flavor=None, availability_zone=None):
        lb = self._loadbalancer_repo.get(db_apis.get_session(), id=load_balancer_id)
        # We are retrying to fetch load-balancer since API could
        # be still busy inserting the LB into the database.
        if not lb:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'load_balancer', load_balancer_id)
            raise db_exceptions.NoResultFound

        self.ensure_amphora_exists(lb.id)
        self.ensure_host_set(lb)
        self.queue.put((lb.vip.network_id, None))

    def update_load_balancer(self, load_balancer_id, load_balancer_updates):
        lb = self._loadbalancer_repo.get(db_apis.get_session(), id=load_balancer_id)
        self.queue.put((lb.vip.network_id, None))

    def delete_load_balancer(self, load_balancer_id, cascade=False):
        lb = self._loadbalancer_repo.get(db_apis.get_session(), id=load_balancer_id)
        # could be deleted by sync-loop meanwhile
        if lb:
            self.queue.put((lb.vip.network_id, None))

    """
    Listener
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_listener(self, listener_id):
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)
        if not listener:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'listener', listener_id)
            raise db_exceptions.NoResultFound

        self.queue.put((listener.load_balancer.vip.network_id, None))

    def update_listener(self, listener_id, listener_updates):
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)
        self.queue.put((listener.load_balancer.vip.network_id, None))

    def delete_listener(self, listener_id):
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)
        # could be deleted by sync-loop meanwhile
        if listener:
            self.queue.put((listener.load_balancer.vip.network_id, None))

    """
    Pool
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_pool(self, pool_id):
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        if not pool:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'pool', pool_id)
            raise db_exceptions.NoResultFound

        self.queue.put((pool.load_balancer.vip.network_id, None))

    def update_pool(self, pool_id, pool_updates):
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        self.queue.put((pool.load_balancer.vip.network_id, None))

    def delete_pool(self, pool_id):
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        # could be deleted by sync-loop meanwhile
        if pool:
            self.queue.put((pool.load_balancer.vip.network_id, None))

    """
    Member
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_member(self, member_id):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        if not member:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'member', member_id)
            raise db_exceptions.NoResultFound

        self.ensure_amphora_exists(member.pool.load_balancer.id)
        self.queue.put((member.pool.load_balancer.vip.network_id, None))

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
        self.queue.put((pool.load_balancer.vip.network_id, None))

    def update_member(self, member_id, member_updates):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        self.queue.put((member.pool.load_balancer.vip.network_id, None))

    def delete_member(self, member_id):
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        # could be deleted by sync-loop meanwhile
        self.queue.put((member.pool.load_balancer.vip.network_id, None))

    """
    Health Monitor
    """

    def create_health_monitor(self, health_monitor_id):
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        if not health_mon:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'health_monitor', health_monitor_id)
            raise db_exceptions.NoResultFound

        self.queue.put((health_mon.pool.load_balancer.vip.network_id, None))

    def update_health_monitor(self, health_monitor_id, health_monitor_updates):
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        self.queue.put((health_mon.pool.load_balancer.vip.network_id, None))

    def delete_health_monitor(self, health_monitor_id):
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        # could be deleted by sync-loop meanwhile
        if health_mon:
            self.queue.put((health_mon.pool.load_balancer.vip.network_id, None))

    """
    l7policy
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_l7policy(self, l7policy_id):
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        if not l7policy:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'l7policy', l7policy_id)
            raise db_exceptions.NoResultFound

        self.queue.put((l7policy.listener.load_balancer.vip.network_id, None))

    def update_l7policy(self, l7policy_id, l7policy_updates):
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        self.queue.put((l7policy.listener.load_balancer.vip.network_id, None))

    def delete_l7policy(self, l7policy_id):
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        # could be deleted by sync-loop meanwhile
        if l7policy:
            self.queue.put((l7policy.listener.load_balancer.vip.network_id, None))

    """
    l7rule
    """

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_l7rule(self, l7rule_id):
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        if not l7rule:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'l7rule', l7rule_id)
            raise db_exceptions.NoResultFound

        self.queue.put((l7rule.l7policy.listener.load_balancer.vip.network_id, None))

    def update_l7rule(self, l7rule_id, l7rule_updates):
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        self.queue.put((l7rule.l7policy.listener.load_balancer.vip.network_id, None))

    def delete_l7rule(self, l7rule_id):
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        # could be deleted by sync-loop meanwhile
        if l7rule:
            self.queue.put((l7rule.l7policy.listener.load_balancer.vip.network_id, None))

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
        """ For now, we are rusing rpc endpoint failover_amphora for receiving failover events
        :param amphora_id: host that detected a failover

        """
        if amphora_id == CONF.host and not CONF.f5_agent.migration:
            self.sync.failover()
            self.l2sync.failover()

    def failover_loadbalancer(self, load_balancer_id):
        pass

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    @lockutils.synchronized("f5sync", fair=True)
    def add_loadbalancer(self, load_balancer_id):
        # forcing a loadbalancer sync even if it's not currently scheduled
        lb = self._loadbalancer_repo.get(db_apis.get_session(), id=load_balancer_id)
        if not lb:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'loadbalancer', load_balancer_id)
            raise db_exceptions.NoResultFound

        network_id = lb.vip.network_id
        LOG.debug("add_loadbalancer: force adding loadbalancer '%s' for tenant '%s'",
                  load_balancer_id, network_id)

        loadbalancers = self._get_all_loadbalancer(network_id)
        if load_balancer_id not in [_lb.id for _lb in loadbalancers]:
            loadbalancers.append(lb)

        selfips = list(chain.from_iterable(
            self.network_driver.ensure_selfips(loadbalancers, CONF.host, cleanup_orphans=False)))

        # If other LBs in the same network already exist on this host, just ensure correct selfips and subnet routes
        lbs_already_present = [lb for lb in loadbalancers if lb.id != load_balancer_id]
        if lbs_already_present:
            LOG.debug(f'Only syncing SelfIPs and subnet routes on network {network_id}')
            self.l2sync.sync_l2_selfips_and_subnet_routes_flow(selfips, network_id)
        else:
            LOG.debug(f'Running complete ensure_l2_flow on network {network_id}')
            self.l2sync.ensure_l2_flow(selfips, network_id)
        self.sync.tenant_update(network_id, selfips=selfips, loadbalancers=loadbalancers).raise_for_status()
        self.network_driver.invalidate_cache()
        return True

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    @lockutils.synchronized("f5sync", fair=True)
    def remove_loadbalancer(self, load_balancer_id):
        # forcing a loadbalancer sync even if it's not currently scheduled
        lb = self._loadbalancer_repo.get(db_apis.get_session(), id=load_balancer_id)
        if not lb:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'loadbalancer', load_balancer_id)
            raise db_exceptions.NoResultFound

        network_id = lb.vip.network_id
        LOG.debug("remove_loadbalancer: force removing loadbalancer '%s' for tenant '%s'",
                  load_balancer_id, network_id)

        # all LBs on this device, including the one to be removed
        loadbalancers = self._get_all_loadbalancer(network_id)
        selfips = list(chain.from_iterable(
            self.network_driver.ensure_selfips(loadbalancers, CONF.host, cleanup_orphans=False)))

        loadbalancers_remaining = [lb for lb in loadbalancers if lb.id != load_balancer_id]
        if loadbalancers_remaining:
            # if there are still load balancers we only need to sync SelfIPs and subnet routes

            selfips_remaining = list(chain.from_iterable(
                self.network_driver.ensure_selfips(loadbalancers_remaining, CONF.host, cleanup_orphans=False)))

            # provision the rest to the device
            self.l2sync.sync_l2_selfips_and_subnet_routes_flow(selfips_remaining, network_id)
            self.sync.tenant_update(
                network_id, selfips=selfips_remaining, loadbalancers=loadbalancers_remaining).raise_for_status()

            # If the subnet of the LB to be removed is now empty, remove the unneeded SelfIP ports. Since they are not
            # considered orphaned (they aren't even considered by ensure_selfips because the subnet is gone) they need
            # to be determined by comparing SelfIP ports for all LBs with those of the remaining LBs.
            selfips_to_delete = [sip for sip in selfips if sip not in selfips_remaining]
            for selfip in selfips_to_delete:
                LOG.info(f'Deleting unneeded SelfIP port {selfip.id} "{selfip.name}"')
            self.network_driver.cleanup_selfips(selfips_to_delete)

        else:
            # this was the last load balancer - delete everything
            self.sync.tenant_delete(network_id).raise_for_status()
            self.l2sync.remove_l2_flow(network_id)
            self.network_driver.cleanup_selfips(selfips)

        # invalidate cache so that workers forget about the old host
        self.network_driver.invalidate_cache()
        return True

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

    @oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
    def register_in_availability_zone(self, az_name):
        """
        Register this worker to an availability zone by creating/modifying the corresponding DB entry.

        An AZ can have multiple workers (multiple F5 device-pairs), so the worker hosts are set in the
        corresponding availability zone profile metadata as a json array.
        """
        with db_apis.get_lock_session() as lock_session:
            az = self._az_repo.get(lock_session, name=az_name)
            if az:
                metadata = self._az_repo.get_availability_zone_metadata_dict(lock_session, az_name)
                hosts = metadata.get('hosts', [])
                if not CONF.host in hosts:
                    # add host to availibility zone profile metadata
                    hosts.append(CONF.host)
                    self._azp_repo.update(lock_session, id=az.availability_zone_profile_id,
                                          availability_zone_data=json.dumps({'hosts': hosts}))
            else:
                # Create availability zone and availability zone profile with current host
                azp_dict = {
                    'id': uuidutils.generate_uuid(),
                    'name': az_name,
                    'provider_name': 'f5',
                    'availability_zone_data': json.dumps({'hosts': [CONF.host]})
                }
                self._azp_repo.create(lock_session, **azp_dict)
                az_dict = {
                    'name': az_name,
                    'description': az_name,
                    'enabled': True,
                    'availability_zone_profile_id': azp_dict['id']
                }
                self._az_repo.create(lock_session, **az_dict)
