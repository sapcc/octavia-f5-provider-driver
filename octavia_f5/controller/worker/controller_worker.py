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

import threading
import time

import prometheus_client as prometheus
import tenacity
from futurist import periodics
from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from requests import HTTPError
from six.moves.queue import Empty
from sqlalchemy.orm import exc as db_exceptions

from octavia.api.drivers import data_models as driver_dm
from octavia.api.drivers import utils as api_driver_utils
from octavia.common import clients
from octavia.common import constants as api_consts
from octavia.db import repositories as repo
from octavia_f5.api.drivers.f5_driver.driver import F5ProviderDriver
from octavia_f5.common import constants
from octavia_f5.controller.worker import status_manager, sync_manager
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
        self._quota_repo = repo.QuotasRepository()

        self.status = status_manager.StatusManager()
        self.sync = sync_manager.SyncManager(self.status, self._loadbalancer_repo)
        self.network_driver = driver_utils.get_network_driver()
        self.queue = SetQueue()
        worker = periodics.PeriodicWorker(
            [(self.pending_sync, None, None),
             (self.full_sync_reappearing_devices, None, None),
             (self.cleanup_orphaned_tenants, None, None)]
        )
        t = threading.Thread(target=worker.start)
        t.daemon = True
        t.start()

        LOG.info("Starting as3worker")
        as3worker = threading.Thread(target=self.as3worker)
        as3worker.setDaemon(True)
        as3worker.start()

        if cfg.CONF.f5_agent.prometheus:
            prometheus_port = CONF.f5_agent.prometheus_port
            LOG.info('Starting Prometheus HTTP server on port {}'.format(prometheus_port))
            prometheus.start_http_server(prometheus_port)

        super(ControllerWorker, self).__init__()

    def as3worker(self):
        """ AS3 Worker thread, pops tenant to refresh from thread-safe set queue"""
        while True:
            try:
                self._metric_as3worker_queue.labels(octavia_host=CONF.host).set(self.queue.qsize())
                network_id, device = self.queue.get()
                loadbalancers = self._get_all_loadbalancer(network_id)
                LOG.debug("AS3Worker after pop (queue_size=%d): Refresh tenant '%s' with loadbalancer %s",
                          self.queue.qsize(), network_id, [lb.id for lb in loadbalancers])
                if all([lb.provisioning_status == lib_consts.PENDING_DELETE for lb in loadbalancers]):
                    ret = self.sync.tenant_delete(network_id, device)
                else:
                    ret = self.sync.tenant_update(network_id, device)

                if not ret:
                    continue

                # update status of just-synced LBs
                self.status.update_status(loadbalancers)
                for lb in loadbalancers:
                    self._reset_in_use_quota(lb.project_id)

            except Empty:
                # Queue empty, pass
                pass
            except (exceptions.RetryException, tenacity.RetryError) as e:
                LOG.warning("Device is busy, retrying with next sync: %s", e)
                time.sleep(15)
            except Exception as e:
                LOG.exception(e)
                # restart
                pass

    @periodics.periodic(86400, run_immediately=True)
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

    @periodics.periodic(240, run_immediately=True)
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
            for network_id in set([lb.vip.network_id for lb in lbs]):
                self.queue.put((network_id, device.cached_zone))

            # Set device ready
            self._amphora_repo.update(session, device.id, status=constants.AMPHORA_READY)
            session.commit()

    @periodics.periodic(120, run_immediately=True)
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
        pending_networks = set([lb.vip.network_id for lb in lbs])
        for network_id in pending_networks:
            self.queue.put_nowait((network_id, None))

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _get_all_loadbalancer(self, network_id):
        LOG.debug("Get load balancers from DB for network id: %s ", network_id)
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
    def create_load_balancer(self, load_balancer_id, flavor=None):
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

    def failover_loadbalancer(self, load_balancer_id):
        pass

    def migrate_loadbalancer(self, load_balancer_id, target_host):
        self._migrate(load_balancer_id, None, target_host)

    def migrate_loadbalancers(self, source_host, target_host):
        self._migrate(None, source_host, target_host)

    def _migrate(self, load_balancer_id, from_host, target_host):
        """Failover a load balancer or all load balancers from a specified host.

        If from_host is None, failover only load balancer specified by load_balancer_id to target_host.
        Else failover every load balancer from from_host to target_host.
        """

        neutron_client = clients.NeutronAuth.get_neutron_client(
            endpoint=CONF.neutron.endpoint,
            region=CONF.neutron.region_name,
            endpoint_type=CONF.neutron.endpoint_type,
            service_name=CONF.neutron.service_name,
            insecure=CONF.neutron.insecure,
            ca_cert=CONF.neutron.ca_certificates_file
        )

        # check arguments and get load balancer(s) to failover
        if from_host is None:
            # if from_host is unspecified, move only this one LB
            # TODO: Is calling get_session each time okay? Or should I store it in a variable?
            lb = self._loadbalancer_repo.get(db_apis.get_session(), id=load_balancer_id);
            if lb.server_group_id != CONF.host:
                return
            if target_host is None:
                LOG.error("Cannot move LB {}: No target host specified".format(load_balancer_id))
                return
            lbs = [lb]
        elif from_host != CONF.host:
            return # ignore requests not meant for this worker
        elif target_host is None:
            LOG.error("Cannot move LBs from this host: No target host specified".format(load_balancer_id))
            return
        else:
            # move all load balancers from this host
            lbs = self._loadbalancer_repo.get_all_from_host(db_apis.get_session())

        # create missing self IP ports
        LOG.info("Checking self IPs...")

        # find subnets that need self IPs on the target device
        # we will need two self IP ports per subnet - One per device in the device pair
        try:
            neutron_ports = neutron_client.list_ports()
        except Exception as e:
            LOG.error("LB migration: Cannot get ports from Neutron: {}".format(e))
            raise e
        selfip_ports = [port for port in neutron_ports.get('ports') if port['device_owner'] == "network:f5selfip"]
        subnets_needing_selfips = set([lb.vip.subnet_id for lb in lbs])

        # find subnets that already have self IPs on the target device
        subnets_with_selfips = []
        for port in selfip_ports:
            for ip in port['fixed_ips']:
                subnet_id = ip['subnet_id']
                if subnet_id in subnets_needing_selfips and subnet_id not in subnets_with_selfips:
                    subnets_with_selfips.append(subnet_id)

        # find subnets that don't have self IP ports on the target device yet and create needed ports
        for subnet in subnets_needing_selfips:
            if subnet not in subnets_with_selfips:
                # Create self IP port on A and B side
                for side in ['a','b']:
                    port_name = "local-{}{}-{}-{}.cc.{}.cloud.sap-{}".format(
                        CONF.neutron.region_name, side, target_host, CONF.f5_agent.network_segment_physical_network,
                        CONF.neutron.region_name, subnet.replace('_', '-'))
                    LOG.info("Creating self IP port with name {}, binding:host_id {}".format(port_name, target_host))
                    port = {'port': {'name': port_name,
                                     'admin_state_up': True,
                                     'device_owner': constants.DEVICE_OWNER_SELF_IP,
                                     'binding:host_id': target_host,
                                     }}
                    neutron_client.create_port(port)

        # start moving load balancers

        # set new host in database
        for lb in lbs:
            LOG.info("LB/Amphora {}: Changing host '{}' to '{}'.".format(lb.id, lb.server_group_id, target_host))
            self._amphora_repo.update(db_apis.get_session(), lb.id, compute_flavor=target_host)
            self._loadbalancer_repo.update(db_apis.get_session(), lb.id, server_group_id=target_host, provisioning_status=constants.PENDING_CREATE)

        # Retrying without limit is okay, since this process is always invoked manually and thus observed by a human.
        # When said human sees a load balancer being stuck, they can then fix it without having to restart this program.
        @tenacity.retry()
        def wait_for_active_lb(lb_id):
            lb = self._loadbalancer_repo.get(db_apis.get_session(), id=load_balancer_id)
            assert (lb.provisioning_status == constants.ACTIVE)

        # Wait for load balancers to be created, then rebind their port. Note that some load balancers will be created
        # before others and thus will stay dormant until this loop tends to them. That should not pose a problem however,
        # since the old load balancers are still in place, still routing traffic.
        f5pd = F5ProviderDriver()
        for lb in lbs:
            # we must reimplement api.drivers.f5_driver.driver.F5ProviderDriver.loadbalancer_create because it selects
            # the wrong host to schedule to and needs another LB instance object than we have
            LOG.info("Telling worker of target host to create load balancer %s on host %s", lb.id, target_host)
            payload = {api_consts.LOAD_BALANCER_ID: lb.id, api_consts.FLAVOR: lb.flavor_id}
            client = f5pd.client.prepare(server=target_host)
            client.cast({}, 'create_load_balancer', **payload) # FIXME requested route domain not found => VLAN not synced

            # wait
            LOG.info("Waiting for load balancer '{}' to be created on new host '{}'...".format(lb.id, target_host))
            wait_for_active_lb(lb.id)

            # invalidate port bindings cached by hierarchical port binding driver
            self.network_driver.invalidate_cache()

            # rebind port
            port_update = {'port': {'binding:host_id': target_host}}
            neutron_client.update_port(lb.vip.port_id, port_update)

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
