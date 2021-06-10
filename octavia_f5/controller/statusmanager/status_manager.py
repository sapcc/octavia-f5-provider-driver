# Copyright 2020 SAP SE
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

import time

import futurist
import oslo_messaging as messaging
import prometheus_client as prometheus
import requests
import sqlalchemy
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from stevedore import driver as stevedore_driver

from octavia.common import rpc
from octavia.common import constants as o_const
from octavia.db import api as db_api
from octavia.db import repositories as repo
from octavia_f5.common import constants
from octavia_f5.restclient.bigip import bigip_restclient, bigip_auth

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

F5_VIRTUAL_STATS = '/mgmt/tm/ltm/virtual/stats'
F5_POOL_STATS = '/mgmt/tm/ltm/pool/stats'
F5_POOL_MEMBERS = '/mgmt/tm/ltm/pool/{}/members'
F5_POOL_MEMBER_STATS = '/mgmt/tm/ltm/pool/{}/members/stats'


class DatabaseLockSession(object):
    """Provides a database session and rolls it back if an exception occured before exiting with-statement."""
    def __enter__(self):
        self._lock_session = db_api.get_session(autocommit=False)
        return self._lock_session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_tb is None:
            self._lock_session.commit()
        else:
            if isinstance(exc_type, db_exc.DBDeadlock):
                LOG.debug('Database reports deadlock. Skipping.')
                self._lock_session.rollback()
            elif isinstance(exc_type, db_exc.RetryRequest):
                LOG.debug('Database is requesting a retry. Skipping.')
                self._lock_session.rollback()
            else:
                with excutils.save_and_reraise_exception():
                    self._lock_session.rollback()


def update_health(obj):
    handler = stevedore_driver.DriverManager(
        namespace='octavia.amphora.health_update_drivers',
        name=CONF.health_manager.health_update_driver,
        invoke_on_load=True
    ).driver
    handler.update_health(obj, '127.0.0.1')


def update_stats(obj):
    handler = stevedore_driver.DriverManager(
        namespace='octavia.amphora.stats_update_drivers',
        name=CONF.health_manager.stats_update_driver,
        invoke_on_load=True
    ).driver
    handler.update_stats(obj, '127.0.0.1')


class StatusManager(object):
    def __init__(self):
        LOG.info('Health Manager starting.')
        self.seq = 0
        self.amp_repo = repo.AmphoraRepository()
        self.amp_health_repo = repo.AmphoraHealthRepository()
        self.lb_repo = repo.LoadBalancerRepository()
        self.health_executor = futurist.ThreadPoolExecutor(
            max_workers=CONF.health_manager.health_update_threads)
        self.stats_executor = futurist.ThreadPoolExecutor(
            max_workers=CONF.health_manager.stats_update_threads)
        self.bigips = [bigip for bigip in self.initialize_bigips()]
        # Cache reachability of every bigip
        self.bigip_status = {bigip.hostname: False
                             for bigip in self.bigips}
        self._active_bigip = None
        self._last_failover_check = 0
        self._last_cleanup_check = 0

        # Create RPC Client
        topic = cfg.CONF.oslo_messaging.topic
        self.target = messaging.Target(
            namespace=o_const.RPC_NAMESPACE_CONTROLLER_AGENT,
            topic=topic, version="1.0", fanout=False)
        self.client = rpc.get_client(self.target)

        if cfg.CONF.f5_agent.prometheus:
            prometheus_port = CONF.f5_agent.prometheus_port
            LOG.info('Starting Prometheus HTTP server on port {}'.format(prometheus_port))
            prometheus.start_http_server(prometheus_port)

    _metric_heartbeat = prometheus.metrics.Counter(
        'octavia_status_heartbeat', 'The amount of heartbeats sent')
    _metric_heartbeat_duration = prometheus.metrics.Summary(
        'octavia_status_heartbeat_duration', 'Time it needs for one heartbeat')
    _metric_heartbeat_exceptions = prometheus.metrics.Counter(
        'octavia_status_heartbeat_exceptions', 'Number of exceptions at heartbeat')
    _metric_failover = prometheus.metrics.Counter(
        'octavia_status_failover', 'Number of failovers')

    def initialize_bigips(self):
        for bigip_url in CONF.f5_agent.bigip_urls:
            # Create REST client for every bigip

            if CONF.f5_agent.bigip_token:
                auth = bigip_auth.BigIPTokenAuth(bigip_url)
            else:
                auth = bigip_auth.BigIPBasicAuth(bigip_url)

            yield(
                bigip_restclient.BigIPRestClient(
                    bigip_url=bigip_url,
                    auth=auth,
                    verify=CONF.f5_agent.bigip_verify)
            )

    @staticmethod
    def _listener_from_path(path):
        """Extract the listener ID from a BigIP path"""
        listener = path.split('/')[-1]
        return listener.replace(constants.PREFIX_LISTENER, '').replace('_', '-')

    @staticmethod
    def _pool_from_path(path):
        """Extract the pool ID from a BigIP path"""
        pool = path.split('/')[-1]
        return pool.replace(constants.PREFIX_POOL, '').replace('_', '-')

    @staticmethod
    def _loadbalancer_from_path(path):
        """Extract the load balancer ID from a BigIP path"""
        pool = path.split('/')[2]
        return pool.replace(constants.PREFIX_LOADBALANCER, '').replace('_', '-')

    @staticmethod
    def _dict_from_pool_path(path):
        _, partition, subpath, pool = path.split('/')
        return {
            'partition': partition,
            'subPath': subpath,
            'name': pool
        }

    @property
    def bigip(self):
        """
        returns AS3RestClient instance for currently active bigip

        :rtype: AS3RestClient
        """
        if not self._active_bigip:
            # Always set one bigip even none of them are active
            self._active_bigip = self.bigips[0]
            for b in self.bigips:
                if b.is_active:
                    self._active_bigip = b

        return self._active_bigip

    def failover_check(self):
        """ We assume that the current active and reachable device (self._active_bigip) is active,
            If it's not the case, a failover happend.
        """
        if self.bigip_status[self.bigip.hostname] and not self.bigip.is_active:
            self._metric_failover.inc()
            self._active_bigip = None
            # Update Amphora master/backup entry
            self.update_availability()

            LOG.info("Sending failover event for %s to the rpc queue", CONF.host)
            payload = {'amphora_id': CONF.host}
            client = self.client.prepare(server=CONF.host)
            client.cast({}, 'failover_amphora', **payload)

    def availability_check(self):
        # Check availability of all devices
        for bigip in self.bigips:
            LOG.debug('Checking availability of device with URL {}'.format(bigip.hostname))
            timeout = CONF.status_manager.failover_timeout

            # Try reaching device
            available = True
            try:
                requests.get(bigip.scheme + '://' + bigip.hostname,
                             timeout=timeout, verify=False)
            except requests.exceptions.Timeout:
                LOG.info('Device timed out, considering it unavailable. Timeout: {}s Hostname: {}'.format(
                         timeout, bigip.hostname))
                available = False

            if self.bigip_status[bigip.hostname] != available:
                # Update database entry
                self.bigip_status[bigip.hostname] = available
                self.update_availability()

    @_metric_heartbeat_exceptions.count_exceptions()
    @_metric_heartbeat_duration.time()
    def heartbeat(self):
        """Sends heartbeat and status information to healthmanager api. The format is specified in
        octavia.amphorae.drivers.health.heartbeat_udp.UDPStatusGetter.dorecv.
        Scrapes Virtual, Pool and Pool Member statistics and status.
        Also updates listener_count for amphora database via update_listener_count() function. This is needed for
        scheduling decisions.
        """
        amphora_messages = {}

        self._metric_heartbeat.inc()
        if time.time() - self._last_failover_check >= CONF.status_manager.failover_check_interval:
            self._last_failover_check = time.time()
            self.availability_check()
            self.failover_check()

        if time.time() - self._last_cleanup_check >= CONF.status_manager.cleanup_check_interval:
            self._last_cleanup_check = time.time()
            self.cleanup()

        def _get_lb_msg(lb_id):
            if lb_id not in amphora_messages:
                amphora_messages[lb_id] = {
                    'id': lb_id,
                    'seq': 0,
                    'listeners': {},
                    'pools': {},
                    'ver': 2
                }
            return amphora_messages[lb_id]

        # update listener count
        vipstats = self.bigip.get(path=F5_VIRTUAL_STATS).json()
        if 'entries' not in vipstats:
            self.update_listener_count(0)
            return

        self.update_listener_count(len(vipstats['entries'].keys()))
        for selfurl, statobj in vipstats['entries'].items():
            stats = statobj['nestedStats']['entries']

            listener_id = self._listener_from_path(stats['tmName'].get('description'))
            loadbalancer_id = self._loadbalancer_from_path(stats['tmName'].get('description'))
            status = constants.OPEN
            _get_lb_msg(loadbalancer_id)['listeners'][listener_id] = {
                'status': status,
                'stats': {
                    'tx': stats['clientside.bitsOut'].get('value'),
                    'rx': stats['clientside.bitsIn'].get('value'),
                    'conns': stats['clientside.curConns'].get('value'),
                    'totconns': stats['clientside.totConns'].get('value'),
                    'ereq': stats['clientside.slowKilled'].get('value'),
                }
            }

        poolstats = self.bigip.get(path=F5_POOL_STATS).json()
        for selfurl, statobj in poolstats.get('entries', {}).items():
            stats = statobj['nestedStats']['entries']

            pool_id = self._pool_from_path(stats['tmName'].get('description'))
            loadbalancer_id = self._loadbalancer_from_path(stats['tmName'].get('description'))
            status = constants.UP
            availability = stats['status.availabilityState'].get('description')
            if availability == 'offline':
                status = constants.DOWN
            msg = _get_lb_msg(loadbalancer_id)
            msg['pools'][pool_id] = {
                'status': status,
                'members': {}
            }

            sub_path = stats['tmName'].get('description').replace('/', '~')
            members = self.bigip.get(path=F5_POOL_MEMBERS.format(sub_path)).json()
            memberstats = self.bigip.get(path=F5_POOL_MEMBER_STATS.format(sub_path)).json()
            for member in members.get('items', []):
                if 'description' in member:
                    member_id = member['description']
                    base_path = memberstats['selfLink'][:memberstats['selfLink'].find('/stats')]
                    member_path = '{}/{}/stats'.format(base_path, member['fullPath'].replace('/', '~'))
                    if member_path in memberstats['entries']:
                        statobj = memberstats['entries'][member_path]
                        stats = statobj['nestedStats']['entries']
                        status = constants.NO_CHECK
                        if stats['status.enabledState'].get('description') == 'disabled':
                            status = constants.DRAIN
                        elif stats['monitorStatus'].get('description') == 'checking':
                            status = constants.MAINT
                        elif stats['monitorStatus'].get('description') == 'down':
                            status = constants.DOWN
                        elif stats['monitorStatus'].get('description') == 'up':
                            status = constants.UP
                        msg['pools'][pool_id]['members'][member_id] = status

        for msg in amphora_messages.values():
            msg['recv_time'] = time.time()
            self.health_executor.submit(update_health, msg)
            self.stats_executor.submit(update_stats, msg)

    def update_listener_count(self, num_listeners):
        """ updates listener count of bigip device (vrrp_priority column in amphora table)

        :param num_listeners: number of listener for the bigip device
        """
        with DatabaseLockSession() as session:
            device_name = self.bigip.hostname
            device_entry = self.amp_repo.get(session,
                                             compute_flavor=CONF.host,
                                             load_balancer_id=None,
                                             cached_zone=device_name)
            if not device_entry:
                self.amp_repo.create(
                    session,
                    compute_flavor=CONF.host,
                    vrrp_priority=num_listeners,
                    cached_zone=device_name,
                    status=constants.AMPHORA_ALLOCATED)
            else:
                self.amp_repo.update(
                    session,
                    device_entry.id,
                    vrrp_priority=num_listeners)

    def update_availability(self):
        """ updates availability status of bigip device (status column in amphora table).
        The values for 'status' are used as follows:
        - 'READY': Device is online, everything is ok.
        - 'ALLOCATED': Device is offline.
        - 'BOOTING': Device is online but needs a full sync, because it was offline before.
          It is the responsibility of the syncing mechanism to set the status to 'READY' again.
        """
        with DatabaseLockSession() as session:
            for bigip in self.bigips:
                amp_dict = {
                    'compute_flavor': CONF.host,
                    'load_balancer_id': None,
                    'cached_zone': bigip.hostname
                }

                # fetch table entry
                device_entry = self.amp_repo.get(session, **amp_dict)

                # determine status
                status = constants.AMPHORA_ALLOCATED  # offline if not available
                if self.bigip_status[bigip.hostname]:
                    status = constants.AMPHORA_READY  # back online if available
                    if device_entry is None or device_entry.status != constants.AMPHORA_READY:
                        status = constants.AMPHORA_BOOTING  # needs full sync if no DB entry or not yet marked as ready

                # update attributes
                amp_dict['status'] = status
                if bigip.is_active:
                    amp_dict['role'] = constants.ROLE_MASTER
                else:
                    amp_dict['role'] = constants.ROLE_BACKUP

                # create/modify entry
                if not device_entry:
                    self.amp_repo.create(session, **amp_dict)
                else:
                    self.amp_repo.update(session, device_entry.id, **amp_dict)

    def cleanup(self):
        """ Deletes old amphora entries whose load balancers don't exist anymore.
        See controller_worker.ensure_amphora_exists for details.
        """
        with DatabaseLockSession() as session:
            filters = {'load_balancer_id': None, 'cached_zone': None, 'compute_flavor': CONF.host,}
            try:
                self.amp_repo.delete(session, **filters)
            except sqlalchemy.exc.InvalidRequestError:
                pass
