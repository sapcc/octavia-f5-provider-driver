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
import prometheus_client as prometheus
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from stevedore import driver as stevedore_driver

from octavia.db import api as db_api
from octavia.db import repositories as repo
from octavia_f5.common import constants
from octavia_f5.restclient.as3restclient import BigipAS3RestClient, authorized

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


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


class StatusManager(BigipAS3RestClient):
    def __init__(self):
        super(StatusManager, self).__init__(bigip_urls=CONF.f5_agent.bigip_urls,
                                            enable_verify=CONF.f5_agent.bigip_verify,
                                            enable_token=CONF.f5_agent.bigip_token)
        self.seq = 0
        LOG.info('Health Manager Sender starting.')
        self.amp_repo = repo.AmphoraRepository()
        self.amp_health_repo = repo.AmphoraHealthRepository()
        self.lb_repo = repo.LoadBalancerRepository()
        self.health_executor = futurist.ThreadPoolExecutor(
            max_workers=CONF.health_manager.health_update_threads)
        self.stats_executor = futurist.ThreadPoolExecutor(
            max_workers=CONF.health_manager.stats_update_threads)

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

    @authorized
    def get(self, **kwargs):
        path = self._url('mgmt/{}'.format(kwargs.pop('path')))
        LOG.debug("Calling GET '%s'", path)
        return self.session.get(path, **kwargs)

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

    @_metric_heartbeat_exceptions.count_exceptions()
    @_metric_heartbeat_duration.time()
    def heartbeat(self):
        """Sends heartbeat and status information to running octavia healthmanager via UDP. The format can be seen in
        octavia.amphorae.drivers.health.heartbeat_udp.UDPStatusGetter.dorecv.
        Scrapes Virtual, Pool and Pool Member statistics and status\.
        Also updates listener_count for amphora database via update_listener_count() function. This is needed for
        scheduling decisions.
        """
        self._metric_heartbeat.inc()

        # Check availability of all devices
        for device in self.bigips:
            device_name = device.hostname
            LOG.debug('Checking availability of device with URL {}'.format(device_name))
            timeout = CONF.f5_agent.availability_timeout

            # Try reaching device
            available = True
            try:
                self.get(path='', timeout=timeout)
            except Exception as e:
                available = False

            # Update database entry
            self.update_availability(device_name, available)

        # Check for failover
        device_json = self.get(path='/tm/cm/device').json()
        for device in device_json['items']:
            if device['name'] == self.active_bigip.hostname and device['failoverState'] != 'active':
                self._failover()
                return

        amphora_messages = {}
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
        vipstats = self.get(path='tm/ltm/virtual/stats').json()
        if 'entries' not in vipstats:
            self.update_listener_count(0)
            return

        self.update_listener_count(len(vipstats['entries'].keys()))
        for selfurl, statobj in vipstats['entries'].items():
            stats = statobj['nestedStats']['entries']

            listener_id = self._listener_from_path(stats['tmName'].get('description'))
            loadbalancer_id = self._loadbalancer_from_path(stats['tmName'].get('description'))
            status = constants.OPEN
            cur_conns = stats['clientside.curConns'].get('value')
            max_conns = stats['clientside.maxConns'].get('value')
            if max_conns != 0 and cur_conns >= max_conns:
                status = constants.FULL
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

        poolstats = self.get(path='tm/ltm/pool/stats').json()
        for selfurl, statobj in poolstats['entries'].items():
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
            members = self.get(path='tm/ltm/pool/{}/members'.format(sub_path)).json()
            memberstats = self.get(path='tm/ltm/pool/{}/members/stats'.format(sub_path)).json()
            for member in members['items']:
                if 'description' in member:
                    member_id = member['description']
                    base_path = memberstats['selfLink'][:memberstats['selfLink'].find('/stats')]
                    statobj = memberstats['entries'][
                        '{}/{}/stats'.format(base_path, member['fullPath'].replace('/', '~'))]
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
        lock_session = None
        try:
            lock_session = db_api.get_session(autocommit=False)
            device_name = self.active_bigip.hostname
            device_amp = self.amp_repo.get(lock_session,
                                           compute_flavor=CONF.host,
                                           load_balancer_id=None,
                                           cached_zone=device_name)
            if not device_amp:
                device_amp = self.amp_repo.create(
                    lock_session,
                    compute_flavor=CONF.host,
                    status=constants.AMPHORA_READY,
                    vrrp_priority=num_listeners,
                    cached_zone=device_name)
            else:
                self.amp_repo.update(lock_session, device_amp.id,
                                     status=constants.AMPHORA_READY,
                                     vrrp_priority=num_listeners)
            lock_session.commit()
        except db_exc.DBDeadlock:
            LOG.debug('Database reports deadlock. Skipping.')
            lock_session.rollback()
        except db_exc.RetryRequest:
            LOG.debug('Database is requesting a retry. Skipping.')
            lock_session.rollback()
        except Exception:
            with excutils.save_and_reraise_exception():
                if lock_session:
                    lock_session.rollback()

    def update_availability(self, device_name, available):
        """ updates availability status of bigip device (status column in amphora table).
        The value will be READY if the device is available or ALLOCATED if it is not.

        :param available: whether the device is available or not
        """
        lock_session = None

        # determine status
        status = constants.AMPHORA_READY
        if not available:
            status = constants.AMPHORA_ALLOCATED

        # update table entry
        try:
            lock_session = db_api.get_session(autocommit=False)
            device_amp = self.amp_repo.get(lock_session,
                                           compute_flavor=CONF.host,
                                           load_balancer_id=None,
                                           cached_zone=device_name)
            if not device_amp:
                device_amp = self.amp_repo.create(
                    lock_session,
                    compute_flavor=CONF.host,
                    status=status,
                    cached_zone=device_name)
            else:
                self.amp_repo.update(lock_session, device_amp.id, status=status)
            lock_session.commit()
        except db_exc.DBDeadlock:
            LOG.debug('Database reports deadlock. Skipping.')
            lock_session.rollback()
        except db_exc.RetryRequest:
            LOG.debug('Database is requesting a retry. Skipping.')
            lock_session.rollback()
        except Exception:
            with excutils.save_and_reraise_exception():
                if lock_session:
                    lock_session.rollback()