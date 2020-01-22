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

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils

from octavia.amphorae.backends.health_daemon import health_sender
from octavia.db import api as db_api
from octavia.db import repositories as repo
from octavia_f5.common import constants
from octavia_f5.restclient.as3restclient import BigipAS3RestClient, authorized

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class StatusManager(BigipAS3RestClient):
    def __init__(self, exit_event):
        super().__init__(bigip_url=CONF.f5_agent.bigip_url,
                         enable_verify=CONF.f5_agent.bigip_verify,
                         enable_token=CONF.f5_agent.bigip_token)
        self.amphora_id = None
        self.seq = 0
        self.dead = exit_event
        LOG.info('Health Manager Sender starting.')
        self.sender = health_sender.UDPStatusSender()
        self.amp_repo = repo.AmphoraRepository()
        self.amp_health_repo = repo.AmphoraHealthRepository()
        self.lb_repo = repo.LoadBalancerRepository()

    @authorized
    def get(self, **kwargs):
        path = self._url('mgmt/{}'.format(kwargs.pop('path')))
        LOG.debug("Calling GET '%s'", path)
        return self.session.get(path, **kwargs)

    @staticmethod
    def _listener_from_path(path):
        listener = path.split('/')[-1]
        return listener.replace(constants.PREFIX_LISTENER, '').replace('_', '-')

    @staticmethod
    def _pool_from_path(path):
        pool = path.split('/')[-1]
        return pool.replace(constants.PREFIX_POOL, '').replace('_', '-')

    @staticmethod
    def _loadbalancer_from_path(path):
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

    def heartbeat(self):
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

        vipstats = self.get(path='tm/ltm/virtual/stats').json()
        if 'entries' not in vipstats:
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
                    statobj = memberstats['entries']['{}/{}/stats'.format(base_path, member['fullPath'].replace('/', '~'))]
                    stats = statobj['nestedStats']['entries']
                    status = constants.NO_CHECK
                    if stats['status.enabledState'].get('description') == 'disabled':
                        status = constants.DRAIN
                    if stats['monitorStatus'].get('description') == 'down':
                        status = constants.DOWN
                    elif stats['monitorStatus'].get('description') == 'up':
                        status = constants.UP
                    msg['pools'][pool_id]['members'][member_id] = status

        for msg in amphora_messages.values():
            msg['recv_time'] = time.time()
            self.sender.dosend(msg)

    def update_listener_count(self, num_listeners):
        lock_session = None
        try:
            lock_session = db_api.get_session(autocommit=False)
            device_amp = self.amp_repo.get(lock_session,
                                           compute_flavor=self.bigip.hostname,
                                           load_balancer_id=None)
            if not device_amp:
                device_amp = self.amp_repo.create(
                    lock_session,
                    compute_flavor=self.bigip.hostname,
                    status=constants.ACTIVE,
                    vrrp_priority=num_listeners)
            else:
                self.amp_repo.update(lock_session, device_amp.id,
                                     status=constants.ACTIVE,
                                     vrrp_priority=num_listeners)
            self.amphora_id = device_amp.id
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
