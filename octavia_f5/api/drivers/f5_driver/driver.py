#    Copyright 2018 SAP SE
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
from oslo_log import log as logging

from octavia.api.drivers.amphora_driver import driver
from octavia.common import constants as consts
from octavia.db import api as db_apis
from octavia_f5.common import constants as f5_consts
from octavia_f5.utils import driver_utils
from octavia_lib.api.drivers import data_models as driver_dm
from octavia_lib.api.drivers import exceptions

CONF = cfg.CONF
CONF.import_group('oslo_messaging', 'octavia.common.config')
LOG = logging.getLogger(__name__)


class F5ProviderDriver(driver.AmphoraProviderDriver):
    """Octavia plugin for the F5 driver."""

    def __init__(self):
        super(F5ProviderDriver, self).__init__()

    def _get_server(self, loadbalancer_id):
        return getattr(
            self.repositories.amphora.get(
                db_apis.get_session(),
                load_balancer_id=loadbalancer_id,
                status=f5_consts.ACTIVE),
            'compute_flavor', None)

    def loadbalancer_create(self, loadbalancer):
        if loadbalancer.flavor == driver_dm.Unset:
            loadbalancer.flavor = None

        network_driver = driver_utils.get_network_driver()
        host = network_driver.get_scheduled_host(loadbalancer.vip_port_id)

        LOG.info("Scheduling loadbalancer %s to %s",
                 loadbalancer.loadbalancer_id,
                 host)
        payload = {consts.LOAD_BALANCER_ID: loadbalancer.loadbalancer_id,
                   consts.FLAVOR: loadbalancer.flavor}
        client = self.client.prepare(server=host)
        client.cast({}, 'create_load_balancer', **payload)

    def loadbalancer_delete(self, loadbalancer, cascade=False):
        loadbalancer_id = loadbalancer.loadbalancer_id
        payload = {consts.LOAD_BALANCER_ID: loadbalancer_id,
                   'cascade': cascade}
        client = self.client.prepare(server=self._get_server(loadbalancer_id))
        client.cast({}, 'delete_load_balancer', **payload)

    def loadbalancer_failover(self, loadbalancer_id):
        payload = {consts.LOAD_BALANCER_ID: loadbalancer_id}
        client = self.client.prepare(server=self._get_server(loadbalancer_id))
        client.cast({}, 'failover_load_balancer', **payload)

    def loadbalancer_update(self, old_loadbalancer, new_loadbalancer):
        lb_id = new_loadbalancer.loadbalancer_id
        payload = {consts.LOAD_BALANCER_ID: lb_id,
                   consts.LOAD_BALANCER_UPDATES: {}}
        client = self.client.prepare(server=self._get_server(lb_id))
        client.cast({}, 'update_load_balancer', **payload)

    # Listener
    def listener_create(self, listener):
        payload = {consts.LISTENER_ID: listener.listener_id}
        client = self.client.prepare(server=self._get_server(listener.loadbalancer_id))
        client.cast({}, 'create_listener', **payload)

    def listener_delete(self, listener):
        listener_id = listener.listener_id
        payload = {consts.LISTENER_ID: listener_id}
        client = self.client.prepare(server=self._get_server(listener.loadbalancer_id))
        client.cast({}, 'delete_listener', **payload)

    def listener_update(self, old_listener, new_listener):
        listener_id = old_listener.listener_id
        payload = {consts.LISTENER_ID: listener_id,
                   consts.LISTENER_UPDATES: {}}
        client = self.client.prepare(server=self._get_server(old_listener.loadbalancer_id))
        client.cast({}, 'update_listener', **payload)

    # Pool
    def pool_create(self, pool):
        payload = {consts.POOL_ID: pool.pool_id}
        client = self.client.prepare(server=self._get_server(pool.loadbalancer_id))
        client.cast({}, 'create_pool', **payload)

    def pool_delete(self, pool):
        pool_id = pool.pool_id
        payload = {consts.POOL_ID: pool_id}
        client = self.client.prepare(server=self._get_server(pool.loadbalancer_id))
        client.cast({}, 'delete_pool', **payload)

    def pool_update(self, old_pool, new_pool):
        pool_id = new_pool.pool_id
        payload = {consts.POOL_ID: pool_id,
                   consts.POOL_UPDATES: {}}
        client = self.client.prepare(server=self._get_server(old_pool.loadbalancer_id))
        client.cast({}, 'update_pool', **payload)

    # Member
    def member_create(self, member):
        db_pool = self.repositories.pool.get(db_apis.get_session(),
                                             id=member.pool_id)
        payload = {consts.MEMBER_ID: member.member_id}
        db_pool = self.repositories.pool.get(db_apis.get_session(), id=member.pool_id)
        client = self.client.prepare(server=self._get_server(db_pool.load_balancer_id))
        client.cast({}, 'create_member', **payload)

    def member_delete(self, member):
        db_pool = self.repositories.pool.get(db_apis.get_session(), id=member.pool_id)
        payload = {consts.MEMBER_ID: member.member_id}
        client = self.client.prepare(server=self._get_server(db_pool.load_balancer_id))
        client.cast({}, 'delete_member', **payload)

    def member_update(self, old_member, new_member):
        db_pool = self.repositories.pool.get(db_apis.get_session(), id=old_member.pool_id)
        payload = {consts.MEMBER_ID: new_member.member_id,
                   consts.MEMBER_UPDATES: {}}
        client = self.client.prepare(server=self._get_server(db_pool.load_balancer_id))
        client.cast({}, 'update_member', **payload)

    def member_batch_update(self, pool_id, members):
        db_pool = self.repositories.pool.get(db_apis.get_session(), id=pool_id)
        payload = {'old_member_ids': [],
                   'new_member_ids': [],
                   'updated_members': []}
        client = self.client.prepare(server=self._get_server(db_pool.loadbalancer_id))
        client.cast({}, 'batch_update_members', **payload)

    # Health Monitor
    def health_monitor_create(self, healthmonitor):
        db_pool = self.repositories.pool.get(db_apis.get_session(), id=healthmonitor.pool_id)
        payload = {consts.HEALTH_MONITOR_ID: healthmonitor.healthmonitor_id}
        client = self.client.prepare(server=self._get_server(db_pool.load_balancer_id))
        client.cast({}, 'create_health_monitor', **payload)

    def health_monitor_delete(self, healthmonitor):
        db_pool = self.repositories.pool.get(db_apis.get_session(), id=healthmonitor.pool_id)
        payload = {consts.HEALTH_MONITOR_ID: healthmonitor.healthmonitor_id}
        client = self.client.prepare(server=self._get_server(db_pool.load_balancer_id))
        client.cast({}, 'delete_health_monitor', **payload)

    def health_monitor_update(self, old_healthmonitor, new_healthmonitor):
        db_pool = self.repositories.pool.get(db_apis.get_session(), id=old_healthmonitor.pool_id)
        payload = {consts.HEALTH_MONITOR_ID: new_healthmonitor.healthmonitor_id,
                   consts.HEALTH_MONITOR_UPDATES: {}}
        client = self.client.prepare(server=self._get_server(db_pool.load_balancer_id))
        client.cast({}, 'update_health_monitor', **payload)

    # L7 Policy
    def l7policy_create(self, l7policy):
        db_listener = self.repositories.listener.get(db_apis.get_session(), id=l7policy.listener_id)
        payload = {consts.L7POLICY_ID: l7policy.l7policy_id}
        client = self.client.prepare(server=self._get_server(db_listener.load_balancer_id))
        client.cast({}, 'create_l7policy', **payload)

    def l7policy_delete(self, l7policy):
        db_listener = self.repositories.listener.get(db_apis.get_session(), id=l7policy.listener_id)
        payload = {consts.L7POLICY_ID: l7policy.l7policy_id}
        client = self.client.prepare(server=self._get_server(db_listener.load_balancer_id))
        client.cast({}, 'delete_l7policy', **payload)

    def l7policy_update(self, old_l7policy, new_l7policy):
        db_listener = self.repositories.listener.get(db_apis.get_session(), id=old_l7policy.listener_id)
        payload = {consts.L7POLICY_ID: new_l7policy.l7policy_id,
                   consts.L7POLICY_UPDATES: {}}
        client = self.client.prepare(server=self._get_server(db_listener.load_balancer_id))
        self.client.cast({}, 'update_l7policy', **payload)

    # L7 Rule
    def l7rule_create(self, l7rule):
        db_l7 = self.repositories.l7policy.get(db_apis.get_session(), id=l7rule.l7policy_id)

        payload = {consts.L7RULE_ID: l7rule.l7rule_id}
        client = self.client.prepare(server=self._get_server(db_l7.listener.load_balancer_id))
        client.cast({}, 'create_l7rule', **payload)

    def l7rule_delete(self, l7rule):
        db_l7 = self.repositories.l7policy.get(db_apis.get_session(), id=l7rule.l7policy_id)

        payload = {consts.L7RULE_ID: l7rule.l7rule_id}
        client = self.client.prepare(server=self._get_server(db_l7.listener.load_balancer_id))
        client.cast({}, 'delete_l7rule', **payload)

    def l7rule_update(self, old_l7rule, new_l7rule):
        db_l7 = self.repositories.l7policy.get(db_apis.get_session(), id=old_l7rule.l7policy_id)

        payload = {consts.L7RULE_ID: new_l7rule.l7rule_id,
                   consts.L7RULE_UPDATES: {}}
        client = self.client.prepare(server=self._get_server(db_l7.listener.load_balancer_id))
        client.cast({}, 'update_l7rule', **payload)

    def create_vip_port(self, loadbalancer_id, project_id, vip_dictionary):
        # Let Octavia create the port
        raise exceptions.NotImplementedError()

    def loadbalancer_failover(self, loadbalancer_id):
        raise exceptions.NotImplementedError()

    def get_supported_flavor_metadata(self):
        raise exceptions.NotImplementedError()

    def validate_flavor(self, flavor_metadata):
        raise exceptions.NotImplementedError()
