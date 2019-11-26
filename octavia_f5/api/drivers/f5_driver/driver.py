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

import oslo_messaging as messaging
from oslo_config import cfg
from oslo_log import log as logging

from octavia_lib.api.drivers import provider_base as driver_base
from octavia_lib.api.drivers import exceptions
from octavia_f5.common import constants as consts

CONF = cfg.CONF
CONF.import_group('oslo_messaging', 'octavia.common.config')
LOG = logging.getLogger(__name__)


class F5ProviderDriver(driver_base.ProviderDriver):
    """Octavia plugin for the F5 driver."""
    def __init__(self):
        super(F5ProviderDriver, self).__init__()
        topic = cfg.CONF.oslo_messaging.topic
        self.transport = messaging.get_rpc_transport(cfg.CONF)
        self.target = messaging.Target(
            namespace=consts.RPC_NAMESPACE_CONTROLLER_AGENT,
            topic=topic, version="1.0", fanout=False)
        self.client = messaging.RPCClient(self.transport, target=self.target)

    def _refresh(self, project_id):
        payload = {consts.PROJECT_ID: project_id}
        self.client.cast({}, 'refresh', **payload)

    # Load Balancer
    def create_vip_port(self, loadbalancer_id, project_id, vip_dictionary):
        """Returns dictionary populated by neutron L2 driver for F5."""
        return vip_dictionary

    def loadbalancer_create(self, loadbalancer):
        self._refresh(loadbalancer.project_id)

    def loadbalancer_delete(self, loadbalancer, cascade=False):
        # TODO also delete neutron port
        self._refresh(loadbalancer.project_id)

    def loadbalancer_failover(self, loadbalancer_id):
        raise exceptions.NotImplementedError()

    def loadbalancer_update(self, old_loadbalancer, new_loadbalancer):
        self._refresh(old_loadbalancer.project_id)

    # Listener
    def listener_create(self, listener):
        self._refresh(listener.project_id)

    def listener_delete(self, listener):
        self._refresh(listener.project_id)

    def listener_update(self, old_listener, new_listener):
        self._refresh(new_listener.project_id)

    # Pool
    def pool_create(self, pool):
        self._refresh(pool.project_id)

    def pool_delete(self, pool):
        self._refresh(pool.project_id)

    def pool_update(self, old_pool, new_pool):
        self._refresh(new_pool.project_id)

    # Member
    def member_create(self, member):
        self._refresh(member.project_id)

    def member_delete(self, member):
        self._refresh(member.project_id)

    def member_update(self, old_member, new_member):
        self._refresh(new_member.project_id)

    def member_batch_update(self, members):
        self._refresh(members[0].project_id)

    # Health Monitor
    def health_monitor_create(self, healthmonitor):
        self._refresh(healthmonitor.project_id)

    def health_monitor_delete(self, healthmonitor):
        self._refresh(healthmonitor.project_id)

    def health_monitor_update(self, old_healthmonitor, new_healthmonitor):
        self._refresh(new_healthmonitor.project_id)

    # L7 Policy
    def l7policy_create(self, l7policy):
        self._refresh("e9141fb24eee4b3e9f25ae69cda31132")

    def l7policy_delete(self, l7policy):
        self._refresh(l7policy.project_id)

    def l7policy_update(self, old_l7policy, new_l7policy):
        self._refresh("e9141fb24eee4b3e9f25ae69cda31132")

    # L7 Rule
    def l7rule_create(self, l7rule):
        self._refresh("e9141fb24eee4b3e9f25ae69cda31132")

    def l7rule_delete(self, l7rule):
        self._refresh(l7rule.project_id)

    def l7rule_update(self, old_l7rule, new_l7rule):
        self._refresh("e9141fb24eee4b3e9f25ae69cda31132x`")

    # Flavor
    def get_supported_flavor_metadata(self):
        raise exceptions.NotImplementedError()

    def validate_flavor(self, flavor_metadata):
        raise exceptions.NotImplementedError()
