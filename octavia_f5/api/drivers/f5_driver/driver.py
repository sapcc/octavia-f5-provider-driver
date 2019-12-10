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

from octavia.common import data_models
from octavia.db import repositories, api
from octavia_f5.utils import driver_utils
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
        # Replace with entity query API in Train+
        self.repositories = repositories.Repositories()

    def _get_lb_project_id(self, session, id):
        """Get a load balancer from the database."""
        lb = self.repositories.load_balancer.get(session, id=id)
        if not lb:
            LOG.exception('%(name)s %(id)s not found',
                          {'name': data_models.LoadBalancer._name(),
                           'id': id})
            raise exceptions.DriverError('Failed fetching loadbalancer {}'.format(id))
        return lb.project_id

    def _get_pool(self, session, id):
        """Get a member from the database."""
        pool = self.repositories.pool.get(session, id=id)
        if not pool:
            LOG.exception('%(name)s %(id)s not found',
                          {'name': data_models.Member._name(),
                           'id': id})
            raise exceptions.DriverError('Failed fetching member {}'.format(id))
        return pool

    def _get_listener(self, session, id):
        """Get a listener from the database."""
        listener = self.repositories.listener.get(session, id=id)
        if not listener:
            LOG.exception('%(name)s %(id)s not found',
                          {'name': data_models.Listener._name(),
                           'id': id})
            raise exceptions.DriverError('Failed fetching listener {}'.format(id))
        return listener

    def _get_l7policy(self, session, id):
        """Get a listener from the database."""
        l7policy = self.repositories.l7policy.get(session, id=id)
        if not l7policy:
            LOG.exception('%(name)s %(id)s not found',
                          {'name': data_models.L7Policy._name(),
                           'id': id})
            raise exceptions.DriverError('Failed fetching l7policy {}'.format(id))
        return l7policy

    def _refresh(self, project_id):
        payload = {consts.PROJECT_ID: project_id}
        self.client.cast({}, 'refresh', **payload)

    # Load Balancer
    def create_vip_port(self, loadbalancer_id, project_id, vip_dictionary):
        # Let Octavia create the port
        raise exceptions.NotImplementedError()

    def loadbalancer_create(self, loadbalancer):
        self._refresh(loadbalancer.project_id)

    def loadbalancer_delete(self, loadbalancer, cascade=False):
        network = driver_utils.get_network_driver()
        vip_obj = driver_utils.lb_to_vip_obj(loadbalancer)
        network.deallocate_vip(vip_obj)
        self._refresh(loadbalancer.project_id)

    def loadbalancer_failover(self, loadbalancer_id):
        raise exceptions.NotImplementedError()

    def loadbalancer_update(self, old_loadbalancer, new_loadbalancer):
        self._refresh(old_loadbalancer.project_id)

    # Listener
    def listener_create(self, listener):
        project_id = self._get_lb_project_id(
            api.get_session(), listener.loadbalancer_id)
        self._refresh(project_id)

    def listener_delete(self, listener):
        project_id = self._get_lb_project_id(
            api.get_session(), listener.loadbalancer_id)
        self._refresh(project_id)

    def listener_update(self, old_listener, new_listener):
        project_id = self._get_lb_project_id(
            api.get_session(), new_listener.loadbalancer_id)
        self._refresh(project_id)

    # Pool
    def pool_create(self, pool):
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    def pool_delete(self, pool):
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    def pool_update(self, old_pool, new_pool):
        project_id = self._get_lb_project_id(
            api.get_session(), new_pool.loadbalancer_id)
        self._refresh(project_id)

    # Member
    def member_create(self, member):
        pool = self._get_pool(
            api.get_session(), member.pool_id)
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    def member_delete(self, member):
        pool = self._get_pool(
            api.get_session(), member.pool_id)
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    def member_update(self, old_member, new_member):
        pool = self._get_pool(
            api.get_session(), new_member.pool_id)
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    def member_batch_update(self, members):
        pool = self._get_pool(
            api.get_session(), members[0].pool_id)
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    # Health Monitor
    def health_monitor_create(self, healthmonitor):
        pool = self._get_pool(
            api.get_session(), healthmonitor.pool_id)
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    def health_monitor_delete(self, healthmonitor):
        pool = self._get_pool(
            api.get_session(), healthmonitor.pool_id)
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    def health_monitor_update(self, old_healthmonitor, new_healthmonitor):
        pool = self._get_pool(
            api.get_session(), new_healthmonitor.pool_id)
        project_id = self._get_lb_project_id(
            api.get_session(), pool.loadbalancer_id)
        self._refresh(project_id)

    # L7 Policy
    def l7policy_create(self, l7policy):
        self._refresh("e9141fb24eee4b3e9f25ae69cda31132")

    def l7policy_delete(self, l7policy):
        listener = self._get_listener(
            api.get_session(), l7policy.listener_id)
        project_id = self._get_lb_project_id(
            api.get_session(), listener.loadbalancer_id)
        self._refresh(project_id)

    def l7policy_update(self, old_l7policy, new_l7policy):
        self._refresh("e9141fb24eee4b3e9f25ae69cda31132")

    # L7 Rule
    def l7rule_create(self, l7rule):
        self._refresh("e9141fb24eee4b3e9f25ae69cda31132")

    def l7rule_delete(self, l7rule):
        l7policy = self._get_l7policy(
            api.get_session(), l7rule.l7policy_id)
        listener = self._get_listener(
            api.get_session(), l7policy.listener_id)
        project_id = self._get_lb_project_id(
            api.get_session(), listener.loadbalancer_id)
        self._refresh(project_id)

    def l7rule_update(self, old_l7rule, new_l7rule):
        self._refresh("e9141fb24eee4b3e9f25ae69cda31132x`")

    # Flavor
    def get_supported_flavor_metadata(self):
        raise exceptions.NotImplementedError()

    def validate_flavor(self, flavor_metadata):
        raise exceptions.NotImplementedError()
