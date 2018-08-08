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

from octavia.api.drivers import exceptions
from octavia.api.drivers import provider_base as driver_base
from octavia.api.drivers import utils as driver_utils
from octavia.common import constants as consts
from octavia.common import data_models
from octavia.common import utils
from octavia.network import base as network_base

CONF = cfg.CONF
CONF.import_group('oslo_messaging', 'octavia.common.config')
LOG = logging.getLogger(__name__)


class F5ProviderDriver(driver_base.ProviderDriver):
    def __init__(self):
        super(F5ProviderDriver, self).__init__()
        topic = cfg.CONF.oslo_messaging.topic
        self.transport = messaging.get_rpc_transport(cfg.CONF)
        self.target = messaging.Target(
            namespace=consts.RPC_NAMESPACE_CONTROLLER_AGENT,
            topic=topic, version="1.0", fanout=False)
        self.client = messaging.RPCClient(self.transport, target=self.target)

    # Load Balancer
    def create_vip_port(self, loadbalancer_id, project_id, vip_dictionary):
        vip_obj = driver_utils.provider_vip_dict_to_vip_obj(vip_dictionary)
        lb_obj = data_models.LoadBalancer(id=loadbalancer_id,
                                          project_id=project_id, vip=vip_obj)

        network_driver = utils.get_network_driver()
        try:
            vip = network_driver.allocate_vip(lb_obj)
        except network_base.AllocateVIPException as e:
            raise exceptions.DriverError(user_fault_string=e.orig_msg,
                                         operator_fault_string=e.orig_msg)

        LOG.info('Provider %s, created VIP port %s for load balancer %s.',
                 self.__class__.__name__, vip.port_id, loadbalancer_id)
        return driver_utils.vip_dict_to_provider_dict(vip.to_dict())

    def loadbalancer_create(self, loadbalancer):
        LOG.debug('Provider %s, loadbalancer_create loadbalancer %s',
                  self.__class__.__name__, loadbalancer.loadbalancer_id)

        payload = {consts.LOAD_BALANCER_ID: loadbalancer.loadbalancer_id}
        self.client.cast({}, 'create_load_balancer', **payload)

    def loadbalancer_delete(self, loadbalancer, cascade=False):
        loadbalancer_id = loadbalancer.loadbalancer_id
        LOG.debug('Provider %s, loadbalancer_delete loadbalancer %s',
                  self.__class__.__name__, loadbalancer_id)

        payload = {consts.LOAD_BALANCER_ID: loadbalancer_id,
                   'cascade': cascade}
        self.client.cast({}, 'delete_load_balancer', **payload)

    def loadbalancer_update(self, old_loadbalancer, new_loadbalancer):
        # Adapt the provider data model to the queue schema
        lb_dict = new_loadbalancer.to_dict()
        if 'admin_state_up' in lb_dict:
            lb_dict['enabled'] = lb_dict.pop('admin_state_up')
        lb_id = lb_dict.pop('loadbalancer_id')
        LOG.debug('Provider %s, loadbalancer_update loadbalancer %s',
                  self.__class__.__name__, lb_id)

        # Put the qos_policy_id back under the vip element the controller
        # expects
        vip_qos_policy_id = lb_dict.pop('vip_qos_policy_id', None)
        if vip_qos_policy_id:
            vip_dict = {"qos_policy_id": vip_qos_policy_id}
            lb_dict["vip"] = vip_dict

        payload = {consts.LOAD_BALANCER_ID: lb_id,
                   consts.LOAD_BALANCER_UPDATES: lb_dict}
        self.client.cast({}, 'update_load_balancer', **payload)

    # Listener
    def listener_create(self, listener):
        payload = {consts.LISTENER_ID: listener.listener_id}
        self.client.cast({}, 'create_listener', **payload)

    def listener_delete(self, listener):
        listener_id = listener.listener_id
        payload = {consts.LISTENER_ID: listener_id}
        self.client.cast({}, 'delete_listener', **payload)

    def listener_update(self, old_listener, new_listener):
        listener_dict = new_listener.to_dict()
        if 'admin_state_up' in listener_dict:
            listener_dict['enabled'] = listener_dict.pop('admin_state_up')
        listener_id = listener_dict.pop('listener_id')

        payload = {consts.LISTENER_ID: listener_id,
                   consts.LISTENER_UPDATES: listener_dict}
        self.client.cast({}, 'update_listener', **payload)

    # Pool
    def pool_create(self, pool):
        payload = {consts.POOL_ID: pool.pool_id}
        self.client.cast({}, 'create_pool', **payload)

    def pool_delete(self, pool):
        pool_id = pool.pool_id
        payload = {consts.POOL_ID: pool_id}
        self.client.cast({}, 'delete_pool', **payload)

    def pool_update(self, old_pool, new_pool):
        pool_dict = new_pool.to_dict()
        if 'admin_state_up' in pool_dict:
            pool_dict['enabled'] = pool_dict.pop('admin_state_up')
        pool_id = pool_dict.pop('pool_id')

        payload = {consts.POOL_ID: pool_id,
                   consts.POOL_UPDATES: pool_dict}
        self.client.cast({}, 'update_pool', **payload)
