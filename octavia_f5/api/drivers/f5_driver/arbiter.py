# Copyright 2022 SAP SE
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

import abc

from oslo_config import cfg
from oslo_log import log as logging
from taskflow import flow
from taskflow.listeners import logging as tf_logging
from taskflow.patterns import linear_flow, unordered_flow

from octavia.common import base_taskflow
from octavia_f5.controller.worker.tasks import network_tasks
from octavia_f5.api.drivers.f5_driver.tasks import reschedule_tasks
from octavia_f5.utils import driver_utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class RescheduleMixin(object, metaclass=abc.ABCMeta):
    """Abstract mixin class for reschedule support in loadbalancer RPC

    """
    def loadbalancer_add(self, loadbalancer_id, target_host):
        """Forces a loadbalancer to be added to the target host

        :param loadbalancer_id: loadbalancer id
        :param target_host: agent
        """

    def loadbalancer_remove(self, loadbalancer_id, target_host):
        """Forces a loadbalancer to be removed from the target host

        :param loadbalancer_id: loadbalancer id
        :param target_host: agent
        """


class MigrationArbiter(RescheduleMixin):
    def __init__(self):
        self.tf_engine = base_taskflow.BaseTaskFlowEngine()
        self.network_driver = driver_utils.get_network_driver()

    def run_flow(self, func, *args, **kwargs):
        tf = self.tf_engine.taskflow_load(
            func(*args), **kwargs)
        with tf_logging.DynamicLoggingListener(tf, log=LOG):
            tf.run()

    def get_reschedule_flow(self) -> flow.Flow:
        # Prepare Self-IPs for target
        get_loadbalancer_task = reschedule_tasks.GetLoadBalancerByID()
        create_selfips_task = network_tasks.CreateSelfIPs(self.network_driver)
        wait_for_selfip_task = network_tasks.WaitForNewSelfIPs(self.network_driver)

        add_loadbalancer_task = reschedule_tasks.ForceAddLoadbalancer(rpc=self)
        get_old_agent_task = reschedule_tasks.GetOldAgentFromLoadBalancer()
        remove_loadbalancer_task = reschedule_tasks.ForceDeleteLoadbalancer(rpc=self)
        rewrite_loadbalancer_task = reschedule_tasks.RewriteLoadBalancerEntry()
        rewrite_amphora_task = reschedule_tasks.RewriteAmphoraEntry()

        all_selfips_task = network_tasks.AllSelfIPs(self.network_driver)
        get_vip_port_task = network_tasks.GetVIPFromLoadBalancer(self.network_driver)
        update_aap_task = network_tasks.UpdateAAP(self.network_driver)
        update_vip_task = network_tasks.UpdateVIP(self.network_driver)
        invalidate_cache_task = network_tasks.InvalidateCache(self.network_driver)

        add_remove_loadbalancer_flow = unordered_flow.Flow('add-remove-lb-flow')
        add_remove_loadbalancer_flow.add(add_loadbalancer_task, remove_loadbalancer_task)

        update_vip_sub_flow = linear_flow.Flow("update-vip-sub-flow")
        update_vip_sub_flow.add(get_vip_port_task, update_vip_task, all_selfips_task, update_aap_task)

        # update loadbalancer, amphora and vip and invalidate cache can be run parallelized
        update_database_flow = unordered_flow.Flow("database-update-flow")
        update_database_flow.add(rewrite_loadbalancer_task, rewrite_amphora_task, update_vip_sub_flow,
                                 invalidate_cache_task)

        reschedule_flow = linear_flow.Flow('reschedule-flow')
        reschedule_flow.add(get_loadbalancer_task, get_old_agent_task, create_selfips_task,
                            wait_for_selfip_task, add_remove_loadbalancer_flow,
                            update_database_flow, update_vip_sub_flow)
        return reschedule_flow
