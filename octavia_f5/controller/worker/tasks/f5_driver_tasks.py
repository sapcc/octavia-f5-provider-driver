# Copyright 2018 SAP SE
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

import uuid

from oslo_log import log as logging
from taskflow import task

import octavia_f5.restclient.as3mapper as map
from octavia.controller.worker import task_utils as task_utilities
from octavia_f5.restclient import as3convert
from octavia_f5.restclient.as3classes import ADC

LOG = logging.getLogger(__name__)


class F5BaseTask(task.Task):
    """Base task to load drivers common to the tasks."""

    def __init__(self, **kwargs):
        super(F5BaseTask, self).__init__(**kwargs)
        self.task_utils = task_utilities.TaskUtils()
        self.converter = as3convert.As3Convert()


class ListenersUpdate(F5BaseTask):
    """Task to update F5s with all specified listeners' configurations."""

    def execute(self, loadbalancer, listeners, bigip):
        """Execute updates per listener for a f5_driver."""

        decl = ADC(
            id="urn:uuid:{}".format(uuid.uuid4()),
            label="ListenerUpdate",
            remark='update of ' + ', '.join([listener.id for
                                             listener in listeners])
        )
        tenant = decl.getOrCreateTenant(
            map.project(loadbalancer.project_id)
        )

        for listener in listeners:
            app = self.converter.create_application(listener)
            tenant.add_application(map.listener(listener.id), app)

        print(decl.to_json())

    def revert(self, loadbalancer, *args, **kwargs):
        """Handle failed listeners updates."""

        LOG.warning("Reverting listeners updates.")

        for listener in loadbalancer.listeners:
            self.task_utils.mark_listener_prov_status_error(listener.id)

        return None


class ListenerDelete(F5BaseTask):
    def execute(self, loadbalancer, listener, bigip):
        virt_path = mapper.get_virtual_path(listener)
        self.delete_resource(bigip.tm.ltm.virtuals.virtual, virt_path)

    def revert(self, listener, *args, **kwargs):
        """Handle a failed listener delete."""
        LOG.warning("Reverting listener delete.")
        self.task_utils.mark_listener_prov_status_error(listener.id)


# Pools
class PoolCreate(F5BaseTask):
    def execute(self, pool, loadbalancer, members, health_monitor, bigip):
        f5_pool = mapper.map_pool(pool, loadbalancer,
                                  members, health_monitor)
        self.delete_resource(bigip.tm.ltm.pools.pool, f5_pool)

    def revert(self, pool, *args, **kwargs):
        """Handle failed pool creation."""
        LOG.warning("Reverting pool creation.")
        self.task_utils.mark_pool_prov_status_error(pool.id)
        return None


class PoolUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, members, health_monitor, bigip):
        pool_path = mapper.get_pool_path(loadbalancer, pool)
        f5_pool = mapper.map_pool(pool, loadbalancer,
                                  members, health_monitor)
        self.update_resource(bigip.tm.ltm.pools.pool,
                             pool_path, f5_pool)


class PoolDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, bigip):
        pool_path = mapper.get_pool_path(loadbalancer, pool)
        self.delete_resource(bigip.tm.ltm.pools.pool, pool_path)

    def revert(self, pool, *args, **kwargs):
        """Handle failed pool deletion."""
        LOG.warning("Reverting pool delete.")
        self.task_utils.mark_pool_prov_status_error(pool.id)
        return None


class HealthMonitorUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class HealthMonitorDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7RuleUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7RuleDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7RuleCreate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7PolicyUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7PolicyDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        policy_path = mapper.get_l7policy_path(loadbalancer, pool)
        self.delete_resource(bigip.tm.ltm.policys.policy, policy_path)


class L7PolicyCreate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError
