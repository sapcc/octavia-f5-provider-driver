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

from octavia.controller.worker import task_utils as task_utilities
from octavia_f5.common import constants
from octavia_f5.restclient.as3classes import ADC, AS3, Application, Member
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import tenant as m_part
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import service as m_service
from octavia_f5.restclient.as3objects import monitor as m_monitor
from octavia_f5.restclient.as3objects import pool_member as m_member
from octavia_f5.restclient.as3objects import irule as m_irule

LOG = logging.getLogger(__name__)


class F5BaseTask(task.Task):
    """Base task to load drivers common to the tasks."""

    def execute(self, *args, **kwargs):
        pass

    def __init__(self, **kwargs):
        super(F5BaseTask, self).__init__(**kwargs)
        self.task_utils = task_utilities.TaskUtils()


class TenantUpdate(F5BaseTask):
    """Task to update F5s with all specified loadbalancers' configurations
       of a tenant (project).

    """

    def execute(self, project_id, loadbalancers, bigip):
        decl = AS3(
            persist=False,
            action='deploy')
        adc = ADC(
            id="urn:uuid:{}".format(uuid.uuid4()),
            label="F5 BigIP Octavia Provider")
        decl.set_adc(adc)

        tenant = adc.get_or_create_tenant(
            m_part.get_name(project_id))

        for loadbalancer in loadbalancers:
            lb_irules = []

            # Create generic application
            app = Application(constants.APPLICATION_GENERIC,
                              label=loadbalancer.id)

            # attach listeners with iRules
            for listener in loadbalancer.listeners:
                irules = m_irule.get_irule_names(
                    listener.l7policies,
                    bigip.esd)
                app.add_service(
                    m_service.get_name(listener.id),
                    m_service.get_service(listener,
                                          irules))

            # attach pools
            for pool in loadbalancer.pools:
                as3pool = m_pool.get_pool(pool)

                for member in pool.members:
                    as3pool.add_member(
                        m_member.get_member(member))

                if pool.health_monitor:
                    app.add_monitor(
                        m_monitor.get_name(pool.health_monitor.id),
                        m_monitor.get_monitor(pool.health_monitor))

                app.add_pool(
                    m_pool.get_name(pool.id),
                    as3pool)

            tenant.add_application(
                m_app.get_name(loadbalancer.id),
                app)

        # send to bigip
        bigip.post(json=decl.to_json())


class ListenerDelete(F5BaseTask):
    def execute(self, listener, bigip):
        bigip.patch('remove', m_service.get_path(listener))
        LOG.debug("Deleted the listener on the vip")

    def revert(self, listener, *args, **kwargs):
        """Handle a failed listener delete."""
        LOG.warning("Reverting listener delete.")
        self.task_utils.mark_listener_prov_status_error(listener.id)


# Pools
class PoolCreate(F5BaseTask):
    def revert(self, pool, *args, **kwargs):
        """Handle failed pool creation."""
        LOG.warning("Reverting pool creation.")
        self.task_utils.mark_pool_prov_status_error(pool.id)
        return None


class PoolUpdate(F5BaseTask):
    pass


class PoolDelete(F5BaseTask):
    def revert(self, pool, *args, **kwargs):
        """Handle failed pool deletion."""
        LOG.warning("Reverting pool delete.")
        self.task_utils.mark_pool_prov_status_error(pool.id)
        return None


class HealthMonitorUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class HealthMonitorDelete(F5BaseTask):
    def execute(self, health_mon, bigip):
        bigip.patch('remove', m_monitor.get_path(health_mon))
        LOG.debug("Deleted the health monitor on the pool")

    def revert(self, health_mon, *args, **kwargs):
        """Handle a failed listener delete."""
        LOG.warning("Reverting health monitor delete.")
        self.task_utils.mark_health_mon_prov_status_error(health_mon.id)


class L7RuleUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7RuleDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7PolicyUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7PolicyDelete(F5BaseTask):
    pass


