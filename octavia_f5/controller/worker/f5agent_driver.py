# Copyright 2019 SAP SE
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

from octavia_f5.common import constants
from octavia_f5.restclient.as3classes import ADC, AS3, Application
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import tenant as m_part
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import service as m_service
from octavia_f5.restclient.as3objects import monitor as m_monitor
from octavia_f5.restclient.as3objects import pool_member as m_member
from octavia_f5.restclient.as3objects import policy_endpoint as m_policy

LOG = logging.getLogger(__name__)


def tenant_update(project_id, loadbalancers, bigip, action='deploy'):
    """Task to update F5s with all specified loadbalancers' configurations
       of a tenant (project).

    """
    decl = AS3(
        persist=True,
        action=action)
    adc = ADC(
        id="urn:uuid:{}".format(uuid.uuid4()),
        label="F5 BigIP Octavia Provider")
    decl.set_adc(adc)

    tenant = adc.get_or_create_tenant(
        m_part.get_name(project_id))

    for loadbalancer in loadbalancers:
        # Create generic application
        app = Application(constants.APPLICATION_GENERIC,
                          label=loadbalancer.id)

        # attach listeners with ESDs / L7Policies
        for listener in loadbalancer.listeners:
            profiles = {}
            for l7policy in listener.l7policies:
                esd = bigip.esd.get_esd(l7policy.name)
                if esd:
                    profiles.update(m_service.process_esd(esd))
                else:
                    app.add_policy_endpoint(
                        m_policy.get_name(l7policy.id),
                        m_policy.get_endpoint_policy(l7policy)
                    )
            app.add_service(
                m_service.get_name(listener.id),
                m_service.get_service(listener)
            )

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
    return bigip.post(json=decl.to_json())
