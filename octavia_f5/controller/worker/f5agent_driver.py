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

from oslo_config import cfg
from oslo_log import log as logging
from requests import ConnectionError
from tenacity import *

from octavia_f5.common import constants
from octavia_f5.restclient.as3classes import ADC, AS3, Application
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import policy_endpoint as m_policy
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import pool_member as m_member
from octavia_f5.restclient.as3objects import service as m_service
from octavia_f5.restclient.as3objects import tenant as m_part
from octavia_f5.utils import driver_utils as utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


@retry(
    retry=retry_if_exception_type(ConnectionError),
    wait=wait_incrementing(
        RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
    stop=stop_after_attempt(RETRY_ATTEMPTS)
)
def tenant_update(bigip,
                  cert_manager,
                  tenant,
                  loadbalancers,
                  segmentation_id,
                  action='deploy'):
    """Task to update F5s with all specified loadbalancers' configurations
       of a tenant (project).

       :param bigip: bigip instance
       :param cert_manager: CertManagerWrapper instance
       :param tenant: tenant_id/project_id
       :param loadbalancers: loadbalancer to update
       :param segmentation_id: segmentation_id of the loadbalancers
       :param action: AS3 action
       :return: requests post result

    """
    decl = AS3(
        persist=True,
        action=action,
        syncToGroup=CONF.f5_agent.sync_to_group,
        _log_level=LOG.logger.level)
    adc = ADC(
        id="urn:uuid:{}".format(uuid.uuid4()),
        label="F5 BigIP Octavia Provider")
    decl.set_adc(adc)

    tenant = adc.get_or_create_tenant(
        m_part.get_name(tenant),
        defaultRouteDomain=segmentation_id
    )

    for loadbalancer in loadbalancers:
        if utils.pending_delete(loadbalancer):
            continue

        # Create generic application
        app = Application(constants.APPLICATION_GENERIC,
                          label=loadbalancer.id)

        # attach listeners with ESDs / L7Policies
        for listener in loadbalancer.listeners:
            if utils.pending_delete(listener):
                continue

            profiles = {}
            for l7policy in listener.l7policies:
                if utils.pending_delete(l7policy):
                    continue

                esd = bigip.esd.get_esd(l7policy.name)
                if esd:
                    profiles.update(m_service.process_esd(esd))
                else:
                    app.add_endpoint_policy(
                        m_policy.get_name(l7policy.id),
                        m_policy.get_endpoint_policy(l7policy)
                    )
            app.add_entities(m_service.get_service(listener, cert_manager))

        # attach pools
        for pool in loadbalancer.pools:
            if utils.pending_delete(pool):
                continue
            app.add_entities(m_pool.get_pool(pool))

        tenant.add_application(
            m_app.get_name(loadbalancer.id),
            app)

    return bigip.post(json=decl.to_json())


@retry(
    retry=retry_if_exception_type(ConnectionError),
    wait=wait_incrementing(
        RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
    stop=stop_after_attempt(RETRY_ATTEMPTS)
)
def tenant_delete(bigip, tenant):
    """ Delete a Tenant

    :param bigip: bigip instance
    :param tenant: tenant/project id
    :return: requests delete result
    """
    tenant = m_part.get_name(tenant)
    return bigip.delete(tenants=[tenant])


def member_create(bigip, member):
    """Patches new member into existing pool

    :param bigip: bigip instance
    :param member: octavia member object
    """
    path = '{}/{}/{}/members/-'.format(
        m_part.get_name(member.pool.load_balancer.vip.network_id),
        m_app.get_name(member.pool.load_balancer.id),
        m_pool.get_name(member.pool.id)
    )
    return bigip.patch(operation='add', path=path,
                       value=m_member.get_member(member).to_dict())
