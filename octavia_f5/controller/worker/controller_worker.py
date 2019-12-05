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
#

import oslo_messaging as messaging
import tenacity
import uuid
from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions as driver_exceptions
from oslo_config import cfg
from oslo_log import log as logging
from sqlalchemy.orm import exc as db_exceptions

from octavia.db import repositories as repo
from octavia_f5.common import constants
from octavia_f5.db import api as db_apis
from octavia_f5.restclient.as3classes import ADC, AS3, Application
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import monitor as m_monitor
from octavia_f5.restclient.as3objects import policy_endpoint as m_policy
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import pool_member as m_member
from octavia_f5.restclient.as3objects import service as m_service
from octavia_f5.restclient.as3objects import tenant as m_part
from octavia_f5.restclient.as3restclient import BigipAS3RestClient
from octavia_f5.utils import esd_repo

CONF = cfg.CONF
CONF.import_group('f5_agent', 'octavia_f5.common.config')
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


def _update_tenant(project_id, loadbalancers, bigip, action='deploy'):
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


class ControllerWorker(object):
    """Worker class to update load balancers."""
    # API version history:
    #   1.0 - Initial version.

    # target for OSLO initialization in ControllerWorker initialization
    target = messaging.Target(
        namespace=constants.RPC_NAMESPACE_CONTROLLER_AGENT,
        version='1.0')

    def __init__(self):
        self._loadbalancer_repo = repo.LoadBalancerRepository()
        self._octavia_driver_lib = driver_lib.DriverLibrary(
            status_socket=CONF.driver_agent.status_socket_path,
            stats_socket=CONF.driver_agent.stats_socket_path
        )
        self._esd = esd_repo.EsdRepository()
        self._l7policy_repo = repo.L7PolicyRepository()
        self._l7rule_repo = repo.L7RuleRepository()
        self.bigip = BigipAS3RestClient(
            bigip_url=CONF.f5_agent.bigip_url,
            enable_verify=CONF.f5_agent.bigip_verify,
            enable_token=CONF.f5_agent.bigip_token,
            esd=self._esd)

        super(ControllerWorker, self).__init__()

    @ tenacity.retry(
        retry=(
                tenacity.retry_if_exception_type()),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _update_status_to_octavia(self, status):
        try:
            self._octavia_driver_lib.update_loadbalancer_status(status)
        except driver_exceptions.UpdateStatusError as e:
            msg = ("Error while updating status to octavia: "
                   "%s") % e.fault_string
            LOG.error(msg)
            raise driver_exceptions.UpdateStatusError(msg)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _get_all_loadbalancer(self, project_id):
        LOG.debug("Get load balancers from DB for project id: %s ",
                  project_id)
        return self._loadbalancer_repo.get_all(
            db_apis.get_session(),
            project_id=project_id,
            show_deleted=False)[0]

    def refresh(self, ctxt, project_id):
        loadbalancers = self._get_all_loadbalancer(project_id)
        if _update_tenant(project_id, loadbalancers, self.bigip, action='dry-run'):
            for lb in loadbalancers:
                status_active = {"loadbalancers": [{"id": lb.id,
                                                    "provisioning_status": "ACTIVE",
                                                    "operating_status": "ONLINE"}],
                                 "healthmonitors": [], "l7policies": [], "l7rules": [],
                                 "listeners": [], "members": [], "pools": [] }
                self._update_status_to_octavia(status_active)
            return True
        return False