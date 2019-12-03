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
from octavia_lib.api.drivers import driver_lib
from oslo_config import cfg
from oslo_log import log as logging
from sqlalchemy.orm import exc as db_exceptions

from octavia.db import repositories as repo
from octavia_f5.common import constants
from octavia_f5.controller.worker.f5agent_driver import tenant_update
from octavia_f5.db import api as db_apis
from octavia_f5.restclient.as3restclient import BigipAS3RestClient
from octavia_f5.utils import esd_repo

CONF = cfg.CONF
CONF.import_group('f5_agent', 'octavia_f5.common.config')
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


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
        self.bigip = BigipAS3RestClient(CONF.f5_agent.bigip_url,
                                        CONF.f5_agent.bigip_verify,
                                        CONF.f5_agent.bigip_token,
                                        CONF.f5_agent.network_segment_physical_network,
                                        self._esd)

        super(ControllerWorker, self).__init__()

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
        if tenant_update(project_id, loadbalancers, self.bigip, action='dry-run'):
            for lb in loadbalancers:
                status_active = {"loadbalancers": [{"id": lb.id,
                                                    "provisioning_status": "ACTIVE",
                                                    "operating_status": "ONLINE"}],
                                 "healthmonitors": [], "l7policies": [], "l7rules": [],
                                 "listeners": [], "members": [], "pools": [] }
                self._update_status_to_octavia(status_active)
            return True
        return False