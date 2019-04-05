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

from oslo_config import cfg
from oslo_log import log as logging
from octavia.controller.worker.tasks.database_tasks import BaseDatabaseTask
from octavia.db import api as db_apis

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class ReloadLoadBalancers(BaseDatabaseTask):
    """Get load balancer objects of tenant from the database."""

    def execute(self, loadbalancer, *args, **kwargs):
        """Get load balancer objects from the database.

        :param loadbalancer: one load balancer of the tenant
        :returns: The load balancer objects
        """

        LOG.debug("Get load balancers from DB for project id: %s ",
                  loadbalancer)
        return self.loadbalancer_repo.get_all(
            db_apis.get_session(),
            project_id=loadbalancer.project_id,
            show_deleted=False)[0]

