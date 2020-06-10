# Copyright 2020 SAP SE
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

"""
Extends octavia base repository with enhanced f5-specific queries
"""

from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import constants as consts
from octavia.db import models
from octavia.db import repositories
from octavia_lib.common import constants as lib_consts

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class AmphoraRepository(repositories.AmphoraRepository):
    def get_candidates(self, session):
        """ Get F5 (active) BigIP host candidate depending on the load

        :param session: A Sql Alchemy database session.
        """

        candidates = session.query(self.model_class)
        candidates = candidates.filter_by(
            role=consts.ROLE_MASTER,
            load_balancer_id=None)
        candidates = candidates.order_by(
            self.model_class.vrrp_priority.asc(),
            self.model_class.updated_at.desc())
        return [candidate.compute_flavor for candidate in candidates.all()
                if candidate.vrrp_interface != 'disabled']


class LoadBalancerRepository(repositories.LoadBalancerRepository):
    def get_all_from_host(self, session, host=CONF.host, **filters):
        """ Get all loadbalancers from specific host

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :param filters: Filters to decide which entities should be retrieved.
        :returns: [octavia.common.data_model]
        """
        filters.update(server_group_id=host)
        return super(LoadBalancerRepository, self).get_all(
            session, **filters)[0]


class PoolRepository(repositories.PoolRepository):
    def get_pending_from_host(self, session, host=CONF.host):
        """Get a list of pending pools from specific host

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :returns: [octavia.common.data_model]
        """

        query = session.query(models.Pool)
        query = query.filter(models.LoadBalancer.server_group_id == host,
                             models.Pool.provisioning_status.in_([
                                 lib_consts.PENDING_UPDATE,
                                 lib_consts.PENDING_CREATE
                             ]))

        return [model.to_data_model() for model in query.all()]


class L7PolicyRepository(repositories.L7PolicyRepository):
    def get_pending_from_host(self, session, host=CONF.host):
        """Get a list of pending l7policies from specific host

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :returns: [octavia.common.data_model]
        """

        query = session.query(models.L7Policy)
        query = query.filter(models.LoadBalancer.server_group_id == host,
                             models.L7Policy.provisioning_status.in_([
                                 lib_consts.PENDING_UPDATE,
                                 lib_consts.PENDING_CREATE
                             ]))

        return [model.to_data_model() for model in query.all()]


class ListenerRepository(repositories.ListenerRepository):
    def get_pending_from_host(self, session, host=CONF.host):
        """Get a list of pending listener from specific host

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :returns: [octavia.common.data_model]
        """

        query = session.query(models.Listener)
        query = query.filter(models.LoadBalancer.server_group_id == host,
                             models.Listener.provisioning_status.in_([
                                 lib_consts.PENDING_UPDATE,
                                 lib_consts.PENDING_CREATE
                             ]))

        return [model.to_data_model() for model in query.all()]
