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

"""
Extends octavia base repository with enhanced f5-specific queries
"""

import sqlalchemy
from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import constants as consts
from octavia.db import models
from octavia.db import repositories

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class LoadBalancerRepository(repositories.LoadBalancerRepository):
    def get_all_from_host(self, session, host=None, **filters):
        """ Get all loadbalancers from specific host

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :param filters: Filters to decide which entities should be retrieved.
        :returns: [octavia.common.data_model]
        """
        if not host:
            host = CONF.host

        filters.update(server_group_id=host)
        return super(LoadBalancerRepository, self).get_all(
            session, **filters)[0]

    def get_all_by_network(self, session, network_id, host=None, **filters):
        """ Get all loadbalancers from specific host and network vip

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :param filters: Filters to decide which entities should be retrieved.
        :returns: [octavia.common.data_model]
        """
        if not host:
            host = CONF.host

        deleted = filters.pop('show_deleted', True)
        query = session.query(models.LoadBalancer)
        query = query.filter(models.LoadBalancer.server_group_id == host,
                             models.LoadBalancer.id == models.Vip.load_balancer_id,
                             models.Vip.network_id == network_id)
        if not deleted:
            query = query.filter(
                models.LoadBalancer.provisioning_status != consts.DELETED)

        return [model.to_data_model() for model in query.all()]


class PoolRepository(repositories.PoolRepository):
    def get_pending_from_host(self, session, host=None):
        """Get a list of pending pools from specific host

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :returns: [octavia.common.data_model]
        """
        if not host:
            host = CONF.host

        query = session.query(models.Pool)
        query = query.filter(models.LoadBalancer.server_group_id == host,
                             models.LoadBalancer.id == models.Pool.load_balancer_id,
                             models.Pool.provisioning_status.in_([
                                 lib_consts.PENDING_DELETE,
                                 lib_consts.PENDING_UPDATE,
                                 lib_consts.PENDING_CREATE
                             ]))

        return [model.to_data_model() for model in query.all()]


class L7PolicyRepository(repositories.L7PolicyRepository):
    def get_pending_from_host(self, session, host=None):
        """Get a list of pending l7policies from specific host

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :returns: [octavia.common.data_model]
        """
        if not host:
            host = CONF.host

        query = session.query(models.L7Policy)
        query = query.filter(models.LoadBalancer.server_group_id == host,
                             models.Listener.id == models.L7Policy.listener_id,
                             models.Listener.load_balancer_id == models.LoadBalancer.id,
                             models.L7Policy.provisioning_status.in_([
                                 lib_consts.PENDING_DELETE,
                                 lib_consts.PENDING_UPDATE,
                                 lib_consts.PENDING_CREATE
                             ]))

        return [model.to_data_model() for model in query.all()]


class ListenerRepository(repositories.ListenerRepository):
    def get_pending_from_host(self, session, host=None):
        """Get a list of pending listener from specific host

        :param session: A Sql Alchemy database session.
        :param host: specify amphora host to fetch loadbalancer from.
        :returns: [octavia.common.data_model]
        """
        if not host:
            host = CONF.host

        query = session.query(models.Listener)
        query = query.filter(models.LoadBalancer.server_group_id == host,
                             models.LoadBalancer.id == models.Listener.load_balancer_id,
                             models.Listener.provisioning_status.in_([
                                 lib_consts.PENDING_DELETE,
                                 lib_consts.PENDING_UPDATE,
                                 lib_consts.PENDING_CREATE
                             ]))

        return [model.to_data_model() for model in query.all()]


class AmphoraRepository(repositories.AmphoraRepository):
    def get_devices_for_host(self, session, host):

        query = session.query(self.model_class.cached_zone)
        query = query.filter(self.model_class.compute_flavor == host,
                             self.model_class.cached_zone.is_not(None))

        return [model[0] for model in query.all()]

    def cleanup(self, session):
        """ Deletes old amphora entries whose load balancers don't exist anymore.
        See controller_worker.ensure_amphora_exists for details.
        """
        try:
            session.query(self.model_class).filter(
                self.model_class.load_balancer_id.is_(None),
                self.model_class.cached_zone.is_(None),
                self.model_class.compute_flavor == CONF.host,
            ).delete()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

class QuotasRepository(repositories.BaseRepository):
    model_class = models.Quotas

    def update(self, session, project_id, **model_kwargs):
        with session.begin(subtransactions=True):
            session.query(self.model_class).filter_by(
                project_id=project_id).update(model_kwargs)
