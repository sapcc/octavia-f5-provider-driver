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

from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import func, asc

from octavia.common import constants as consts
from octavia.common import exceptions
from octavia.db import api as db_api
from octavia.db import models
from octavia.db import repositories

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class DatabaseLockSession(object):
    """Provides a database session and rolls it back if an exception occured before exiting with-statement. """
    def __enter__(self):
        self._lock_session = db_api.get_session(autocommit=False)
        return self._lock_session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_tb is None:
            self._lock_session.commit()
        else:
            if isinstance(exc_type, db_exc.DBDeadlock):
                LOG.debug('Database reports deadlock. Skipping.')
                self._lock_session.rollback()
            elif isinstance(exc_type, db_exc.RetryRequest):
                LOG.debug('Database is requesting a retry. Skipping.')
                self._lock_session.rollback()
            else:
                with excutils.save_and_reraise_exception():
                    self._lock_session.rollback()

class AmphoraRepository(repositories.AmphoraRepository):
    def get_candidates(self, session, az_name=None):
        """ Get F5 (active) BigIP host candidate depending on the load (amount of listeners in amphora vrrp_priority
        column) and the desired availability zone.

        :param session: A Sql Alchemy database session.
        :param az_name: Name of the availability zone to schedule to. If it is None, all F5 amphora are considered.
        """

        candidates_query = session.query(self.model_class)
        candidates_query = candidates_query.filter_by(
            role=consts.ROLE_MASTER,
            load_balancer_id=None)
        candidates_query = candidates_query.order_by(
            self.model_class.vrrp_priority.asc(),
            self.model_class.updated_at.desc())
        candidates_amphora_entries = candidates_query.all()

        # If no specific AZ is requested, just return all candidates
        if not az_name:
            return [candidate.compute_flavor for candidate in candidates_amphora_entries
                    if candidate.vrrp_interface != 'disabled']

        # filter by AZ
        az_repo = repositories.AvailabilityZoneRepository()
        az = az_repo.get(name=az_name)
        if not az:
            raise exceptions.NotFound()
        hosts = az.description.split()
        return [candidate.compute_flavor for candidate in candidates_amphora_entries
                if candidate.vrrp_interface != 'disabled' and candidate.compute_flavor in hosts]

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

    def get_candidates(self, session):
        """ Get F5 (active) BigIP host candidate depending on loadbalancers scheduled

        :param session: A Sql Alchemy database session.
        """
        # FIXME logical error: LBs are only scheduled to where LBs already exist
        # Get possible candidates subquery first
        possible_candidates = session.query(models.Amphora.compute_flavor)
        possible_candidates = possible_candidates.filter_by(
            status=consts.AMPHORA_READY, load_balancer_id=None, vrrp_interface=None)
        possible_candidates = possible_candidates.subquery()

        # but schedule according to loadbalancer usage
        candidates = session.query(models.LoadBalancer.server_group_id, func.count(models.LoadBalancer.id).label('lb_count'))
        # Skip deleted
        candidates = candidates.filter(models.LoadBalancer.provisioning_status != consts.DELETED)
        candidates = candidates.filter(models.LoadBalancer.server_group_id.in_(possible_candidates))
        candidates = candidates.group_by(models.LoadBalancer.server_group_id)
        candidates = candidates.order_by(asc('lb_count'))
        return [candidate[0] for candidate in candidates.all() if candidate[0]]


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
