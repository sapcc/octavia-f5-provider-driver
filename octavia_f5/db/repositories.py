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
from sqlalchemy import func, asc, or_

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

        # get all hosts
        candidates = session.query(self.model_class.compute_flavor)
        candidates = candidates.filter_by(
            role=consts.ROLE_MASTER,
            load_balancer_id=None,
        ).filter(or_(
            # !='disabled' gives False on NULL, so we need to check for NULL (None) explicitly
            self.model_class.vrrp_interface == None, self.model_class.vrrp_interface != 'disabled'))

        # order by listener count
        candidates = candidates.order_by(
            self.model_class.vrrp_priority.asc(),
            self.model_class.updated_at.desc())
        candidates = candidates.all()

        # optionally schedule according to load balancer count instead of (just) listener count
        if CONF.networking.agent_scheduler == "loadbalancer":
            lb_count = session.query(models.LoadBalancer.server_group_id.label('host'),
                                     func.count(models.LoadBalancer.id))\
                .group_by('host').order_by(func.count(models.LoadBalancer.id).asc()).all()
            lb_count = { host:lbs for (host,lbs) in lb_count }
            # Now we have LB count per host, but some may have no LBs, so no entry in lb_count.
            # But we need to include all hosts from the candidates list.
            candidates = [ (c[0], lb_count.get(c[0]) or 0) for c in candidates]
            candidates.sort(key=lambda x: x[1]) # TODO check that sort is ascending

        # If no specific AZ is requested, just return all candidates
        if not az_name:
            return [ c[0] for c in candidates ]

        # get hosts from AZ
        az_repo = repositories.AvailabilityZoneRepository()
        az = az_repo.get(session, name=az_name)
        if not az:
            LOG.error("Can't schedule VIP/LB: Availability zone not found: {}".format(az_name))
            raise exceptions.NotFound()
        hosts_in_az = az.description.split()

        # get hosts from AZ that are candidates
        candidates = [ c[0] for c in candidates if c[0] in hosts_in_az ]
        if len(candidates) == 0:
            LOG.error("Can't schedule VIP/LB: No host candidates in availability zone {}".format(az_name))
            raise exceptions.NotFound()
        return candidates

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
