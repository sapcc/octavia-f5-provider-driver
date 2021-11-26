#  Copyright 2021 SAP SE
#  #
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#  #
#  http://www.apache.org/licenses/LICENSE-2.0
#  #
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from sqlalchemy import func, or_
from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import constants as consts
from octavia.db import models
from octavia.db import repositories

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class Scheduler(object):
    def __init__(self):
        self.az_repo = repositories.AvailabilityZoneRepository()

    def get_candidates(self, session, az_name=None):
        """ Get F5 (active) BigIP host candidate depending on the load (amount of listeners in amphora vrrp_priority
        column) and the desired availability zone.

        :param session: A Sql Alchemy database session.
        :param az_name: Name of the availability zone to schedule to. If it is None, all F5 amphora are considered.
        """

        # get all hosts
        candidates = session.query(
            models.Amphora.compute_flavor,
            func.count(models.LoadBalancer.id)
        ).join(
            models.LoadBalancer,
            models.Amphora.compute_flavor == models.LoadBalancer.server_group_id
        ).filter(
            models.Amphora.role == consts.ROLE_MASTER,
            models.Amphora.load_balancer_id == None,
            or_(
                # !='disabled' gives False on NULL, so we need to check for NULL (None) explicitly
                models.Amphora.vrrp_interface == None,
                models.Amphora.vrrp_interface != 'disabled')
        ).group_by(models.Amphora.compute_flavor)

        if CONF.networking.agent_scheduler == "loadbalancer":
            # order by loadbalancer count
            candidates.order_by(
                func.count(models.LoadBalancer.id).asc(),
                models.Amphora.updated_at.desc())
        else:
            # order by listener count
            candidates = candidates.order_by(
                models.Amphora.vrrp_priority.asc(),
                models.Amphora.updated_at.desc())

        if az_name:
            # if az provided, filter hosts
            metadata = self.az_repo.get_availability_zone_metadata_dict(session, az_name)
            hosts = metadata.get('hosts', [])
            candidates = candidates.filter(
                models.Amphora.compute_flavor.in_(hosts))
        else:
            # we need to filter out all az-aware hosts
            azs = set([az.name for az in self.az_repo.get_all(session)[0]])
            omit_hosts = set()
            for az in azs:
                metadata = self.az_repo.get_availability_zone_metadata_dict(session, az)
                omit_hosts.add(metadata.get('hosts', []))
            candidates = candidates.filter(
                models.Amphora.compute_flavor.notin_(omit_hosts))
        return [candidate[0] for candidate in candidates.all()]