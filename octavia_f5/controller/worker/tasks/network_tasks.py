#  Copyright 2022 SAP SE
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from oslo_config import cfg
from oslo_log import log as logging
from taskflow import task
from taskflow.types import failure

from octavia.common import data_models
from octavia.db import api as db_apis
from octavia.i18n import _
from octavia.network import base
from octavia.network import data_models as network_models
from octavia_f5.common import constants
from octavia_f5.db import repositories as repo
from octavia_f5.db import scheduler

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class BaseNetworkTask(task.Task):
    """Base task to load drivers common to the tasks."""

    def __init__(self, network_driver, **kwargs):
        super(BaseNetworkTask, self).__init__(**kwargs)
        self.network_driver = network_driver
        self.scheduler = scheduler.Scheduler()
        self.lb_repo = repo.LoadBalancerRepository()


class GetCandidate(BaseNetworkTask):
    default_provides = 'candidate'

    def execute(self, load_balancer: data_models.LoadBalancer):
        # select a candidate to schedule to
        try:
            session = db_apis.get_session()
            candidate = self.scheduler.get_candidates(session, load_balancer.availability_zone)[0]
        except (ValueError, IndexError) as e:
            message = _('Scheduling failed, no target devices found')
            LOG.error(message)
            raise base.AllocateVIPException(
                message,
                orig_msg=getattr(e, 'message', None),
                orig_code=getattr(e, 'status_code', None),
            )

        LOG.debug("Found candidate for new LB %s: %s", load_balancer.id, candidate)
        return candidate


class AllSelfIPs(BaseNetworkTask):
    default_provides = 'selfips'

    def execute(self, existing_selfips: [network_models.Port],
                new_selfips: [network_models.Port]) -> [network_models.Port]:
        return existing_selfips + new_selfips


class CreateSelfIPs(BaseNetworkTask):
    default_provides = ('existing_selfips', 'new_selfips')

    def execute(self, load_balancer: data_models.LoadBalancer,
                candidate: str) -> ([network_models.Port],
                                    [network_models.Port]):
        try:
            # create_only imposes only to return selfips that needed
            # to be created from ground up, this is to ensure
            # that we don't delete existing selfips in case of a revert operation
            return self.network_driver.ensure_selfips(
                [load_balancer], agent=candidate)
        except Exception as e:
            message = _('Error creating selfips for network '
                        '{network_id}: {err}.').format(
                network_id=load_balancer.vip.network_id,
                err=e
            )
            LOG.error(message)
            raise base.AllocateVIPException(
                message,
                orig_msg=getattr(e, 'message', None),
                orig_code=getattr(e, 'status_code', None),
            )

    def revert(self, result: ([network_models.Port], [network_models.Port]),
               *args, **kwargs):
        """Handle a failure to create selfip ports."""

        if isinstance(result, failure.Failure):
            LOG.error("CreateSelfIPs: Unable to create selfips")
            return
        LOG.warning("Reverting: deleting selfip ports %s",
                    [p.name for p in result[1]])
        for selfip in result[1]:
            self.network_driver.delete_port(selfip.id)


class CreateVIPPort(BaseNetworkTask):
    default_provides = 'vip_port'

    def execute(self, load_balancer: data_models.LoadBalancer,
                candidate: str) -> network_models.Port:
        return self.network_driver.create_vip(load_balancer, candidate)

    def revert(self, result: network_models.Port, load_balancer: data_models.LoadBalancer,
               *args, **kwargs):
        """Handle a failure to create neutron vip port."""

        if isinstance(result, failure.Failure):
            LOG.error("Unable to create VIP Port")
            return
        LOG.warning("Reverting: deleting vip port %s", result)
        self.network_driver.delete_port(result.id)


class UpdateAAP(BaseNetworkTask):
    def execute(self, vip_port: dict, selfips: [network_models.Port]):
        # Update allowed address pairs
        self.network_driver.update_aap(vip_port, selfips)


class DeleteVIP(BaseNetworkTask):
    def execute(self, port_id):
        self.network_driver.delete_port(port_id)


class GetAllLoadBalancersForNetwork(BaseNetworkTask):
    default_provides = 'load_balancers'

    def execute(self, network_id, agent):
        LOG.debug("Get load balancers from DB for network id: %s ", network_id)
        return self.lb_repo.get_all_by_network(
            db_apis.get_session(),
            network_id=network_id,
            host=agent,
            show_deleted=False)


class GetAllSelfIPsForNetwork(BaseNetworkTask):
    default_provides = 'selfips'

    def execute(self, network_id, agent):
        filter = {'device_owner': [constants.DEVICE_OWNER_SELFIP,
                                   constants.DEVICE_OWNER_LEGACY],
                  'binding:host_id': agent,
                  'network_id': network_id}
        return self.network_driver.neutron_client.list_ports(**filter).get('ports', [])


class CleanupSelfIPs(BaseNetworkTask):
    default_provides = 'selfips'

    def execute(self, load_balancers, selfips):
        if not load_balancers:
            for selfip in selfips:
                self.network_driver.delete_port(selfip['id'])
