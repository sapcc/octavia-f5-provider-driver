# Copyright 10/6/22 SAP SE
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

from abc import ABCMeta

from oslo_config import cfg
from oslo_log import log as logging
from taskflow import task
from taskflow.types import failure
from taskflow import exceptions

from octavia.common import data_models as models
from octavia.db import api as db_apis
from octavia_f5.db import repositories as repo

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class RescheduleTasks(task.Task, metaclass=ABCMeta):
    """Base task to load drivers common to the tasks."""
    def __init__(self, **kwargs):
        self.rpc = kwargs.pop("rpc", None)
        super(RescheduleTasks, self).__init__(**kwargs)
        self._loadbalancer_repo = repo.LoadBalancerRepository()
        self._amphora_repo = repo.AmphoraRepository()


class GetLoadBalancerByID(RescheduleTasks):
    default_provides = 'load_balancer'

    def execute(self, loadbalancer_id):
        LOG.debug("Get load balancer from DB by id: %s ", loadbalancer_id)
        return self._loadbalancer_repo.get(db_apis.get_session(),
                                           id=loadbalancer_id)


class CheckTargetHost(RescheduleTasks):
    def execute(self, target_host: str):
        devices = self._amphora_repo.get_devices_for_host(db_apis.get_session(), host=target_host)
        if not devices:
            raise exceptions.NotFound(f"Target host not found: {target_host}")


class GetOldAgentFromLoadBalancer(RescheduleTasks):
    default_provides = 'removal_host'

    def execute(self, load_balancer: models.LoadBalancer):
        return load_balancer.server_group_id


class ForceAddLoadbalancer(RescheduleTasks):
    def execute(self, loadbalancer_id: str, candidate: str):
        self.rpc.loadbalancer_add(loadbalancer_id=loadbalancer_id,
                                  target_host=candidate)

    def revert(self, result, loadbalancer_id: str, candidate: str, **kwargs):
        """Handle a failure to force adding a loadbalancer."""

        if isinstance(result, failure.Failure):
            LOG.error("ForceAddLoadbalancer: Unable to create loadbalancer")
            return
        LOG.warning("ForceAddLoadbalancer: Reverting create loadbalancer %s from %s",
                    loadbalancer_id, candidate)
        self.rpc.loadbalancer_remove(loadbalancer_id=loadbalancer_id,
                                     target_host=candidate)


class ForceDeleteLoadbalancer(RescheduleTasks):
    def execute(self, loadbalancer_id: str, removal_host: str):
        self.rpc.loadbalancer_remove(loadbalancer_id=loadbalancer_id,
                                     target_host=removal_host)

    def revert(self, result, loadbalancer_id: str, removal_host: str, **kwargs):
        """Handle a failure to force adding a loadbalancer."""

        if isinstance(result, failure.Failure):
            LOG.error("ForceDeleteLoadbalancer: Unable to delete loadbalancer")
            return
        LOG.warning("ForceDeleteLoadbalancer: Reverting delete loadbalancer %s from %s",
                    loadbalancer_id, removal_host)
        self.rpc.loadbalancer_add(loadbalancer_id=loadbalancer_id,
                                  target_host=removal_host)


class RewriteAmphoraEntry(RescheduleTasks):
    def execute(self, load_balancer: models.LoadBalancer, candidate: str, *args, **kwargs):
        LOG.debug("RewriteAmphoraEntry %s: Changing host '%s' to '%s'.",
                  load_balancer.id, load_balancer.server_group_id, candidate)
        self._amphora_repo.update(db_apis.get_session(), load_balancer.id, compute_flavor=candidate)

    def revert(self, result, load_balancer: models.LoadBalancer, candidate: str, removal_host: str, **kwargs):
        """Handle a failure to force adding a loadbalancer."""

        if isinstance(result, failure.Failure):
            LOG.error("RewriteAmphoraEntry: Unable to update Amphora entry for %s",
                      load_balancer.id)
            return
        LOG.warning("RewriteAmphoraEntry: Reverting host change of amphora %s from '%s' to '%s'",
                    load_balancer.id, candidate, removal_host)
        self._amphora_repo.update(db_apis.get_session(), load_balancer.id, compute_flavor=removal_host)


class RewriteLoadBalancerEntry(RescheduleTasks):
    def execute(self, load_balancer: models.LoadBalancer, candidate: str, *args, **kwargs):
        LOG.debug("RewriteLoadBalancerEntry %s: Changing host '%s' to '%s'.",
                  load_balancer.id, load_balancer.server_group_id, candidate)
        self._loadbalancer_repo.update(db_apis.get_session(), load_balancer.id, server_group_id=candidate)

    def revert(self, result, load_balancer: models.LoadBalancer, candidate: str, removal_host: str, **kwargs):
        """Handle a failure to force adding a loadbalancer."""

        if isinstance(result, failure.Failure):
            LOG.error("RewriteLoadBalancerEntry: Unable to update loadbalancer %s",
                      load_balancer.id)
            return
        LOG.warning("RewriteLoadBalancerEntry: Reverting host change of loadbalancer %s from '%s' to '%s'",
                    load_balancer.id, candidate, removal_host)
        self._loadbalancer_repo.update(db_apis.get_session(), load_balancer.id, server_group_id=removal_host)
