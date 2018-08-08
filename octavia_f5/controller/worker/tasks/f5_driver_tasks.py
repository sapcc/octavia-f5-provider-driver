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
import json

from oslo_log import log as logging
from taskflow import task

from octavia.controller.worker import task_utils as task_utilities
from octavia.db import repositories as repo
from octavia_f5.utils import mapper

LOG = logging.getLogger(__name__)

class F5BaseTask(task.Task):
    """Base task to load drivers common to the tasks."""

    def __init__(self, **kwargs):
        super(F5BaseTask, self).__init__(**kwargs)
        self.task_utils = task_utilities.TaskUtils()

    def _path_to_str(self, path):
        if 'name' in path:
            return path['partition'] + '/' + path['name']

        return path['partition']

    def create_resource(self, resource, path, create_dict):
        try:
            return resource.create(**create_dict)
        except Exception:
            LOG.exception("failed creating resource %s: %s failed",
                          resource.__class__.__name__,
                          self._path_to_str(path))
            raise

    def update_resource(self, resource, path, update_dict):
        try:
            obj = resource.load(**path)
            return obj.modify(**update_dict)
        except Exception:
            LOG.exception("failed updating resource %s: %s failed",
                          resource.__class__.__name__,
                          self._path_to_str(path))
            raise

    def delete_resource(self, resource, path):
        try:
            obj = resource.load(**path)
            return obj.delete()
        except Exception:
            LOG.exception("failed deleting resource %s: %s failed",
                          resource.__class__.__name__,
                          self._path_to_str(path))
            raise


class EnsurePartitionCreated(F5BaseTask):
    """Create the compute instance for a new amphora."""

    def execute(self, loadbalancer, bigip):
        folder = mapper.get_folder(loadbalancer)

        f = bigip.tm.sys.folders.folder

        try:
            if f.exists(name=folder['name']):
                return
            return f.create(**folder)
        except Exception:
            LOG.exception("failed creating partiton: %s failed",
                          folder['name'])
            raise

class DeletePartition(F5BaseTask):
    def execute(self, loadbalancer, bigip):
        folder_path = mapper.get_partition_path(loadbalancer.project_id)
        self.delete_resource(bigip.tm.sys.folders.folder, folder_path)

class ListenersUpdate(F5BaseTask):
    """Task to update F5s with all specified listeners' configurations."""

    def execute(self, loadbalancer, listeners, bigip):
        """Execute updates per listener for a f5."""

        f = bigip.tm.ltm.virtuals.virtual
        for listener in listeners:
            listener.load_balancer = loadbalancer
            path = mapper.get_virtual_path(listener)
            virtual = mapper.get_virtual(listener)

            if f.exists(**path):
                obj = f.load(**path)
                LOG.debug(json.dumps(virtual, indent=4, sort_keys=True))
                obj.modify(**virtual)
            else:
                LOG.debug(json.dumps(virtual, indent=4, sort_keys=True))
                f.create(**virtual)

    def revert(self, loadbalancer, *args, **kwargs):
        """Handle failed listeners updates."""

        LOG.warning("Reverting listeners updates.")

        for listener in loadbalancer.listeners:
            self.task_utils.mark_listener_prov_status_error(listener.id)

        return None

class ListenerDelete(F5BaseTask):
    def execute(self, loadbalancer, listener, bigip):
        virt_path = mapper.get_virtual_path(listener)
        self.delete_resource(bigip.tm.ltm.virtuals.virtual, virt_path)

    def revert(self, listener, *args, **kwargs):
        """Handle a failed listener delete."""
        LOG.warning("Reverting listener delete.")
        self.task_utils.mark_listener_prov_status_error(listener.id)


# Pools
class PoolCreate(F5BaseTask):
    def execute(self, pool, loadbalancer, members, health_monitor, bigip):
        f5_pool = mapper.map_pool(pool, loadbalancer,
                                 members, health_monitor)
        self.delete_resource(bigip.tm.ltm.pools.pool, f5_pool)

    def revert(self, pool, *args, **kwargs):
        """Handle failed pool creation."""
        LOG.warning("Reverting pool creation.")
        self.task_utils.mark_pool_prov_status_error(pool.id)
        return None


class PoolUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, members, health_monitor, bigip):
        pool_path = mapper.get_pool_path(loadbalancer, pool)
        f5_pool = mapper.map_pool(pool, loadbalancer,
                                  members, health_monitor)
        self.update_resource(bigip.tm.ltm.pools.pool,
                             pool_path, f5_pool)


class PoolDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, bigip):
        pool_path = mapper.get_pool_path(loadbalancer, pool)
        self.delete_resource(bigip.tm.ltm.pools.pool, pool_path)

    def revert(self, pool, *args, **kwargs):
        """Handle failed pool deletion."""
        LOG.warning("Reverting pool delete.")
        self.task_utils.mark_pool_prov_status_error(pool.id)
        return None


class HealthMonitorUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError

class HealthMonitorDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class HealthMonitorCreate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7RuleUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7RuleDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7RuleCreate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7PolicyUpdate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError


class L7PolicyDelete(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        policy_path = mapper.get_l7policy_path(loadbalancer, pool)
        self.delete_resource(bigip.tm.ltm.policys.policy, policy_path)


class L7PolicyCreate(F5BaseTask):
    def execute(self, pool, loadbalancer, listeners, health_monitor, bigip):
        raise NotImplementedError
