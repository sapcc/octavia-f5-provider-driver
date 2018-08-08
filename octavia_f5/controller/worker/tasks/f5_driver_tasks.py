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
        self.listener_repo = repo.ListenerRepository()
        self.loadbalancer_repo = repo.LoadBalancerRepository()
        self.task_utils = task_utilities.TaskUtils()

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
    """Create the compute instance for a new amphora."""

    def execute(self, loadbalancer, bigip):
        name = mapper.get_partition_name(loadbalancer.project_id)

        f = bigip.tm.sys.folders.folder

        try:
            if f.exists(name=name):
                obj = f.load(name=name)
                return obj.delete()
        except Exception:
            LOG.exception("failed deleting partiton: %s failed",
                          name)
            raise

class ListenersUpdate(F5BaseTask):
    """Task to update F5s with all specified listeners' configurations."""

    def execute(self, loadbalancer, listeners, bigip):
        """Execute updates per listener for a f5."""

        f = bigip.tm.ltm.virtuals.virtual
        for listener in listeners:
            listener.load_balancer = loadbalancer
            #virtual_name = mapper.get_virtual_name(listener)
            path = mapper.get_virtual_name(listener)
            virtual = mapper.get_virtual(listener)

            if f.exists(**path):
                obj = f.load(**path)
                print(virtual)
                print(obj)
            else:
                f.create(**virtual)

    def revert(self, loadbalancer, *args, **kwargs):
        """Handle failed listeners updates."""

        LOG.warning("Reverting listeners updates.")

        for listener in loadbalancer.listeners:
            self.task_utils.mark_listener_prov_status_error(listener.id)

        return None

class ListenerDelete(F5BaseTask):
    """Task to delete the listener on the vip."""

    def execute(self, loadbalancer, listener, bigip):
        """Execute listener delete routines for an f5."""

        #self.amphora_driver.delete(listener, loadbalancer.vip)
        f = bigip.tm.ltm.virtuals.virtual
        virt = mapper.get_virtual_name(listener)

        try:
            if f.exists(**virt):
                obj = f.load(**virt)
                return obj.delete()
        except Exception:
            LOG.exception("failed deleting virtual: %s failed",
                          virt)
            raise

        LOG.debug("Deleted the listener on the vip")

    def revert(self, listener, *args, **kwargs):
        """Handle a failed listener delete."""

        LOG.warning("Reverting listener delete.")

        self.task_utils.mark_listener_prov_status_error(listener.id)
