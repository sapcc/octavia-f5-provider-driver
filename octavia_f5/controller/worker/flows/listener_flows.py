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

from taskflow.patterns import linear_flow

from octavia_f5.common import constants
from octavia_f5.controller.worker.tasks import f5_driver_tasks
from octavia.controller.worker.tasks import database_tasks
from octavia.controller.worker.tasks import lifecycle_tasks
from octavia.controller.worker.tasks import network_tasks
from octavia.controller.worker.flows.listener_flows \
    import ListenerFlows as OctaviaListenerFlows

class ListenerFlows(OctaviaListenerFlows):

    def get_create_listener_flow(self):
        """Create a flow to create a listener

        :returns: The flow for creating a listener
        """
        create_listener_flow = linear_flow.Flow(constants.CREATE_LISTENER_FLOW)
        create_listener_flow.add(lifecycle_tasks.ListenersToErrorOnRevertTask(
            requires=[constants.LOADBALANCER, constants.LISTENERS]))
        create_listener_flow.add(f5_driver_tasks.EnsurePartitionCreated(
            requires=[constants.LOADBALANCER, constants.BIGIP]))
        create_listener_flow.add(f5_driver_tasks.ListenersUpdate(
            requires=[constants.LOADBALANCER, constants.LISTENERS,
                      constants.BIGIP]))
        create_listener_flow.add(network_tasks.UpdateVIP(
            requires=constants.LOADBALANCER))
        create_listener_flow.add(database_tasks.
            MarkLBAndListenersActiveInDB(
            requires=[constants.LOADBALANCER,
                      constants.LISTENERS]))
        return create_listener_flow

    def get_create_all_listeners_flow(self):
        """Create a flow to create all listeners

        :returns: The flow for creating all listeners
        """
        create_all_listeners_flow = linear_flow.Flow(
            constants.CREATE_LISTENERS_FLOW)
        create_all_listeners_flow.add(
            database_tasks.GetListenersFromLoadbalancer(
                requires=constants.LOADBALANCER,
                provides=constants.LISTENERS))
        create_all_listeners_flow.add(database_tasks.ReloadLoadBalancer(
            requires=constants.LOADBALANCER_ID,
            provides=constants.LOADBALANCER))
        create_all_listeners_flow.add(f5_driver_tasks.ListenersUpdate(
            requires=[constants.LOADBALANCER, constants.LISTENERS]))
        create_all_listeners_flow.add(network_tasks.UpdateVIP(
            requires=constants.LOADBALANCER))
        return create_all_listeners_flow

    def get_delete_listener_flow(self):
        """Create a flow to delete a listener

        :returns: The flow for deleting a listener
        """
        delete_listener_flow = linear_flow.Flow(constants.DELETE_LISTENER_FLOW)
        delete_listener_flow.add(lifecycle_tasks.ListenerToErrorOnRevertTask(
            requires=constants.LISTENER))
        delete_listener_flow.add(f5_driver_tasks.ListenerDelete(
            requires=[constants.LOADBALANCER, constants.LISTENER]))
        delete_listener_flow.add(network_tasks.UpdateVIPForDelete(
            requires=constants.LOADBALANCER))
        delete_listener_flow.add(database_tasks.DeleteListenerInDB(
            requires=constants.LISTENER))
        delete_listener_flow.add(database_tasks.DecrementListenerQuota(
            requires=constants.LISTENER))
        delete_listener_flow.add(database_tasks.MarkLBActiveInDB(
            requires=constants.LOADBALANCER))

        return delete_listener_flow

    def get_update_listener_flow(self):
        """Create a flow to update a listener

        :returns: The flow for updating a listener
        """
        update_listener_flow = linear_flow.Flow(constants.UPDATE_LISTENER_FLOW)
        update_listener_flow.add(lifecycle_tasks.ListenersToErrorOnRevertTask(
            requires=[constants.LOADBALANCER, constants.LISTENERS]))
        update_listener_flow.add(f5_driver_tasks.ListenersUpdate(
            requires=[constants.LOADBALANCER, constants.LISTENERS]))
        update_listener_flow.add(database_tasks.UpdateListenerInDB(
            requires=[constants.LISTENER, constants.UPDATE_DICT]))
        update_listener_flow.add(database_tasks.
                                 MarkLBAndListenersActiveInDB(
                                     requires=[constants.LOADBALANCER,
                                               constants.LISTENERS]))

        return update_listener_flow