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
from oslo_log import log as logging
from taskflow import flow
from taskflow.patterns import unordered_flow, linear_flow

from octavia.network import data_models as network_models
from octavia_f5.controller.worker.tasks import f5_tasks_iseries
from octavia_f5.utils import driver_utils

LOG = logging.getLogger(__name__)


class F5Flows(object):

    def __init__(self, tasks=f5_tasks_iseries):
        self.tasks = tasks

    def make_ensure_l2_flow(self, selfips: [network_models.Port], store: dict) -> flow.Flow:
        """
        Construct and return a flow to ensure complete L2 configuration for a new partition.
        The flow assumes that no L2 objects exist yet for the network so nothing is cleaned up.

        We have to inject all required variables to each flow/task because these flows will
        be running as part of Graph flow and storage contains equal variables but for two F5
        devices, their variables' names overlap. Also in graph flow, every subflow/task should
        have a unique name that's why we have to add BigIP hostname.
        """
        bigip_hostname = store["bigip"].hostname
        # make SelfIP creation subflow
        ensure_selfips_subflow = unordered_flow.Flow(
            f'ensure-selfips-subflow-{bigip_hostname}')
        for selfip_port in selfips:
            ensure_selfip_task = self.tasks.EnsureSelfIP(
                name=f'ensure-selfip-{bigip_hostname}-{selfip_port.id}',
                inject={
                    # store data should come first because it also contains port data
                    **store,
                    'port': selfip_port
                }
            )
            ensure_selfips_subflow.add(ensure_selfip_task)

        # create subnet routes for all subnets that don't have a SelfIP
        network = store['network']
        subnets_to_create_routes_for = [subnet for subnet in network.subnets
                                        if not driver_utils.selfip_for_subnet_exists(subnet, selfips)]
        ensure_subnet_routes_subflow = unordered_flow.Flow(
            f'ensure-subnet-routes-subflow-{bigip_hostname}')

        # make subnet route creation subflow
        for subnet_id in subnets_to_create_routes_for:
            subnet_route_name = driver_utils.get_subnet_route_name(network.id, subnet_id)
            ensure_subnet_route_task = self.tasks.EnsureSubnetRoute(
                name=f'ensure-subnet-route-{bigip_hostname}-{subnet_route_name}',
                inject={
                    # store data should come first because it also contains subnet_id
                    **store,
                    'subnet_id': subnet_id
                }
            )
            ensure_subnet_routes_subflow.add(ensure_subnet_route_task)

        get_existing_route_domain = self.tasks.GetExistingRouteDomain(
            name=f'get-existing-route-domain-{bigip_hostname}',
            inject=store)
        ensure_route_domain = self.tasks.EnsureRouteDomain(
            name=f'ensure-route-domain-{bigip_hostname}',
            inject=store)
        ensure_default_route = self.tasks.EnsureDefaultRoute(
            name=f'ensure-default-route-{bigip_hostname}',
            inject=store)
        ensure_vlan = self.tasks.EnsureVLANGuest(
            name=f'ensure-vlan-guest-{bigip_hostname}',
            inject=store)

        ensure_l2_flow = linear_flow.Flow(f'ensure-l2-flow-{bigip_hostname}')
        ensure_l2_flow.add(ensure_vlan,
                           get_existing_route_domain,
                           ensure_route_domain,
                           # SelfIPs must be present for routes to work
                           ensure_selfips_subflow,
                           ensure_default_route,
                           ensure_subnet_routes_subflow)
        return ensure_l2_flow

    def make_remove_l2_flow(self, store: dict) -> flow.Flow:
        """
        Construct and return a flow to remove complete L2 configuration of a partition.

        We have to inject all required variables to each flow/task because these flows will
        be running as part of main flow and storage contains equal variables but for two F5
        devices, their variables' names overlap. Also in one flow, every subflow/task should
        have a unique name that's why we have to add BigIP hostname.
        """
        bigip_hostname = store["bigip"].hostname

        existing_selfips = store['existing_selfips']
        existing_subnet_routes = store['existing_subnet_routes']

        # remove subnet routes
        remove_subnet_routes_subflow = unordered_flow.Flow(
            f'remove-subnet-routes-subflow-{bigip_hostname}')
        for subnet_route in existing_subnet_routes:
            remove_subnet_route_task = self.tasks.RemoveSubnetRoute(
                name=f"remove-subnet-route-{bigip_hostname}-{subnet_route['name']}",
                inject={
                    **store,
                    'subnet_route': subnet_route
                }
            )
            remove_subnet_routes_subflow.add(remove_subnet_route_task)

        # remove SelfIPs
        remove_selfips_subflow = unordered_flow.Flow(f'remove-selfips-subflow-{bigip_hostname}')
        for selfip in existing_selfips:
            remove_selfip_task = self.tasks.RemoveSelfIP(
                name=f"remove-selfip-{bigip_hostname}-{selfip['port_id']}",
                inject={
                    **store,
                    'selfip': selfip
                }
            )
            remove_selfips_subflow.add(remove_selfip_task)

        # remove other L2 objects
        remove_default_route_task = self.tasks.RemoveDefaultRoute(
            name=f'remove-defult-route-{bigip_hostname}',
            inject=store)
        get_existing_route_domain = self.tasks.GetExistingRouteDomain(
            name=f'get-existing-route-domain-{bigip_hostname}',
            inject=store)
        remove_route_domain_task = self.tasks.RemoveRouteDomain(
            name=f'remove-route-domain-{bigip_hostname}',
            inject=store)
        get_existing_vlan = self.tasks.GetExistingVLAN(
            name=f'get-existing-vlan-{bigip_hostname}',
            inject=store)
        remove_vlan_task = self.tasks.RemoveVLAN(
            name=f'remove-vlan-{bigip_hostname}',
            inject=store)

        remove_l2_flow = linear_flow.Flow(f'remove-l2-flow-{bigip_hostname}')
        # SubnetRoute and DefaultRoute have to be removed only from active device.
        if store["bigip"].is_active:
            remove_l2_flow.add(remove_subnet_routes_subflow,
                               remove_default_route_task)
        # SelfIPs must be deleted after routes, otherwise a route would be unreachable
        remove_l2_flow.add(remove_selfips_subflow,
                           get_existing_route_domain,
                           remove_route_domain_task,
                           get_existing_vlan,
                           remove_vlan_task)
        return remove_l2_flow

    def make_sync_selfips_and_subnet_routes_flow(self, needed_selfips, subnets_that_need_routes,
                                                 store: dict) -> flow.Flow:
        """ Construct and return a flow that syncs SelfIPs and static subnet routes.
        Since SelfIPs and subnet routes are mutually exclusive (per subnet), first remove unneeded SelfIPs/subnet
        routes, then add missing SelfIPs/subnet routes. Put the two stages into one single (linear) flow, so that they
        can both be rolled back together.

        :param needed_selfips: SelfIPs that must exist
        :param subnets_that_need_routes: Subnets for which subnet routes must exist
        """

        # create subflow to remove unneeded SelfIPs and subnet routes
        remove_selfips_and_subnet_routes_flow = self.make_remove_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store)

        # create subflow to ensure needed SelfIPs and subnet routes
        ensure_selfips_and_subnet_routes_flow = self.make_ensure_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store)

        # return linear flow
        sync_flow = linear_flow.Flow('sync-selfips-and-subnet-routes-flow')
        sync_flow.add(remove_selfips_and_subnet_routes_flow)
        sync_flow.add(ensure_selfips_and_subnet_routes_flow)
        return sync_flow

    def make_remove_selfips_and_subnet_routes_flow(self, needed_selfips, subnets_that_need_routes,
                                                   store: dict) -> flow.Flow:
        """ Remove unneeded SelfIPs and subnet routes of a specific network

        :param needed_selfips: Ports for SelfIPs that must exist
        :param subnets_that_need_routes: Subnets for which subnet routes must exist
        """
        host = store['bigip'].hostname
        network = store['network']
        existing_selfips = store['existing_selfips']
        existing_subnet_routes = store['existing_subnet_routes']

        # remove subnet routes that are existing but don't belong to one of the subnets that need routes
        subnet_route_network_part = driver_utils.get_subnet_route_name(network.id, '')
        subnet_routes_to_remove = [r for r in existing_subnet_routes
                                   if r['name'].startswith(subnet_route_network_part) and
                                   r['name'][len(subnet_route_network_part):] not in subnets_that_need_routes]
        LOG.debug(f"{host}: Subnet routes to remove for network {network.id} (subnet IDs):"
                  f" {[r['name'] for r in subnet_routes_to_remove]}")

        # make subnet routes removal subflow
        remove_subnet_routes_subflow = unordered_flow.Flow('remove-subnet-routes-subflow')
        for subnet_route in subnet_routes_to_remove:
            remove_subnet_route_task = self.tasks.RemoveSubnetRoute(name=f"remove-subnet-route-{subnet_route['name']}",
                                                                    inject={'subnet_route': subnet_route})
            remove_subnet_routes_subflow.add(remove_subnet_route_task)

        # remove SelfIPs that are existing but not needed
        selfips_to_remove = [sip for sip in existing_selfips if sip['port_id'] not in [p.id for p in needed_selfips]]
        LOG.debug(f"{host}: SelfIPs to remove for network {network.id}: {[sip['port_id'] for sip in selfips_to_remove]}")

        # make SelfIPs removal subflow
        remove_selfips_subflow = unordered_flow.Flow('remove-selfips-subflow')
        for selfip in selfips_to_remove:
            remove_selfip = self.tasks.RemoveSelfIP(name=f"remove-selfip-{selfip['port_id']}",
                                                    inject={'selfip': selfip})
            remove_selfips_subflow.add(remove_selfip)

        # make and return flow
        remove_selfips_and_subnet_routes_flow = linear_flow.Flow('remove-selfips-and-subnet-routes-flow')
        if store['bigip'].is_active:
            remove_selfips_and_subnet_routes_flow.add(remove_subnet_routes_subflow)
        remove_selfips_and_subnet_routes_flow.add(remove_selfips_subflow)
        return remove_selfips_and_subnet_routes_flow

    def make_ensure_selfips_and_subnet_routes_flow(self, needed_selfips, subnets_that_need_routes,
                                                   store: dict) -> flow.Flow:
        """ Add needed SelfIPs and subnet routes of a specific network

        :param needed_selfips: SelfIPs that must exist
        :param subnets_that_need_routes: Subnets for which subnet routes must exist
        """
        host = store['bigip'].hostname
        network = store['network']
        preexisting_selfips = store['existing_selfips']
        preexisting_subnet_routes = store['existing_subnet_routes']

        # find SelfIPs that are expected but not existing
        selfips_to_create = [port for port in needed_selfips
                             if port.id not in [sip['port_id'] for sip in preexisting_selfips]]
        LOG.debug(f"{host}: SelfIPs to add for network {network.id}: {[p.id for p in selfips_to_create]}")

        # make SelfIP creation subflow
        ensure_selfips_subflow = unordered_flow.Flow('ensure-selfips-subflow')
        for selfip_port in selfips_to_create:
            ensure_selfip_task = self.tasks.EnsureSelfIP(
                name=f'ensure-selfip-{store["bigip"].hostname}-{selfip_port.id}',
                inject={'port': selfip_port})
            ensure_selfips_subflow.add(ensure_selfip_task)

        # find subnet routes for subnets that need them but don't have any yet
        subnet_route_network_part = driver_utils.get_subnet_route_name(network.id, '')
        subnets_of_preexisting_subnet_routes = [
            r['name'][len(subnet_route_network_part):] for r in preexisting_subnet_routes
            if r['name'].startswith(subnet_route_network_part)
        ]
        subnets_to_create_routes_for = [s for s in subnets_that_need_routes
                                        if s not in subnets_of_preexisting_subnet_routes]
        LOG.debug(f"{host}: Subnet of network {network.id} for which routes will be created: "
                  f"{subnets_to_create_routes_for}")

        # make subnet route creation subflow
        ensure_subnet_routes_subflow = unordered_flow.Flow('ensure-subnet-routes-subflow')
        for subnet_id in subnets_to_create_routes_for:
            subnet_route_name = driver_utils.get_subnet_route_name(network.id, subnet_id)
            ensure_subnet_route_task = self.tasks.EnsureSubnetRoute(name=f"ensure-subnet-route-{subnet_route_name}",
                                                                    inject={'subnet_id': subnet_id})
            ensure_subnet_routes_subflow.add(ensure_subnet_route_task)

        # make and return flow
        ensure_selfips_and_subnet_routes_flow = linear_flow.Flow('ensure-selfips-and-subnet-routes-flow')
        ensure_selfips_and_subnet_routes_flow.add(ensure_selfips_subflow,
                                                  ensure_subnet_routes_subflow)
        return ensure_selfips_and_subnet_routes_flow

    def make_get_existing_selfips_and_subnet_routes_flow(self) -> flow.Flow:
        """Return a flow that gets all SelfIPs and subnet routes that currently
        exist on a particular device for a particular network."""

        get_selfips_task = self.tasks.GetExistingSelfIPsForVLAN(name='get-existing-selfips')
        get_subnet_routes_task = self.tasks.GetExistingSubnetRoutesForNetwork(name='get-existing-subnet-routes')

        get_existing_sip_sr_flow = unordered_flow.Flow('get-existing-selfips-and-subnet-routes-flow')
        get_existing_sip_sr_flow.add(get_selfips_task)
        get_existing_sip_sr_flow.add(get_subnet_routes_task)

        return get_existing_sip_sr_flow

    def make_ensure_vcmp_l2_flow(self) -> flow.Flow:
        get_existing_vlan = self.tasks.GetExistingVLAN()
        ensure_vlan = self.tasks.EnsureVLANHost()
        ensure_vlan_interface = self.tasks.EnsureVLANInterface()
        ensure_vlan_guest_assignment = self.tasks.EnsureVLANGuestAssignment()

        ensure_vcmp_l2_flow = linear_flow.Flow('ensure-vcmp-l2-flow')
        ensure_vcmp_l2_flow.add(get_existing_vlan,
                                ensure_vlan,
                                ensure_vlan_interface,
                                ensure_vlan_guest_assignment)
        return ensure_vcmp_l2_flow

    def make_remove_vcmp_l2_flow(self) -> flow.Flow:
        get_vcmp_guests = self.tasks.GetVCMPGuests()
        remove_vlan_guest_assignment = self.tasks.RemoveVLANGuestAssignment()
        # Don't unassign the VLAN from the interface/LAG. It's going to happen
        # during VLAN deletion. We only want it to happen if VLAN deletion
        # succeeds.
        remove_vlan_if_not_owned_by_other_guest = self.tasks.RemoveVLANIfNotOwnedByOtherGuest()

        remove_vcmp_l2_flow = linear_flow.Flow('remove-vcmp-l2-flow')
        remove_vcmp_l2_flow.add(get_vcmp_guests,
                                remove_vlan_guest_assignment,
                                remove_vlan_if_not_owned_by_other_guest)
        return remove_vcmp_l2_flow
