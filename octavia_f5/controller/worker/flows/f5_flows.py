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
from octavia_f5.controller.worker.tasks import f5_tasks

LOG = logging.getLogger(__name__)


class F5Flows(object):
    def make_ensure_l2_flow(self, selfips: [network_models.Port], store: dict) -> flow.Flow:
        """
        Construct and return a flow to ensure complete L2 configuration for a new partition.
        The flow assumes that no L2 objects exist yet for the network so nothing is cleaned up.
        """

        # make SelfIP creation subflow
        ensure_selfips_subflow = unordered_flow.Flow('ensure-selfips-subflow')
        for selfip in selfips:
            ensure_selfip_task = f5_tasks.EnsureSelfIP(name=f"ensure-selfip-{selfip.id}", inject={'port': selfip})
            ensure_selfips_subflow.add(ensure_selfip_task)

        # create subnet routes for all subnets that don't have a SelfIP
        network = store['network']
        subnets_to_create_routes_for = [subnet for subnet in network.subnets
                                        if not f5_tasks.selfip_for_subnet_exists(subnet, selfips)]
        ensure_subnet_routes_subflow = unordered_flow.Flow('ensure-subnet-routes-subflow')

        # make subnet route creation subflow
        for subnet_id in subnets_to_create_routes_for:
            subnet_route_name = f5_tasks.get_subnet_route_name(network.id, subnet_id)
            ensure_subnet_route_task = f5_tasks.EnsureSubnetRoute(name=f"ensure-subnet-route-{subnet_route_name}",
                                                                  inject={'subnet_id': subnet_id})
            ensure_subnet_routes_subflow.add(ensure_subnet_route_task)

        ensure_routedomain = f5_tasks.EnsureRouteDomain()
        ensure_default_route = f5_tasks.EnsureDefaultRoute()
        ensure_vlan = f5_tasks.EnsureVLAN()

        ensure_l2_flow = linear_flow.Flow('ensure-l2-flow')
        ensure_l2_flow.add(ensure_vlan,
                           ensure_routedomain,
                           # SelfIPs must be present for routes to work
                           ensure_selfips_subflow,
                           ensure_default_route,
                           ensure_subnet_routes_subflow)
        return ensure_l2_flow

    def make_remove_l2_flow(self, store: dict) -> flow.Flow:
        """Construct and return a flow to remove complete L2 configuration of a partition."""
        existing_selfips = store['existing_selfips']
        existing_subnet_routes = store['existing_subnet_routes']

        # remove subnet routes
        remove_subnet_routes_subflow = unordered_flow.Flow('remove-subnet-routes-subflow')
        for subnet_route in existing_subnet_routes:
            remove_subnet_route_task = f5_tasks.RemoveSubnetRoute(name=f"remove-subnet-route-{subnet_route['name']}",
                                                                  inject={'subnet_route': subnet_route})
            remove_subnet_routes_subflow.add(remove_subnet_route_task)

        # remove SelfIPs
        remove_selfips_subflow = unordered_flow.Flow('remove-selfips-subflow')
        for selfip in existing_selfips:
            remove_selfip_task = f5_tasks.RemoveSelfIP(name=f"remove-selfip-{selfip.id}", inject={'port': selfip})
            remove_selfips_subflow.add(remove_selfip_task)

        # remove other L2 objects
        remove_default_route_task = f5_tasks.RemoveDefaultRoute()
        remove_route_domain_task = f5_tasks.RemoveRouteDomain()
        remove_vlan_task = f5_tasks.RemoveVLAN()

        remove_l2_flow = linear_flow.Flow('remove-l2-flow')
        remove_l2_flow.add(remove_subnet_routes_subflow,
                           remove_default_route_task,
                           # SelfIPs must be deleted after routes, otherwise a route would be unreachable
                           remove_selfips_subflow,
                           remove_route_domain_task,
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

        sync_flow = linear_flow.Flow('sync-selfips-and-subnet-routes-flow')

        # remove unneeded SelfIPs and subnet routes
        sync_flow.add(self.make_remove_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store))

        # create needed SelfIPs and subnet routes
        sync_flow.add(self.make_ensure_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store))
        return sync_flow

    def make_remove_selfips_and_subnet_routes_flow(self, needed_selfips, subnets_that_need_routes,
                                                   store: dict) -> flow.Flow:
        """ Remove unneeded SelfIPs and subnet routes of a specific network

        :param needed_selfips: SelfIPs that must exist
        :param subnets_that_need_routes: Subnets for which subnet routes must exist
        """
        host = store['bigip'].hostname
        network = store['network']
        preexisting_selfips = store['existing_selfips']
        preexisting_subnet_routes = store['existing_subnet_routes']

        # remove subnet routes that are existing but don't belong to one of the subnets that need routes
        subnet_route_network_part = f5_tasks.get_subnet_route_name(network.id, '')
        subnet_routes_to_remove = [r for r in preexisting_subnet_routes
                                   if r['name'].startswith(subnet_route_network_part)
                                   and r['name'][len(subnet_route_network_part):] not in subnets_that_need_routes]
        LOG.debug(f"{host}: Subnet routes to remove for network {network.id} (subnet IDs): {subnet_routes_to_remove}")

        # make subnet routes removal subflow
        remove_subnet_routes_subflow = unordered_flow.Flow('remove-subnet-routes-subflow')
        for subnet_route in subnet_routes_to_remove:
            remove_subnet_route_task = f5_tasks.RemoveSubnetRoute(name=f"remove-subnet-route-{subnet_route['name']}",
                                                                  inject={'subnet_route': subnet_route['name']})
            remove_subnet_routes_subflow.add(remove_subnet_route_task)

        # remove SelfIPs that are existing but not needed
        selfips_to_remove = [port for port in preexisting_selfips if port.id not in [p.id for p in needed_selfips]]
        LOG.debug(f"{host}: SelfIPs to remove for network {network.id}: {[p.id for p in selfips_to_remove]}")

        # make SelfIPs removal subflow
        remove_selfips_subflow = unordered_flow.Flow('remove-selfips-subflow')
        for selfip in selfips_to_remove:
            remove_selfip = f5_tasks.RemoveSelfIP(name=f"remove-selfip-{selfip.id}", inject={'port': selfip})
            remove_selfips_subflow.add(remove_selfip)

        # make and return flow
        remove_selfips_and_subnet_routes_flow = linear_flow.Flow('remove-selfips-and-subnet-routes-flow')
        remove_selfips_and_subnet_routes_flow.add(remove_subnet_routes_subflow,
                                                  remove_selfips_subflow)
        return remove_selfips_and_subnet_routes_flow

    def make_ensure_selfips_and_subnet_routes_flow(self, needed_selfips, subnets_that_need_routes,
                                                   store: dict) -> flow.Flow:
        """ Add needed SelfIPs and subnet routes of a specific network

        :param needed_selfips: SelfIPs that must exist
        :param subnets_that_need_routes: Subnets for which subnet routes must exist
        """
        host = store['bigip'].hostname
        network = store['network'].id
        preexisting_selfips = store['existing_selfips']
        preexisting_subnet_routes = store['existing_subnet_routes']

        # find SelfIPs that are expected but not existing
        selfips_to_create = [port for port in needed_selfips if port.id not in [p.id for p in preexisting_selfips]]
        LOG.debug(f"{host}: SelfIPs to add for network {network.id}: {[p.id for p in selfips_to_create]}")

        # make SelfIP creation subflow
        ensure_selfips_subflow = unordered_flow.Flow('ensure-selfips-subflow')
        for selfip in selfips_to_create:
            ensure_selfip_task = f5_tasks.EnsureSelfIP(name=f"ensure-selfip-{selfip.id}", inject={'port': selfip})
            ensure_selfips_subflow.add(ensure_selfip_task)

        # find subnet routes for subnets that need them but don't have any yet
        subnet_route_network_part = f5_tasks.get_subnet_route_name(network.id, '')
        subnets_of_preexisting_subnet_routes = [
            r['name'][len(subnet_route_network_part):] for r in preexisting_subnet_routes
            if r['name'].startswith(subnet_route_network_part)
        ]
        subnets_to_create_routes_for = [s for s in subnets_that_need_routes
                                        if s not in subnets_of_preexisting_subnet_routes]

        # make subnet route creation subflow
        ensure_subnet_routes_subflow = unordered_flow.Flow('ensure-subnet-routes-subflow')
        for subnet_id in subnets_to_create_routes_for:
            subnet_route_name = f5_tasks.get_subnet_route_name(network.id, subnet_id)
            ensure_subnet_route_task = f5_tasks.EnsureSubnetRoute(name=f"ensure-subnet-route-{subnet_route_name}",
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
        get_existing_sip_sr_flow = unordered_flow.Flow('get-existing-selfips-and-subnet-routes-flow')
        get_existing_sip_sr_flow.add(f5_tasks.GetExistingSelfIPsForVLAN(name='get-existing-selfips'))
        get_existing_sip_sr_flow.add(f5_tasks.GetExistingSubnetRoutesForNetwork(name='get-existing-subnet-routes'))
        return get_existing_sip_sr_flow

    def ensure_vcmp_l2(self) -> flow.Flow:
        ensure_vlan = f5_tasks.EnsureVLAN()
        ensure_vlan_interface = f5_tasks.EnsureVLANInterface()
        ensure_guest_vlan = f5_tasks.EnsureGuestVLAN()

        ensure_vcmp_l2_flow = linear_flow.Flow('ensure-vcmp-l2-flow')
        ensure_vcmp_l2_flow.add(ensure_vlan,
                                ensure_vlan_interface,
                                ensure_guest_vlan)
        return ensure_vcmp_l2_flow

    def remove_vcmp_l2(self) -> flow.Flow:
        get_vcmp_guests = f5_tasks.GetVCMPGuests()
        remove_guest_vlan = f5_tasks.RemoveGuestVLAN()
        remove_vlan_if_not_owned_by_guest = f5_tasks.RemoveVLANIfNotOwnedByGuest()

        remove_vcmp_l2_flow = linear_flow.Flow('remove-vcmp-l2-flow')
        remove_vcmp_l2_flow.add(get_vcmp_guests,
                                remove_guest_vlan,
                                remove_vlan_if_not_owned_by_guest)
        return remove_vcmp_l2_flow
