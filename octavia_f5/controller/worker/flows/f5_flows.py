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
    def ensure_l2(self, selfips: [network_models.Port], existing_routes: [str]) -> flow.Flow:
        """ Ensure all L2 objects exist for a given network.
        This flow assumes that no L2 objects exist yet for the network so
        nothing is cleaned up.

        :param selfips: SelfIPs to create. This is a function argument instead
        of being in the store, because an EnsureSelfIP subtask is appended to
        the flow for each SelfIP.
        """

        # We can parallelize selfip creation
        ensure_selfip_subflow = unordered_flow.Flow('ensure-selfip-subflow')
        for selfip in selfips:
            ensure_selfip = f5_tasks.EnsureSelfIP(name=f"ensure-selfip-{selfip.id}",
                                                  inject={'port': selfip})
            ensure_selfip_subflow.add(ensure_selfip)

        ensure_routedomain = f5_tasks.EnsureRouteDomain()
        ensure_default_route = f5_tasks.EnsureDefaultRoute()
        ensure_static_routes = f5_tasks.EnsureSubnetRoutes(inject={
            'selfips': selfips, 'existing_routes': existing_routes})
        ensure_vlan = f5_tasks.EnsureVLAN()

        ensure_l2_flow = linear_flow.Flow('ensure-l2-flow')
        ensure_l2_flow.add(ensure_vlan,
                           ensure_routedomain,
                           ensure_selfip_subflow,
                           ensure_default_route,
                           ensure_static_routes)
        return ensure_l2_flow

    def remove_l2(self, selfips: [str], existing_routes: [str]) -> flow.Flow:
        """ Remove all L2 objects for a given network.

        :param selfips: SelfIPs to remove. This is a function argument instead
        of being in the store, because an RemoveSelfIP subtask is appended to
        the flow for each SelfIP.
        """

        # We can parallelize selfip deletion
        cleanup_selfip_subflow = unordered_flow.Flow('cleanup-selfip-subflow')
        for selfip in selfips:
            cleanup_selfip = f5_tasks.RemoveSelfIP(name=f"cleanup-selfip-{selfip.id}",
                                                   inject={'port': selfip})
            cleanup_selfip_subflow.add(cleanup_selfip)

        cleanup_subnet_routes = f5_tasks.CleanupSubnetRoutes(inject={
            'selfips': selfips, 'delete_all': True,
            'existing_routes': existing_routes})
        cleanup_route = f5_tasks.CleanupDefaultRoute()
        cleanup_routedomain = f5_tasks.CleanupRouteDomain()
        cleanup_vlan = f5_tasks.CleanupVLAN()

        cleanup_l2_flow = linear_flow.Flow('cleanup-l2-flow')
        cleanup_l2_flow.add(cleanup_subnet_routes,
                            cleanup_route,
                            cleanup_selfip_subflow,
                            cleanup_routedomain,
                            cleanup_vlan)
        return cleanup_l2_flow

    def sync_selfips_and_subnet_routes(self, expected_selfips, device_selfips,
            existing_routes, store: dict) -> flow.Flow:
        """ Sync SelfIPs and static subnet routes for a given network.

        Since SelfIPs and subnet routes are mutually exclusive we have to first
        remove the ones that aren't needed anymore and then add the needed
        ones.

        :param expected_selfips: SelfIPs that must exist
        :param device_selfips: SelfIPs that currently exist
        :param existing_routes: Static subnet routes that currently exist
        """

        sync_selfips_and_subnet_routes_flow = linear_flow.Flow(
                'sync-selfips-and-subnet-routes-flow')

        # remove unneeded SelfIPs/subnet routes
        sync_selfips_and_subnet_routes_flow.add(
                self.cleanup_selfips_and_subnet_routes(expected_selfips,
                    device_selfips, existing_routes, store))

        # add missing SelfIPs/subnet routes
        sync_selfips_and_subnet_routes_flow.add(
                self.ensure_selfips_and_subnet_routes(expected_selfips,
                    device_selfips, existing_routes, store))

        return sync_selfips_and_subnet_routes_flow

    def cleanup_selfips_and_subnet_routes(self, expected_selfips,
            device_selfips, existing_routes, store: dict) -> flow.Flow:
        """ Remove unneeded SelfIPs and subnet routes of a specific network

        :param expected_selfips: SelfIPs that must exist
        :param device_selfips: SelfIPs that currently exist
        :param existing_routes: Static subnet routes that currently exist
        """

        cleanup_selfips_and_subnet_routes_flow = unordered_flow.Flow('cleanup-selfips-and-subnet-routes-flow')

        # remove unneeded SelfIPs
        selfips_to_remove = [port for port in device_selfips if port.id not in [p.id for p in expected_selfips]]
        LOG.debug("%s: SelfIPs to remove for network %s: %s",
                  store['bigip'].hostname, store['network'].id, [p.id for p in selfips_to_remove])
        for selfip in selfips_to_remove:
            cleanup_selfip = f5_tasks.RemoveSelfIP(name=f"cleanup-selfip-{selfip.id}", inject={'port': selfip})
            cleanup_selfips_and_subnet_routes_flow.add(cleanup_selfip)

        # remove unneeded subnet routes
        cleanup_selfips_and_subnet_routes_flow.add(
            f5_tasks.CleanupSubnetRoutes(inject={
                'expected_selfips': expected_selfips,
                'existing_routes': existing_routes}))

        return cleanup_selfips_and_subnet_routes_flow

    def ensure_selfips_and_subnet_routes(self, expected_selfips,
            device_selfips, existing_routes, store: dict) -> flow.Flow:
        """ Add needed SelfIPs and subnet routes of a specific network

        :param expected_selfips: SelfIPs that must exist
        :param device_selfips: SelfIPs that currently exist
        :param existing_routes: Static subnet routes that currently exist
        """

        ensure_selfips_and_subnet_routes_flow = unordered_flow.Flow('ensure-selfips-and-subnet-routes-flow')

        # add missing SelfIPs
        selfips_to_add = [port for port in expected_selfips if port.id not in [p.id for p in device_selfips]]
        LOG.debug("%s: SelfIPs to add for network %s: %s",
                  store['bigip'].hostname, store['network'].id, [p.id for p in selfips_to_add])

        for selfip in selfips_to_add:
            ensure_selfip = f5_tasks.EnsureSelfIP(name=f"ensure-selfip-{selfip.id}", inject={'port': selfip})
            ensure_selfips_and_subnet_routes_flow.add(ensure_selfip)

        # add missing subnet routes
        ensure_selfips_and_subnet_routes_flow.add(
            f5_tasks.EnsureSubnetRoutes(inject={
                'expected_selfips': expected_selfips,
                'existing_routes': existing_routes}))

        return ensure_selfips_and_subnet_routes_flow

    def get_selfips_from_device_for_vlan(self) -> [network_models.Port]:
        return f5_tasks.GetAllSelfIPsForVLAN(name='all-selfips')

    def get_subnet_routes_from_device_for_network(self) -> [str]:
        return f5_tasks.GetAllSubnetRoutesForNetwork(name='existing_routes')

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
        cleanup_guest_vlan = f5_tasks.CleanupGuestVLAN()
        cleanup_vlan_if_not_owned_by_guest = f5_tasks.CleanupVLANIfNotOwnedByGuest()

        cleanup_vcmp_l2_flow = linear_flow.Flow('cleanup-vcmp-l2-flow')
        cleanup_vcmp_l2_flow.add(get_vcmp_guests,
                                 cleanup_guest_vlan,
                                 cleanup_vlan_if_not_owned_by_guest)
        return cleanup_vcmp_l2_flow
