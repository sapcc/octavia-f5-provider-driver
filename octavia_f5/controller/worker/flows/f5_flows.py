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

from taskflow import flow
from taskflow.patterns import unordered_flow, linear_flow

from octavia.network import data_models as network_models
from octavia_f5.controller.worker.tasks import f5_tasks


class F5Flows(object):
    def ensure_l2(self, selfips: [network_models.Port]) -> flow.Flow:
        # We can parallelize selfip creation
        ensure_selfip_subflow = unordered_flow.Flow('ensure-selfip-subflow')
        for selfip in selfips:
            ensure_selfip = f5_tasks.EnsureSelfIP(name=f"ensure-selfip-{selfip.id}",
                                                  inject={'port': selfip})
            ensure_selfip_subflow.add(ensure_selfip)

        ensure_routedomain = f5_tasks.EnsureRouteDomain()
        ensure_default_route = f5_tasks.EnsureDefaultRoute()
        ensure_static_routes = f5_tasks.SyncSubnetRoutes(inject={'selfips': selfips})
        ensure_vlan = f5_tasks.EnsureVLAN()

        ensure_l2_flow = linear_flow.Flow('ensure-l2-flow')
        ensure_l2_flow.add(ensure_vlan,
                           ensure_routedomain,
                           ensure_selfip_subflow,
                           ensure_default_route,
                           ensure_static_routes)
        return ensure_l2_flow

    def remove_l2(self, selfips: [str]) -> flow.Flow:
        # We can parallelize selfip deletion
        cleanup_selfip_subflow = unordered_flow.Flow('cleanup-selfip-subflow')
        for selfip in selfips:
            cleanup_selfip = f5_tasks.RemoveSelfIP(name=f"cleanup-selfip-{selfip.id}",
                                                   inject={'port': selfip})
            cleanup_selfip_subflow.add(cleanup_selfip)

        cleanup_static_routes = f5_tasks.CleanupSubnetRoutes()
        cleanup_route = f5_tasks.CleanupDefaultRoute()
        cleanup_routedomain = f5_tasks.CleanupRouteDomain()
        cleanup_vlan = f5_tasks.CleanupVLAN()

        cleanup_l2_flow = linear_flow.Flow('cleanup-l2-flow')
        cleanup_l2_flow.add(cleanup_static_routes,
                            cleanup_route,
                            cleanup_selfip_subflow,
                            cleanup_routedomain,
                            cleanup_vlan)
        return cleanup_l2_flow

    def sync_l2_selfips(self, selfips: dict) -> flow.Flow:
        """ Updates SelfIPs of a specific network
            * Adding new ones
            * Removing orphaned ones

        :param selfips: 'add' and 'remove' dictionary of selfips
        """

        sync_l2_selfips_flow = unordered_flow.Flow('sync-l2-selfips-flow')
        for selfip in selfips.get('add', []):
            ensure_selfip = f5_tasks.EnsureSelfIP(name=f"ensure-selfip-{selfip.id}", inject={'port': selfip})
            sync_l2_selfips_flow.add(ensure_selfip)

        for selfip in selfips.get('remove', []):
            cleanup_selfip = f5_tasks.RemoveSelfIP(name=f"cleanup-selfip-{selfip.id}", inject={'port': selfip})
            sync_l2_selfips_flow.add(cleanup_selfip)

        return sync_l2_selfips_flow

    def get_selfips_from_device_for_vlan(self) -> [network_models.Port]:
        return f5_tasks.GetAllSelfIPsForVLAN(name='all-selfips')

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
