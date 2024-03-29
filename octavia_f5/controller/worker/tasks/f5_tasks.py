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
import requests
import tenacity
from netaddr import IPNetwork
from oslo_config import cfg
from oslo_log import log as logging
from taskflow import task

from octavia.network import data_models as network_models
from octavia_f5.common import constants
from octavia_f5.network import data_models as f5_network_models
from octavia_f5.restclient.bigip import bigip_restclient
from octavia_f5.utils import driver_utils, decorators

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def subnet_in_selfips(subnet, selfips):
    for selfip in selfips:
        for fixed_ip in selfip.fixed_ips:
            if fixed_ip.subnet_id == subnet:
                return True
    return False

def get_subnet_route_name(network_id, subnet_id):
    return "{}{}_{}{}".format(constants.PREFIX_NETWORK, network_id,
                              constants.PREFIX_SUBNET, subnet_id)


class EnsureVLAN(task.Task):
    default_provides = 'device_vlan'

    """ Task to create or update VLAN if needed """

    @decorators.RaisesIControlRestError()
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(requests.HTTPError),
        wait=tenacity.wait_fixed(2),
        stop=tenacity.stop_after_attempt(3)
    )
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network,
                *args, **kwargs):

        vlan = {
            'name': f'vlan-{network.vlan_id}',
            'tag': network.vlan_id,
            'mtu': network.mtu,
            'hardwareSyncookie': 'enabled' if CONF.networking.hardware_syncookie else 'disabled',
            'synFloodRateLimit': CONF.networking.syn_flood_rate_limit,
            'syncacheThreshold': CONF.networking.syncache_threshold
        }

        device_response = bigip.get(path=f"/mgmt/tm/net/vlan/~Common~{vlan['name']}?expandSubcollections=true")
        # Create vlan if not existing
        if device_response.status_code == 404:
            res = bigip.post(path='/mgmt/tm/net/vlan', json=vlan)
            res.raise_for_status()
            return res.json()

        device_vlan = device_response.json()
        if not vlan.items() <= device_vlan.items():
            res = bigip.patch(path=f"/mgmt/tm/net/vlan/~Common~{vlan['name']}",
                              json=vlan)
            res.raise_for_status()
            return res.json()

        # No Changes needed
        return device_vlan


class EnsureVLANInterface(task.Task):
    """ Task to create or update VLAN interface attachment if needed """

    @decorators.RaisesIControlRestError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                device_vlan: dict,
                *args, **kwargs):
        network_driver = driver_utils.get_network_driver()
        interface = {
            'name': device_vlan['name'],
            'interfaces': [{
                'tagged': True,
                'tagMode': 'service',
                'name': network_driver.physical_interface
            }]
        }

        # Create vlan interface if not existing or not correct
        device_vlan_interfaces = device_vlan['interfacesReference'].get('items')
        if not device_vlan_interfaces or not interface.items() <= device_vlan_interfaces[0].items():
            res = bigip.patch(
                path=f"/mgmt/tm/net/vlan/{device_vlan['name']}",
                json=interface)
            res.raise_for_status()
            return res.json()

        return None


class EnsureGuestVLAN(task.Task):
    default_provides = 'device_guest'

    """ Task to assign correct vlan to vcmp guest """

    @decorators.RaisesIControlRestError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: [str],
                device_vlan: dict,
                *args, **kwargs):

        device_guest = None
        device_response = bigip.get(path='/mgmt/tm/vcmp/guest')
        device_response.raise_for_status()
        guests = device_response.json()
        for guest in guests.get('items', []):
            # Check if it's a managed guest
            if guest['name'] not in bigip_guest_names:
                continue

            device_guest = guest

            if device_vlan['name'] in ['/Common/' + vlan for vlan in guest['vlans']]:
                continue

            res = bigip.patch(
                path=f"/mgmt/tm/vcmp/guest/{guest['name']}",
                json={'vlans': guest['vlans'] + [f"/Common/{device_vlan['name']}"]})
            res.raise_for_status()
            return res.json()

        # No Changes needed
        return device_guest


class EnsureRouteDomain(task.Task):
    default_provides = 'device_routedomain'

    """ Task to create or update Route Domain if needed """

    @decorators.RaisesIControlRestError()
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient):

        vlans = [f"/Common/vlan-{network.vlan_id}"]
        rd = {'name': f"vlan-{network.vlan_id}", 'vlans': vlans, 'id': network.vlan_id}

        device_response = bigip.get(path=f"/mgmt/tm/net/route-domain/{rd['name']}")
        if device_response.status_code == 404:
            path = f"/mgmt/tm/net/route-domain/net-{network.id}"
            device_response = bigip.get(path=path)

        # Create route_domain if not existing
        if device_response.status_code == 404:
            res = bigip.post(path='/mgmt/tm/net/route-domain', json=rd)
            res.raise_for_status()
            return res.json()

        device_rd = device_response.json()
        if device_rd.get('vlans', []) != vlans:
            res = bigip.patch(path=f"/mgmt/tm/net/route-domain/{device_rd['fullPath']}",
                              json={'vlans': vlans})
            res.raise_for_status()
            return res.json()
        return device_rd


class EnsureSelfIP(task.Task):
    """ Task to create or update Self-IP if needed """

    @decorators.RaisesIControlRestError()
    def execute(self, network: f5_network_models.Network,
                port: network_models.Port,
                bigip: bigip_restclient.BigIPRestClient,
                *args, **kwargs):

        network_driver = driver_utils.get_network_driver()
        name = f"port-{port.id}"
        vlan = f"/Common/vlan-{network.vlan_id}"
        subnet = network_driver.get_subnet(port.fixed_ips[0].subnet_id)
        ipnetwork = IPNetwork(subnet.cidr)
        address = f"{port.fixed_ips[0].ip_address}%{network.vlan_id}/{ipnetwork.prefixlen}"
        selfip = {'name': name, 'vlan': vlan, 'address': address}

        device_response = bigip.get(path=f"/mgmt/tm/net/self/{name}")

        # Create selfip if not existing
        if device_response.status_code == 404:
            res = bigip.post(path='/mgmt/tm/net/self', json=selfip)
            res.raise_for_status()
            return res.json()

        # Update if dict differs from on-device state
        device_selfip = device_response.json()
        if not selfip.items() <= device_selfip.items():
            res = bigip.patch(path='/mgmt/tm/net/self/{}'.format(device_selfip['name']),
                              json=selfip)
            res.raise_for_status()
            return res.json()

        # No Changes needed
        return device_selfip


class GetAllSelfIPsForVLAN(task.Task):
    default_provides = 'selfips'

    @staticmethod
    def _remove_port_prefix(name: str):
        return name[len('port-'):]

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network):
        vlan = f"/Common/vlan-{network.vlan_id}"
        device_response = bigip.get(path='/mgmt/tm/net/self?$select=vlan,name')
        device_response.raise_for_status()
        items = device_response.json().get('items', [])
        return [network_models.Port(id=self._remove_port_prefix(item['name']))
                for item in items
                if item['vlan'] == vlan
                and item['name'].startswith('port-')]


class EnsureDefaultRoute(task.Task):
    default_provides = 'device_route'

    """ Task to create or update Route if needed """

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                subnet_id: str,
                network: f5_network_models.Network):

        if CONF.networking.route_on_active and not bigip.is_active:
            # Skip passive device if route_on_active is enabled
            return None

        name = f"vlan-{network.vlan_id}"
        gw = f"{network.default_gateway_ip(subnet_id)}%{network.vlan_id}"
        network_name = f"default%{network.vlan_id}"
        route = {'name': name, 'gw': gw, 'network': network_name}

        device_response = bigip.get(path=f"/mgmt/tm/net/route/~Common~{route['name']}")
        if device_response.status_code == 404:
            path=f"/mgmt/tm/net/route/~Common~net-{network.id}"
            device_response = bigip.get(path=path)

        if device_response.status_code == 404:
            # Create route_domain if not existing
            res = bigip.post(path='/mgmt/tm/net/route', json=route)
            res.raise_for_status()
            return res.json()

        device_route = device_response.json()
        if route['gw'] != device_route['gw'] or route['network'] != device_route['network']:
            # Change gw if needed
            res = bigip.patch(path=f"/mgmt/tm/net/route/~Common~{device_route['name']}",
                              json={'gw': route['gw'], 'network': route['network']})
            if not res.ok:
                # If the network also changed, we probably had a legacy named route with wrong values.
                # re-create it (last resort)
                bigip.delete(path=f"/mgmt/tm/net/route/~Common~{device_route['name']}")
                res = bigip.post(path='/mgmt/tm/net/route', json=route)
                res.raise_for_status()
            return res.json()

        # No Changes needed
        return device_route


class EnsureSubnetRoutes(task.Task):
    """ Task to create missing needed static subnet routes"""

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                selfips: [network_models.Port],
                network: f5_network_models.Network):

        # Skip passive device if route_on_active is enabled
        if CONF.networking.route_on_active and not bigip.is_active:
            return None

        # Fetch existing routes
        response = bigip.get(path=f"/mgmt/tm/net/route?$filter=partition+eq+Common").json()
        existing_routes = response.get('items', [])

        # subnet routes that must exist (routes already exist for SelfIPs)
        subnets_that_need_routes = [subnet for subnet in network.subnets if not subnet_in_selfips(subnet, selfips)]

        # common prefix for subnet routes of this network
        subnet_route_network_part = get_subnet_route_name(network.id, '')

        # delete existing subnet routes that aren't needed anymore - we'll only provision the missing ones
        for existing_route in existing_routes:
            existing_route_name = existing_route['name']

            # ignore routes that are not subnet routes of this network
            if not existing_route_name.startswith(subnet_route_network_part):
                continue

            existing_route_subnet = existing_route_name[len(subnet_route_network_part):]
            if existing_route_subnet in subnets_that_need_routes:
                # if the subnet route is a needed one there's no need to provision it again
                subnets_that_need_routes.remove(existing_route_subnet)

        # Add missing subnet routes
        network_driver = driver_utils.get_network_driver()
        for subnet_id in subnets_that_need_routes:
            cidr = IPNetwork(network_driver.get_subnet(subnet_id).cidr)

            name = get_subnet_route_name(network.id, subnet_id)
            vlan = f"/Common/vlan-{network.vlan_id}"
            net = f"{cidr.ip}%{network.vlan_id}/{cidr.prefixlen}"
            route = {'name': name, 'tmInterface': vlan, 'network': net}

            res = bigip.post(path='/mgmt/tm/net/route', json=route)
            res.raise_for_status()


""" Cleanup Tasks """


class CleanupDefaultRoute(task.Task):

    @decorators.RaisesIControlRestError()
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient):

        """ Task to delete VLAN """
        paths = [
            f"/mgmt/tm/net/route/~Common~vlan-{network.vlan_id}",
            f"/mgmt/tm/net/route/~Common~net-{network.id}",  # legacy naming
        ]

        res = None
        for path in paths:
            if bigip.get(path=path).ok:
                res = bigip.delete(path=path)
                break

        if res and not res.ok:
            LOG.warning("%s: Failed cleanup Route for network_id=%s vlan=%s "
                        "(could be already done by autosync): %s",
                        bigip.hostname, network.id, network.vlan_id, res.content)


class CleanupSubnetRoutes(task.Task):
    """Task to clean up static subnet routes. If the network is to be deleted, set delete_all=True.
    Else only the unneeded subnet routes of this network are deleted."""

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                selfips: [network_models.Port],
                network: f5_network_models.Network,
                delete_all=False):

        subnets_that_need_routes = []
        if not delete_all:
            subnets_that_need_routes = [subnet for subnet in network.subnets if not subnet_in_selfips(subnet, selfips)]

        # prefix of subnet routes that belong to this network
        subnet_route_network_part = get_subnet_route_name(network.id, '')

        # Fetch existing routes in the partition
        response = bigip.get(path=f"/mgmt/tm/net/route").json()
        existing_routes = response.get('items', [])

        # delete routes from this network
        for existing_route in existing_routes:
            existing_route_name = existing_route['name']

            # ignore routes that are not subnet routes of this network
            if not existing_route_name.startswith(subnet_route_network_part):
                continue

            # delete subnet route if it's not needed
            existing_route_subnet = existing_route_name[len(subnet_route_network_part):]
            if existing_route_subnet not in subnets_that_need_routes:
                res = bigip.delete(path=f"/mgmt/tm/net/route/~Common~{existing_route_name}")
                res.raise_for_status()


class RemoveSelfIP(task.Task):
    def execute(self, port: network_models.Port,
                bigip: bigip_restclient.BigIPRestClient):
        """ Task to delete SelfIP """
        res = bigip.delete(path=f"/mgmt/tm/net/self/port-{port.id}")
        if not res.ok:
            LOG.warning("%s: Failed cleanup SelfIP %s: %s",
                        port.id, bigip.hostname, res.content)


class CleanupRouteDomain(task.Task):
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient):

        paths = [
            f"/mgmt/tm/net/route-domain/vlan-{network.vlan_id}",
            f"/mgmt/tm/net/route-domain/net-{network.id}"
        ]

        """ Task to delete Route Domain """
        res = None
        for path in paths:
            if bigip.get(path=path).ok:
                res = bigip.delete(path=path)
                break

        if res and not res.ok:
            LOG.warning("%s: Failed cleanup RouteDomain for network_id=%s vlan_id=%s: %s",
                        bigip.hostname, network.id, network.vlan_id, res.content)


class CleanupVLAN(task.Task):
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient):
        """ Task to delete VLAN """
        name = f'vlan-{network.vlan_id}'
        res = bigip.delete(path=f"/mgmt/tm/net/vlan/~Common~{name}")
        if not res.ok:
            LOG.warning("%s: Failed CleanupVLAN for vlan_id=%s: %s",
                        bigip.hostname, network.vlan_id, res.content)


class GetVCMPGuests(task.Task):
    default_provides = 'device_guests'

    """ Provides guests dict of a VCMP host """
    @decorators.RaisesIControlRestError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient):

        device_response = bigip.get(path='/mgmt/tm/vcmp/guest')
        device_response.raise_for_status()
        return device_response.json()['items']


class CleanupVLANIfNotOwnedByGuest(task.Task):
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: [str],
                device_guests: list):
        """ Task to delete VLAN on a VCMP Host  """
        name = f'vlan-{network.vlan_id}'

        for guest in device_guests:
            # skip own guest
            if guest['name'] in bigip_guest_names:
                continue

            # if vlan is in use by other guest, don't delete it
            if f"/Common/{name}" in guest['vlans']:
                return

        res = bigip.delete(path=f"/mgmt/tm/net/vlan/{name}")
        if not res.ok:
            LOG.warning("%s: Failed CleanupVLANIfNotOwnedByGuest for vlan_id=%s: %s",
                        bigip.hostname, network.vlan_id, res.content)


class CleanupGuestVLAN(task.Task):
    """ Removes vlan assignment of a VCMP Guest """
    @decorators.RaisesIControlRestError()
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: [str],
                device_guests: list):

        path = f"/Common/vlan-{network.vlan_id}"
        for guest in device_guests:
            # Check if it's a managed guest
            if guest['name'] not in bigip_guest_names:
                continue

            # Remove vlan from list
            vlans = [vlan for vlan in guest['vlans']
                     if vlan != path]

            # Already removed?
            if vlans == guest['vlans']:
                return

            res = bigip.patch(
                path=f"/mgmt/tm/vcmp/guest/{guest['name']}",
                json={'vlans': vlans})
            if not res.ok:
                LOG.warning("%s: Failed CleanupGuestVLAN for vlan_id=%s: %s",
                            bigip.hostname, network.vlan_id, res.content)
