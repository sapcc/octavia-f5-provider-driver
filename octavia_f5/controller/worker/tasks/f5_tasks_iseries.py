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
from typing import List

from netaddr import IPNetwork
from oslo_config import cfg
from oslo_log import log as logging
from taskflow import task
from taskflow.types import failure

from octavia.network import data_models as network_models
from octavia_f5.network import data_models as f5_network_models
from octavia_f5.restclient.bigip import bigip_restclient
from octavia_f5.utils import driver_utils, decorators

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


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
                existing_vlan: dict):
        vlan = {
            'name': f'vlan-{network.vlan_id}',
            'tag': network.vlan_id,
            'mtu': network.mtu,
            'hardwareSyncookie': 'enabled' if CONF.networking.hardware_syncookie else 'disabled',
            'synFloodRateLimit': CONF.networking.syn_flood_rate_limit,
            'syncacheThreshold': CONF.networking.syncache_threshold
        }

        # Create vlan if not existing
        if existing_vlan is None:
            res = bigip.post(path='/mgmt/tm/net/vlan', json=vlan)
            res.raise_for_status()
            return res.json()

        # patch VLAN if it differs (<= is a subset operator here)
        if not vlan.items() <= existing_vlan.items():
            res = bigip.patch(path=f"/mgmt/tm/net/vlan/~Common~{vlan['name']}",
                              json=vlan)
            res.raise_for_status()
            return res.json()

        # No Changes needed
        return existing_vlan

    @decorators.RaisesIControlRestError()
    def revert(self, network: f5_network_models.Network,
               bigip: bigip_restclient.BigIPRestClient,
               existing_vlan, *args, **kwargs):
        if existing_vlan is not None:
            LOG.warning(f"Reverting EnsureVLAN: Not deleting VLAN, since it existed before "
                        f"the task was run: {existing_vlan}")
            return
        res = bigip.delete(path=f"/mgmt/tm/net/vlan/~Common~vlan-{network.vlan_id}")
        if not res.ok:
            LOG.warning("Reverting EnsureVLAN: Failed removing VLAN on the device %s for "
                        "vlan_id=%s: %s", bigip.hostname, network.vlan_id, res.content)
            res.raise_for_status()


class EnsureVLANInterface(task.Task):
    """ Task to create or update VLAN interface attachment if needed """

    @decorators.RaisesIControlRestError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                device_vlan: dict):
        network_driver = driver_utils.get_network_driver()
        interface = {
            'name': device_vlan['name'],
            'interfaces': [{
                'tagged': True,
                'tagMode': 'service',
                'name': network_driver.physical_interface
            }]
        }

        # Create VLAN interface if not existing or not correct
        device_vlan_interfaces = device_vlan['interfacesReference'].get('items')
        if not device_vlan_interfaces or not interface.items() <= device_vlan_interfaces[0].items():
            res = bigip.patch(
                path=f"/mgmt/tm/net/vlan/{device_vlan['name']}",
                json=interface)
            res.raise_for_status()
            return res.json()

        # VLAN interface exists and is correct
        return None


class EnsureGuestVLAN(task.Task):
    """ Task to assign correct vlan to vcmp guest """

    @decorators.RaisesIControlRestError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: List[str],
                device_vlan: dict):

        device_response = bigip.get(path='/mgmt/tm/vcmp/guest')
        device_response.raise_for_status()
        guests = device_response.json()
        for guest in guests.get('items', []):
            # Check if it's a managed guest
            if guest['name'] not in bigip_guest_names:
                continue

            # Check if the VLAN is already configured on the guest
            if device_vlan['name'] in ['/Common/' + vlan for vlan in guest['vlans']]:
                continue

            res = bigip.patch(
                path=f"/mgmt/tm/vcmp/guest/{guest['name']}",
                json={'vlans': guest['vlans'] + [f"/Common/{device_vlan['name']}"]})
            res.raise_for_status()


class EnsureRouteDomain(task.Task):
    default_provides = 'device_routedomain'

    """ Task to create or update Route Domain if needed """

    @decorators.RaisesIControlRestError()
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(requests.HTTPError),
        wait=tenacity.wait_fixed(2),
        stop=tenacity.stop_after_attempt(3)
    )
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient,
                existing_route_domain: dict):
        vlans = [f"/Common/vlan-{network.vlan_id}"]
        rd = {'name': f"vlan-{network.vlan_id}", 'vlans': vlans, 'id': network.vlan_id}

        # Create route_domain if not existing
        if existing_route_domain is None:
            res = bigip.post(path='/mgmt/tm/net/route-domain', json=rd)
            res.raise_for_status()
            return res.json()

        if existing_route_domain.get('vlans', []) != vlans:
            res = bigip.patch(path=f"/mgmt/tm/net/route-domain/{existing_route_domain['fullPath']}",
                              json={'vlans': vlans})
            res.raise_for_status()
            return res.json()

        return existing_route_domain

    @decorators.RaisesIControlRestError()
    def revert(self, network: f5_network_models.Network,
               bigip: bigip_restclient.BigIPRestClient,
               existing_route_domain, *args, **kwargs):
        paths = [
            f"/mgmt/tm/net/route-domain/vlan-{network.vlan_id}",
            f"/mgmt/tm/net/route-domain/net-{network.id}"
        ]
        if existing_route_domain is not None:
            LOG.warning(f"Reverting EnsureRouteDomain: Not deleting RouteDomain, since it existed before "
                        f"the task was run: {existing_route_domain}")
            return

        res = None
        for path in paths:
            if bigip.get(path=path).ok:
                res = bigip.delete(path=path)
                break

        if res and not res.ok:
            LOG.warning("Reverting EnsureRouteDomain: Failed removing route domain on the device %s "
                        "for network_id=%s vlan_id=%s: %s",
                        bigip.hostname, network.id, network.vlan_id, res.content)
            res.raise_for_status()


class EnsureSelfIP(task.Task):
    """ Task to create or update Self-IP if needed """

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network,
                port: network_models.Port):
        # payload
        name = f"port-{port.id}"
        vlan = f"/Common/vlan-{network.vlan_id}"
        network_driver = driver_utils.get_network_driver()
        subnet = network_driver.get_subnet(port.fixed_ips[0].subnet_id)
        subnet_cidr = IPNetwork(subnet.cidr)
        address = f"{port.fixed_ips[0].ip_address}%{network.vlan_id}/{subnet_cidr.prefixlen}"
        selfip = {'name': name, 'vlan': vlan, 'address': address}

        # Check whether SelfIP already exists
        device_response = bigip.get(path=f"/mgmt/tm/net/self/{name}")

        # Create selfip if not existing
        if device_response.status_code == 404:
            res = bigip.post(path='/mgmt/tm/net/self', json=selfip)
            res.raise_for_status()
            return res.json()

        # Otherwise update existing selfip (if our selfip isn't a subset)
        device_selfip = device_response.json()
        if not selfip.items() <= device_selfip.items():
            res = bigip.patch(path=f'/mgmt/tm/net/self/{device_selfip['name']}',
                              json=selfip)
            res.raise_for_status()
            return res.json()

        # No Changes needed
        return device_selfip

    @decorators.RaisesIControlRestError()
    def revert(self, port: network_models.Port,
               bigip: bigip_restclient.BigIPRestClient,
               existing_selfips, *args, **kwargs):
        selfip_name = f"port-{port.id}"
        # don't remove the SelfIP if it existed before this task was executed
        if port.id in [p['port_id'] for p in existing_selfips]:
            LOG.warning("Reverting EnsureSelfIP: Not deleting SelfIP, since it existed before the task was run: "
                        f"{selfip_name}")
            return

        # delete SelfIP, ignoring 404
        LOG.warning(f"Reverting EnsureSelfIP: Deleting SelfIP: {selfip_name}")
        device_response = bigip.delete(path=f"/mgmt/tm/net/self/{selfip_name}")
        if device_response.status_code == 404:
            LOG.warning(f"Reverting EnsureSelfIP: SelfIP {selfip_name} was already removed")
        else:
            device_response.raise_for_status()


class GetExistingVLAN(task.Task):
    default_provides = 'existing_vlan'

    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network):
        device_response = bigip.get(path=f"/mgmt/tm/net/vlan/~Common~vlan-{network.vlan_id}?expandSubcollections=true")
        if device_response.status_code == 404:
            return None
        return device_response.json()


class GetExistingRouteDomain(task.Task):
    default_provides = 'existing_route_domain'

    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network):
        device_response = bigip.get(path=f"/mgmt/tm/net/route-domain/vlan-{network.vlan_id}")
        if device_response.status_code == 404:
            path = f"/mgmt/tm/net/route-domain/net-{network.id}"
            device_response = bigip.get(path=path)

        if device_response.status_code == 404:
            return None
        return device_response.json()


class GetExistingSelfIPsForVLAN(task.Task):
    default_provides = 'existing_selfips'

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network):

        # get items
        device_response = bigip.get(path='/mgmt/tm/net/self?$select=vlan,name,address')
        device_response.raise_for_status()
        items = device_response.json().get('items', [])

        # filter for VLAN
        vlan = f"/Common/vlan-{network.vlan_id}"
        items = [i for i in items if i['vlan'] == vlan and i['name'].startswith('port-')]

        # we have to get the port ID oftentimes, so inject it for ease of use
        for i in items:
            i['port_id'] = i['name'][len('port-'):]

        return items


class GetExistingSubnetRoutesForNetwork(task.Task):
    default_provides = 'existing_subnet_routes'

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network):

        # get all routes
        response = bigip.get(path="/mgmt/tm/net/route").json()
        routes = response.get('items', [])

        # filter for only the subnet routes belonging to this network
        subnet_route_network_part = driver_utils.get_subnet_route_name(network.id, '')
        return [r for r in routes if r['name'].startswith(subnet_route_network_part)]


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
            path = f"/mgmt/tm/net/route/~Common~net-{network.id}"
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


class EnsureSubnetRoute(task.Task):
    """ Task to make sure a subnet route exists. """

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network,
                subnet_id):
        # Skip passive device if route_on_active is enabled
        if CONF.networking.route_on_active and not bigip.is_active:
            return

        # payload
        subnet_route_name = driver_utils.get_subnet_route_name(network.id, subnet_id)
        network_driver = driver_utils.get_network_driver()
        subnet = network_driver.get_subnet(subnet_id)
        subnet_cidr = IPNetwork(subnet.cidr)
        vlan = f"/Common/vlan-{network.vlan_id}"
        net = f"{subnet_cidr.ip}%{network.vlan_id}/{subnet_cidr.prefixlen}"
        subnet_route = {'name': subnet_route_name, 'tmInterface': vlan, 'network': net}

        # Check whether subnet route already exists
        device_response = bigip.get(path=f"/mgmt/tm/net/route/~Common~{subnet_route_name}")

        # Create subnet route if not existing
        if device_response.status_code == 404:
            res = bigip.post(path='/mgmt/tm/net/route', json=subnet_route)
            res.raise_for_status()
            return res.json()

        # Otherwise update existing subnet route (if our route isn't a subset)
        device_subnet_route = device_response.json()
        if not subnet_route.items() <= device_subnet_route.items():
            res = bigip.patch(path=f"/mgmt/tm/net/route/~Common~{subnet_route_name}",
                              json=subnet_route)
            res.raise_for_status()
            return res.json()

        # No changes needed
        return device_subnet_route

    @decorators.RaisesIControlRestError()
    def revert(self, bigip: bigip_restclient.BigIPRestClient,
               network: f5_network_models.Network,
               subnet_id, existing_subnet_routes,
               *args, **kwargs):
        subnet_route_name = driver_utils.get_subnet_route_name(network.id, subnet_id)
        # Don't remove the route if it existed before this task was executed
        if subnet_route_name in [r['name'] for r in existing_subnet_routes]:
            LOG.warning("Reverting EnsureSubnetRoute: Not deleting route, since it existed before the task was run: "
                        f"{subnet_route_name}")
            return

        # delete subnet route, ignoring 404
        LOG.warning(f"Reverting EnsureSubnetRoute: Deleting subnet route: {subnet_route_name}")
        device_response = bigip.delete(path=f"/mgmt/tm/net/route/~Common~{subnet_route_name}")
        if device_response.status_code == 404:
            LOG.warning(f"Reverting EnsureSubnetRoute: Subnet route {subnet_route_name} was already removed")
        else:
            device_response.raise_for_status()


""" Removal Tasks """


class RemoveDefaultRoute(task.Task):

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
            LOG.warning("%s: Failed removing route for network_id=%s vlan=%s "
                        "(could be already done by autosync): %s",
                        bigip.hostname, network.id, network.vlan_id, res.content)


class RemoveSubnetRoute(task.Task):
    """Task to remove a static subnet route."""

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient,
                subnet_route):
        subnet_route_name = subnet_route['name']
        res = bigip.delete(path=f"/mgmt/tm/net/route/~Common~{subnet_route_name}")

        if res.status_code == 404:
            LOG.warning(f"Subnet route {subnet_route_name} was already removed")
        else:
            res.raise_for_status()

    @decorators.RaisesIControlRestError()
    def revert(self, bigip: bigip_restclient.BigIPRestClient,
               subnet_route, existing_subnet_routes, network,
               *args, **kwargs):
        subnet_route_name = subnet_route['name']

        # don't restore subnet route if it didn't exist before this task was executed
        if subnet_route_name not in [r['name'] for r in existing_subnet_routes]:
            LOG.warning("Reverting RemoveSubnetRoute: Not restoring subnet route since it didn't exist before the task "
                        f"was run: {subnet_route_name}")
            return

        # don't restore subnet route if it wasn't removed
        res = bigip.get(path=f"/mgmt/tm/net/route/~Common~{subnet_route_name}")
        if res.status_code != 404:
            LOG.warning(f"Reverting RemoveSubnetRoute: Subnet route {subnet_route_name} was not removed, no need to restore")
            return

        # restore subnet route
        payload = {'name': subnet_route_name,
                   'tmInterface': subnet_route['tmInterface'],
                   'network': subnet_route['network']}
        LOG.warning(f"Reverting RemoveSubnetRoute: Restoring subnet route: {subnet_route_name}")
        res = bigip.post(path='/mgmt/tm/net/route', json=payload)
        res.raise_for_status()


class RemoveSelfIP(task.Task):

    @decorators.RaisesIControlRestError()
    def execute(self, bigip: bigip_restclient.BigIPRestClient, selfip: dict):
        res = bigip.delete(path=f"/mgmt/tm/net/self/port-{selfip['port_id']}")

        if res.status_code == 404:
            LOG.warning(f"SelfIP port-{selfip['port_id']} was already removed")
        else:
            res.raise_for_status()

    @decorators.RaisesIControlRestError()
    def revert(self, bigip: bigip_restclient.BigIPRestClient,
               selfip: dict, existing_selfips: List[dict], *args, **kwargs):

        # don't restore SelfIP if it didn't exist before this task was executed
        if selfip['name'] not in [sip['name'] for sip in existing_selfips]:
            LOG.warning("Reverting RemoveSelfIP: Not restoring SelfIP since it didn't exist before the task "
                        f"was run: {selfip['name']}")
            return

        # don't restore SelfIP if it wasn't removed
        res = bigip.get(path=f"/mgmt/tm/net/self/{selfip['port_id']}")
        if res.status_code != 404:
            LOG.warning(f"Reverting RemoveSelfIP: SelfIP {selfip['name']} was not removed, no need to restore")
            return

        # restore SelfIP
        payload = {'name': selfip['name'], 'vlan': selfip['vlan'], 'address': selfip['address']}
        LOG.warning(f"Reverting RemoveSelfIP: Restoring SelfIP: {selfip['name']}")
        res = bigip.post(path="/mgmt/tm/net/self/", json=payload)
        res.raise_for_status()


class RemoveRouteDomain(task.Task):

    @decorators.RaisesIControlRestError()
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient,
                existing_route_domain):

        """ Task to delete Route Domain """
        if existing_route_domain is None:
            return
        res = bigip.delete(path=f"/mgmt/tm/net/route-domain/{existing_route_domain['fullPath']}")
        res.raise_for_status()

    @decorators.RaisesIControlRestError()
    def revert(self, bigip: bigip_restclient.BigIPRestClient,
               existing_route_domain, result, *args, **kwargs):
        if isinstance(result, failure.Failure):
            # If this task failed it means that object was not removed
            return
        # Restore RouteDomain if it existed before
        if existing_route_domain is not None:
            res = bigip.post(
                path='/mgmt/tm/net/route-domain',
                json={
                    'name': existing_route_domain['name'],
                    'vlans': existing_route_domain['vlans'],
                    'id': existing_route_domain['id']
                }
            )
            res.raise_for_status()


class RemoveVLAN(task.Task):

    @decorators.RaisesIControlRestError()
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient,
                existing_vlan: dict):
        """ Task to delete VLAN """
        if existing_vlan is None:
            return
        res = bigip.delete(path=f"/mgmt/tm/net/vlan/~Common~vlan-{network.vlan_id}")
        res.raise_for_status()

    @decorators.RaisesIControlRestError()
    def revert(self, bigip: bigip_restclient.BigIPRestClient,
               existing_vlan: dict, result, *args, **kwargs):
        if isinstance(result, failure.Failure):
            # If this task failed it means that object was not removed
            return
        # Restore VLAN existed before
        if existing_vlan is not None:
            res = bigip.post(
                path='/mgmt/tm/net/vlan',
                json={
                    'name': existing_vlan['name'],
                    'tag': existing_vlan['tag'],
                    'mtu': existing_vlan['mtu'],
                    'hardwareSyncookie': existing_vlan['hardwareSyncookie'],
                    'synFloodRateLimit': existing_vlan['synFloodRateLimit'],
                    'syncacheThreshold': existing_vlan['syncacheThreshold']
                }
            )
            res.raise_for_status()


class GetVCMPGuests(task.Task):
    default_provides = 'device_guests'

    """ Provides guests dict of a VCMP host """
    @decorators.RaisesIControlRestError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient):

        device_response = bigip.get(path='/mgmt/tm/vcmp/guest')
        device_response.raise_for_status()
        return device_response.json()['items']


class RemoveVLANIfNotOwnedByGuest(task.Task):
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: List[str],
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
            LOG.warning("%s: Failed RemoveVLANIfNotOwnedByGuest for vlan_id=%s: %s",
                        bigip.hostname, network.vlan_id, res.content)


class RemoveGuestVLAN(task.Task):
    """ Removes vlan assignment of a VCMP Guest """
    @decorators.RaisesIControlRestError()
    def execute(self, network: f5_network_models.Network,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: List[str],
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
                LOG.warning("%s: Failed removing guest VLAN for vlan_id=%s: %s",
                            bigip.hostname, network.vlan_id, res.content)
