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

from unittest import mock

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_log import log as logging
from taskflow import engines

import octavia.tests.unit.base as base
from octavia.common import constants
from octavia.network import data_models as network_models
# pylint: disable=unused-import
from octavia_f5.common import config  # noqa
from octavia_f5.controller.worker.flows import f5_flows_iseries, f5_flows_rseries
from octavia_f5.network import data_models as f5_network_models
from octavia_f5.restclient import as3restclient

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = status_code < 400

    def json(self):
        return self.json_data

    def raise_for_status(self):
        pass


def empty_response(*args, **kwargs):
    return MockResponse({}, 404)


class TestF5Flows(base.TestCase):
    def setUp(self):
        self.amphora_mock = mock.MagicMock()
        self.load_balancer_mock = mock.MagicMock()
        self.vip_mock = mock.MagicMock()
        self.load_balancer_mock.vip = self.vip_mock
        self.load_balancer_mock.amphorae = []
        self.amphora_mock.status = constants.AMPHORA_ALLOCATED
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="controller_worker",
                    network_driver='network_noop_driver_f5')

        super().setUp()

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_ensure_l2_flow(self, mock_get_subnet):
        """Check that the ensure_l2 flow creates VLAN, RD, SelfIP, and default route"""

        # mock network with one subnet
        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_get_subnet.return_value = network_models.Subnet(
            id=mock_subnet_id, gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id=mock_network_id)
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='1.2.3.2', subnet_id=mock_subnet_id)
        selfip_port = network_models.Port(
            id='test-selfip-port-id', fixed_ips=[selfip_fixed_ip],
        )

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.side_effect = [empty_response(), empty_response(),
                                      empty_response(), empty_response(),
                                      empty_response(), empty_response(),
                                      MockResponse({'items': []}, status_code=200)]
        f5flows = f5_flows_iseries.F5Flows()

        store = {'network': mock_network,
                 'bigip': mock_bigip,
                 'subnet_id': mock_subnet_id,
                 'existing_selfips': []}
        needed_selfips = [selfip_port]
        ensure_l2_flow = f5flows.make_ensure_l2_flow(needed_selfips, store=store)
        engines.run(ensure_l2_flow, store=store)

        # check that VLAN, RD, SelfIP, and default route have been created
        calls = [
            mock.call(json={'name': 'vlan-1234', 'tag': 1234,
                            'mtu': 9000, 'hardwareSyncookie': 'enabled',
                            'synFloodRateLimit': 2000, 'syncacheThreshold': 32000},
                      path='/mgmt/tm/net/vlan'),
            mock.call(json={'name': 'vlan-1234', 'id': 1234,
                            'vlans': ['/Common/vlan-1234']},
                      path='/mgmt/tm/net/route-domain'),
            mock.call(json={'name': 'port-test-selfip-port-id',
                            'vlan': '/Common/vlan-1234',
                            'address': '1.2.3.2%1234/24'},
                      path='/mgmt/tm/net/self'),
            mock.call(json={'name': 'vlan-1234',
                            'gw': '1.2.3.1%1234',
                            'network': 'default%1234'},
                      path='/mgmt/tm/net/route')
        ]
        mock_bigip.post.assert_has_calls(calls, any_order=True)
        mock_bigip.get.assert_called()
        mock_bigip.patch.assert_not_called()

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_ensure_l2_flow_existing_l2(self, mock_get_subnet):
        """Check that the ensure_l2 flow works when VLAN, RD, and default route already exist"""

        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_get_subnet.return_value = network_models.Subnet(
            id=mock_subnet_id, gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id=mock_network_id)
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='1.2.3.2', subnet_id=mock_subnet_id)
        selfip_port = network_models.Port(
            id='test-selfip-port-id', fixed_ips=[selfip_fixed_ip],
        )

        mock_vlan_response = MockResponse({
            'name': 'vlan-1234',
            'tag': 1234,
            'mtu': 9000,
            'hardwareSyncookie': 'enabled',
            'synFloodRateLimit': 2000,
            'syncacheThreshold': 32000
        }, status_code=200)
        mock_routedomain_response = MockResponse({
            'name': 'vlan-1234',
            'vlans': ['/Common/vlan-1234'],
            'id': 1234
        }, status_code=200)
        mock_selfip_response = MockResponse({
            'name': 'port-test-selfip-port-id',
            'vlan': '/Common/vlan-1234',
            'address': '1.2.3.2%1234/24'
        }, status_code=200)
        mock_route_response = MockResponse({
            'name': 'vlan-1234',
            'gw': '1.2.3.1%1234',
            'network': 'default%1234'
        }, status_code=200)

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        # Flow ensures entities in order [vlan, route-domain, selfips, route]
        mock_bigip.get.side_effect = [mock_vlan_response,
                                      mock_routedomain_response,
                                      mock_selfip_response,
                                      mock_route_response,
                                      MockResponse({'items': []}, status_code=200)]
        f5flows = f5_flows_iseries.F5Flows()

        store = {'network': mock_network,
                 'bigip': mock_bigip,
                 'subnet_id': mock_subnet_id,
                 'existing_selfips': []}
        needed_selfips = [selfip_port]
        ensure_l2_flow = f5flows.make_ensure_l2_flow(needed_selfips, store=store)
        engines.run(ensure_l2_flow, store=store)

        mock_bigip.get.assert_called()
        mock_bigip.patch.assert_not_called()
        mock_bigip.post.assert_not_called()

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_ensure_selfip(self, mock_get_subnet):
        """Test the flow returned by make_ensure_selfips_and_subnet_routes_flow
        to create non-existent but needed SelfIP"""

        # network with one subnet with an LB, no SelfIPs, and no routes
        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_get_subnet.return_value = network_models.Subnet(
            id=mock_subnet_id, gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id=mock_network_id)
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        # SelfIP port
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='1.2.3.2', subnet_id=mock_subnet_id)
        selfip_port = network_models.Port(
            id='test-selfip-port-id', fixed_ips=[selfip_fixed_ip],
        )

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.return_value = empty_response()

        store = {'network': mock_network,
                 'bigip': mock_bigip,
                 'existing_selfips': [],
                 'existing_subnet_routes': []}
        needed_selfips = [selfip_port]
        subnets_that_need_routes = []
        f5flows = f5_flows_iseries.F5Flows()
        ensure_selfips_and_subnet_routes_flow = f5flows.make_ensure_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store=store)
        engines.run(ensure_selfips_and_subnet_routes_flow, store=store)

        mock_bigip.get.assert_called()
        mock_bigip.patch.assert_not_called()
        mock_bigip.post.assert_called_with(
            path="/mgmt/tm/net/self",
            json={'name': f'port-{selfip_port.id}',
                  'vlan': '/Common/vlan-1234',
                  'address': '1.2.3.2%1234/24'}
        )

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_ensure_subnet_route(self, mock_get_subnet):
        """Test the flow returned by make_ensure_selfips_and_subnet_routes_flow
        to create non-existent but needed subnet route"""

        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_get_subnet.return_value = network_models.Subnet(
            id=mock_subnet_id, gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id=mock_network_id)
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.return_value = empty_response()

        store = {'network': mock_network,
                 'bigip': mock_bigip,
                 'existing_selfips': [],
                 'existing_subnet_routes': []}
        needed_selfips = []
        subnets_that_need_routes = [mock_subnet_id]
        f5flows = f5_flows_iseries.F5Flows()
        ensure_selfips_and_subnet_routes_flow = f5flows.make_ensure_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store=store)
        engines.run(ensure_selfips_and_subnet_routes_flow, store=store)

        mock_bigip.get.assert_called()
        mock_bigip.patch.assert_not_called()
        mock_bigip.post.assert_called_with(
            path="/mgmt/tm/net/route",
            json={'name': f'net_{mock_network_id}_sub_{mock_subnet_id}',
                  'tmInterface': '/Common/vlan-1234',
                  'network': '1.2.3.0%1234/24'}
        )

    def test_remove_selfip(self):
        """Test the flow returned by make_remove_selfips_and_subnet_routes_flow
        to remove unneeded SelfIP"""

        # network with one subnet supposedly deleted LB whose SelfIP still exists, and no routes
        mock_network_id = 'test-network-id'
        mock_network = f5_network_models.Network(id=mock_network_id)

        # SelfIP port
        selfip_port = network_models.Port(id='test-selfip-port-id')

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.return_value = empty_response()

        store = {'network': mock_network,
                 'bigip': mock_bigip,
                 'existing_selfips': [{'name': f"port-{selfip_port.id}", 'port_id': selfip_port.id}],
                 'existing_subnet_routes': []}
        needed_selfips = []
        subnets_that_need_routes = []
        f5flows = f5_flows_iseries.F5Flows()
        ensure_selfips_and_subnet_routes_flow = f5flows.make_remove_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store=store)
        engines.run(ensure_selfips_and_subnet_routes_flow, store=store)

        mock_bigip.get.assert_not_called()
        mock_bigip.patch.assert_not_called()
        mock_bigip.post.assert_not_called()
        mock_bigip.delete.assert_called_with(
            path=f"/mgmt/tm/net/self/port-{selfip_port.id}"
        )

    def test_remove_subnet_route(self):
        """Test the flow returned by make_remove_selfips_and_subnet_routes_flow
        to remove unneeded subnet route"""

        # network with one subnet that has an unneeded subnet route
        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_network = f5_network_models.Network(id=mock_network_id)

        # subnet route
        subnet_route = {'name': f'net_{mock_network_id}_sub_{mock_subnet_id}'}

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.return_value = empty_response()

        store = {'network': mock_network,
                 'bigip': mock_bigip,
                 'existing_selfips': [],
                 'existing_subnet_routes': [subnet_route]}
        needed_selfips = []
        subnets_that_need_routes = []
        f5flows = f5_flows_iseries.F5Flows()
        ensure_selfips_and_subnet_routes_flow = f5flows.make_remove_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store=store)
        engines.run(ensure_selfips_and_subnet_routes_flow, store=store)

        mock_bigip.get.assert_not_called()
        mock_bigip.patch.assert_not_called()
        mock_bigip.post.assert_not_called()
        mock_bigip.delete.assert_called_with(
            path=f"/mgmt/tm/net/route/~Common~{subnet_route['name']}"
        )

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_replace_selfip_with_subnet_route(self, mock_get_subnet):
        """Test the flow returned by make_sync_selfips_and_subnet_routes_flow
        to replace SelfIP with subnet route"""

        # network with one subnet without LB, but a SelfIP, and no routes
        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_get_subnet.return_value = network_models.Subnet(
            id=mock_subnet_id, gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id=mock_network_id)
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        # SelfIP port
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='1.2.3.2', subnet_id=mock_subnet_id)
        selfip_port = network_models.Port(
            id='test-selfip-port-id', fixed_ips=[selfip_fixed_ip],
        )

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.return_value = empty_response()

        store = {'network': mock_network,
                 'bigip': mock_bigip,
                 'existing_selfips': [{'name': f"port-{selfip_port.id}", 'port_id': selfip_port.id}],
                 'existing_subnet_routes': []}
        needed_selfips = []
        subnets_that_need_routes = [mock_subnet_id]
        f5flows = f5_flows_iseries.F5Flows()
        sync_selfips_and_subnet_routes_flow = f5flows.make_sync_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store=store)
        engines.run(sync_selfips_and_subnet_routes_flow, store=store)

        # Check that SelfIP got deleted
        mock_bigip.delete.assert_called_with(
            path=f"/mgmt/tm/net/self/port-{selfip_port.id}"
        )

        # Check that subnet route got created
        mock_bigip.get.assert_called_with(
            path=f"/mgmt/tm/net/route/~Common~net_{mock_network_id}_sub_{mock_subnet_id}"
        )
        mock_bigip.post.assert_called_with(
            path="/mgmt/tm/net/route",
            json={'name': f'net_{mock_network_id}_sub_{mock_subnet_id}',
                  'tmInterface': '/Common/vlan-1234',
                  'network': '1.2.3.0%1234/24'}
        )
        mock_bigip.patch.assert_not_called()

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_replace_subnet_route_with_selfip(self, mock_get_subnet):
        """Test the flow returned by make_sync_selfips_and_subnet_routes_flow
        to replace subnet route with SelfIP"""

        # network with one subnet with LB, but no SelfIP, and a route
        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_get_subnet.return_value = network_models.Subnet(
            id=mock_subnet_id, gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id=mock_network_id)
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        # SelfIP port
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='1.2.3.2', subnet_id=mock_subnet_id)
        selfip_port = network_models.Port(
            id='test-selfip-port-id', fixed_ips=[selfip_fixed_ip],
        )

        # subnet route
        subnet_route = {'name': f'net_{mock_network_id}_sub_{mock_subnet_id}'}

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.return_value = empty_response()

        store = {'network': mock_network,
                 'bigip': mock_bigip,
                 'existing_selfips': [],
                 'existing_subnet_routes': [subnet_route]}
        needed_selfips = [selfip_port]
        subnets_that_need_routes = []
        f5flows = f5_flows_iseries.F5Flows()
        sync_selfips_and_subnet_routes_flow = f5flows.make_sync_selfips_and_subnet_routes_flow(
            needed_selfips, subnets_that_need_routes, store=store)
        engines.run(sync_selfips_and_subnet_routes_flow, store=store)

        # Check that subnet route got deleted
        mock_bigip.delete.assert_called_with(
            path=f"/mgmt/tm/net/route/~Common~net_{mock_network_id}_sub_{mock_subnet_id}"
        )

        # Check that SelfIP got created
        mock_bigip.get.assert_called_with(
            path=f"/mgmt/tm/net/self/port-{selfip_port.id}"
        )
        mock_bigip.post.assert_called_with(
            path="/mgmt/tm/net/self",
            json={'name': f'port-{selfip_port.id}',
                  'vlan': '/Common/vlan-1234',
                  'address': '1.2.3.2%1234/24'}
        )
        mock_bigip.patch.assert_not_called()

    def test_ensure_vcmp_l2_flow_iseries(self):
        """Check that the ensure_vcmp_l2_flow flow correctly configures the VLAN"""

        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_guests_response = MockResponse(
            {'items': [
                {'name': 'test-host-1',
                 'vlans': []}
            ]}, 200)
        mock_vlan_response = MockResponse(
            {'name': 'vlan-1234',
             'interfacesReference': {
                 'items': []
             }}, 200)
        mock_vcmp = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_vcmp.post.side_effect = [mock_vlan_response]
        mock_vcmp.get.side_effect = [MockResponse({}, 404),
                                     mock_guests_response,
                                     mock_vlan_response]
        mock_vcmp.patch.side_effect = empty_response
        f5flows = f5_flows_iseries.F5Flows()

        store = {'network': mock_network,
                 'bigip': mock_vcmp,
                 'bigip_guest_names': ['test-host-1']}
        ensure_vcmp_l2_flow = f5flows.make_ensure_vcmp_l2_flow()
        engines.run(ensure_vcmp_l2_flow, store=store)

        get_calls = [
            mock.call(path='/mgmt/tm/net/vlan/~Common~vlan-1234?expandSubcollections=true'),
            mock.call(path='/mgmt/tm/vcmp/guest'),
        ]
        patch_calls = [
            mock.call(json={'name': 'vlan-1234',
                            'interfaces': [{'tagged': True,
                                            'tagMode': 'service',
                                            'name': 'portchannel1'}]},
                      path='/mgmt/tm/net/vlan/vlan-1234'),
            mock.call(json={'vlans': ['/Common/vlan-1234']},
                      path='/mgmt/tm/vcmp/guest/test-host-1')
        ]
        mock_vcmp.get.assert_has_calls(get_calls)
        mock_vcmp.patch.assert_has_calls(patch_calls)
        mock_vcmp.post.assert_called_with(
            json={'name': 'vlan-1234', 'tag': 1234,
                  'mtu': 9000, 'hardwareSyncookie': 'enabled',
                  'synFloodRateLimit': 2000, 'syncacheThreshold': 32000},
            path='/mgmt/tm/net/vlan'
        )

    def test_ensure_vcmp_l2_flow_rseries(self):
        """Check that the ensure_vcmp_l2_flow flow correctly configures the VLAN on an rSeries host"""

        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_guests_response = MockResponse({}, 200)
        mock_vlan_get_response = MockResponse({
            'ietf-restconf:errors': {
                'error': [{
                    "error-type": "application",
                    "error-tag": "invalid-value",
                    "error-message": "uri keypath not found",
                }]
            }
        }, 404)
        mock_tenants_response = MockResponse({
            "f5-tenants:tenants": {
                "tenant": [
                    {
                        "name": "test-host-1",
                        "config": {
                            "vlans": [],  # VLAN not yet configured
                        }
                    }
                ]
            }
        }, 200)
        mock_vlan_put_response = MockResponse({}, 201)
        mock_interface_response = MockResponse({}, 201)
        mock_vcmp = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_vcmp.get.side_effect = [mock_vlan_get_response,
                                     mock_tenants_response]
        mock_vcmp.put.side_effect = [mock_vlan_put_response,
                                     mock_interface_response,
                                     mock_guests_response,
                                     mock_guests_response]
        f5flows = f5_flows_rseries.F5Flows()

        store = {'network': mock_network,
                 'bigip': mock_vcmp,
                 # since F5OS-A API tenant endpoint yields only the hostname and not the whole domain (as
                 # iControlREST does), we check it via startswith and a dot appended. But the hostname attribute of
                 # the BigIPRestClient instance always contains the domain, so it has to be contained here as well.
                 'bigip_guest_names': ['test-host-1.some.domain']
                 }
        ensure_vcmp_l2_flow = f5flows.make_ensure_vcmp_l2_flow()
        engines.run(ensure_vcmp_l2_flow, store=store)

        get_calls = [
            mock.call(path='/api/data/openconfig-vlan:vlans/vlan=1234'),
        ]
        put_calls = [
            mock.call(path="/api/data/openconfig-vlan:vlans/vlan=1234",
                      json={'openconfig-vlan:vlan': [{
                          'vlan-id': 1234, 'config': {'vlan-id': 1234, 'name': 'vlan-1234'}}
                      ]}),
            mock.call(path="/api/data/openconfig-interfaces:interfaces/interface=portchannel1/openconfig-if-aggregate"
                           ":aggregation/openconfig-vlan:switched-vlan/config/trunk-vlans=1234",
                      json={'openconfig-vlan:trunk-vlans': [1234]}),
            mock.call(path="/api/data/f5-tenants:tenants/tenant=test-host-1/config/vlans=1234",
                      json={'f5-tenants:vlans': [1234]}),
        ]
        mock_vcmp.get.assert_has_calls(get_calls)
        mock_vcmp.put.assert_has_calls(put_calls)

    def test_remove_vcmp_l2_flow_iseries(self):
        """Check correct L2 configuration on L2 removal"""

        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_guests_response = MockResponse(
            {'items': [
                {'name': 'test-host-1',
                 'vlans': ['/Common/vlan-1234']},
                {'name': 'test-2',
                 'vlans': []},
            ]}, 200)

        mock_vcmp = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_vcmp.get.side_effect = [mock_guests_response]
        f5flows = f5_flows_iseries.F5Flows()

        store = {'network': mock_network,
                 'bigip': mock_vcmp,
                 'bigip_guest_names': ['test-host-1']}
        remove_vcmp_l2_flow = f5flows.make_remove_vcmp_l2_flow()
        engines.run(remove_vcmp_l2_flow, store=store)

        mock_vcmp.get.assert_called_with(path='/mgmt/tm/vcmp/guest')
        mock_vcmp.delete.assert_called_with(path='/mgmt/tm/net/vlan/vlan-1234')
        mock_vcmp.patch.assert_called_with(json={'vlans': []},
                                           path='/mgmt/tm/vcmp/guest/test-host-1')

    def test_remove_vcmp_l2_flow_rseries(self):
        """Check correct L2 configuration on L2 removal on rSeries hosts"""

        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_guests_response = MockResponse(
            {'f5-tenants:tenants': {'tenant': [
                {'name': 'test-host-1',
                 'config': {'vlans': [1234]}},
            ]}},
            200)
        mock_delete_response = MockResponse({}, 204)
        delete_calls = [
            mock.call(path='/api/data/f5-tenants:tenants/tenant=test-host-1/config/vlans=1234'),
            mock.call(path=("/api/data/openconfig-interfaces:interfaces/interface=portchannel1/openconfig-if-aggregate:"
                            "aggregation/openconfig-vlan:switched-vlan/config/trunk-vlans=1234")),
            mock.call(path="/api/data/openconfig-vlan:vlans/vlan=1234"),
        ]

        mock_vcmp = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_vcmp.get.side_effect = [mock_guests_response]
        mock_vcmp.delete.side_effect = [mock_delete_response,
                                        mock_delete_response,
                                        mock_delete_response]
        f5flows = f5_flows_rseries.F5Flows()

        store = {'network': mock_network,
                 'bigip': mock_vcmp,
                 # since F5OS-A API tenant endpoint yields only the hostname and not the whole domain (as
                 # iControlREST does), we check it via startswith and a dot appended. But the hostname attribute of
                 # the BigIPRestClient instance always contains the domain, so it has to be contained here as well.
                 'bigip_guest_names': ['test-host-1.some.domain']}
        remove_vcmp_l2_flow = f5flows.make_remove_vcmp_l2_flow()
        engines.run(remove_vcmp_l2_flow, store=store)

        mock_vcmp.get.assert_called_with(path='/api/data/f5-tenants:tenants')
        mock_vcmp.delete.assert_has_calls(delete_calls)

    def test_remove_vcmp_l2_flow_vlan_in_use_iseries(self):
        """Check that the remove_vcmp_l2_flow does not delete a VLAN in use by another guest"""

        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_guests_response = MockResponse(
            {'items': [
                {'name': 'test-host-1', 'vlans': ['/Common/vlan-1234']},
                {'name': 'test-host-2', 'vlans': []},
                {'name': 'test-host-3', 'vlans': ['/Common/vlan-1234']}
            ]}, 200)
        mock_vcmp = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_vcmp.get.side_effect = [mock_guests_response]
        f5flows = f5_flows_iseries.F5Flows()

        remove_vcmp_l2_flow = f5flows.make_remove_vcmp_l2_flow()
        store = {'network': mock_network,
                 'bigip': mock_vcmp,
                 'bigip_guest_names': ['test-host-1']}
        engines.run(remove_vcmp_l2_flow, store=store)

        mock_vcmp.get.assert_called_with(path='/mgmt/tm/vcmp/guest')
        mock_vcmp.delete.assert_not_called()
        mock_vcmp.patch.assert_called_with(json={'vlans': []},
                                           path='/mgmt/tm/vcmp/guest/test-host-1')

    def test_remove_vcmp_l2_flow_vlan_in_use_rseries(self):
        """Check that the remove_vcmp_l2_flow does not delete a VLAN in use by another guest"""

        mock_network_id = 'test-network-id'
        mock_subnet_id = 'test-subnet-id'
        mock_network = f5_network_models.Network(
            mtu=9000, id=mock_network_id, subnets=[mock_subnet_id],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_guests_response = MockResponse(
            {'f5-tenants:tenants': {'tenant': [
                {'name': 'test-host-1',
                 'config': {'vlans': [1234]}},
                # other guest using the same VLAN
                {'name': 'test-host-2',
                 'config': {'vlans': [1234]}},
            ]}},
            200)
        mock_delete_response = MockResponse({}, 204)
        delete_calls = [
            mock.call(path='/api/data/f5-tenants:tenants/tenant=test-host-1/config/vlans=1234'),
            mock.call(path=("/api/data/openconfig-interfaces:interfaces/interface=portchannel1/openconfig-if-aggregate:"
                            "aggregation/openconfig-vlan:switched-vlan/config/trunk-vlans=1234")),
            # no VLAN deletion call
        ]

        mock_vcmp = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_vcmp.get.side_effect = [mock_guests_response]
        mock_vcmp.delete.side_effect = [mock_delete_response,
                                        mock_delete_response]
        f5flows = f5_flows_rseries.F5Flows()

        store = {'network': mock_network,
                 'bigip': mock_vcmp,
                 # since F5OS-A API tenant endpoint yields only the hostname and not the whole domain (as
                 # iControlREST does), we check it via startswith and a dot appended. But the hostname attribute of
                 # the BigIPRestClient instance always contains the domain, so it has to be contained here as well.
                 'bigip_guest_names': ['test-host-1.some.domain']}
        remove_vcmp_l2_flow = f5flows.make_remove_vcmp_l2_flow()
        engines.run(remove_vcmp_l2_flow, store=store)

        mock_vcmp.get.assert_called_with(path='/api/data/f5-tenants:tenants')
        mock_vcmp.delete.assert_has_calls(delete_calls)
