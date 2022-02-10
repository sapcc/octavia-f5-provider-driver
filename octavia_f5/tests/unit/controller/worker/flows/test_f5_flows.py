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
from octavia_f5.controller.worker.flows import f5_flows
from octavia_f5.network import data_models as f5_network_models
from octavia_f5.restclient import as3restclient

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = True

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

        super(TestF5Flows, self).setUp()

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_f5_flow_ensure_l2(self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id', gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=9000, id='test-network-id', subnets=['test-subnet-id'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='1.2.3.2', subnet_id='test-subnet-id')
        selfip_port = network_models.Port(
            id='test-selfip-port-id', fixed_ips=[selfip_fixed_ip],
        )

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.side_effect = empty_response
        f5flows = f5_flows.F5Flows()

        engines.run(f5flows.ensure_l2([selfip_port]),
                    store={'network': mock_network,
                           'bigip': mock_bigip,
                           'subnet_id': selfip_fixed_ip.subnet_id})

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
    def test_f5_flow_ensure_existing_l2(self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id', gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=9000, id='test-network-id', subnets=['test-subnet-id'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='1.2.3.2', subnet_id='test-subnet-id')
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
                                      mock_route_response]
        f5flows = f5_flows.F5Flows()

        engines.run(f5flows.ensure_l2([selfip_port]),
                    store={'network': mock_network,
                           'bigip': mock_bigip,
                           'subnet_id': selfip_fixed_ip.subnet_id})

        mock_bigip.get.assert_called()
        mock_bigip.patch.assert_not_called()
        mock_bigip.post.assert_not_called()

    def test_f5_flow_ensure_vcmp_l2(self):
        mock_network = f5_network_models.Network(
            mtu=9000, id='test-network-id', subnets=['test-subnet-id'],
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
        f5flows = f5_flows.F5Flows()

        engines.run(f5flows.ensure_vcmp_l2(),
                    store={'network': mock_network,
                           'bigip': mock_vcmp,
                           'bigip_guest_names': ['test-host-1']})

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

    def test_f5_flow_remove_vcmp_l2(self):
        mock_network = f5_network_models.Network(
            mtu=9000, id='test-network-id', subnets=['test-subnet-id'],
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
        f5flows = f5_flows.F5Flows()

        engines.run(f5flows.remove_vcmp_l2(),
                    store={'network': mock_network,
                           'bigip': mock_vcmp,
                           'bigip_guest_names': ['test-host-1']})

        mock_vcmp.get.assert_called_with(path='/mgmt/tm/vcmp/guest')
        mock_vcmp.delete.assert_called_with(path='/mgmt/tm/net/vlan/vlan-1234')
        mock_vcmp.patch.assert_called_with(json={'vlans': []},
                                           path='/mgmt/tm/vcmp/guest/test-host-1')

    def test_f5_flow_remove_vcmp_l2_vlan_in_use(self):
        mock_network = f5_network_models.Network(
            mtu=9000, id='test-network-id', subnets=['test-subnet-id'],
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
        f5flows = f5_flows.F5Flows()

        engines.run(f5flows.remove_vcmp_l2(),
                    store={'network': mock_network,
                           'bigip': mock_vcmp,
                           'bigip_guest_names': ['test-host-1']})

        mock_vcmp.get.assert_called_with(path='/mgmt/tm/vcmp/guest')
        mock_vcmp.delete.assert_not_called()
        mock_vcmp.patch.assert_called_with(json={'vlans': []},
                                           path='/mgmt/tm/vcmp/guest/test-host-1')
