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
from oslo_utils import uuidutils

import octavia.tests.unit.base as base
from octavia.network import data_models as network_models
# pylint: disable=unused-import
from octavia_f5.common import config  # noqa
from octavia_f5.controller.worker import l2_sync_manager
from octavia_f5.network import data_models as f5_network_models
from octavia_f5.restclient import as3restclient

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

MOCK_BIGIP_HOSTNAME = 'test-guest-hostname'
MOCK_VCMP_HOSTNAME = 'test-vcmp-hostname'
MOCK_FIXED_IP = network_models.FixedIP(
    ip_address='1.2.3.4',
    subnet_id=uuidutils.generate_uuid()
)
MOCK_SELFIP = network_models.Port(
    name=f"local-{MOCK_BIGIP_HOSTNAME}-{MOCK_FIXED_IP.subnet_id}",
    fixed_ips=[MOCK_FIXED_IP]
)


class MockResponse:
    def __init__(self, json_data, status_code, content=""):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = status_code < 400
        self.content = content

    def json(self):
        return self.json_data

    def raise_for_status(self):
        if self.status_code > 500:
            raise Exception('Boom!')


class TestL2SyncManager(base.TestCase):
    def setUp(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='controller_worker',
                    network_driver='network_noop_driver_f5')
        with mock.patch("octavia_f5.controller.worker.l2_sync_manager.L2SyncManager"
                        ".initialize_bigips") as init_bigips:
            bigips = []
            vcmps = []
            for i in range(2):
                bigip = mock.Mock()
                bigip.hostname = f"{MOCK_BIGIP_HOSTNAME}_{i}"
                bigips.append(bigip)

                vcmp = mock.Mock()
                vcmp.hostname = f"{MOCK_VCMP_HOSTNAME}_{i}"
                vcmps.append(vcmp)

            init_bigips.side_effect = [bigips, vcmps]
            self.manager = l2_sync_manager.L2SyncManager()
        super().setUp()

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_host_flow")
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_guest_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_ensure_l2_flow_all_available(self, mock_get_network,
                                          mock_l2_guest_flow, mock_l2_host_flow):
        mocked_selfips = [
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_0-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_1-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
            network_models.Port(
                name=f"local-OTHER_HOST-{uuidutils.generate_uuid()}")
        ]
        self.manager.ensure_l2_flow(mocked_selfips, 'test-network-id')
        mock_l2_guest_flow.assert_called_once_with(data=[
            {
                'selfips': [mocked_selfips[0]],
                'store': {'bigip': self.manager._bigips[0],
                          'network': mock_get_network.return_value,
                          'subnet_id': MOCK_FIXED_IP.subnet_id}
            },
            {
                'selfips': [mocked_selfips[1]],
                'store': {'bigip': self.manager._bigips[1],
                          'network': mock_get_network.return_value,
                          'subnet_id': MOCK_FIXED_IP.subnet_id}
            }])
        self.assertEqual(mock_l2_host_flow.call_count, 2)
        vcmp_l2_flow_calls = [
            mock.call(store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                             'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]}),
            mock.call(store={'bigip': self.manager._vcmps[1], 'network': mock_get_network.return_value,
                             'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]})
        ]
        mock_l2_host_flow.assert_has_calls(vcmp_l2_flow_calls, any_order=True)

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_host_flow")
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_guest_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_ensure_l2_flow_second_unavailable(self, mock_get_network,
                                               mock_l2_guest_flow, mock_l2_host_flow):
        mocked_selfips = [
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_0-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_1-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
            network_models.Port(
                name=f"local-OTHER_HOST-{uuidutils.generate_uuid()}")
        ]
        self.manager._bigips[1].is_available.side_effect = [False]
        self.manager.ensure_l2_flow(mocked_selfips, 'test-network-id')
        self.manager._bigips[1].is_available.assert_called_once_with(timeout=5)
        # expect only one call for BigIP, only for available device
        mock_l2_guest_flow.assert_called_once_with(data=[
            {
                'selfips': [mocked_selfips[0]],
                'store': {'bigip': self.manager._bigips[0],
                          'network': mock_get_network.return_value,
                          'subnet_id': MOCK_FIXED_IP.subnet_id}
            }])
        self.assertEqual(mock_l2_host_flow.call_count, 2)
        vcmp_l2_flow_calls = [
            mock.call(store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                             'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]}),
            mock.call(store={'bigip': self.manager._vcmps[1], 'network': mock_get_network.return_value,
                             'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]})
        ]
        mock_l2_host_flow.assert_has_calls(vcmp_l2_flow_calls, any_order=True)

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_host_flow")
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_guest_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_ensure_l2_flow_override_host(self, mock_get_network,
                                          mock_l2_guest_flow, mock_l2_host_flow):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='networking',
                    override_vcmp_guest_names=['test-host-2'])
        mocked_selfips = [
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_0-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_1-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
            network_models.Port(
                name=f"local-OTHER_HOST-{uuidutils.generate_uuid()}")
        ]
        self.manager.ensure_l2_flow(mocked_selfips, 'test-network-id')
        mock_l2_guest_flow.assert_called_once_with(data=[
            {
                'selfips': [mocked_selfips[0]],
                'store': {'bigip': self.manager._bigips[0],
                          'network': mock_get_network.return_value,
                          'subnet_id': MOCK_FIXED_IP.subnet_id}
            },
            {
                'selfips': [mocked_selfips[1]],
                'store': {'bigip': self.manager._bigips[1],
                          'network': mock_get_network.return_value,
                          'subnet_id': MOCK_FIXED_IP.subnet_id}
            }])
        self.assertEqual(mock_l2_host_flow.call_count, 2)
        vcmp_l2_flow_calls = [
            mock.call(store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                             'bigip_guest_names': ['test-host-2']}),
            mock.call(store={'bigip': self.manager._vcmps[1], 'network': mock_get_network.return_value,
                             'bigip_guest_names': ['test-host-2']})
        ]
        mock_l2_host_flow.assert_has_calls(vcmp_l2_flow_calls, any_order=True)

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_host_flow", side_effect=Exception('Boom!'))
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_guest_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_ensure_l2_flow_exception(self, mock_get_network,
                                      mock_l2_guest_flow, mock_l2_host_flow):
        mocked_selfips = [
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_0-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_1-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
        ]
        try:
            self.manager.ensure_l2_flow(mocked_selfips, 'test-network-id')
        except Exception as e:
            self.assertEqual("Failed ensure_l2_flow for all vcmp devices of network_id=test-network-id",
                             e.args[0])

        mock_l2_guest_flow.assert_called_once_with(data=[
            {
                'selfips': [mocked_selfips[0]],
                'store': {'bigip': self.manager._bigips[0],
                          'network': mock_get_network.return_value,
                          'subnet_id': MOCK_FIXED_IP.subnet_id}
            },
            {
                'selfips': [mocked_selfips[1]],
                'store': {'bigip': self.manager._bigips[1],
                          'network': mock_get_network.return_value,
                          'subnet_id': MOCK_FIXED_IP.subnet_id}
            }])
        self.assertEqual(mock_l2_host_flow.call_count, 2)
        vcmp_l2_flow_calls = [
            mock.call(store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                             'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]}),
            mock.call(store={'bigip': self.manager._vcmps[1], 'network': mock_get_network.return_value,
                             'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]})
        ]
        mock_l2_host_flow.assert_has_calls(vcmp_l2_flow_calls, any_order=True)

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test__do_ensure_l2_guest_flow_nothing_exist_no_errors(self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id-1', gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=8950, id='test-network-id', subnets=['test-subnet-id-1', 'test-subnet-id-2'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='5.6.7.8', subnet_id='test-subnet-id-2')
        selfip_port = network_models.Port(
            id='test-selfip-port-id', fixed_ips=[selfip_fixed_ip],
        )
        mock_bigips = []
        for i in range(0, 2):
            mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
            mock_bigip.hostname = f'hostname-{i}'
            mock_bigip.get.side_effect = [
                MockResponse({}, 404) for _ in range(9)]
            mock_bigips.append(mock_bigip)
        mock_bigips[0].is_active = True
        data = [
            {
                'selfips': [selfip_port],
                'store': {
                    'network': mock_network,
                    'bigip': mock_bigips[0],
                    'subnet_id': 'test-subnet-id-2',
                    'existing_selfips': []
                }
            },
            {
                'selfips': [selfip_port],
                'store': {
                    'network': mock_network,
                    'bigip': mock_bigips[1],
                    'subnet_id': 'test-subnet-id-2',
                    'existing_selfips': []
                }
            }
        ]
        self.manager._do_ensure_l2_guest_flow(data=data)
        # check that both devices were called and REVERT tasks were not called
        self.assertEqual(mock_bigips[0].get.call_count, 9)
        self.assertEqual(mock_bigips[1].get.call_count, 9)
        self.assertEqual(mock_bigips[0].post.call_count, 5)
        self.assertEqual(mock_bigips[1].post.call_count, 5)
        self.assertEqual(mock_bigips[0].delete.call_count, 0)
        self.assertEqual(mock_bigips[1].delete.call_count, 0)
        for i in range(0, 2):
            # check SelfIP creation
            mock_bigips[i].post.assert_any_call(
                path='/mgmt/tm/net/self',
                json={'name': 'port-test-selfip-port-id', 'vlan': '/Common/vlan-1234',
                      'address': '5.6.7.8%1234/24'})
            # check DefaultRoute creation
            mock_bigips[i].post.assert_any_call(
                path='/mgmt/tm/net/route',
                json={'name': 'vlan-1234', 'gw': '1.2.3.1%1234',
                      'network': 'default%1234'})
            # check SubnetRoute existence
            mock_bigips[i].get.assert_any_call(
                path='/mgmt/tm/net/route/~Common~net_test-network-id_sub_test-subnet-id-1')
            # check SubnetRoute creation
            mock_bigips[i].post.assert_any_call(
                path='/mgmt/tm/net/route',
                json={'name': 'net_test-network-id_sub_test-subnet-id-1',
                      'tmInterface': '/Common/vlan-1234', 'network': '1.2.3.0%1234/24'})

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test__do_ensure_l2_guest_flow_nothing_exist_route_domain_failed_on_second_device(
            self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id', gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=8950, id='test-network-id', subnets=['test-subnet-id'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )
        selfip_fixed_ip = network_models.FixedIP(
            ip_address='1.2.3.2', subnet_id='test-subnet-id-2')
        selfip_port = network_models.Port(
            id='test-selfip-port-id', fixed_ips=[selfip_fixed_ip],
        )
        mock_bigip_1 = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip_1.hostname = 'hostname-1'
        mock_bigip_1.is_active = True
        mock_bigip_1.get.side_effect = [
            MockResponse({}, 404),
            MockResponse({}, 404),
            MockResponse({}, 404),
            MockResponse({}, 404),
            MockResponse({}, 404),
            MockResponse({}, 404),
            MockResponse({}, 404),
            MockResponse({}, 404),
            MockResponse({}, 404),
            MockResponse({}, 200),
        ]
        mock_bigip_2 = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip_2.hostname = 'hostname-2'
        mock_bigip_2.get.side_effect = [
            MockResponse({}, 404) for _ in range(8)]
        mock_bigip_2.post.side_effect = [
            # VLAN creation
            MockResponse({}, 202),
            # Route Domain creation
            MockResponse({}, 502)
        ]
        data = [
            {
                'selfips': [selfip_port],
                'store': {
                    'network': mock_network,
                    'bigip': mock_bigip_1,
                    'subnet_id': 'test-subnet-id',
                    'existing_selfips': []
                }
            },
            {
                'selfips': [selfip_port],
                'store': {
                    'network': mock_network,
                    'bigip': mock_bigip_2,
                    'subnet_id': 'test-subnet-id',
                    'existing_selfips': []
                }
            }
        ]
        self.assertRaises(Exception, self.manager._do_ensure_l2_guest_flow, data=data)
        # check that both devices were called and REVERT tasks were also called
        self.assertEqual(mock_bigip_1.get.call_count, 10)
        self.assertEqual(mock_bigip_2.get.call_count, 7)
        self.assertEqual(mock_bigip_1.post.call_count, 5)
        self.assertEqual(mock_bigip_2.post.call_count, 2)
        self.assertEqual(mock_bigip_1.delete.call_count, 4)
        self.assertEqual(mock_bigip_2.delete.call_count, 1)
        bigip_1_delete_calls = [
            # check that VLAN reverted
            mock.call(path='/mgmt/tm/net/vlan/~Common~vlan-1234'),
            # check that Route Domain was reverted
            mock.call(path='/mgmt/tm/net/route-domain/vlan-1234'),
            # check that Self IP was reverted
            mock.call(path='/mgmt/tm/net/self/port-test-selfip-port-id'),
            # check that Subnet Route was reverted
            mock.call(path='/mgmt/tm/net/route/~Common~net_test-network-id_sub_test-subnet-id')
        ]
        mock_bigip_1.delete.assert_has_calls(bigip_1_delete_calls, any_order=True)
        bigip_2_delete_calls = [
            # check that VLAN reverted
            mock.call(path='/mgmt/tm/net/vlan/~Common~vlan-1234'),
        ]
        mock_bigip_2.delete.assert_has_calls(bigip_2_delete_calls, any_order=True)

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_remove_l2_host_flow")
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_remove_l2_guest_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_remove_l2_guest_flow_all_available(self, mock_get_network,
                                                mock_remove_l2_guest_flow,
                                                mock_remove_l2_host_flow):
        self.manager.remove_l2_guest_flow('test-network-id')
        mock_remove_l2_guest_flow.assert_called_once_with(data=[
            {
                'store': {'bigip': self.manager._bigips[0],
                          'network': mock_get_network.return_value}
            },
            {
                'store': {'bigip': self.manager._bigips[1],
                          'network': mock_get_network.return_value}
            }])
        self.assertEqual(mock_remove_l2_host_flow.call_count, 2)
        vcmp_l2_flow_calls = [
            mock.call(store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                      'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]}),
            mock.call(store={'bigip': self.manager._vcmps[1], 'network': mock_get_network.return_value,
                      'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]})
        ]
        mock_remove_l2_host_flow.assert_has_calls(vcmp_l2_flow_calls, any_order=True)

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_remove_l2_host_flow")
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_remove_l2_guest_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_remove_l2_guest_flow_second_unavailable(self, mock_get_network,
                                                     mock_remove_l2_guest_flow,
                                                     mock_remove_l2_host_flow):
        self.manager._bigips[1].is_available.side_effect = [False]
        self.manager.remove_l2_guest_flow('test-network-id')
        self.manager._bigips[1].is_available.assert_called_once_with(timeout=5)
        # expect only one call for BigIP, only for available device
        mock_remove_l2_guest_flow.assert_called_once_with(data=[
            {
                'store': {'bigip': self.manager._bigips[0],
                          'network': mock_get_network.return_value}
            }])
        self.assertEqual(mock_remove_l2_host_flow.call_count, 2)
        vcmp_l2_flow_calls = [
            mock.call(store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                      'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]}),
            mock.call(store={'bigip': self.manager._vcmps[1], 'network': mock_get_network.return_value,
                      'bigip_guest_names': [MOCK_BIGIP_HOSTNAME + "_0", MOCK_BIGIP_HOSTNAME + "_1"]})
        ]
        mock_remove_l2_host_flow.assert_has_calls(vcmp_l2_flow_calls, any_order=True)

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test__do_remove_l2_guest_flow_nothing_exist_no_errors(self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id', gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=8950, id='test-network-id', subnets=['test-subnet-id'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )
        mock_bigips = []
        for i in range(0, 2):
            mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
            mock_bigip.hostname = f'hostname-{i}'
            mock_bigip.get.side_effect = [
                MockResponse({}, 404) for _ in range(9)]
            mock_bigips.append(mock_bigip)
        mock_bigips[0].is_active = True
        data = [
            {
                'store': {
                    'network': mock_network,
                    'bigip': mock_bigips[0],
                    'subnet_id': 'test-subnet-id',
                }
            },
            {
                'store': {
                    'network': mock_network,
                    'bigip': mock_bigips[1],
                    'subnet_id': 'test-subnet-id',
                }
            }
        ]
        self.manager._do_remove_l2_guest_flow(data=data)
        # check that both devices were called and REVERT tasks were not called
        self.assertEqual(mock_bigips[0].get.call_count, 7)
        self.assertEqual(mock_bigips[1].get.call_count, 7)
        self.assertEqual(mock_bigips[0].post.call_count, 0)
        self.assertEqual(mock_bigips[1].post.call_count, 0)
        self.assertEqual(mock_bigips[0].delete.call_count, 0)
        self.assertEqual(mock_bigips[1].delete.call_count, 0)

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test__do_remove_l2_guest_flow_all_exist_vlan_failed_on_second_device(
            self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id', gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=8950, id='test-network-id', subnets=['test-subnet-id'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )
        mock_bigip_1 = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip_1.hostname = 'hostname-1'
        mock_bigip_1.is_active = True
        mock_bigip_1.get.side_effect = [
            MockResponse({}, 404),
            MockResponse({}, 404),
            # DefaultRoute
            MockResponse({}, 200),
            # RouteDomain
            MockResponse(
                {
                    'name': 'vlan-1234',
                    'vlans': ['/Common/vlan-1234'],
                    'id': '1234',
                    'fullPath': 'vlan-1234'
                },
                200
            ),
            # VLAN
            MockResponse(
                {
                    'name': 'vlan-1234',
                    'tag': 1234,
                    'mtu': 8950,
                    'hardwareSyncookie': 'enabled',
                    'synFloodRateLimit': 123,
                    'syncacheThreshold': 123
                },
                200
            )
        ]
        mock_bigip_1.delete.side_effect = [
            # DefaultRoute delete
            MockResponse({}, 200),
            # RouteDomain delete
            MockResponse({}, 200),
            # VLAN delete
            MockResponse({}, 200)
        ]
        mock_bigip_2 = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip_2.hostname = 'hostname-2'
        mock_bigip_2.get.side_effect = [
            MockResponse({}, 404),
            MockResponse({}, 404),
            # DefaultRoute
            MockResponse({}, 200),
            # RouteDomain
            MockResponse(
                {
                    'name': 'vlan-1234',
                    'vlans': ['/Common/vlan-1234'],
                    'id': '1234',
                    'fullPath': 'vlan-1234'
                },
                200
            ),
            # VLAN
            MockResponse(
                {
                    'name': 'vlan-1234',
                    'tag': 1234,
                    'mtu': 8950,
                    'hardwareSyncookie': 'enabled',
                    'synFloodRateLimit': 123,
                    'syncacheThreshold': 123
                },
                200
            )
        ]
        mock_bigip_2.delete.side_effect = [
            # DefaultRoute delete
            MockResponse({}, 200),
            # RouteDomain delete
            MockResponse({}, 200),
            # VLAN delete
            MockResponse({}, 502, "something happened")
        ]
        data = [
            {
                'store': {
                    'network': mock_network,
                    'bigip': mock_bigip_1,
                    'subnet_id': 'test-subnet-id',
                }
            },
            {
                'store': {
                    'network': mock_network,
                    'bigip': mock_bigip_2,
                    'subnet_id': 'test-subnet-id',
                }
            }
        ]
        self.assertRaises(Exception, self.manager._do_remove_l2_guest_flow, data=data)
        # check that both devices were called and REVERT tasks were not called
        self.assertEqual(mock_bigip_1.get.call_count, 5)
        self.assertEqual(mock_bigip_2.get.call_count, 5)
        self.assertEqual(mock_bigip_1.post.call_count, 2)
        self.assertEqual(mock_bigip_2.post.call_count, 1)
        self.assertEqual(mock_bigip_1.delete.call_count, 3)
        self.assertEqual(mock_bigip_2.delete.call_count, 3)
        bigip_1_post_calls = [
            # check that VLAN reverted
            mock.call(path='/mgmt/tm/net/vlan',
                      json={'name': 'vlan-1234', 'tag': 1234, 'mtu': 8950,
                            'hardwareSyncookie': 'enabled', 'synFloodRateLimit': 123,
                            'syncacheThreshold': 123}),
            # check that RouteDomain was reverted
            mock.call(path='/mgmt/tm/net/route-domain',
                      json={'name': 'vlan-1234', 'vlans': ['/Common/vlan-1234'], 'id': '1234'}),
        ]
        mock_bigip_1.post.assert_has_calls(bigip_1_post_calls, any_order=True)
        bigip_2_post_calls = [
            # check that RouteDomain reverted
            mock.call(path='/mgmt/tm/net/route-domain',
                      json={'name': 'vlan-1234', 'vlans': ['/Common/vlan-1234'], 'id': '1234'}),
        ]
        mock_bigip_2.post.assert_has_calls(bigip_2_post_calls, any_order=True)

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_host_flow")
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_guest_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_ensure_l2_flow_hosts_before_guests(self, mock_get_network,
                                                mock_l2_guest_flow, mock_l2_host_flow):
        """Ensure VCMP host flows finish before guest flows start."""
        import time
        host_times = []
        guest_times = []

        def host_side_effect(store):
            # simulate some work
            time.sleep(0.05)
            host_times.append(time.time())

        def guest_side_effect(data):
            guest_times.append(time.time())

        mock_l2_host_flow.side_effect = host_side_effect
        mock_l2_guest_flow.side_effect = guest_side_effect

        mocked_selfips = [
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_0-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
            network_models.Port(
                name=f"local-{MOCK_BIGIP_HOSTNAME}_1-{MOCK_FIXED_IP.subnet_id}",
                fixed_ips=[MOCK_FIXED_IP]
            ),
        ]

        self.manager.ensure_l2_flow(mocked_selfips, 'test-network-id')

        # expect host flows called for both vcmps
        self.assertEqual(mock_l2_host_flow.call_count, 2)
        self.assertTrue(len(guest_times) >= 1)
        self.assertTrue(len(host_times) >= 2)
        # assert that the latest host completion time is before the guest start time
        self.assertLess(max(host_times), min(guest_times))
