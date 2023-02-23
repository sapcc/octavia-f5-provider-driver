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
from octavia.network import data_models as network_models
# pylint: disable=unused-import
from octavia_f5.common import config  # noqa
from octavia_f5.controller.worker.tasks import f5_tasks
from octavia_f5.network import data_models as f5_network_models
from octavia_f5.restclient import as3restclient
from octavia_f5.tests.unit.controller.worker.flows import test_f5_flows

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class TestF5Tasks(base.TestCase):
    def setUp(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="controller_worker",
                    network_driver='network_noop_driver_f5')

        super(TestF5Tasks, self).setUp()

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_EnsureRoute(self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id', gateway_ip='2.3.4.5',
            cidr='2.3.4.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=9000, id='test-network-id', subnets=['test-subnet-id'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_route_response = test_f5_flows.MockResponse({
            'name': 'vlan-1234',
            'gw': '1.2.3.1%1234',
            'network': 'default%1234',
            'fullPath': '~Common~vlan-1234'
        }, status_code=200)

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.return_value = mock_route_response

        engines.run(f5_tasks.EnsureRoute(),
                    store={'network': mock_network,
                           'bigip': mock_bigip,
                           'subnet_id': 'test-subnet-id'})

        mock_bigip.get.assert_called_with(path='/mgmt/tm/net/route/~Common~vlan-1234')
        mock_bigip.patch.assert_called_with(path='/mgmt/tm/net/route/~Common~vlan-1234',
                                            json={'gw': '2.3.4.5%1234', 'network': 'default%1234'})
        mock_bigip.post.assert_not_called()


    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_EnsureRoute_legacy(self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id', gateway_ip='1.2.3.1',
            cidr='1.2.3.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=9000, id='test-network-id', subnets=['test-subnet-id'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_route_response = test_f5_flows.MockResponse({
            'name': 'net-test-network-id',
            'gw': '1.2.3.1%1234',
            'network': 'default%1234',
            'fullPath': '~Common~net-test-network-id'
        }, status_code=200)

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.side_effect = [test_f5_flows.MockResponse({}, 404),
                                      mock_route_response]

        engines.run(f5_tasks.EnsureRoute(),
                    store={'network': mock_network,
                           'bigip': mock_bigip,
                           'subnet_id': 'test-subnet-id'})

        calls = [
            mock.call(path='/mgmt/tm/net/route/~Common~vlan-1234'),
            mock.call(path='/mgmt/tm/net/route/~Common~net-test-network-id')
        ]
        mock_bigip.get.assert_has_calls(calls)
        mock_bigip.patch.assert_not_called()
        mock_bigip.post.assert_not_called()

    @mock.patch("octavia.network.drivers.noop_driver.driver.NoopManager"
                ".get_subnet")
    def test_EnsureRoute_legacy_conflict(self, mock_get_subnet):
        mock_get_subnet.return_value = network_models.Subnet(
            id='test-subnet-id', gateway_ip='8.8.8.8',
            cidr='1.2.3.0/24', network_id='test-network-id')
        mock_network = f5_network_models.Network(
            mtu=9000, id='test-network-id', subnets=['test-subnet-id'],
            segments=[{'provider:physical_network': 'physnet',
                       'provider:segmentation_id': 1234}]
        )

        mock_route_response = test_f5_flows.MockResponse({
            'name': 'net-test-network-id',
            'gw': '1.2.3.1%1234',
            'network': 'default%1234',
            'fullPath': '~Common~net-test-network-id'
        }, status_code=200)

        mock_bigip = mock.Mock(spec=as3restclient.AS3RestClient)
        mock_bigip.get.side_effect = [test_f5_flows.MockResponse({}, 404),
                                      mock_route_response]
        # Patch should fail
        mock_bigip.patch.side_effect = test_f5_flows.empty_response

        engines.run(f5_tasks.EnsureRoute(),
                    store={'network': mock_network,
                           'bigip': mock_bigip,
                           'subnet_id': 'test-subnet-id'})

        calls = [
            mock.call(path='/mgmt/tm/net/route/~Common~vlan-1234'),
            mock.call(path='/mgmt/tm/net/route/~Common~net-test-network-id')
        ]
        mock_bigip.get.assert_has_calls(calls)
        mock_bigip.patch.assert_called_once()
        mock_bigip.delete.assert_called_with(
            path='/mgmt/tm/net/route/~Common~net-test-network-id')
        mock_bigip.post.assert_called_with(json={
            'name': 'vlan-1234', 'gw': '8.8.8.8%1234', 'network': 'default%1234'},
            path='/mgmt/tm/net/route')
