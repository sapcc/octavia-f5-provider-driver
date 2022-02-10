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


class TestL2SyncManager(base.TestCase):
    def setUp(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='controller_worker',
                    network_driver='network_noop_driver_f5')
        with mock.patch("octavia_f5.controller.worker.l2_sync_manager.L2SyncManager"
                        ".initialize_bigips") as init_bigips:
            self.bigip = mock.Mock()
            self.bigip.hostname = MOCK_BIGIP_HOSTNAME

            self.vcmp = mock.Mock()
            self.vcmp.hostname = MOCK_VCMP_HOSTNAME

            init_bigips.side_effect = [[self.bigip], [self.vcmp]]
            self.manager = l2_sync_manager.L2SyncManager()
        super(TestL2SyncManager, self).setUp()

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_vcmp_l2_flow")
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_ensure_l2_flow(self, mock_get_network,
                            mock_l2_flow, mock_vcmp_l2_flow):
        other_selfip = network_models.Port(
            name=f"local-OTHER_HOST-{uuidutils.generate_uuid()}")
        self.manager.ensure_l2_flow([MOCK_SELFIP, other_selfip], 'test-network-id')
        mock_l2_flow.assert_called_once_with(selfips=[MOCK_SELFIP],
            store={'bigip': self.manager._bigips[0], 'network': mock_get_network.return_value,
                   'subnet_id': MOCK_FIXED_IP.subnet_id})
        mock_vcmp_l2_flow.assert_called_once_with(
            store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                   'bigip_guest_names': [MOCK_BIGIP_HOSTNAME]})

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_vcmp_l2_flow")
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_ensure_l2_flow_override_host(self, mock_get_network,
                                          mock_l2_flow, mock_vcmp_l2_flow):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='networking',
                    override_vcmp_guest_names=['test-host-2'])

        self.manager.ensure_l2_flow([MOCK_SELFIP], 'test-network-id')
        mock_l2_flow.assert_called_once_with(selfips=[MOCK_SELFIP],
            store={'bigip': self.manager._bigips[0], 'network': mock_get_network.return_value,
                   'subnet_id': MOCK_FIXED_IP.subnet_id})
        mock_vcmp_l2_flow.assert_called_once_with(
            store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                   'bigip_guest_names': ['test-host-2']})

    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_vcmp_l2_flow", side_effect=Exception('Boom!'))
    @mock.patch("octavia_f5.controller.worker.l2_sync_manager."
                "L2SyncManager._do_ensure_l2_flow")
    @mock.patch('octavia_f5.network.drivers.noop_driver_f5.driver.'
                'NoopNetworkDriverF5.get_network')
    def test_ensure_l2_flow_exception(self, mock_get_network,
                                          mock_l2_flow, mock_vcmp_l2_flow):
        try:
            self.manager.ensure_l2_flow([MOCK_SELFIP], 'test-network-id')
        except Exception as e:
            self.assertEqual("Failed ensure_l2_flow for all vcmp devices of network_id=test-network-id",
                             e.args[0])

        mock_l2_flow.assert_called_once_with(selfips=[MOCK_SELFIP],
            store={'bigip': self.manager._bigips[0], 'network': mock_get_network.return_value,
                   'subnet_id': MOCK_FIXED_IP.subnet_id})
        mock_vcmp_l2_flow.assert_called_once_with(
            store={'bigip': self.manager._vcmps[0], 'network': mock_get_network.return_value,
                   'bigip_guest_names': [MOCK_BIGIP_HOSTNAME]})
