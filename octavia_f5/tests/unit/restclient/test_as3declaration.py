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

from octavia.db import models
from octavia.tests.unit import base
from octavia_f5.common import config  # noqa
from octavia_f5.restclient import as3declaration

CONF = None


class TestGetDeclaration(base.TestCase):

    def setUp(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(group='controller_worker',
                    network_driver='network_noop_driver_f5')
        super(TestGetDeclaration, self).setUp()

    @mock.patch("octavia_f5.utils.esd_repo.EsdRepository")
    @mock.patch("octavia_f5.network.drivers.noop_driver_f5.driver.NoopNetworkDriverF5"
                ".get_segmentation_id")
    def test_get_declaration(self, mock_get_segmentation_id, mock_esd_repo):
        mock_status_manager = mock.MagicMock()
        as3 = as3declaration.AS3DeclarationManager(mock_status_manager)
        mock_get_segmentation_id.side_effect = [1234, 2345]
        mock_lb = mock.Mock(spec=models.LoadBalancer)
        mock_lb.pools=[]
        mock_lb.listeners=[]

        self.assertIsInstance(as3, as3declaration.AS3DeclarationManager)

        # Ensure host / segment_ids are depending on the agent host
        self.conf.config(host="host1")
        decl = as3.get_declaration({'net1': [mock_lb]}, [])
        self.assertEqual(decl.declaration.net_net1.defaultRouteDomain, 1234)
        mock_get_segmentation_id.assert_called_with('net1', 'host1')

        self.conf.config(host="host2")
        decl = as3.get_declaration({'net1': [mock_lb]}, [])
        self.assertEqual(decl.declaration.net_net1.defaultRouteDomain, 2345)
        mock_get_segmentation_id.assert_called_with('net1', 'host2')
