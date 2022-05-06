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

import octavia.tests.unit.base as base
from octavia.db import models
from octavia.network import data_models as network_models
# pylint: disable=unused-import
from octavia_f5.common import config  # noqa
from octavia_f5.controller.worker import sync_manager

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

MOCK_BIGIP_HOSTNAME = 'test-guest-hostname'

class TestSyncManager(base.TestCase):
    def setUp(self):
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='controller_worker',
                    network_driver='network_noop_driver_f5')
        super(TestSyncManager, self).setUp()

    @mock.patch("octavia_f5.controller.worker.sync_manager.SyncManager"
                        ".initialize_bigips")
    @mock.patch("octavia_f5.utils.esd_repo.EsdRepository")
    @mock.patch("octavia_f5.restclient.as3declaration.AS3DeclarationManager")
    def test_tenant_update_skip_selfips(self, mock_as3, mock_esd_repo, mock_init_bigips):
        mock_decl_manager = mock.Mock()
        mock_as3.return_value = mock_decl_manager

        bigip = mock.Mock()
        bigip.hostname = MOCK_BIGIP_HOSTNAME

        mock_init_bigips.side_effect = [[bigip]]
        status_manger = mock.MagicMock()
        loadbalancer_repo = mock.MagicMock()
        manager = sync_manager.SyncManager(
            status_manger, loadbalancer_repo)

        selfips = [network_models.Port(fixed_ips=[
            network_models.FixedIP(ip_address='1.2.3.4')])]

        mock_lb = mock.Mock(spec=models.LoadBalancer)
        loadbalancer_repo.get_all_by_network.return_value = [mock_lb]
        with mock.patch('octavia_f5.db.api.get_session'):
            manager.tenant_update('test-net-id', selfips=selfips)
        mock_decl_manager.get_declaration.assert_called_with(
            {'test-net-id': [mock_lb]}, ['1.2.3.4'])
        pass
