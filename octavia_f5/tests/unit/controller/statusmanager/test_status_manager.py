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

import octavia.tests.unit.base as base
from octavia_f5.controller.statusmanager import status_manager

CONF = cfg.CONF


class TestStatusManager(base.TestCase):
    def setUp(self):
        super(TestStatusManager, self).setUp()
        conf = self.useFixture(oslo_fixture.Config(CONF))
        conf.config(group="f5_agent", prometheus=False)
        conf.config(group="controller_worker", network_driver='network_noop_driver_f5')

    @mock.patch('octavia.db.repositories.AmphoraRepository')
    def test_update_availability(self, mock_amp_repo):
        pass

    @mock.patch('octavia.db.repositories.AmphoraRepository')
    @mock.patch('requests.get')
    def test_heartbeat(self, mock_amp_repo, mock_requests_get):
        # TODO test message format agnostically
        self.conf.f5_agent.bigip_urls = ["bigip_url_1", "bigip_url_2"]
        sm = status_manager.StatusManager()
        sm.heartbeat()