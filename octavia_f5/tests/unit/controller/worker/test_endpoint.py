# Copyright 2020 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.controller.queue.v1 import endpoints
from octavia.controller.worker.v1 import controller_worker
from octavia.tests.unit.controller.queue.v1 import test_endpoints


class TestEndpoint(test_endpoints.TestEndpoints):

    def setUp(self):
        super(TestEndpoint, self).setUp()

        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(octavia_plugins='f5_plugin')

        mock_class = mock.create_autospec(controller_worker.ControllerWorker)
        self.worker_patcher = mock.patch('octavia.controller.queue.v1.'
                                         'endpoints.stevedore_driver')
        self.worker_patcher.start().ControllerWorker = mock_class

        self.ep = endpoints.Endpoints()
        self.context = {}
        self.resource_updates = {}
        self.resource_id = 1234
        self.server_group_id = 3456
        self.flavor_id = uuidutils.generate_uuid()

