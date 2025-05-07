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

import inspect
import mock
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.common import constants
from octavia.controller.queue.v2 import endpoints
from octavia.controller.worker.v2 import controller_worker as orig_controller_worker
from octavia.tests.unit import base
from octavia.tests.unit.controller.queue.v2 import test_endpoints
from octavia_f5.controller.worker import controller_worker


class TestEndpoint(test_endpoints.TestEndpoints):

    def setUp(self):
        super().setUp()

        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(octavia_plugins='f5_plugin')

        self.worker_patcher = mock.patch('octavia_f5.controller.worker.'
                                         'controller_worker.ControllerWorker',
                                         spec=controller_worker.ControllerWorker)
        self.worker_patcher.start()

        self.ep = endpoints.Endpoints()
        self.context = {}
        self.resource_updates = {}
        self.resource_id = 1234
        self.resource = {constants.ID: self.resource_id}
        self.server_group_id = 3456
        self.listener_dict = {constants.LISTENER_ID: uuidutils.generate_uuid()}
        self.loadbalancer_dict = {
            constants.LOADBALANCER_ID: uuidutils.generate_uuid()
        }
        self.flavor_id = uuidutils.generate_uuid()
        self.availability_zone = uuidutils.generate_uuid()

    def tearDown(self):
        super().tearDown()
        self.worker_patcher.stop()

    def test_add_loadbalancer(self):
        self.ep.add_loadbalancer(self.context,
                                 self.loadbalancer_dict['loadbalancer_id'])
        self.ep.worker.add_loadbalancer.assert_called_once_with(
            self.loadbalancer_dict['loadbalancer_id'])

    def test_remove_loadbalancer(self):
        self.ep.remove_loadbalancer(self.context,
                                    self.loadbalancer_dict['loadbalancer_id'])
        self.ep.worker.remove_loadbalancer.assert_called_once_with(
            self.loadbalancer_dict['loadbalancer_id'])


class TestEndpointsCompatibillity(base.TestCase):

    def test_compatibility(self):
        supported = ['load_balancer', 'listener', 'pool', 'member',
                     'l7policy', 'health_monitor']
        orig_methods = [m for m in dir(orig_controller_worker.ControllerWorker) if callable(
            getattr(orig_controller_worker.ControllerWorker, m)) and not m.startswith(
                '__') and any(r in m for r in supported)]
        for m in orig_methods:
            orig_args = list(inspect.signature(getattr(orig_controller_worker.ControllerWorker, m)).parameters.keys())
            f5_args = list(inspect.signature(getattr(controller_worker.ControllerWorker, m)).parameters.keys())
            self.assertEqual(orig_args, f5_args, f"Arguments for the method {m} are not identical")
