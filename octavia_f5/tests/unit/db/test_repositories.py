#  Copyright 2021 SAP SE
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

from octavia.common import constants
from octavia.tests.functional.db import base
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia_f5.common import config, constants as f5_const  # noqa
from octavia_f5.db import repositories as repos

CONF = cfg.CONF


class TestAmphoraRepository(base.OctaviaDBTestBase):
    FAKE_DEVICE_AMPHORA_ID_1 = uuidutils.generate_uuid()
    FAKE_DEVICE_AMPHORA_ID_2 = uuidutils.generate_uuid()
    FAKE_DEVICE_HOSTNAME_1 = "fake.device.pair.hostname1"
    FAKE_DEVICE_HOSTNAME_2 = "fake.device.pair.hostname2"
    FAKE_DEVICE_PAIR = "fake.device.pair"

    def setUp(self):
        super(TestAmphoraRepository, self).setUp()
        self.amp_repo = repos.AmphoraRepository()
        # two device amphoras belonging to the same pair
        self.device_amphora_1 = self.amp_repo.create(
            self.session, id=self.FAKE_DEVICE_AMPHORA_ID_1,
            role=constants.ROLE_MASTER, vrrp_interface=None,
            status=constants.ACTIVE, compute_flavor=self.FAKE_DEVICE_PAIR,
            vrrp_priority=1, cached_zone=self.FAKE_DEVICE_HOSTNAME_1
        )
        self.device_amphora_2 = self.amp_repo.create(
            self.session, id=self.FAKE_DEVICE_AMPHORA_ID_2,
            role=constants.ROLE_MASTER, vrrp_interface=None,
            status=constants.ACTIVE, compute_flavor=self.FAKE_DEVICE_PAIR,
            vrrp_priority=100, cached_zone=self.FAKE_DEVICE_HOSTNAME_2
        )
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

    def test_get_devices_for_host(self):
        devices = self.amp_repo.get_devices_for_host(self.session, self.FAKE_DEVICE_PAIR)
        self.assertEqual(len(devices), 2)
        self.assertIn(self.FAKE_DEVICE_HOSTNAME_1, devices)
        self.assertIn(self.FAKE_DEVICE_HOSTNAME_2, devices)
