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
    FAKE_DEVICE_AMPHORA_ID_1a = uuidutils.generate_uuid()
    FAKE_DEVICE_AMPHORA_ID_1b = uuidutils.generate_uuid()
    FAKE_DEVICE_AMPHORA_ID_2 = uuidutils.generate_uuid()
    FAKE_DEVICE_HOSTNAME_1a = "fake.device.pair.hostname1a"
    FAKE_DEVICE_HOSTNAME_1b = "fake.device.pair.hostname1b"
    FAKE_DEVICE_HOSTNAME_2 = "fake.device.pair.hostname2"
    FAKE_DEVICE_PAIR_1 = "fake.device.pair1"
    FAKE_DEVICE_PAIR_2 = "fake.device.pair2"

    def setUp(self):
        super(TestAmphoraRepository, self).setUp()
        self.amp_repo = repos.AmphoraRepository()

        # two device amphoras belonging to the same pair
        def add_device_amphora(**overwrite_kwargs):
            kwargs = {'id': uuidutils.generate_uuid(), 'role': constants.ROLE_MASTER, 'vrrp_interface': None,
                      'status': constants.ACTIVE, 'compute_flavor': 'compute_flavor_' + uuidutils.generate_uuid(),
                      'vrrp_priority': 1, 'cached_zone': 'cached_zone_' + uuidutils.generate_uuid()}
            kwargs.update(overwrite_kwargs)
            return self.amp_repo.create(self.session, **kwargs)
        self.device_amphora_1a = add_device_amphora(
            id=self.FAKE_DEVICE_AMPHORA_ID_1a, compute_flavor=self.FAKE_DEVICE_PAIR_1,
            cached_zone=self.FAKE_DEVICE_HOSTNAME_1a)
        self.device_amphora_1b = add_device_amphora(
            id=self.FAKE_DEVICE_AMPHORA_ID_1b, compute_flavor=self.FAKE_DEVICE_PAIR_1, vrrp_priority=100,
            cached_zone=self.FAKE_DEVICE_HOSTNAME_1b)
        self.device_amphora_2 = add_device_amphora(
            id=self.FAKE_DEVICE_AMPHORA_ID_2, compute_flavor=self.FAKE_DEVICE_PAIR_2,
            cached_zone=self.FAKE_DEVICE_HOSTNAME_2)
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

    def test_get_devices(self):
        devices = self.amp_repo.get_devices(self.session)
        for hostname in [self.FAKE_DEVICE_HOSTNAME_1a, self.FAKE_DEVICE_HOSTNAME_1b, self.FAKE_DEVICE_HOSTNAME_2]:
            self.assertIn(hostname, devices, message='Device {} not found in device list from pair: {}'
                          .format(hostname, devices))
        self.assertEqual(len(devices), 3, message='Not the right amount of devices: {}'.format(len(devices)))

    def test_get_devices_for_host(self):
        devices = self.amp_repo.get_devices(self.session, host=self.FAKE_DEVICE_PAIR_1)
        for hostname in [self.FAKE_DEVICE_HOSTNAME_1a, self.FAKE_DEVICE_HOSTNAME_1b]:
            self.assertIn(hostname, devices, message='Device {} not found in device list from pair: {}'
                          .format(hostname, devices))
        self.assertEqual(len(devices), 2, message='Not the right amount of devices: {}'.format(len(devices)))
