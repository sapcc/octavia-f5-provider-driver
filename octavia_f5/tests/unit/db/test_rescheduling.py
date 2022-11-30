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

from oslo_config import cfg
from oslo_utils import uuidutils

from octavia.common import constants
from octavia.common import exceptions as api_exceptions
from octavia.tests.functional.db import base
from octavia_f5.api.drivers.f5_driver.tasks import reschedule_tasks
from octavia_f5.common import config, constants as f5_const  # noqa
from octavia_f5.db import repositories as repos
from octavia_f5.utils import exceptions

CONF = cfg.CONF


class TestRescheduling(base.OctaviaDBTestBase):
    LB_ID = uuidutils.generate_uuid()
    LB_ID_NONEXISTING = uuidutils.generate_uuid()
    DEVICE_AMPHORA_ID = uuidutils.generate_uuid()
    DEVICE_HOST_LB = 'fake.host.lb'
    DEVICE_HOST_FREE = 'fake.host.free'
    DEVICE_HOST_NONEXISTING = 'fake.host.nonexisting'
    DEVICE_HOSTNAME = "fake.device.pair.hostname"

    def setUp(self):
        super(TestRescheduling, self).setUp()

        self.amp_repo = repos.AmphoraRepository()
        self.lb_repo = repos.LoadBalancerRepository()
        self.sanity_check_task = reschedule_tasks.SanityCheck()

        self.lb = self.lb_repo.create(
            self.session, id=self.LB_ID, provisioning_status=constants.ACTIVE,
            operating_status=constants.ONLINE, enabled=True, server_group_id=self.DEVICE_HOST_LB)
        self.device_amphora = self.amp_repo.create(
            self.session, id=self.DEVICE_AMPHORA_ID, role=constants.ROLE_MASTER, vrrp_interface=None,
            status=constants.ACTIVE, compute_flavor=self.DEVICE_HOST_LB, vrrp_priority=1,
            cached_zone=self.DEVICE_HOSTNAME)

    def test_sanity_check_lb_nonexisting(self):
        self.assertRaises(api_exceptions.NotFound,
                          self.sanity_check_task.execute, self.LB_ID_NONEXISTING, self.DEVICE_HOST_FREE)

    def test_sanity_check_target_host_nonexisting(self):
        self.assertRaises(exceptions.ReschedulingTargetHostException,
                          self.sanity_check_task.execute, self.LB_ID, self.DEVICE_HOST_NONEXISTING)

    def test_sanity_check_target_host_same(self):
        self.assertRaises(exceptions.ReschedulingTargetHostException,
                          self.sanity_check_task.execute, self.LB_ID, self.DEVICE_HOST_LB)
