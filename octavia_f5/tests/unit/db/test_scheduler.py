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

from unittest import mock

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils
from oslo_db.sqlalchemy import session as db_session

from octavia.db import repositories as repo
from octavia.tests.functional.db import base
from octavia_f5.common import config, constants  # noqa
from octavia_f5.controller.worker import controller_worker
from octavia_f5.db import scheduler

CONF = cfg.CONF


class TestScheduler(base.OctaviaDBTestBase):
    FAKE_AZ = "fake-az"
    FAKE_LB_ID = uuidutils.generate_uuid()
    FAKE_PROJ_ID = uuidutils.generate_uuid()
    FAKE_DEVICE_AMPHORA_ID_1 = uuidutils.generate_uuid()
    FAKE_DEVICE_AMPHORA_ID_2 = uuidutils.generate_uuid()
    FAKE_DEVICE_PAIR_1 = "fake.device.pair1"
    FAKE_DEVICE_PAIR_2 = "fake.device.pair2"

    def setUp(self):
        super(TestScheduler, self).setUp()
        self.repos = repo.Repositories()
        self.device_amphora_1 = self.repos.amphora.create(
            self.session, id=self.FAKE_DEVICE_AMPHORA_ID_1,
            role=constants.ROLE_MASTER, vrrp_interface=None,
            status=constants.ACTIVE, compute_flavor=self.FAKE_DEVICE_PAIR_1,
            vrrp_priority=1
        )
        self.device_amphora_2 = self.repos.amphora.create(
            self.session, id=self.FAKE_DEVICE_AMPHORA_ID_2,
            role=constants.ROLE_MASTER, vrrp_interface=None,
            status=constants.ACTIVE, compute_flavor=self.FAKE_DEVICE_PAIR_2,
            vrrp_priority=100
        )
        self.scheduler = scheduler.Scheduler()
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))

    def test_get_candidate_without_lbs(self):
        self.conf.config(group="networking", agent_scheduler="loadbalancer")

        candidates = self.scheduler.get_candidates(self.session)
        self.assertEqual(
            candidates, [self.FAKE_DEVICE_PAIR_1, self.FAKE_DEVICE_PAIR_2],
            "Active device pairs without lbs not considered as candidates")

    def test_get_candidate_with_lbs(self):
        self.conf.config(group="networking", agent_scheduler="loadbalancer")
        lb = self._create_lb(self.FAKE_LB_ID, self.FAKE_DEVICE_PAIR_1)

        candidates = self.scheduler.get_candidates(self.session)
        self.assertEqual(
            candidates, [self.FAKE_DEVICE_PAIR_2, self.FAKE_DEVICE_PAIR_1],
            "Order of device pairs not consistent")
        self.repos.load_balancer.delete(self.session, id=lb.id)

    def test_get_candidate_by_listener(self):
        self.conf.config(group="networking", agent_scheduler="listener")

        candidates = self.scheduler.get_candidates(self.session)
        self.assertEqual(
            candidates, [self.FAKE_DEVICE_PAIR_1, self.FAKE_DEVICE_PAIR_2],
            "Order of device pairs not consistent")

        old_prio = self.device_amphora_1.vrrp_priority
        self.repos.amphora.update(self.session, self.device_amphora_1.id,
                                  vrrp_priority=1000)
        candidates = self.scheduler.get_candidates(self.session)
        self.assertEqual(
            candidates, [self.FAKE_DEVICE_PAIR_2, self.FAKE_DEVICE_PAIR_1],
            "Order of device pairs not consistent")
        self.repos.amphora.update(self.session, self.device_amphora_1.id,
                                  vrrp_priority=old_prio)

    @mock.patch('octavia_f5.controller.worker.status_manager.StatusManager')
    @mock.patch('octavia_f5.controller.worker.sync_manager.SyncManager')
    def test_get_candidate_by_az(self, mock_sync_manager, mock_status_manager):
        self.conf.config(group="networking", agent_scheduler="loadbalancer")
        self.conf.config(group="f5_agent", prometheus=False)

        # Register host FAKE_DEVICE_PAIR_1 as fake-az
        cw = controller_worker.ControllerWorker()
        with mock.patch('octavia_f5.db.api.get_session', return_value=self.session):
            self.session.autocommit = False
            self.conf.config(host=self.FAKE_DEVICE_PAIR_1)
            cw.register_in_availability_zone(self.FAKE_AZ)
            self.session.autocommit = True

        candidates = self.scheduler.get_candidates(self.session, az_name=self.FAKE_AZ)
        self.assertEqual([self.FAKE_DEVICE_PAIR_1], candidates,
                         "Candidates should only include AZ device pairs")

        candidates = self.scheduler.get_candidates(self.session)
        self.assertEqual([self.FAKE_DEVICE_PAIR_2], candidates,
                         "Candidates should only include non-AZ device pairs")

    def _create_lb(self, id, host=FAKE_DEVICE_PAIR_1):
        return self.repos.load_balancer.create(
            self.session, id=id, project_id=self.FAKE_PROJ_ID,
            name="lb_name", description="lb_description",
            provisioning_status=constants.ACTIVE,
            operating_status=constants.ONLINE,
            server_group_id=host, enabled=True
        )
