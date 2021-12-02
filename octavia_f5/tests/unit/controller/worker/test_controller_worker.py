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

import json
from unittest import mock

from oslo_config import cfg
from oslo_utils import uuidutils

import octavia.tests.unit.base as base
from octavia_f5.controller.worker import controller_worker

CONF = cfg.CONF

_health_mon_mock = mock.MagicMock()
_status_manager = mock.MagicMock()
_vip_mock = mock.MagicMock()
_listener_mock = mock.MagicMock()
_load_balancer_mock = mock.MagicMock()
_load_balancer_mock.listeners = [_listener_mock]
_load_balancer_mock.flavor_id = None
_load_balancer_mock.availability_zone = None
_member_mock = mock.MagicMock()
_pool_mock = mock.MagicMock()
_l7policy_mock = mock.MagicMock()
_l7rule_mock = mock.MagicMock()
_az_mock = mock.MagicMock()
_db_session = mock.MagicMock()


@mock.patch('octavia_f5.controller.worker.status_manager.StatusManager')
@mock.patch('octavia_f5.controller.worker.sync_manager.SyncManager')
@mock.patch('octavia_f5.db.api.get_session', return_value=_db_session)
class TestControllerWorker(base.TestCase):
    @mock.patch('octavia.db.repositories.AvailabilityZoneRepository')
    @mock.patch('octavia.db.repositories.AvailabilityZoneProfileRepository')
    def test_register_in_availability_zone(self,
                                           mock_azp_repo,
                                           mock_az_repo,
                                           mock_api_get_session,
                                           mock_sync_manager,
                                           mock_status_manager):
        az = 'fake_az'
        fake_azp_id = uuidutils.generate_uuid()
        cw = controller_worker.ControllerWorker()

        # existing empty az
        mock_az_repo_instance = mock_az_repo.return_value
        mock_az_repo_instance.get.return_value.availability_zone_profile_id = fake_azp_id
        mock_az_repo_instance.get_availability_zone_metadata_dict.return_value = {'hosts': []}

        cw.register_in_availability_zone(az)

        mock_az_repo_instance.get.assert_called_once_with(_db_session, name=az)
        mock_az_repo_instance.get_availability_zone_metadata_dict.assert_called_once_with(_db_session, az)
        mock_azp_repo.return_value.update.assert_called_once_with(
            _db_session, id=fake_azp_id, availability_zone_data=json.dumps({'hosts': [CONF.host]}))

        # non-existing az
        mock_az_repo_instance.get.return_value = None
        cw.register_in_availability_zone(az)
        mock_az_repo.return_value.create.assert_called_once()
        mock_azp_repo.return_value.create.assert_called_once()
