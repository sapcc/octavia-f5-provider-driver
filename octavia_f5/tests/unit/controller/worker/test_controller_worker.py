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

import json
from unittest import mock

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_utils import uuidutils

from octavia.tests.unit import base
from octavia_f5.controller.worker import controller_worker

CONF = cfg.CONF

LB_ID = uuidutils.generate_uuid()
NETWORK_ID = uuidutils.generate_uuid()
_status_manager = mock.MagicMock()
_vip_mock = mock.MagicMock()
_vip_mock.network_id = NETWORK_ID
_listener_mock = mock.MagicMock()
_load_balancer_mock = mock.MagicMock()
_load_balancer_mock.id = LB_ID
_load_balancer_mock.listeners = [_listener_mock]
_load_balancer_mock.vip = _vip_mock
_load_balancer_mock.flavor_id = None
_load_balancer_mock.availability_zone = None
_selfip = mock.MagicMock()
_db_session = mock.MagicMock()
_network_driver = mock.MagicMock()
_loadbalancer_repo = mock.MagicMock()
_vip_repo = mock.MagicMock()


@mock.patch('octavia_f5.controller.worker.status_manager.StatusManager')
@mock.patch('octavia_f5.controller.worker.sync_manager.SyncManager')
@mock.patch('octavia_f5.db.api.session', return_value=_db_session)
class TestControllerWorker(base.TestCase):
    def setUp(self):
        super().setUp()
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group="f5_agent", prometheus=False)
        conf.config(group="controller_worker", network_driver='network_noop_driver_f5')
        # prevent ControllerWorker() from spawning threads
        conf.config(group="f5_agent", sync_immediately=False)

    # pylint: disable=too-many-positional-arguments
    @mock.patch('octavia.db.repositories.AvailabilityZoneRepository')
    @mock.patch('octavia.db.repositories.AvailabilityZoneProfileRepository')
    def test_register_in_availability_zone(self,
                                           mock_azp_repo,
                                           mock_az_repo,
                                           mock_api_session,
                                           mock_sync_manager,
                                           mock_status_manager):
        az = 'fake_az'
        fake_azp_id = uuidutils.generate_uuid()
        cw = controller_worker.ControllerWorker()

        begin_session = mock_api_session().begin().__enter__()  # pylint: disable=unnecessary-dunder-call

        # existing empty az
        mock_az_repo_instance = mock_az_repo.return_value
        mock_az_repo_instance.get.return_value.availability_zone_profile_id = fake_azp_id
        mock_az_repo_instance.get_availability_zone_metadata_dict.return_value = {'hosts': []}

        cw.register_in_availability_zone(az)

        mock_az_repo_instance.get.assert_called_once_with(begin_session, name=az)
        mock_az_repo_instance.get_availability_zone_metadata_dict.assert_called_once_with(begin_session, az)
        mock_azp_repo.return_value.update.assert_called_once_with(
            begin_session, id=fake_azp_id, availability_zone_data=json.dumps({'hosts': [CONF.host]}))

        # non-existing az
        mock_az_repo_instance.get.return_value = None
        cw.register_in_availability_zone(az)
        mock_az_repo.return_value.create.assert_called_once()
        mock_azp_repo.return_value.create.assert_called_once()

    @mock.patch('octavia.db.repositories.LoadBalancerRepository.get',
                return_value=_load_balancer_mock)
    @mock.patch('octavia_f5.db.repositories.LoadBalancerRepository.get_all_by_network',
                return_value=[_load_balancer_mock])
    @mock.patch("octavia_f5.network.drivers.noop_driver_f5.driver.NoopNetworkDriverF5"
                ".ensure_selfips",
                return_value=([_selfip], []))
    @mock.patch("octavia_f5.network.drivers.noop_driver_f5.driver.NoopNetworkDriverF5"
                ".cleanup_selfips")
    def test_remove_loadbalancer_last(self,
                                      mock_cleanup_selfips,
                                      mock_ensure_selfips,
                                      mock_lb_repo_get_all_by_network,
                                      mock_lb_repo_get,
                                      mock_api_session,
                                      mock_sync_manager,
                                      mock_status_manager):
        cw = controller_worker.ControllerWorker()
        cw.remove_loadbalancer(LB_ID)

        begin_session = mock_api_session().begin().__enter__()  # pylint: disable=unnecessary-dunder-call

        mock_lb_repo_get_all_by_network.assert_called_once_with(begin_session, network_id=NETWORK_ID, show_deleted=False)
        mock_lb_repo_get.assert_called_once_with(begin_session, id=LB_ID)
        mock_ensure_selfips.assert_called_with([_load_balancer_mock], CONF.host, cleanup_orphans=False)
        mock_cleanup_selfips.assert_called_with([_selfip])


@mock.patch('octavia_f5.utils.driver_utils.get_network_driver', return_value=_network_driver)
@mock.patch('octavia_f5.db.repositories.LoadBalancerRepository', return_value=_loadbalancer_repo)
@mock.patch('octavia.db.repositories.VipRepository', return_value=_vip_repo)
@mock.patch('octavia.common.rpc.get_client')
@mock.patch('octavia_f5.db.api.session', return_value=_db_session)
class TestControllerWorkerNotifications(base.TestCase):

    def setUp(self):
        super().setUp()
        _network_driver.reset_mock()
        _loadbalancer_repo.reset_mock()
        _vip_repo.reset_mock()

    def test__get_server(self, mock_api_session, mock_rpc_client, *args):
        mock_lb = mock.MagicMock()
        mock_lb.server_group_id = 'test-server'
        cwn = controller_worker.ControllerWorkerNotifications()
        self.assertEqual('test-server', cwn._get_server(mock_lb))
        mock_lb.server_group_id = None
        _network_driver.get_scheduled_host.return_value = 'test-host'
        self.assertEqual('test-host', cwn._get_server(mock_lb))

    def test__get_all_sgs(self, mock_api_session, mock_rpc_client, *args):
        _network_driver.network_proxy.security_group_rules.side_effect = [
            [{'remote_group_id': 'second-sg-id'}, {}, {}],
            [{}, {}, {'remote_group_id': 'third-sg-id'}],
            [{}, {}]
        ]
        cwn = controller_worker.ControllerWorkerNotifications()
        sgs = cwn._get_all_sgs('first-sg-id')
        self.assertEqual(['first-sg-id', 'second-sg-id', 'third-sg-id'], sgs)
        self.assertEqual(3, _network_driver.network_proxy.security_group_rules.call_count)
        _network_driver.network_proxy.security_group_rules.assert_has_calls([
            mock.call(security_group_id='first-sg-id'),
            mock.call(security_group_id='second-sg-id'),
            mock.call(security_group_id='third-sg-id')
        ])

    @mock.patch.object(controller_worker.ControllerWorkerNotifications, '_get_server')
    @mock.patch.object(controller_worker.ControllerWorkerNotifications, '_get_all_sgs')
    def test_process_security_group_update_notification_sg_deleted(
            self, mock_get_all_sgs, mock_get_server, mock_api_session,
            mock_rpc_client, *args):
        lb_1 = mock.MagicMock()
        lb_1.id = 'lb-1-uuid'
        lb_1.vip.sg_ids = ['test-sg-id', 'first-sg-id', 'second-sg-id']
        lb_2 = mock.MagicMock()
        lb_2.id = 'lb-2-uuid'
        lb_2.vip.sg_ids = ['test-sg-id', 'third-sg-id']
        _loadbalancer_repo.get_all_by_security_group.return_value = [lb_1, lb_2]
        mock_get_server.side_effect = ['server-1', 'server-2']
        begin_session = mock_api_session().begin().__enter__()  # pylint: disable=unnecessary-dunder-call

        cwn = controller_worker.ControllerWorkerNotifications()
        cwn.process_security_group_update_notification('test-sg-id', 'deleted')

        _loadbalancer_repo.get_all_by_security_group.assert_called_once_with(
            begin_session, security_group_id='test-sg-id')
        _vip_repo.update.assert_has_calls([
            mock.call(begin_session, 'lb-1-uuid', sg_ids=['first-sg-id', 'second-sg-id']),
            mock.call(begin_session, 'lb-2-uuid', sg_ids=['third-sg-id'])
        ])
        mock_get_server.assert_has_calls([mock.call(lb_1), mock.call(lb_2)])
        self.assertEqual(0, mock_get_all_sgs.call_count)
        mock_rpc_client.return_value.prepare.assert_has_calls([
            mock.call(server='server-1'),
            mock.call().cast({}, 'update_load_balancer',
                             original_load_balancer={'loadbalancer_id': 'lb-1-uuid'},
                             load_balancer_updates={}),
            mock.call(server='server-2'),
            mock.call().cast({}, 'update_load_balancer',
                             original_load_balancer={'loadbalancer_id': 'lb-2-uuid'},
                             load_balancer_updates={}),
        ])

    # pylint: disable=too-many-positional-arguments
    @mock.patch.object(controller_worker.ControllerWorkerNotifications, '_get_server')
    @mock.patch.object(controller_worker.ControllerWorkerNotifications, '_get_all_sgs')
    @mock.patch('octavia.db.models.VipSecurityGroup', return_value=mock.MagicMock())
    def test_process_security_group_update_notification_sg_updated(
            self, mock_model_vip, mock_get_all_sgs, mock_get_server,
            mock_api_session, mock_rpc_client, *args):
        lb_1 = mock.MagicMock()
        lb_1.id = 'lb-1-uuid'
        lb_1.vip.sg_ids = ['test-sg-id', 'first-sg-id', 'second-sg-id']
        lb_2 = mock.MagicMock()
        lb_2.id = 'lb-2-uuid'
        lb_2.vip.sg_ids = ['test-sg-id', 'third-sg-id']
        _loadbalancer_repo.get_all_by_security_group.return_value = [lb_1, lb_2]
        mock_get_server.side_effect = ['server-1', 'server-2']
        begin_session = mock_api_session().begin().__enter__()  # pylint: disable=unnecessary-dunder-call
        mock_get_all_sgs.side_effect = [
            ['test-sg-id'],
            ['first-sg-id'],
            ['second-sg-id', 'remote-sg-id-1'],
            ['test-sg-id'],
            ['third-sg-id', 'remote-sg-id-2']
        ]
        vip_sg_1 = mock.MagicMock()
        vip_sg_2 = mock.MagicMock()
        mock_model_vip.side_effect = [vip_sg_1, vip_sg_2]

        cwn = controller_worker.ControllerWorkerNotifications()
        cwn.process_security_group_update_notification('test-sg-id', 'updated')

        _loadbalancer_repo.get_all_by_security_group.assert_called_once_with(
            begin_session, security_group_id='test-sg-id')
        self.assertEqual(0, _vip_repo.update.call_count)
        self.assertEqual(5, mock_get_all_sgs.call_count)
        mock_model_vip.assert_has_calls([
            mock.call(load_balancer_id='lb-1-uuid', sg_id='remote-sg-id-1'),
            mock.call(load_balancer_id='lb-2-uuid', sg_id='remote-sg-id-2')
        ])
        begin_session.add.assert_has_calls([
            mock.call(vip_sg_1),
            mock.call(vip_sg_2)
        ])
        mock_get_server.assert_has_calls([mock.call(lb_1), mock.call(lb_2)])
        mock_rpc_client.return_value.prepare.assert_has_calls([
            mock.call(server='server-1'),
            mock.call().cast({}, 'update_load_balancer',
                             original_load_balancer={'loadbalancer_id': 'lb-1-uuid'},
                             load_balancer_updates={}),
            mock.call(server='server-2'),
            mock.call().cast({}, 'update_load_balancer',
                             original_load_balancer={'loadbalancer_id': 'lb-2-uuid'},
                             load_balancer_updates={}),
        ])
