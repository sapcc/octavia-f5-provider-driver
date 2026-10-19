#  Copyright 2026 SAP SE
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
"""VIP port cleanup when the worker reports a load balancer DELETED.

The worker reports DELETED through Octavia's DriverUpdater, which deletes
the VIP port only for vip.octavia_owned=True. A claimed caller port
(octavia-issues#66) has to be handed back instead. The tests go through the
public update_loadbalancer_status(), so they also notice if Octavia stops
calling the overridden hook.
"""

from unittest import mock

from octavia_lib.common import constants as lib_consts

from octavia.common import data_models
from octavia.network import base as network_base
from octavia.tests.unit import base

from octavia_f5.controller.worker import status_manager
from octavia_f5.network.drivers.neutron import neutron_client

LB_ID = 'lb-1'


class TestDriverUpdater(base.TestCase):

    def setUp(self):
        super().setUp()
        # autospec: fails if NeutronClient has no release_vip(vip)
        self.network_driver = mock.create_autospec(
            neutron_client.NeutronClient, instance=True)
        mock.patch('octavia.common.utils.get_network_driver',
                   return_value=self.network_driver).start()
        mock.patch('octavia.db.repositories.Repositories.decrement_quota').start()
        with mock.patch('octavia.db.api.get_session'), \
                mock.patch('octavia.db.repositories.LoadBalancerRepository'):
            self.updater = status_manager.DriverUpdater()
        self.lb_repo = self.updater.loadbalancer_repo
        # read by the quota decrement that follows the VIP cleanup
        self.lb_repo.model_class.__data_model__ = data_models.LoadBalancer

    def deleting_lb(self, octavia_owned):
        vip = data_models.Vip(load_balancer_id=LB_ID, port_id='vip-port-1',
                              network_id='net-1', octavia_owned=octavia_owned)
        lb = data_models.LoadBalancer(
            id=LB_ID, project_id='project-1', vip=vip,
            provisioning_status=lib_consts.PENDING_DELETE)
        self.lb_repo.get.return_value = lb
        return lb

    def report_deleted(self):
        return self.updater.update_loadbalancer_status({
            lib_consts.LOADBALANCERS: [{
                lib_consts.ID: LB_ID,
                lib_consts.PROVISIONING_STATUS: lib_consts.DELETED}]})

    def deleted_written(self):
        return mock.call(mock.ANY, LB_ID,
                         provisioning_status=lib_consts.DELETED) in \
            self.lb_repo.update.call_args_list

    def test_caller_port_is_released(self):
        lb = self.deleting_lb(octavia_owned=False)

        result = self.report_deleted()

        self.assertEqual(lib_consts.DRVR_STATUS_CODE_OK,
                         result[lib_consts.STATUS_CODE])
        self.network_driver.release_vip.assert_called_once_with(lb.vip)
        self.assertIs(lb, lb.vip.load_balancer)
        self.network_driver.deallocate_vip.assert_not_called()
        self.assertTrue(self.deleted_written())

    def test_octavia_port_is_deleted(self):
        lb = self.deleting_lb(octavia_owned=True)

        self.report_deleted()

        self.network_driver.deallocate_vip.assert_called_once_with(lb.vip)
        self.network_driver.release_vip.assert_not_called()
        self.assertTrue(self.deleted_written())

    def test_unknown_ownership_is_left_alone(self):
        # octavia_owned NULL (very old rows): same as upstream, port untouched
        self.deleting_lb(octavia_owned=None)

        self.report_deleted()

        self.network_driver.deallocate_vip.assert_not_called()
        self.network_driver.release_vip.assert_not_called()
        self.assertTrue(self.deleted_written())

    def test_failed_release_keeps_lb_pending_delete(self):
        # Same as a failed deallocate_vip(): DELETED is not written, the LB
        # stays PENDING_DELETE and pending_sync deletes it again later.
        self.deleting_lb(octavia_owned=False)
        self.network_driver.release_vip.side_effect = \
            network_base.DeallocateVIPException('neutron down')

        result = self.report_deleted()

        self.assertEqual(lib_consts.DRVR_STATUS_CODE_FAILED,
                         result[lib_consts.STATUS_CODE])
        self.assertFalse(self.deleted_written())

    def test_worker_status_manager_uses_it(self):
        with mock.patch('octavia.db.api.get_session'):
            manager = status_manager.StatusManager()
        self.assertIsInstance(manager._octavia_driver_updater,
                              status_manager.DriverUpdater)
