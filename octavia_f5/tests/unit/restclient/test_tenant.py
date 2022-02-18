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

import mock

from octavia.common import constants
from octavia.db import models
from octavia.tests.unit import base
from octavia_f5.restclient.as3classes import Tenant
from octavia_f5.restclient.as3objects import tenant


class TestGetTenant(base.TestCase):

    def test_get_tenant_with_skip_ips(self):
        mock_status_manager = mock.MagicMock()

        mock_members = [
            models.Member(id='test_id_1', ip_address='1.2.3.4', weight=1, protocol_port=1234),
            models.Member(id='test_id_2', ip_address='2.3.4.5', weight=1, protocol_port=2345),
            models.Member(id='test_id_3', ip_address='3.4.5.6', weight=1, protocol_port=3456)]

        mock_lb = models.LoadBalancer(
            id='test_lb_id',
            vip=models.Vip(ip_address='1.2.3.4'),
            listeners=[],
            pools=[
                models.Pool(
                    id='test_pool_id',
                    name='test_pool',
                    lb_algorithm=constants.LB_ALGORITHM_ROUND_ROBIN,
                    members=mock_members
                )],
        )
        skip_member = '2.3.4.5'

        as3 = tenant.get_tenant(
            segmentation_id=1234,
            loadbalancers=[mock_lb],
            skip_members=[skip_member],
            status_manager=mock_status_manager,
            cert_manager=None,
            esd_repo=None)

        self.assertIsInstance(as3, Tenant)
        members = as3.lb_test_lb_id.pool_test_pool_id.members
        self.assertEqual(1, len(members))
        self.assertEqual(['3.4.5.6'], members[0].serverAddresses)
        self.assertEqual(3456, members[0].servicePort)
        self.assertEqual('test_id_3', members[0].remark)
        mock_status_manager.set_error.assert_has_calls([
            mock.call(mock_members[0]),
            mock.call(mock_members[1]),
        ])
