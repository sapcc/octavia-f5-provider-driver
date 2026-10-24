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

from oslo_utils import uuidutils

from octavia.common import constants
from octavia.db import repositories as repo
from octavia.tests.functional.db import base

from octavia_f5.db import repositories as f5_repo


class TestLoadBalancerRepository(base.OctaviaDBTestBase):

    def _create_lb_with_vip(self, port_id, provisioning_status=constants.ACTIVE):
        repos = repo.Repositories()
        lb_id = uuidutils.generate_uuid()
        repos.load_balancer.create(
            self.session, id=lb_id, project_id='project-1',
            provisioning_status=provisioning_status,
            operating_status=constants.ONLINE, enabled=True)
        repos.vip.create(self.session, load_balancer_id=lb_id, port_id=port_id)
        return lb_id

    def test_get_ids_by_vip_port(self):
        active = self._create_lb_with_vip('port-1')
        deleting = self._create_lb_with_vip('port-1', constants.PENDING_DELETE)
        self._create_lb_with_vip('port-1', constants.DELETED)
        self._create_lb_with_vip('port-2')

        lb_repo = f5_repo.LoadBalancerRepository()
        self.assertCountEqual([active, deleting],
                              lb_repo.get_ids_by_vip_port(self.session, 'port-1'))
        self.assertEqual([], lb_repo.get_ids_by_vip_port(self.session, 'port-3'))
        self.assertEqual([], lb_repo.get_ids_by_vip_port(self.session, None))
