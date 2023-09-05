# Copyright 2023 SAP SE
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

from unittest import mock

from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from octavia.db import models
from octavia.tests.unit import base
from octavia_f5.common import config  # noqa
from octavia_f5.restclient.as3objects import service

CONF = None


class TestService(base.TestCase):
    def setUp(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(group='f5_agent',
                         tcp_service_type='Service_L4')
        super(TestService, self).setUp()


    @mock.patch("octavia_f5.utils.esd_repo.EsdRepository")
    @mock.patch("octavia_f5.utils.cert_manager.CertManagerWrapper")
    def test_get_service_l4(self, cert_manager, esd_repo):
        mock_listener = mock.Mock(spec=models.Listener)
        mock_listener.id = "test_listener_id"
        mock_listener.name = "test_listener"
        mock_listener.allowed_cidrs = []
        mock_listener.connection_limit = 0
        mock_listener.protocol = "TCP"
        mock_listener.l7policies = []
        mock_listener.tags = ["test_l4_tag"]

        test_profile_name = "test_f5_fastl4_profile"
        esd_repo.get_esd.return_value = {
            "lbaas_fastl4" : test_profile_name,
        }

        svc = service.get_service(mock_listener, cert_manager, esd_repo)
        self.assertEqual(1, len(svc))
        svc_name, svc_as3 = svc[0]
        self.assertEqual(f"listener_{mock_listener.id}", svc_name)
        self.assertEqual("Service_L4", getattr(svc_as3, "class"))
        self.assertEqual(f"/Common/{test_profile_name}", svc_as3.profileL4.bigip)
