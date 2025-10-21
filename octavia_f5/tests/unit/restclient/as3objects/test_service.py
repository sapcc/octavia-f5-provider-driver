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
from octavia_f5.common import config  # pylint: disable=unused-import # noqa
from octavia_f5.restclient.as3objects import service

CONF = None


class TestService(base.TestCase):
    def setUp(self):
        self.conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.conf.config(group='f5_agent',
                         tcp_service_type='Service_L4')
        super().setUp()

    @mock.patch("octavia_f5.utils.esd_repo.EsdRepository")
    @mock.patch("octavia_f5.utils.cert_manager.CertManagerWrapper")
    def test_get_service_l4(self, cert_manager, esd_repo):
        mock_listener = mock.Mock(spec=models.Listener)
        mock_listener.id = "test_listener_id"
        mock_listener.default_pool_id = "test_default_pool_id"
        mock_listener.load_balancer.vip.ip_address = '4.4.4.4'
        mock_listener.name = "test_listener"
        # 0.0.0.0/0 means no filtration, so declaration will not contain any iRules
        mock_listener.allowed_cidrs = [mock.Mock(cidr='0.0.0.0/0')]
        mock_listener.connection_limit = 0
        mock_listener.protocol = "TCP"
        mock_listener.protocol_port = 80
        mock_listener.l7policies = []
        mock_listener.tags = ["test_l4_tag"]

        test_profile_name = "test_f5_fastl4_profile"
        esd_repo.get_esd.return_value = {
            "lbaas_fastl4": test_profile_name,
        }

        svc = service.get_service(mock_listener, cert_manager, esd_repo, ())
        self.assertEqual(1, len(svc))
        svc_name, svc_as3 = svc[0]
        self.assertEqual(f"listener_{mock_listener.id}", svc_name)
        self.assertEqual("Service_L4", getattr(svc_as3, "class"))
        self.assertEqual(f"/Common/{test_profile_name}", svc_as3.profileL4.bigip)

    @mock.patch("octavia_f5.utils.esd_repo.EsdRepository")
    @mock.patch("octavia_f5.utils.cert_manager.CertManagerWrapper")
    def test_get_service_l4_with_acess_filtering_tcp(self, cert_manager, esd_repo):
        mock_listener = mock.Mock(spec=models.Listener)
        mock_listener.id = "test_listener_id"
        mock_listener.default_pool_id = "test_default_pool_id"
        mock_listener.load_balancer.vip.ip_address = '4.4.4.4'
        mock_listener.name = "test_listener"
        mock_listener.allowed_cidrs = [mock.Mock(cidr='8.8.8.8/32'), mock.Mock(cidr='1.1.1.1/32')]
        mock_listener.connection_limit = 0
        mock_listener.protocol = "TCP"
        mock_listener.protocol_port = 80
        mock_listener.l7policies = []
        mock_listener.tags = ["test_l4_tag"]

        declarations = service.get_service(
            mock_listener, cert_manager, esd_repo,
            # first rule will be used second ignored because TCP port different
            [{'protocol': 'TCP', 'ports': (80, 80), 'prefixes': ['2.2.2.2/32']},
             {'protocol': 'TCP', 'ports': (8080, 8080), 'prefixes': ['0.0.0.0/0']}])
        self.assertEqual(2, len(declarations))
        for declaration in declarations:
            name, as3 = declaration
            if '_access_filtering' in name:
                # check Data_Group declaration
                self.assertEqual(f"listener_{mock_listener.id}_access_filtering", name)
                self.assertEqual("Data_Group", getattr(as3, "class"))
                self.assertEqual([{'key': '2.2.2.2/32', 'value': 'sg'},
                                  {'key': '8.8.8.8/32', 'value': 'ac'},
                                  {'key': '1.1.1.1/32', 'value': 'ac'}],
                                 as3.records)
            else:
                # check listerner service declaration
                self.assertEqual(f"listener_{mock_listener.id}", name)
                self.assertEqual("Service_TCP", getattr(as3, "class"))
                self.assertEqual(1, len(as3.iRules))
                self.assertEqual("/Common/sci_access_filtering", as3.iRules[0].bigip)

    @mock.patch("octavia_f5.utils.esd_repo.EsdRepository")
    @mock.patch("octavia_f5.utils.cert_manager.CertManagerWrapper")
    def test_get_service_l4_with_acess_filtering_udp(self, cert_manager, esd_repo):
        mock_listener = mock.Mock(spec=models.Listener)
        mock_listener.id = "test_listener_id"
        mock_listener.default_pool_id = "test_default_pool_id"
        mock_listener.load_balancer.vip.ip_address = '4.4.4.4'
        mock_listener.name = "test_listener"
        mock_listener.allowed_cidrs = [mock.Mock(cidr='8.8.8.8/32'), mock.Mock(cidr='1.1.1.1/32')]
        mock_listener.connection_limit = 0
        mock_listener.protocol = "UDP"
        mock_listener.protocol_port = 53
        mock_listener.l7policies = []
        mock_listener.tags = ["test_l4_tag"]

        declarations = service.get_service(
            mock_listener, cert_manager, esd_repo,
            # first rule will be used second ignored because TCP port different
            [{'protocol': 'UDP', 'ports': (50, 60), 'prefixes': ['2001:db8::1/128']},
             {'protocol': 'TCP', 'ports': (8080, 8080), 'prefixes': ['0.0.0.0/0']}])
        self.assertEqual(2, len(declarations))
        for declaration in declarations:
            name, as3 = declaration
            if '_access_filtering' in name:
                # check Data_Group declaration
                self.assertEqual(f"listener_{mock_listener.id}_access_filtering", name)
                self.assertEqual("Data_Group", getattr(as3, "class"))
                self.assertEqual([{'key': '8.8.8.8/32', 'value': 'ac'},
                                  {'key': '1.1.1.1/32', 'value': 'ac'},
                                  {'key': '2001:db8::1/128', 'value': 'sg'}],
                                 as3.records)
            else:
                # check listerner service declaration
                self.assertEqual(f"listener_{mock_listener.id}", name)
                self.assertEqual("Service_UDP", getattr(as3, "class"))
                self.assertEqual(1, len(as3.iRules))
                self.assertEqual("/Common/sci_access_filtering", as3.iRules[0].bigip)

    @mock.patch("octavia_f5.utils.esd_repo.EsdRepository")
    @mock.patch("octavia_f5.utils.cert_manager.CertManagerWrapper")
    def test_get_service_l4_with_acess_filtering_and_zero_cidrs(self, cert_manager, esd_repo):
        mock_listener = mock.Mock(spec=models.Listener)
        mock_listener.id = "test_listener_id"
        mock_listener.default_pool_id = "test_default_pool_id"
        mock_listener.load_balancer.vip.ip_address = '4.4.4.4'
        mock_listener.name = "test_listener"
        mock_listener.allowed_cidrs = [mock.Mock(cidr='8.8.8.8/32'), mock.Mock(cidr='1.1.1.1/32')]
        mock_listener.connection_limit = 0
        mock_listener.protocol = "TCP"
        mock_listener.protocol_port = 80
        mock_listener.l7policies = []
        mock_listener.tags = ["test_l4_tag"]

        declarations = service.get_service(
            mock_listener, cert_manager, esd_repo,
            # IPv6 rule will be ignored because the are ::/0
            [{'protocol': 'TCP', 'ports': (80, 80),
              'prefixes': ['2001:db8::1/128', '::/128', '::/0']}]
        )
        self.assertEqual(2, len(declarations))
        for declaration in declarations:
            name, as3 = declaration
            if '_access_filtering' in name:
                # check Data_Group declaration
                self.assertEqual(f"listener_{mock_listener.id}_access_filtering", name)
                self.assertEqual("Data_Group", getattr(as3, "class"))
                self.assertEqual([{'key': '8.8.8.8/32', 'value': 'ac'},
                                  {'key': '1.1.1.1/32', 'value': 'ac'}],
                                 as3.records)
            else:
                # check listerner service declaration
                self.assertEqual(f"listener_{mock_listener.id}", name)
                self.assertEqual("Service_TCP", getattr(as3, "class"))
                self.assertEqual(1, len(as3.iRules))
                self.assertEqual("/Common/sci_access_filtering", as3.iRules[0].bigip)

        declarations = service.get_service(
            mock_listener, cert_manager, esd_repo,
            # IPv6 rule will be ignored because the are 0.0.0.0/0
            [{'protocol': 'TCP', 'ports': (80, 80),
              'prefixes': ['3.3.3.0/24', '0.0.0.0/0']}]
        )
        # All filtering will be ignored
        self.assertEqual(1, len(declarations))
