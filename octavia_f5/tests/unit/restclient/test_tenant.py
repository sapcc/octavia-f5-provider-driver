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

from unittest import mock

from octavia.common import constants
from octavia.db import models
from octavia.tests.unit import base
from octavia_f5.restclient.as3classes import Tenant
from octavia_f5.restclient.as3objects import tenant


test_rules = [
    {
        "direction": "egress",
        "ether_type": "IPv6",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": None,
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": None,
        "security_group_id": "40d4e6bd-b202-4854-ba62-b45c5e7a03d1",
        "id": "00ee79dc-642a-440e-90f3-79293ffceb1e"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": 22,
        "port_range_min": 22,
        "protocol": "tcp",
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": "0.0.0.0/0",
        "security_group_id": "40d4e6bd-b202-4854-ba62-b45c5e7a03d1",
        "id": "4ee185aa-3cc6-4825-986b-6f86952351df"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": "icmp",
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": "0.0.0.0/0",
        "security_group_id": "40d4e6bd-b202-4854-ba62-b45c5e7a03d1",
        "id": "6c58c558-f3b1-4a71-a0d7-e37f5c422c54"
    },
    {
        "direction": "egress",
        "ether_type": "IPv4",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": None,
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": None,
        "security_group_id": "40d4e6bd-b202-4854-ba62-b45c5e7a03d1",
        "id": "dc45cadf-6f9a-45ff-8066-7bce3e1a9c14"
    },
    {
        "direction": "egress",
        "ether_type": "IPv6",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": None,
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": None,
        "security_group_id": "5674bef2-1ad3-4539-abc2-108874b754a6",
        "id": "15e89bab-1b8c-463e-bb0f-f89c2c68f823"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": None,
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": "0.0.0.0/0",
        "security_group_id": "5674bef2-1ad3-4539-abc2-108874b754a6",
        "id": "2c0dfed2-77ad-4e99-ade5-0cb20bdb4a62"
    },
    {
        "direction": "egress",
        "ether_type": "IPv4",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": None,
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": None,
        "security_group_id": "5674bef2-1ad3-4539-abc2-108874b754a6",
        "id": "605ac7d4-e3d9-4969-a69b-7e24e44a7a12"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": 80,
        "port_range_min": 80,
        "protocol": "tcp",
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": "0.0.0.0/0",
        "security_group_id": "5674bef2-1ad3-4539-abc2-108874b754a6",
        "id": "6d78c497-5daa-46ae-80a8-9fd7a48c486a"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": 8080,
        "port_range_min": 8080,
        "protocol": "tcp",
        "remote_group_id": "f6bdedc7-6887-41f1-9869-ef995d8f8c6b",
        "remote_address_group_id": None,
        "remote_ip_prefix": None,
        "security_group_id": "5674bef2-1ad3-4539-abc2-108874b754a6",
        "id": "7b56dfa9-5fda-4550-a8e5-946e1ff439d8"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": 8081,
        "port_range_min": 8081,
        "protocol": "tcp",
        "remote_group_id": None,
        "remote_address_group_id": "d1fe5ca0-b8b3-4353-a45b-3c0d7536c612",
        "remote_ip_prefix": None,
        "security_group_id": "5674bef2-1ad3-4539-abc2-108874b754a6",
        "id": "7c3835fa-5631-47b3-84be-8c122e938938"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": "icmp",
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": "0.0.0.0/0",
        "security_group_id": "5674bef2-1ad3-4539-abc2-108874b754a6",
        "id": "f8f485c4-9de1-4bb3-ba0d-69f428a7aa22"
    },
    {
        "direction": "egress",
        "ether_type": "IPv6",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": None,
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": None,
        "security_group_id": "f6bdedc7-6887-41f1-9869-ef995d8f8c6b",
        "id": "0fc228ef-93b5-4b8c-953c-277ba98123de"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": "udp",
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": "0.0.0.0/0",
        "security_group_id": "f6bdedc7-6887-41f1-9869-ef995d8f8c6b",
        "id": "5ac313ba-5601-41d1-8eef-207df8061820"
    },
    {
        "direction": "egress",
        "ether_type": "IPv4",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": None,
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": None,
        "security_group_id": "f6bdedc7-6887-41f1-9869-ef995d8f8c6b",
        "id": "ac7a9e24-eb10-4801-9152-93f86eae8439"
    },
    {
        "direction": "ingress",
        "ether_type": "IPv4",
        "port_range_max": None,
        "port_range_min": None,
        "protocol": "tcp",
        "remote_group_id": None,
        "remote_address_group_id": None,
        "remote_ip_prefix": "0.0.0.0/0",
        "security_group_id": "f6bdedc7-6887-41f1-9869-ef995d8f8c6b",
        "id": "ca71365a-94b9-49ff-a649-f3ed23337bbf"
    }
]
test_address_groups = [
    {
        "id": "d1fe5ca0-b8b3-4353-a45b-3c0d7536c612",
        "name": "cc-demo-address-group",
        "addresses": [
            '0.0.0.0/24',
            '1.1.1.1/32',
            '1.2.3.4/32',
            '2.3.4.5/32',
            '2001:db8::1/128',
            '::/128',
            '::/64',
            '::64/128'
        ],
        "description": "",
    }
]
test_result_rules = [
    {'protocol': 'TCP', 'ports': (80, 80), 'prefixes': ['0.0.0.0/0']},
    {'protocol': 'TCP', 'ports': (8080, 8080), 'prefixes': ['0.0.0.0/0']},
    {'protocol': 'TCP', 'ports': (8081, 8081),
     'prefixes': ['0.0.0.0/24', '1.1.1.1/32', '1.2.3.4/32', '2.3.4.5/32',
                  '2001:db8::1/128', '::/128', '::/64', '::64/128']},
    {'protocol': 'TCP', 'ports': (22, 22), 'prefixes': ['0.0.0.0/0']}
]


def mock_security_group_rules(security_group_id):
    rules = []
    for r in test_rules:
        if r.get('security_group_id') == security_group_id:
            rules.append(r)
    return rules


def mock_get_address_group(address_group):  # pylint: disable=inconsistent-return-statements
    for ag in test_address_groups:
        if ag.get('id') == address_group:
            return ag


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
        skip_ip = '2.3.4.5'

        as3 = tenant.get_tenant(
            segmentation_id=1234,
            loadbalancers=[mock_lb],
            self_ips=[skip_ip],
            status_manager=mock_status_manager,
            cert_manager=None,
            network_manager=None,
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

    def test__get_sg_rules_for_lb(self):
        network_manager = mock.MagicMock()
        proxy = mock.MagicMock()
        proxy.security_group_rules.side_effect = mock_security_group_rules
        proxy.get_address_group.side_effect = mock_get_address_group
        network_manager.network_proxy = proxy
        test_rules = ['5674bef2-1ad3-4539-abc2-108874b754a6',
                      '40d4e6bd-b202-4854-ba62-b45c5e7a03d1']
        rules = tenant._get_sg_rules_for_lb(network_manager, test_rules)
        self.assertEqual(test_result_rules, rules)
