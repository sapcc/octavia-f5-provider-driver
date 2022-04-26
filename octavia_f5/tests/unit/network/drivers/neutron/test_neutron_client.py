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

import copy

import futurist
from neutronclient.common import exceptions as neutron_client_exceptions
from octavia_lib.common import constants as lib_consts
from oslo_utils import uuidutils

from octavia.common import clients, data_models
from octavia.network import base as network_base
from octavia.network import data_models as network_models
from octavia.network.drivers.neutron import allowed_address_pairs
from octavia.network.drivers.neutron import base as neutron_base
from octavia.tests.common import constants as t_constants
from octavia.tests.common import data_model_helpers as dmh
from octavia.tests.unit import base
from octavia_f5.common import constants as f5_constants
from octavia_f5.network.drivers.neutron import neutron_client as neutron_driver

MOCK_CANDIDATE = 'mock_candidate'
MOCK_HOSTNAME = 'mock_hostname'
MOCK_SUBNET_ID = 'e99b5451-aa70-4a71-878e-fc841adadfc9'
MOCK_SELFIP_IPADDRESS = '1.2.3.4'
MOCK_NEUTRON_SELFIP_PORTS = {'ports': [{
    'id': 'mock-selfip-id-1',
    'name': f"local-{MOCK_HOSTNAME}-{MOCK_SUBNET_ID}",
    'network_id': t_constants.MOCK_NETWORK_ID,
    'fixed_ips': [{
        'ip_address': MOCK_SELFIP_IPADDRESS,
        'subnet_id': MOCK_SUBNET_ID}]
}]}
EXP_MOCK_SELFIP_PORT = {'port': {
    'name': f'local-{MOCK_HOSTNAME}-{MOCK_SUBNET_ID}',
    'device_id': MOCK_SUBNET_ID,
    'device_owner': f5_constants.DEVICE_OWNER_SELFIP,
    'admin_state_up': True,
    'network_id': t_constants.MOCK_NETWORK_ID,
    'binding:host_id': MOCK_CANDIDATE,
    'tenant_id': 'test-project',
    'description': MOCK_HOSTNAME,
    'fixed_ips': [{'subnet_id': MOCK_SUBNET_ID}]
}}
MOCK_NEUTRON_PORT = copy.deepcopy(t_constants.MOCK_NEUTRON_PORT)
MOCK_NEUTRON_PORT['port']['fixed_ips'][0]['subnet_id'] = MOCK_SUBNET_ID
EXP_MOCK_NEUTRON_PORT = {'port': {
    'name': 'loadbalancer-1',
    'device_id': '1',
    'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
    'admin_state_up': True,
    'network_id': t_constants.MOCK_NETWORK_ID,
    'binding:host_id': MOCK_CANDIDATE,
    'project_id': 'test-project',
    'fixed_ips': [{'subnet_id': MOCK_SUBNET_ID}]
}}


class TestNeutronClient(base.TestCase):

    def setUp(self):
        super(TestNeutronClient, self).setUp()
        with mock.patch('octavia.common.clients.neutron_client.Client',
                        autospec=True) as neutron_client:
            with mock.patch('stevedore.driver.DriverManager.driver',
                            autospec=True):
                client = neutron_client(clients.NEUTRON_VERSION)
                client.list_extensions.return_value = {
                    'extensions': [
                        {'alias': allowed_address_pairs.AAP_EXT_ALIAS},
                        {'alias': neutron_base.SEC_GRP_EXT_ALIAS}
                    ]
                }
                self.k_session = mock.patch(
                    'keystoneauth1.session.Session').start()
                self._get_f5_hostnames = mock.patch(
                    'octavia_f5.network.drivers.neutron.neutron_client.'
                    'NeutronClient._get_f5_hostnames',
                    return_value=[MOCK_HOSTNAME]).start()
                self.driver = neutron_driver.NeutronClient()
                self.driver.executor = futurist.ThreadPoolExecutor(max_workers=4)

    @mock.patch('octavia_f5.db.repositories.LoadBalancerRepository.'
                'get_all_by_network',
                return_value=[])
    def test_deallocate_vip(self, mock_get_all_by_network):
        lb = dmh.generate_load_balancer_tree()
        lb.vip.load_balancer = lb
        vip = lb.vip
        show_port = self.driver.neutron_client.show_port
        show_port.return_value = {'port': {
            'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
            'binding:host_id': MOCK_CANDIDATE
        }}
        delete_port = self.driver.neutron_client.delete_port
        self.driver.deallocate_vip(vip)
        delete_port.assert_called_once_with(vip.port_id)

    @mock.patch('octavia_f5.db.repositories.LoadBalancerRepository.'
                'get_all_by_network',
                return_value=[])
    def test_deallocate_vip_no_port(self, mock_get_all_by_network):
        lb = dmh.generate_load_balancer_tree()
        lb.vip.load_balancer = lb
        vip = lb.vip
        show_port = self.driver.neutron_client.show_port
        port = {'port': {
            'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
            'binding:host_id': MOCK_CANDIDATE
        }}
        show_port.side_effect = [port, Exception]
        self.driver.deallocate_vip(vip)
        self.driver.neutron_client.update_port.assert_not_called()

    @mock.patch('octavia_f5.db.repositories.LoadBalancerRepository.'
                'get_all_by_network',
                return_value=[])
    def test_deallocate_vip_when_delete_port_fails(
            self, mock_get_all_by_network):
        lb = dmh.generate_load_balancer_tree()
        vip = data_models.Vip(port_id='1')
        vip.load_balancer = lb
        show_port = self.driver.neutron_client.show_port
        show_port.return_value = {'port': {
            'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
            'binding:host_id': MOCK_CANDIDATE
        }}
        delete_port = self.driver.neutron_client.delete_port
        delete_port.side_effect = TypeError
        self.assertRaises(network_base.DeallocateVIPException,
                          self.driver.deallocate_vip, vip)

    @mock.patch('octavia_f5.db.repositories.LoadBalancerRepository.'
                'get_all_by_network',
                return_value=[])
    def test_deallocate_vip_when_port_not_owned_by_octavia(
            self, mock_get_all_by_network):
        lb = dmh.generate_load_balancer_tree()
        lb.vip.load_balancer = lb
        vip = lb.vip
        show_port = self.driver.neutron_client.show_port
        show_port.return_value = {'port': {
            'id': vip.port_id,
            'device_owner': 'neutron:LOADBALANCERV2'}}
        delete_port = self.driver.neutron_client.delete_port
        self.driver.deallocate_vip(vip)
        delete_port.assert_not_called()

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_with_selfips(self, mock_get_candidates):
        update_port = self.driver.neutron_client.update_port
        create_port = self.driver.neutron_client.create_port
        show_subnet = self.driver.neutron_client.show_subnet

        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port.return_value = port_create_dict
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        vip = self.driver.allocate_vip(fake_lb)
        create_port.assert_has_calls([mock.call(EXP_MOCK_NEUTRON_PORT),
                                      mock.call(EXP_MOCK_SELFIP_PORT)],
                                     any_order=True)
        self.assertIsInstance(vip, data_models.Vip)
        self.assertEqual(t_constants.MOCK_IP_ADDRESS, vip.ip_address)
        self.assertEqual(MOCK_SUBNET_ID, vip.subnet_id)
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(fake_lb.id, vip.load_balancer_id)
        update_port.assert_called_once_with(
            'mock-port-1', {'port': {'allowed_address_pairs': [
                {'ip_address': t_constants.MOCK_IP_ADDRESS}]}})

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_with_existing_selfips(self, mock_get_candidates):
        show_subnet = self.driver.neutron_client.show_subnet
        create_port = self.driver.neutron_client.create_port
        list_ports = self.driver.neutron_client.list_ports
        update_port = self.driver.neutron_client.update_port

        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port.return_value = port_create_dict
        list_ports_dict = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        list_ports.return_value = list_ports_dict
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        self.driver.allocate_vip(fake_lb)
        create_port.assert_called_once_with(EXP_MOCK_NEUTRON_PORT)
        update_port.assert_called_once_with(
            'mock-port-1', {'port': {'allowed_address_pairs': [
                {'ip_address': MOCK_SELFIP_IPADDRESS}]}})

    @mock.patch('octavia.network.drivers.neutron.base.BaseNeutronDriver.'
                'get_port', side_effect=Exception('boom'))
    def test_allocate_vip_unkown_exception(self, mock_get_port):
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID,
                                      port_id=t_constants.MOCK_PORT_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        self.assertRaises(network_base.AllocateVIPException,
                          self.driver.allocate_vip, fake_lb)

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_revert(self, mock_get_candidates):
        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port = self.driver.neutron_client.create_port
        create_port.side_effect = [port_create_dict, Exception('foo')]
        show_subnet = self.driver.neutron_client.show_subnet
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        self.assertRaises(network_base.AllocateVIPException,
                          self.driver.allocate_vip, fake_lb)
        create_port.assert_has_calls([mock.call(EXP_MOCK_NEUTRON_PORT),
                                      mock.call(EXP_MOCK_SELFIP_PORT)],
                                     any_order=True)
        self.driver.neutron_client.delete_port.assert_called_once_with(
            MOCK_NEUTRON_PORT['port']['id']
        )

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_revert_selfips(self, mock_get_candidates):
        def create_port_side_effect(port):
            if port['port']['device_owner'] == f5_constants.DEVICE_OWNER_SELFIP:
                if port['port']['description'] == MOCK_HOSTNAME:
                    selfip_create_dict = copy.deepcopy(port)
                    selfip_create_dict['port']['id'] = 'self-ip-id-1'
                    return selfip_create_dict
                if port['port']['description'] == 'boom_host':
                    raise neutron_client_exceptions.NeutronClientException('boom')
            else:
                vip_create_dict = copy.deepcopy(port)
                vip_create_dict['port']['id'] = 'vip-ip-id'
                return vip_create_dict

        create_port = self.driver.neutron_client.create_port
        create_port.side_effect = create_port_side_effect
        delete_port = self.driver.neutron_client.delete_port
        show_subnet = self.driver.neutron_client.show_subnet
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        with mock.patch('octavia_f5.network.drivers.neutron.neutron_client.'
                        'NeutronClient._get_f5_hostnames',
                        return_value=[MOCK_HOSTNAME, 'boom_host']):
            self.assertRaises(network_base.AllocateVIPException,
                              self.driver.allocate_vip, fake_lb)
        create_port.assert_has_calls([mock.call(EXP_MOCK_NEUTRON_PORT),
                                      mock.call(EXP_MOCK_SELFIP_PORT)],
                                     any_order=True)
        delete_port.assert_has_calls([mock.call('vip-ip-id'),
                                      mock.call('self-ip-id-1')],
                                     any_order=True)


    def test_allocate_vip_when_port_already_provided(self):
        show_port = self.driver.neutron_client.show_port
        show_port.return_value = MOCK_NEUTRON_PORT
        fake_lb_vip = data_models.Vip(
            port_id=t_constants.MOCK_PORT_ID,
            subnet_id=MOCK_SUBNET_ID,
            network_id=t_constants.MOCK_NETWORK_ID,
            ip_address=t_constants.MOCK_IP_ADDRESS)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip)
        vip = self.driver.allocate_vip(fake_lb)
        self.assertIsInstance(vip, data_models.Vip)
        self.assertEqual(t_constants.MOCK_IP_ADDRESS, vip.ip_address)
        self.assertEqual(MOCK_SUBNET_ID, vip.subnet_id)
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(fake_lb.id, vip.load_balancer_id)

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_with_port_mismatch(self, mock_get_candidates):
        bad_existing_port = mock.MagicMock()
        bad_existing_port.port_id = uuidutils.generate_uuid()
        bad_existing_port.network_id = uuidutils.generate_uuid()
        bad_existing_port.subnet_id = uuidutils.generate_uuid()
        show_port = self.driver.neutron_client.show_port
        show_port.return_value = bad_existing_port
        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port = self.driver.neutron_client.create_port
        create_port.return_value = port_create_dict
        show_subnet = self.driver.neutron_client.show_subnet
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        list_ports = self.driver.neutron_client.list_ports
        list_ports.return_value = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID,
                                      port_id=t_constants.MOCK_PORT_ID,
                                      octavia_owned=True)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        vip = self.driver.allocate_vip(fake_lb)
        exp_create_port_call = {
            'port': {
                'name': 'loadbalancer-1',
                'network_id': t_constants.MOCK_NETWORK_ID,
                'device_id': '1',
                'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
                'admin_state_up': True,
                'binding:host_id': MOCK_CANDIDATE,
                'project_id': 'test-project',
                'fixed_ips': [{'subnet_id': MOCK_SUBNET_ID}]
            }
        }
        self.driver.neutron_client.delete_port.assert_called_once_with(
            t_constants.MOCK_PORT_ID)
        create_port.assert_called_once_with(exp_create_port_call)
        self.assertIsInstance(vip, data_models.Vip)
        self.assertEqual(t_constants.MOCK_IP_ADDRESS, vip.ip_address)
        self.assertEqual(MOCK_SUBNET_ID, vip.subnet_id)
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(fake_lb.id, vip.load_balancer_id)

    @mock.patch('octavia.network.drivers.neutron.base.BaseNeutronDriver.'
                'get_port', side_effect=network_base.PortNotFound)
    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_when_port_not_found(self, mock_get_candidates,
                                              mock_get_port):
        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port = self.driver.neutron_client.create_port
        create_port.return_value = port_create_dict
        show_subnet = self.driver.neutron_client.show_subnet
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        list_ports = self.driver.neutron_client.list_ports
        list_ports_dict = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        list_ports.return_value = list_ports_dict
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID,
                                      port_id=t_constants.MOCK_PORT_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        vip = self.driver.allocate_vip(fake_lb)
        exp_create_port_call = {
            'port': {
                'name': 'loadbalancer-1',
                'network_id': t_constants.MOCK_NETWORK_ID,
                'device_id': '1',
                'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
                'admin_state_up': True,
                'binding:host_id': MOCK_CANDIDATE,
                'project_id': 'test-project',
                'fixed_ips': [{'subnet_id': MOCK_SUBNET_ID}]
            }
        }
        create_port.assert_called_once_with(exp_create_port_call)
        self.assertIsInstance(vip, data_models.Vip)
        self.assertEqual(t_constants.MOCK_IP_ADDRESS, vip.ip_address)
        self.assertEqual(MOCK_SUBNET_ID, vip.subnet_id)
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(fake_lb.id, vip.load_balancer_id)

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_when_port_creation_fails(self, mock_get_candidates):
        fake_lb_vip = data_models.Vip(
            network_id=t_constants.MOCK_NETWORK_ID,
            subnet_id=MOCK_SUBNET_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip)
        create_port = self.driver.neutron_client.create_port
        create_port.side_effect = Exception
        self.assertRaises(network_base.AllocateVIPException,
                          self.driver.allocate_vip, fake_lb)

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_when_no_port_provided(self, mock_get_candidates):
        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port = self.driver.neutron_client.create_port
        create_port.return_value = port_create_dict
        show_subnet = self.driver.neutron_client.show_subnet
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        list_ports_dict = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        list_ports = self.driver.neutron_client.list_ports
        list_ports.return_value = list_ports_dict
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        vip = self.driver.allocate_vip(fake_lb)
        exp_create_port_call = {
            'port': {
                'name': 'loadbalancer-1',
                'network_id': t_constants.MOCK_NETWORK_ID,
                'device_id': '1',
                'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
                'admin_state_up': True,
                'binding:host_id': MOCK_CANDIDATE,
                'project_id': 'test-project',
                'fixed_ips': [{'subnet_id': MOCK_SUBNET_ID}]
            }
        }
        create_port.assert_called_once_with(exp_create_port_call)
        self.assertIsInstance(vip, data_models.Vip)
        self.assertEqual(t_constants.MOCK_IP_ADDRESS, vip.ip_address)
        self.assertEqual(MOCK_SUBNET_ID, vip.subnet_id)
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(fake_lb.id, vip.load_balancer_id)

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_when_no_port_fixed_ip(self, mock_get_candidates):
        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port = self.driver.neutron_client.create_port
        create_port.return_value = port_create_dict
        show_subnet = self.driver.neutron_client.show_subnet
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        list_ports = self.driver.neutron_client.list_ports
        list_ports_dict = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        list_ports.return_value = list_ports_dict
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID,
                                      ip_address=t_constants.MOCK_IP_ADDRESS)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        vip = self.driver.allocate_vip(fake_lb)
        exp_create_port_call = {
            'port': {
                'name': 'loadbalancer-1',
                'network_id': t_constants.MOCK_NETWORK_ID,
                'device_id': '1',
                'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
                'admin_state_up': True,
                'binding:host_id': MOCK_CANDIDATE,
                'project_id': 'test-project',
                'fixed_ips': [{'subnet_id': MOCK_SUBNET_ID,
                               'ip_address': t_constants.MOCK_IP_ADDRESS}]
            }
        }
        create_port.assert_called_once_with(exp_create_port_call)
        self.assertIsInstance(vip, data_models.Vip)
        self.assertEqual(t_constants.MOCK_IP_ADDRESS, vip.ip_address)
        self.assertEqual(MOCK_SUBNET_ID, vip.subnet_id)
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(fake_lb.id, vip.load_balancer_id)

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_when_no_port_no_fixed_ip(self, mock_get_candidates):
        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port = self.driver.neutron_client.create_port
        create_port.return_value = port_create_dict
        show_subnet = self.driver.neutron_client.show_subnet
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        list_ports = self.driver.neutron_client.list_ports
        list_ports_dict = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        list_ports.return_value = list_ports_dict
        fake_lb_vip = data_models.Vip(network_id=t_constants.MOCK_NETWORK_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id='test-project')
        vip = self.driver.allocate_vip(fake_lb)
        exp_create_port_call = {
            'port': {
                'name': 'loadbalancer-1',
                'network_id': t_constants.MOCK_NETWORK_ID,
                'device_id': '1',
                'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
                'admin_state_up': True,
                'binding:host_id': MOCK_CANDIDATE,
                'project_id': 'test-project'}
        }
        create_port.assert_called_once_with(exp_create_port_call)
        self.assertIsInstance(vip, data_models.Vip)
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(fake_lb.id, vip.load_balancer_id)

    @mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
                return_value=[MOCK_CANDIDATE])
    def test_allocate_vip_when_no_port_provided_tenant(self, mock_get_candidates):
        port_create_dict = copy.deepcopy(MOCK_NEUTRON_PORT)
        create_port = self.driver.neutron_client.create_port
        create_port.return_value = port_create_dict
        show_subnet = self.driver.neutron_client.show_subnet
        show_subnet.return_value = {'subnet': {
            'id': MOCK_SUBNET_ID,
            'network_id': t_constants.MOCK_NETWORK_ID
        }}
        list_ports = self.driver.neutron_client.list_ports
        list_ports_dict = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        list_ports.return_value = list_ports_dict
        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        fake_lb = data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                           project_id=t_constants.MOCK_PROJECT_ID)
        vip = self.driver.allocate_vip(fake_lb)
        exp_create_port_call = {
            'port': {
                'name': 'loadbalancer-1',
                'network_id': t_constants.MOCK_NETWORK_ID,
                'device_id': '1',
                'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
                'admin_state_up': True,
                'project_id': t_constants.MOCK_PROJECT_ID,
                'binding:host_id': MOCK_CANDIDATE,
                'fixed_ips': [{'subnet_id': MOCK_SUBNET_ID}]
            }
        }
        create_port.assert_called_once_with(exp_create_port_call)
        self.assertIsInstance(vip, data_models.Vip)
        self.assertEqual(t_constants.MOCK_IP_ADDRESS, vip.ip_address)
        self.assertEqual(MOCK_SUBNET_ID, vip.subnet_id)
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(fake_lb.id, vip.load_balancer_id)

    def test_ensure_selfips_create(self):
        list_ports = self.driver.neutron_client.list_ports
        list_ports.return_value = {'ports': []}
        create_port = self.driver.neutron_client.create_port

        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        lbs = [data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                        project_id='test-project')]
        existing_selfips, new_selfips = self.driver.ensure_selfips(lbs, MOCK_CANDIDATE)
        exp_create_port_call = {
            'port': {
                'tenant_id': 'test-project',
                'name': f"local-{MOCK_HOSTNAME}-{MOCK_SUBNET_ID}",
                'network_id': t_constants.MOCK_NETWORK_ID,
                'device_owner': f5_constants.DEVICE_OWNER_SELFIP,
                'device_id': MOCK_SUBNET_ID,
                'description': MOCK_HOSTNAME,
                'admin_state_up': True,
                'binding:host_id': MOCK_CANDIDATE,
                'fixed_ips': [{'subnet_id': MOCK_SUBNET_ID}]
            }
        }
        create_port.assert_called_once_with(exp_create_port_call)
        self.assertEqual(len(new_selfips), 1)
        self.assertEqual(len(existing_selfips), 0)
        self.assertIsInstance(new_selfips[0], network_models.Port)

    def test_ensure_selfips_noop(self):
        list_ports = self.driver.neutron_client.list_ports
        list_ports_dict = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        list_ports.return_value = list_ports_dict
        create_port = self.driver.neutron_client.create_port

        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        lbs = [data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                        project_id='test-project')]
        selfips, new_selfips = self.driver.ensure_selfips(lbs, MOCK_CANDIDATE)

        create_port.assert_not_called()
        self.assertEqual(len(selfips), 1)
        self.assertEqual(len(new_selfips), 0)
        self.assertIsInstance(selfips[0], network_models.Port)

    def test_ensure_selfips_delete_duplicate(self):
        selfip_ports = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        # append a duplicate port
        selfip_ports['ports'].append({
            'id': 'mock-selfip-id-2',
            'name': f"local-{MOCK_HOSTNAME}-{MOCK_SUBNET_ID}",
            'network_id': t_constants.MOCK_NETWORK_ID,
            'fixed_ips': [{
                'ip_address': MOCK_SELFIP_IPADDRESS,
                'subnet_id': MOCK_SUBNET_ID}]
        })
        list_ports = self.driver.neutron_client.list_ports
        list_ports.return_value = selfip_ports
        delete_port = self.driver.neutron_client.delete_port
        create_port = self.driver.neutron_client.create_port

        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        lbs = [data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                        project_id='test-project')]
        selfips, _ = self.driver.ensure_selfips(lbs, MOCK_CANDIDATE, True)
        delete_port.assert_called_once_with('mock-selfip-id-2')
        create_port.assert_not_called()
        self.assertEqual(len(selfips), 1)
        self.assertIsInstance(selfips[0], network_models.Port)

    def test_ensure_selfips_delete(self):
        selfip_ports = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        # append a unexpected port
        unexpected_subnet_id = uuidutils.generate_uuid()
        selfip_ports['ports'].append({
            'id': 'mock-selfip-id-2',
            'name': f"local-{MOCK_HOSTNAME}-{unexpected_subnet_id}",
            'network_id': t_constants.MOCK_NETWORK_ID,
            'fixed_ips': [{'subnet_id': unexpected_subnet_id}]
        })
        list_ports = self.driver.neutron_client.list_ports
        list_ports.return_value = selfip_ports
        delete_port = self.driver.neutron_client.delete_port
        create_port = self.driver.neutron_client.create_port

        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        lbs = [data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                        project_id='test-project')]

        # check if deletes unexpected subnet selfip
        selfips, _ = self.driver.ensure_selfips(lbs, MOCK_CANDIDATE, True)
        delete_port.assert_called_once_with('mock-selfip-id-2')
        create_port.assert_not_called()
        self.assertEqual(len(selfips), 1)
        self.assertIsInstance(selfips[0], network_models.Port)

    def test_ensure_selfips_no_network(self):
        create_port = self.driver.neutron_client.create_port
        create_port.side_effect = [neutron_client_exceptions.NetworkNotFoundClient()]
        delete_port = self.driver.neutron_client.delete_port

        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        lbs = [data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                        project_id='test-project')]

        _, selfips = self.driver.ensure_selfips(lbs, MOCK_CANDIDATE, True)
        delete_port.assert_not_called()
        self.assertEqual(len(selfips), 0)

    def test_ensure_selfips_delete_orphaned(self):
        selfip_ports = copy.deepcopy(MOCK_NEUTRON_SELFIP_PORTS)
        list_ports = self.driver.neutron_client.list_ports
        list_ports.return_value = selfip_ports
        delete_port = self.driver.neutron_client.delete_port
        create_port = self.driver.neutron_client.create_port

        fake_lb_vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                                      network_id=t_constants.MOCK_NETWORK_ID)
        lbs = [data_models.LoadBalancer(id='1', vip=fake_lb_vip,
                                        project_id='test-project',
                                        provisioning_status=lib_consts.PENDING_DELETE)]

        # check if deletes unexpected subnet selfip
        _, selfips = self.driver.ensure_selfips(lbs, MOCK_CANDIDATE, True)
        delete_port.assert_called_once_with(MOCK_NEUTRON_SELFIP_PORTS['ports'][0]['id'])
        create_port.assert_not_called()
        self.assertEqual(len(selfips), 0)
