# Copyright 2018 SAP SE
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

from octavia.tests.unit import base
from octavia_f5.restclient import as3classes, as3exceptions
from octavia_f5.restclient.as3classes import constants


class TestAS3Classes(base.TestCase):
    def test_as3(self):
        # erroneous creation
        self.assertRaises(as3exceptions.TypeNotSupportedException,
                          as3classes.AS3, None, {'action': 'NONEXISTENT'})

        # creation with default arguments
        as3 = {'action': 'deploy', 'class': 'AS3', 'persist': True}
        self.assertTrue(as3.items() <= as3classes.AS3().to_dict().items())

    def test_adc(self):
        # erroneous creation
        self.assertRaises(as3exceptions.RequiredKeyMissingException, as3classes.ADC)

        # creation
        adc = {'class': 'ADC', 'schemaVersion': '3.0.0',
               'id': 123, 'label': 'test', 'updateMode': 'selective'}
        adc_obj = as3classes.ADC(label='test', id=123)
        self.assertEqual(adc, adc_obj.to_dict())

        # adding a tenant
        tenant_name = 'test_tenant1'
        adc[tenant_name] = {'class': 'Tenant'}
        adc_obj.set_tenant(tenant_name, adc[tenant_name])
        self.assertEqual(adc, adc_obj.to_dict())

        # adding a duplicate tenant => no change
        adc_obj.set_tenant(tenant_name, adc[tenant_name])
        self.assertEqual(adc, adc_obj.to_dict())

        # retrieving a tenant
        tenant_name = 'test_tenant2'
        adc[tenant_name] = {'class': 'Tenant'}
        tenannt_obj = adc_obj.get_or_create_tenant(tenant_name)
        self.assertIsInstance(tenannt_obj, as3classes.Tenant)
        self.assertEqual(adc, adc_obj.to_dict())

    def test_tenant(self):
        # creation
        tenant = {'class': 'Tenant'}
        tenant_obj = as3classes.Tenant()
        self.assertEqual(tenant, tenant_obj.to_dict())

        # adding an application
        app_name = 'test_app'
        app = {app_name: 'app_content'}
        tenant_obj.add_application(app_name, app[app_name])
        self.assertEqual(app[app_name], tenant_obj.to_dict()[app_name])

        # adding a duplicate application => no change
        tenant_obj.add_application(app_name, app[app_name])
        self.assertEqual(app[app_name], tenant_obj.to_dict()[app_name])

    def test_application(self):
        # application templates
        error_msg = 'No supported application templates defined'
        self.assertIsNotNone(constants.SUPPORTED_APPLICATION_TEMPLATES, message=error_msg)
        self.assertIsNot(0, len(constants.SUPPORTED_APPLICATION_TEMPLATES), message=error_msg)

        # erroneous creation
        NON_EXISTENT_APPLICATION_CONSTANT = None
        self.assertRaises(as3exceptions.TypeNotSupportedException,
                          as3classes.Application, NON_EXISTENT_APPLICATION_CONSTANT)

        # creation
        application = {'class': 'Application',
                       'template': 'generic'}
        self.assertEqual(application['template'], constants.APPLICATION_GENERIC)
        self.assertIn(constants.APPLICATION_GENERIC, constants.SUPPORTED_APPLICATION_TEMPLATES)
        application_obj = as3classes.Application(constants.APPLICATION_GENERIC)
        self.assertEqual(application, application_obj.to_dict())

        # set primary service
        service = {'class': 'Service_Generic',
                   'virtualAddresses': None,
                   'virtualPort': None}
        application['serviceMain'] = service
        service_obj = as3classes.Service(constants.SERVICE_GENERIC)
        application_obj.set_service_main(service_obj)
        self.assertIsInstance(application_obj.serviceMain, as3classes.Service)
        self.assertEqual(application, application_obj.to_dict())

        # add endpoint policy
        ep_name = 'test_endpoint_policy'
        ep = {'class': 'Endpoint_Policy',
              'strategy': 'custom'}
        application[ep_name] = ep
        ep_obj = as3classes.Endpoint_Policy('custom')
        application_obj.add_endpoint_policy(ep_name, ep_obj)
        self.assertEqual(application, application_obj.to_dict())

        # add duplicate endpoint policy
        self.assertRaises(as3exceptions.DuplicatedKeyException,
                          application_obj.add_endpoint_policy, ep_name, ep_obj)
        self.assertEqual(application, application_obj.to_dict())

        # add TLS server
        tls_name = 'test_tls_server'
        tls = {'class': 'TLS_Server'}
        application[tls_name] = tls
        tls_obj = as3classes.TLS_Server()
        application_obj.add_tls_server(tls_name, tls_obj)
        self.assertEqual(application, application_obj.to_dict())

        # add duplicate TLS server
        application_obj.add_tls_server(tls_name, tls_obj)
        self.assertEqual(application, application_obj.to_dict())

        # add certificate
        cert_name = 'test_certificate'
        cert = {'class': 'Certificate',
                'certificate': 'certificate-content'}
        application[cert_name] = cert
        cert_obj = as3classes.Certificate(certificate=cert['certificate'])
        application_obj.add_certificate(cert_name, cert_obj)
        self.assertEqual(application, application_obj.to_dict())

        # add duplicate certificate
        application_obj.add_certificate(cert_name, cert_obj)
        self.assertEqual(application, application_obj.to_dict())

    def test_service(self):
        # service templates
        error_msg = 'No supported application templates defined'
        self.assertIsNotNone(constants.SUPPORTED_SERVICES, message=error_msg)
        self.assertIsNot(0, len(constants.SUPPORTED_SERVICES), message=error_msg)

        # erroneous creation
        self.assertRaises(as3exceptions.TypeNotSupportedException,
                          as3classes.Service, 'NONEXISTENT_SERVICETYPE')

        # creation
        service = {'class': 'Service_Generic',
                   'virtualAddresses': None,
                   'virtualPort': None}
        self.assertIn(service['class'], constants.SUPPORTED_SERVICES)
        service_obj = as3classes.Service(service['class'])
        self.assertEqual(service, service_obj.to_dict())

    def test_pool(self):
        # creation
        pool = {'class': 'Pool'}
        pool_obj = as3classes.Pool()
        self.assertEqual(pool, pool_obj.to_dict())

    def test_member(self):
        arg_servicePort = 'test_servicePort'
        arg_serverAddresses = 'test_serverAddresses'
        # erroneous creation
        self.assertRaises(as3exceptions.RequiredKeyMissingException,
                          as3classes.Member)
        self.assertRaises(as3exceptions.RequiredKeyMissingException,
                          as3classes.Member, servicePort=arg_servicePort)
        self.assertRaises(as3exceptions.RequiredKeyMissingException,
                          as3classes.Member, serverAddresses=arg_serverAddresses)

        # creation
        member = {'enable': True,
                  'servicePort': arg_servicePort,
                  'serverAddresses': arg_serverAddresses}
        member_obj = as3classes.Member(servicePort=arg_servicePort,
                                       serverAddresses=arg_serverAddresses)
        self.assertEqual(member, member_obj.to_dict())

    def test_monitor(self):
        monitor = {'class': 'Monitor'}
        monitor_obj = as3classes.Monitor()
        self.assertEqual(monitor, monitor_obj.to_dict())

    def test_bigip(self):
        # creation
        bigip = {'bigip': 'test_bigip'}
        bigip_obj = as3classes.BigIP(bigip['bigip'])
        self.assertEqual(bigip, bigip_obj.to_dict())

    def test_servicegenericprofile_tcp(self):
        sgptcp = {'ingress': 'test_ingress',
                  'egress': 'test_egress'}
        sgptcp_obj = as3classes.Service_Generic_profileTCP(sgptcp['ingress'], sgptcp['egress'])
        self.assertEqual(sgptcp, sgptcp_obj.to_dict())

    def test_irule(self):
        irule = {'class': 'iRule',
                 'iRule': 'test_iRule'}
        irule_obj = as3classes.IRule(irule['iRule'])
        self.assertEqual(irule, irule_obj.to_dict())

    def test_persist(self):
        persist = {'class': 'Persist'}
        persist_obj = as3classes.Persist()
        self.assertEqual(persist, persist_obj.to_dict())

    def test_endpoint_policy(self):
        # erroneous creation
        self.assertRaises(as3exceptions.TypeNotSupportedException,
                          as3classes.Endpoint_Policy, 'NONEXISTENT_POLICYTYPE')

        # creation
        ep = {'class': 'Endpoint_Policy',
              'strategy': 'custom'}
        ep_obj = as3classes.Endpoint_Policy('custom')
        self.assertEqual(ep, ep_obj.to_dict())

    def test_endpoint_policy_rule(self):
        epr = {}
        epr_obj = as3classes.Endpoint_Policy_Rule()
        self.assertEqual(epr, epr_obj.to_dict())

    def test_policy_condition(self):
        # erroneous creation
        self.assertRaises(as3exceptions.TypeNotSupportedException,
                          as3classes.Policy_Condition, 'NONEXISTENT_POLICYTYPE')

        # creation
        pc = {'type': 'httpHeader'}
        pc_obj = as3classes.Policy_Condition(pc['type'])
        self.assertEqual(pc, pc_obj.to_dict())