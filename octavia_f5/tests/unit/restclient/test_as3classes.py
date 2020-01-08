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


class TestAS3Classes(base.TestCase):
    def test_as3(self):
        # erroneous creation
        self.assertRaises(as3exceptions.TypeNotSupportedException,
                          as3classes.AS3, None, {'action': 'NONEXISTENT'})

        # creation with default arguments
        as3 = {'action': 'deploy', 'class': 'AS3', 'persist': True}
        self.assertEqual(as3, as3classes.AS3().to_dict())

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

        # retrieving a tenant
        tenant_name = 'test_tenant2'
        adc[tenant_name] = {'class': 'Tenant'}
        tenannt_obj = adc_obj.get_or_create_tenant(tenant_name)
        self.assertIsInstance(tenannt_obj, as3classes.Tenant)
        self.assertEqual(adc, adc_obj.to_dict())

        adc = {'class': 'ADC', 'id': 123, 'updateMode': 'selective',
                  'schemaVersion': '3.0.0', 'my-tenant': {'class': 'Tenant'},
                  'label': 'test'}
        adc_obj = as3classes.ADC(label='test', id=123)
        adc_obj.set_tenant('my-tenant', as3classes.Tenant())
        self.assertEqual(adc, adc_obj.to_dict())

    def test_tenant(self):
        tenant = {'class': 'Tenant'}
        self.assertEqual(tenant, as3classes.Tenant().__dict__)

    def test_tenant_attributes(self):
        result = {'updateMode': 'selective', 'class': 'ADC',
                  'schemaVersion': '3.0.0', 'id': 123,
                  'my-tenant': {'class': 'Tenant'},
                  'label': 'test'}

        adc = as3classes.ADC(label='test', id=123)
        adc.set_tenant('my-tenant', as3classes.Tenant())
        self.assertEqual(result, adc.to_dict())