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

from octavia_f5.restclient.as3classes import *
from octavia.tests.unit import base


class TestAS3Classes(base.TestCase):
    def test_as3(self):
        as3 = {'action': 'deploy', 'class': 'AS3', 'persist': True}
        self.assertEqual(as3, AS3().__dict__)

    def test_adc(self):
        self.assertRaises(RequiredKeyMissingException, ADC)
        adc = {'class': 'ADC', 'schemaVersion': '3.0.0',
               'id': 123, 'label': 'test', 'updateMode': 'selective'}
        self.assertEqual(adc, ADC(label='test', id=123).__dict__)

    def test_tenant(self):
        tenant = {'class': 'Tenant'}
        self.assertEqual(tenant, Tenant().__dict__)

    def test_tenant_attributes(self):
        result = {'updateMode': 'selective', 'class': 'ADC',
                  'schemaVersion': '3.0.0', 'id': 123,
                  'my-tenant': {'class': 'Tenant'},
                  'label': 'test'}

        adc = ADC(label='test', id=123)
        adc.setTenant('my-tenant', Tenant())
        self.assertEqual(result, adc.to_dict())

