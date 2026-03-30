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
from octavia_f5.restclient import as3logging


class TestAS3Logging(base.TestCase):

    def test_as3logging_truncates_secret(self):
        privkey = '-----BEGIN RSA PRIVATE KEY-----\nprivate key data that should be stripped\n-----END RSA PRIVATE KEY-----'
        as3_decl = {
            'other_key': 'should_not_be_modified',
            'net_test_net': {
                'other_key': 'should_not_be_modified',
                'lb_test_lb': {
                    'other_key': 'should_not_be_modified',
                    'cert_test_cert': {
                        'name': 'my-cert',
                        'privateKey': privkey,
                        'certificate': '-----BEGIN CERTIFICATE-----\ncert data\n-----END CERTIFICATE-----'
                    }
                }
            }
        }

        # backup declaration, then truncating it
        as3_decl_backup = as3_decl.copy()
        as3logging.truncate_as3_secrets(as3_decl)

        # verify that the private key was truncated
        truncated_key = as3_decl['net_test_net']['lb_test_lb']['cert_test_cert']['privateKey']
        expected_truncated = privkey.split('\n')[0] + '\n(...)'
        self.assertEqual(truncated_key, expected_truncated)

        # verify that other certificate fields were not modified
        # by setting the private key to the same value and comparing
        override = {'net_test_net': {'lb_test_lb': {'cert_test_cert': {'privateKey': None}}}}
        as3_decl_backup_no_key = as3_decl_backup | override
        as3_decl_no_key = as3_decl | override
        self.assertEqual(as3_decl_backup_no_key, as3_decl_no_key)
