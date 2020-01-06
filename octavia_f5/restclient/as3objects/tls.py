# Copyright 2019 SAP SE
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

from octavia_f5.common import constants
from octavia_f5.restclient.as3classes import TLS_Server


def get_name(listener_id):
    return "{}{}".format(constants.PREFIX_TLS_LISTENER,
                         listener_id.replace('-', '_'))


def get_tls_server(certificate_ids):
    service_args = {
        'certificates': [{'certificate': cert_id} for cert_id in certificate_ids]
    }
    return TLS_Server(**service_args)
