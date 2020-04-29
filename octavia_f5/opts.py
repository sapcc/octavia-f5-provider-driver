# Copyright 2018, 2020 SAP SE
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

import octavia_f5.common.config


def list_opts():
    return [
        ('f5_agent', octavia_f5.common.config.f5_agent_opts),
        ('f5_tls_server', octavia_f5.common.config.f5_tls_server_opts),
        ('f5_tls_client', octavia_f5.common.config.f5_tls_client_opts),
    ]
