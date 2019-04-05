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

from octavia.common.constants import *

PROJECT_ID = 'project_id'

BIGIP = 'bigip'
PREFIX_PROJECT = 'project_'
PREFIX_LISTENER = 'listener_'
PREFIX_POOL = 'pool_'
PREFIX_HEALTH_MONITOR = 'hm_'
PREFIX_LOADBALANCER = 'lb_'
PREFIX_POLICY = 'l7policy_'

APPLICATION_TCP = 'tcp'
APPLICATION_UDP = 'udp'
APPLICATION_HTTP = 'http'
APPLICATION_HTTPS = 'https'
APPLICATION_L4 = 'l4'
APPLICATION_GENERIC = 'generic'
APPLICATION_SHARED = 'shared'
SUPPORTED_APPLICATION_TEMPLATES = (APPLICATION_TCP, APPLICATION_UDP,
                                   APPLICATION_HTTP, APPLICATION_HTTPS,
                                   APPLICATION_L4, APPLICATION_GENERIC,
                                   APPLICATION_SHARED)

SERVICE_TCP = 'Service_TCP'
SERVICE_UDP = 'Service_UDP'
SERVICE_HTTP = 'Service_HTTP'
SERVICE_HTTPS = 'Service_HTTPS'
SERVICE_L4 = 'Service_L4'
SERVICE_GENERIC = 'Service_Generic'
SUPPORTED_SERVICES = (SERVICE_TCP, SERVICE_UDP, SERVICE_HTTP,
                      SERVICE_HTTPS, SERVICE_L4, SERVICE_GENERIC)

SEGMENT = 'segment'
VIF_TYPE = 'f5'
