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

from octavia_lib.common.constants import *

PROJECT_ID = 'project_id'

BIGIP = 'bigip'
PREFIX_PROJECT = 'project_'
PREFIX_LISTENER = 'listener_'
PREFIX_TLS_LISTENER = 'tls_listener_'
PREFIX_TLS_POOL = 'tls_pool_'
PREFIX_CONTAINER = 'container_'
PREFIX_CERTIFICATE = 'cert_'
PREFIX_POOL = 'pool_'
PREFIX_HEALTH_MONITOR = 'hm_'
PREFIX_LOADBALANCER = 'lb_'
PREFIX_POLICY = 'l7policy_'
PREFIX_WRAPPER_POLICY = 'wrapper_policy_'
PREFIX_NETWORK = 'net_'
PREFIX_IRULE = 'irule_'
PREFIX_MEMBER = 'member_'
PREFIX_SECRET = 'secret_'

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
SERVICE_TCP_TYPES = (SERVICE_TCP, SERVICE_GENERIC, SERVICE_HTTP, SERVICE_HTTPS)
SERVICE_HTTP_TYPES = (SERVICE_HTTP, SERVICE_HTTPS)

SINGLE_USE_DH = 'singleUseDh'
STAPLER_OCSP = 'staplerOCSP'
TLS_1_0 = 'tls1_0'
TLS_1_1 = 'tls1_1'
TLS_1_2 = 'tls1_2'
TLS_1_3 = 'tls1_3'
TLS_OPTIONS_SERVER = (SINGLE_USE_DH, STAPLER_OCSP, TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3)
TLS_OPTIONS_CLIENT = (SINGLE_USE_DH, TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3)

ROLE_MASTER = 'MASTER'
ROLE_BACKUP = 'BACKUP'

SEGMENT = 'segment'
VIF_TYPE = 'f5'
ESD = 'esd'
RPC_NAMESPACE_CONTROLLER_AGENT = 'f5controller'
DEVICE_OWNER_LISTENER = 'network:' + 'f5listener'
PROFILE_L4 = 'basic'

OPEN = 'OPEN'
FULL = 'FULL'
UP = 'UP'
DOWN = 'DOWN'
DRAIN = 'DRAIN'
NO_CHECK = 'no check'
MAINT = 'MAINT'

F5_NETWORK_AGENT_TYPE = 'F5 Agent'
