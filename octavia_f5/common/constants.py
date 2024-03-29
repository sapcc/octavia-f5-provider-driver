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

PROJECT_ID = 'project_id'

BIGIP = 'bigip'
PREFIX_PROJECT = 'project_'
PREFIX_LISTENER = 'listener_'
PREFIX_TLS_LISTENER = 'tls_listener_'
PREFIX_TLS_POOL = 'tls_pool_'
PREFIX_CONTAINER = 'container_'
PREFIX_CERTIFICATE = 'cert_'
PREFIX_CIPHER_RULE = 'cipher_rule_'
PREFIX_CIPHER_GROUP = 'cipher_group_'
PREFIX_POOL = 'pool_'
PREFIX_HEALTH_MONITOR = 'hm_'
PREFIX_LOADBALANCER = 'lb_'
PREFIX_POLICY = 'l7policy_'
PREFIX_WRAPPER_POLICY = 'wrapper_policy_'
PREFIX_NETWORK_LEGACY = 'net-'
PREFIX_NETWORK = 'net_'
PREFIX_SUBNET = 'sub_'
PREFIX_IRULE = 'irule_'
PREFIX_MEMBER = 'member_'
PREFIX_SECRET = 'secret_'
SUFFIX_ALLOWED_CIDRS = '_allowed_cidrs'

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

# special listener tags
LISTENER_TAG_NO_SNAT = 'ccloud_special_l4_deactivate_snat'

ROLE_MASTER = 'MASTER'
ROLE_BACKUP = 'BACKUP'

SEGMENT = 'segment'
VIF_TYPE = 'f5'
ESD = 'esd'
PROFILE_L4 = 'basic'
DEVICE_OWNER_NETWORK_PREFIX = "network:"
DEVICE_OWNER_LISTENER = DEVICE_OWNER_NETWORK_PREFIX + 'f5listener'
DEVICE_OWNER_SELFIP = DEVICE_OWNER_NETWORK_PREFIX + 'f5selfip'
DEVICE_OWNER_LEGACY = DEVICE_OWNER_NETWORK_PREFIX + 'f5lbaasv2'
DEFAULT_PHYSICAL_INTERFACE = 'portchannel1'

OPEN = 'OPEN'
FULL = 'FULL'
UP = 'UP'
DOWN = 'DOWN'
DRAIN = 'DRAIN'
NO_CHECK = 'no check'
MAINT = 'MAINT'

F5_NETWORK_AGENT_TYPE = 'F5 Agent'

HEALTH_MONITOR_DELAY_MAX = 3600

# The list of required ciphers for HTTP2
CIPHERS_HTTP2 = ['ECDHE-RSA-AES128-GCM-SHA256']
