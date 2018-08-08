# Copyright 2018 SAP SE, F5 Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Routines for configuring Octavia F5 Provider
"""

from octavia.common.config import *
from octavia.i18n import _

LOG = logging.getLogger(__name__)

f5_agent_opts = [
    cfg.StrOpt('network_segment_physical_network',
               help=_("Restrict discovery of network segmentation ID to  "
                      "a specific physical network name. ")),
    cfg.StrOpt('bigip_username', default='admin',
               help=_('The username to use for iControl REST access')),
    cfg.StrOpt('bigip_password', default='admin',
               help=_('The password to use for iControl REST access')),
    cfg.IntOpt('bigip_port', default=443,
               help=_('The port to use for iControl REST access')),
    cfg.BoolOpt('bigip_token', default=False,
                help=_('Use token authentication against iControl REST.')),
    cfg.BoolOpt('bigip_verify', default=False,
                help=_('Verify iControl REST TLS Cert.')),
    cfg.StrOpt('bigip_host', help=_('The Hostname/IP to use for '
                                    'iControl REST access')),
]

# Register the configuration options
cfg.CONF.register_opts(f5_agent_opts, group='f5_agent')
