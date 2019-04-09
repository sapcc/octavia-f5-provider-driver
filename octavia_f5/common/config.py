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
    cfg.BoolOpt('bigip_token', default=True,
                help=_('Use token authentication.')),
    cfg.BoolOpt('bigip_verify', default=False,
                help=_('Verify AS3 endpoint TLS cert.')),
    cfg.StrOpt('bigip_url',
               help=_('The URL to the bigip host device with AS3 endpoint')),
    cfg.StrOpt('esd_dir',
               help=_('Directory of the esd files'))
]

# Register the configuration options
cfg.CONF.register_opts(f5_agent_opts, group='f5_agent')
