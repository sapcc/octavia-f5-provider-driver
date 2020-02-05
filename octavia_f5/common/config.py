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
import sys

from oslo_config import cfg
from oslo_log import log as logging
from octavia_f5.common import constants

from octavia_lib.i18n import _

LOG = logging.getLogger(__name__)


def init(args, **kwargs):
    cfg.CONF(args=args, project='octavia_f5',
             **kwargs)

def setup_logging(conf):
    """Sets up the logging options for a log with supplied name.

    :param conf: a cfg.ConfOpts object
    """
    product_name = "octavia_f5"
    logging.setup(conf, product_name)
    LOG.info("Logging enabled!")
    LOG.debug("command line: %s", " ".join(sys.argv))


f5_agent_opts = [
    cfg.BoolOpt('bigip_token', default=True,
                help=_('Use token authentication.')),
    cfg.BoolOpt('bigip_verify', default=False,
                help=_('Verify AS3 endpoint TLS cert.')),
    cfg.StrOpt('bigip_url',
               help=_('The URL to the bigip host device with AS3 endpoint')),
    cfg.StrOpt('esd_dir',
               help=_('Directory of the esd files')),

    cfg.StrOpt('tcp_service_type', default=constants.SERVICE_TCP,
               choices=[constants.SERVICE_L4,
                        constants.SERVICE_TCP],
               help=_("Service type used for TCP listener")),
    cfg.StrOpt('profile_l4', default=None,
               help=_("Path to default l4 acceleration profile"
                      "(e.g. /Common/custom_fastl4)")),
    cfg.StrOpt('profile_multiplex', default=None,
               help=_("Path to default multiplex (oneconnect) acceleration"
                      " profile (e.g. /Common/custom_oneconnect)")),
    cfg.StrOpt('healthmonitor_receive', default='"HTTP/1.(0|1) 200',
               help=_("Default HTTP health monitor receive string")),
    cfg.StrOpt('sync_to_group', default='',
               help=_("Name (like /Common/my_dg) of the config-sync "
                      "group TO which the system should synchronize the "
                      "targetHost configuration after (and only if) "
                      "this request deploys any changes."
                      "When empty (default) this request will not affect "
                      "config-sync at all.")),
    cfg.BoolOpt('prometheus', default=True,
                help=_("Enable prometheus metrics exporter")),
    cfg.PortOpt('prometheus_port', default=8000,
                help=_('Port for prometheus to expose, defaults to 8000.')),

]

f5_networking_opts = [
]

# Register the configuration options
cfg.CONF.register_opts(f5_agent_opts, group='f5_agent')
cfg.CONF.register_opts(f5_networking_opts, group='networking')
