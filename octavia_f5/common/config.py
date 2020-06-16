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
    cfg.ListOpt('bigip_urls',
                item_type=cfg.types.URI(schemes=['http', 'https']),
                help=_('The URL to the bigip host device with AS3 endpoint')),
    cfg.StrOpt('esd_dir',
               help=_('Directory of the esd files')),

    cfg.StrOpt('tcp_service_type', default=constants.SERVICE_TCP,
               choices=[constants.SERVICE_L4,
                        constants.SERVICE_TCP],
               help=_("Service type used for TCP listener")),
    cfg.StrOpt('profile_http', default=None,
               help=_("Path to default HTTP profile"
                      "(e.g. custom_http)")),
    cfg.StrOpt('profile_http_compression', default=None,
               help=_("Path to default http compression profile"
                      " profile (e.g. custom_http_compression)")),
    cfg.StrOpt('profile_l4', default=None,
               help=_("Path to default L4 acceleration profile"
                      "(e.g. custom_fastl4)")),
    cfg.StrOpt('profile_tcp', default=None,
               help=_("Path to default TCP profile"
                      "(e.g. custom_tcp)")),
    cfg.StrOpt('profile_udp', default=None,
               help=_("Path to default UDP profile"
                      "(e.g. custom_udp)")),
    cfg.StrOpt('profile_multiplex', default=None,
               help=_("Path to default multiplex (oneconnect) acceleration"
                      " profile (e.g. /Common/custom_oneconnect)")),
    cfg.StrOpt('profile_healthmonitor_tls', default=None,
               help=_("Path to default Client TLS profile"
                      "e.g. custom_https")),
    cfg.StrOpt('healthmonitor_receive', default='HTTP/1.(0|1) 200',
               help=_("Default HTTP health monitor receive string")),
    cfg.StrOpt('sync_to_group', default='',
               help=_("Name (like /Common/my_dg) of the config-sync "
                      "group TO which the system should synchronize the "
                      "targetHost configuration after (and only if) "
                      "this request deploys any changes."
                      "When empty (default) this request will not affect "
                      "config-sync at all.")),
    cfg.StrOpt('service_address_icmp_echo', default=None,
               choices=['enable', 'disable', 'selective'],
               help=_("If set, the system answers ICMP echo requests on this "
                      "address always, selective or never.")),
    cfg.BoolOpt('prometheus', default=True,
                help=_("Enable prometheus metrics exporter")),
    cfg.PortOpt('prometheus_port', default=8000,
                help=_('Port for prometheus to expose, defaults to 8000.')),
    cfg.BoolOpt('dry_run', default=False,
                help=_("Run in dry-run, do not realize AS3 definitions.")),
    cfg.BoolOpt('snat_virtual', default=False,
                help=_("Use the virtual-server address as SNAT address.")),
    cfg.BoolOpt('migration', default=False,
                help=_("Enable migration mode (disable syncing active devices)")),
]

f5_tls_shared = {
    cfg.StrOpt('default_ciphers', default=None,
               help=_("Use Cipher String for ciphers used in TLS profiles")),
    cfg.BoolOpt('forward_proxy_bypass', default=None,
                help=_("Enables or disables (default) SSL forward proxy bypass.")),
    cfg.BoolOpt('forward_proxy', default=None,
                help=_("Enables or disables (default) SSL forward proxy.")),
    cfg.BoolOpt('insert_empty_fragments', default=None,
                help=_("Enables a countermeasure against an SSL 3.0/TLS 1.0 protocol "
                       "vulnerability affecting CBC ciphers. These ciphers cannot be "
                       "handled by certain broken SSL implementations.")),
    cfg.BoolOpt('single_use_dh', default=None,
                help=_("Creates a new key when using temporary/ephemeral DH parameters. "
                       "This option must be used to prevent small subgroup attacks, when " 
                       "the DH parameters were not generated using strong primes (for " 
                       "example. when using DSA-parameters). If strong primes were used, " 
                       "it is not strictly necessary to generate a new DH key during each " 
                       "handshake, but F5 Networks recommends it. Enable the Single DH Use " 
                       "option whenever temporary or ephemeral DH parameters are used.")),
    cfg.BoolOpt('tls_1_0', default=None,
                help=_("Allow TLS 1.0 Ciphers.")),
    cfg.BoolOpt('tls_1_1', default=None,
                help=_("Allow TLS 1.1 Ciphers.")),
    cfg.BoolOpt('tls_1_2', default=None,
                help=_("Allow TLS 1.2 Ciphers.")),
    cfg.BoolOpt('tls_1_3', default=None,
                help=_("Allow TLS 1.3 Ciphers. Note: tls_1_1 is only supported in tmos " 
                       "version 14.0+.")),
}

f5_tls_server_opts = {
    cfg.BoolOpt('cache_certificate', default=None,
                help=_("Enables or disables (default) caching certificates by IP address " 
                       "and port number.")),
    cfg.BoolOpt('stapler_ocsp', default=None,
                help=_("Specifies whether to enable OCSP stapling.")),
}
f5_tls_server_opts.update(f5_tls_shared)
f5_tls_client_opts = f5_tls_shared

f5_networking_opts = [
    cfg.BoolOpt('caching', default=True,
                help=_('Enable caching of segmentation ids and ports')),
    cfg.IntOpt('cache_time', default=3600,
               help=_('Caching time in seconds (default=3600)')),
    cfg.StrOpt('f5_network_segment_physical_network', default=None,
               help=_('Restrict discovery of network segmentation ID '
                      'to a specific physical network name, autodiscovery by default.')),
]

f5_status_manager_opts = [
    cfg.IntOpt('health_check_interval',
               default=5,
               help=_('Sleep time between health checks in seconds.')),
    cfg.IntOpt('failover_check_interval',
               default=30,
               help=_('Sleep time between failover checks in seconds.')),
    cfg.IntOpt('cleanup_check_interval',
               default=60*10,
               help=_('Sleep time between cleanup checks in seconds.')),
    cfg.IntOpt('failover_timeout',
               default=5,
               help=_("Time in seconds before a device is marked as offline.")),
]

f5_util_opts = [
    cfg.BoolOpt('all', default=False,
                help='Sync all load balancers'),
    cfg.StrOpt('lb_id',
               help='Load balancer ID to sync'),
    cfg.StrOpt('project_id',
               help='Sync all load balancers owned by this project'),
    cfg.StrOpt('agent_host',
               help='Sync all load balancers hosted on this agent'),
]

# Register the configuration options
cfg.CONF.register_opts(f5_tls_server_opts, group='f5_tls_server')
cfg.CONF.register_opts(f5_tls_client_opts, group='f5_tls_client')
cfg.CONF.register_opts(f5_agent_opts, group='f5_agent')
cfg.CONF.register_opts(f5_networking_opts, group='networking')
cfg.CONF.register_opts(f5_status_manager_opts, group='status_manager')
