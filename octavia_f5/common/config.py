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

import sys
from octavia_lib.i18n import _
from oslo_config import cfg
from oslo_log import log as logging

# pylint: disable=unused-import
from octavia.common import config  # noqa
from octavia_f5.common import constants

LOG = logging.getLogger(__name__)

"""
Routines for configuring Octavia F5 Provider
"""

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
                default=[],
                item_type=cfg.types.URI(schemes=['http', 'https']),
                help=_('The URL to the bigip host device with AS3 endpoint')),
    cfg.StrOpt('as3_endpoint',
               help=_("Use optional AS3 container endpoint for configuring"
                      "BigIPs.")),
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
    cfg.BoolOpt('sync_immediately', default=True,
                help=_("Run sync functions immediately. Can be too noisy when dry-running.")),
    cfg.BoolOpt('snat_virtual', default=False,
                help=_("Use the virtual-server address as SNAT address.")),
    cfg.BoolOpt('migration', default=False,
                help=_("Enable migration mode (disable syncing active devices)")),
    cfg.BoolOpt('async_mode', default=False,
                help=_("Use asynchronous mode for posting as3 declarations.")),
    cfg.IntOpt('persist_every', default=-1,
                help=_("When persist_every >= 0 make the whole working configuration "
                       "persistent on targetHost after (and only if) this request "
                       "deploys any changes and after the value of seconds passed since "
                       "last persist. If persist_every = 0, persist with every delcaration. "
                       "Set persist_every < 0, leave the working "
                       "configuration in memory only (if targetHost restart, you may "
                       "lose the configuration from memory")),
    cfg.BoolOpt('unsafe_mode', default=False,
                help=_("Use unsafe mode for posting AS3 declarations.")),
    cfg.StrOpt('availability_zone', default=None,
                help=_("Name of the availability zone the F5 device of this worker is assigned to.")),
]

f5_tls_shared = {
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
    cfg.IntOpt('max_workers',
               default=10,
               help=_('The maximum number of l2 taskflow workers')),
    cfg.IntOpt("l2_timeout",
               default=60,
               help=_('The timeout value in seconds for l2 task flows')),
    cfg.StrOpt('physical_interface_mapping',
               default=None,
               deprecated_name='f5_network_segment_physical_network',
               help=_('<physical_network>:<physical_interface> tuple '
                      'mapping the used physical network name to the '
                      'BigIP-specific physical network interface to be used '
                      'for flat and VLAN networks. If no physical_interface '
                      'specified, "portchannel1" will be used.')),
    cfg.StrOpt('agent_scheduler', default='loadbalancer',
               choices=['listener', 'loadbalancer'],
               help=_('Select scheduler for new VIPs (and therefore loadbalancers). '
                      'Possible options: "listener": Use agent with lowest amount of listener, '
                      '"loadbalancer": use agent with lowest amount of loadbalancer.')),
    cfg.BoolOpt('hardware_syncookie',
                default=True,
                help=_("Enables hardware syncookie mode on a VLAN. When "
                       "enabled, the hardware per-VLAN SYN cookie protection "
                       "will be triggered when the certain traffic threshold "
                       "is reached on supported platforms.")),
    cfg.IntOpt('syn_flood_rate_limit',
               default=2000,
               help=_("Specifies the max number of SYN flood packets per "
                      "second received on the VLAN before the hardware "
                      "per-VLAN SYN cookie protection is triggered.")),
    cfg.IntOpt('syncache_threshold',
               default=32000,
               help=_("Specifies the number of outstanding SYN packets on "
                      "the VLAN that will trigger the hardware per-VLAN SYN "
                      "cookie protection.")),
    cfg.ListOpt('vcmp_urls',
                item_type=cfg.types.URI(schemes=['http', 'https']),
                default=[],
                help=_('The URL of the bigip vcmp host devices')),
    cfg.ListOpt('override_vcmp_guest_names',
                default=[],
                help=_('List of vcmp guest names to use for identifying the '
                       'correct vcmp guest - defaults to the bigip hostname.')),
    cfg.BoolOpt('route_on_active',
                default=True,
                help=_("Sync routes only to active bigip device, this option"
                       "is useful if automatic full-sync is activated.")),
]

f5_status_manager_opts = [
    cfg.IntOpt('health_check_interval',
               default=60,
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
    cfg.IntOpt('health_update_threads',
               default=10,
               help=_('Number of threads for processing health update.')),
    cfg.IntOpt('stats_update_threads',
               default=10,
               help=_('Number of threads for processing stats update.')),
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
