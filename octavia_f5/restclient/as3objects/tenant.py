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

from oslo_config import cfg
from oslo_log import log as logging

from octavia_lib.common import constants as lib_consts
from octavia.common import exceptions as o_exceptions
from octavia_f5.common import constants
from octavia_f5.restclient import as3classes as as3
from octavia_f5.restclient.as3classes import Application
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import service as m_service
from octavia_f5.utils import driver_utils

CONF = cfg.CONF
LAST_PERSIST = 0
LOG = logging.getLogger(__name__)


def get_name(network_id):
    return f"{constants.PREFIX_NETWORK}{network_id.replace('-', '_')}"


# pylint: disable=too-many-positional-arguments
def get_tenant(segmentation_id, loadbalancers, self_ips, status_manager, cert_manager, network_manager, esd_repo):

    project_id = None
    if loadbalancers:
        project_id = loadbalancers[-1].project_id

    tenant_dict = {}
    if segmentation_id:
        tenant_dict['label'] = f'{constants.PREFIX_PROJECT}{project_id or 'none'}'
        tenant_dict['defaultRouteDomain'] = segmentation_id

    tenant = as3.Tenant(**tenant_dict)

    # Skip members with the same IP as a VIP or SelfIP
    ips_to_skip = [load_balancer.vip.ip_address for load_balancer in loadbalancers
                   if not driver_utils.pending_delete(load_balancer)] + self_ips

    for loadbalancer in loadbalancers:
        # Skip load balancer in (pending) deletion
        if loadbalancer.provisioning_status in [lib_consts.PENDING_DELETE]:
            continue

        # Create generic application
        app = Application(constants.APPLICATION_GENERIC, label=loadbalancer.id)

        # Parse Security Groups attached to LoadBalancer
        parsed_rules = _get_sg_rules_for_lb(network_manager, loadbalancer.vip.sg_ids)

        # Attach Octavia listeners as AS3 service objects
        for listener in loadbalancer.listeners:
            if not driver_utils.pending_delete(listener):
                try:
                    service_entities = m_service.get_service(listener, cert_manager, esd_repo, parsed_rules)
                    app.add_entities(service_entities)
                except o_exceptions.CertificateRetrievalException as e:
                    if getattr(e, 'status_code', 0) != 400:
                        # Error connecting to keystore, skip tenant update
                        raise e

                    LOG.error("Could not retrieve certificate, assuming it is deleted, skipping "
                              "listener '%s': %s", listener.id, e)
                    if status_manager:
                        # Key / Container not found in keystore
                        status_manager.set_error(listener)

        # Attach pools
        for pool in loadbalancer.pools:
            if not driver_utils.pending_delete(pool):
                app.add_entities(m_pool.get_pool(pool, ips_to_skip, status_manager))

        # Attach newly created application
        tenant.add_application(m_app.get_name(loadbalancer.id), app)

    return tenant


def _get_sg_rules_for_lb(network_manager, sg_ids):
    parsed_rules = []
    parsed_sgs = []
    for sg_id in sg_ids:
        if sg_id in parsed_sgs:
            # skip SGs that we already parsed as remote groups
            continue
        sub_sgs, sub_rules = _get_sg_rules_for_sg(network_manager, sg_id)
        parsed_sgs += sub_sgs
        parsed_rules += sub_rules

    unique_rules = []
    for rule in parsed_rules:
        if rule not in unique_rules:
            unique_rules.append(rule)

    return unique_rules


def _get_sg_rules_for_sg(network_manager, sg_id, parent_rule=None):
    parsed_rules = []
    parsed_sgs = [sg_id]

    all_rules = list(tuple(network_manager.network_proxy.security_group_rules(
        security_group_id=sg_id)))
    for rule in all_rules:
        if (rule.get('direction') != 'ingress' or
                rule.get('protocol') is None or
                rule['protocol'].upper() not in
                [lib_consts.PROTOCOL_TCP, lib_consts.PROTOCOL_UDP]):
            LOG.debug(f"Skip SG rule with protocol {rule.get('protocol')} and direction {rule.get('direction')}")
            continue

        if parent_rule:
            # Override protocol and ports from parent SG rule because protocol
            # required for any rules and it cannot be differnet for parent and
            # sub rules.
            parsed_rule = parent_rule.copy()
        else:
            # None means Any port
            if rule['port_range_min'] is None:
                rule['port_range_min'] = 1
            if rule['port_range_max'] is None:
                rule['port_range_max'] = 65535
            parsed_rule = {
                'protocol': rule['protocol'].upper(),
                'ports': (rule['port_range_min'], rule['port_range_max'])
            }

        prefixes = []
        remote_ag_id = rule.get('remote_address_group_id')
        remote_sg_id = rule.get('remote_group_id')

        if remote_ag_id:
            addr_group = network_manager.network_proxy.get_address_group(
                address_group=remote_ag_id)
            prefixes = addr_group['addresses']
        elif remote_sg_id:
            sub_sgs, sub_rules = _get_sg_rules_for_sg(
                network_manager, remote_sg_id, parsed_rule)
            parsed_sgs += sub_sgs
            parsed_rules += sub_rules
        else:
            if rule['remote_ip_prefix']:
                prefixes.append(rule['remote_ip_prefix'])

        if prefixes:
            parsed_rule['prefixes'] = prefixes
            parsed_rules.append(parsed_rule)

    return parsed_sgs, parsed_rules
