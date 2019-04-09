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

from octavia_f5.common import constants
from oslo_log import log as logging
from octavia_f5.utils.mapper import partition as mapper

LOG = logging.getLogger(__name__)


def get_name(policy):
    return constants.PREFIX_POLICY + policy.id


def get_l7policy_path( loadbalancer, policy):
    name = _get_l7policy_name(policy)
    partition = mapper.get_partition_name(loadbalancer.project_id)

    return dict(name=name, partition=partition)


def _apply_l7_and_esd_policies( listener, policies, vip):
    if not policies:
        return

    partition = mapper.get_partition_path(listener.project_id)
    policy_name = "wrapper_policy_" + str(listener.id)
    bigip_policy = listener.get('f5_policy', {})  # todo: do smthg
    if bigip_policy.get('rules', list()):
        vip['policies'] = [{'name': policy_name,
                            'partition': partition}]

    esd_composite = dict()
    for policy in sorted(
            policies, key=itemgetter('position'), reverse=True):
        if policy['provisioning_status'] == "PENDING_DELETE":
            continue

        policy_name = policy.get('name', None)
        esd = self.esd.get_esd(policy_name)
        if esd:
            esd_composite.update(esd)

    if listener['protocol'] == 'TCP':
        _apply_fastl4_esd(vip, esd_composite)
    else:
        _apply_esd(vip, esd_composite)


def get_esd(self, name):
    if self.esd:
        return self.esd.get_esd(name)

    return None


def is_esd(self, name):
    return self.esd.get_esd(name) is not None


def _apply_fastl4_esd(vip, esd):
    if not esd:
        return

    # Application of ESD implies some type of L7 traffic routing.  Add
    # an HTTP profile.
    vip['profiles'] = ["/Common/http", "/Common/fastL4"]

    # persistence
    if 'lbaas_persist' in esd:
        if vip.get('persist'):
            LOG.warning("Overwriting the existing VIP persist profile: %s",
                        vip['persist'])
        vip['persist'] = [{'name': esd['lbaas_persist']}]

    if 'lbaas_fallback_persist' in esd and vip.get('persist'):
        if vip.get('fallbackPersistence'):
            LOG.warning(
                "Overwriting the existing VIP fallback persist "
                "profile: %s", vip['fallbackPersistence'])
        vip['fallbackPersistence'] = esd['lbaas_fallback_persist']

    # iRules
    vip['rules'] = list()
    if 'lbaas_irule' in esd:
        irules = []
        for irule in esd['lbaas_irule']:
            irules.append('/Common/' + irule)
        vip['rules'] = irules

    # L7 policies
    if 'lbaas_policy' in esd:
        if vip.get('policies'):
            LOG.warning(
                "LBaaS L7 policies and rules will be overridden "
                "by ESD policies")
            vip['policies'] = list()

        policies = list()
        for policy in esd['lbaas_policy']:
            policies.append({'name': policy, 'partition': 'Common'})
        vip['policies'] = policies


def _apply_esd(vip, esd):
    if not esd:
        return

    profiles = vip['profiles']

    # start with server tcp profile
    if 'lbaas_stcp' in esd:
        # set serverside tcp profile
        profiles.append({'name': esd['lbaas_stcp'],
                         'partition': 'Common',
                         'context': 'serverside'})
        # restrict client profile
        ctcp_context = 'clientside'
    else:
        # no serverside profile; use client profile for both
        ctcp_context = 'all'

    # must define client profile; default to tcp if not in ESD
    if 'lbaas_ctcp' in esd:
        ctcp_profile = esd['lbaas_ctcp']
    else:
        ctcp_profile = 'tcp'
    profiles.append({'name': ctcp_profile,
                     'partition': 'Common',
                     'context': ctcp_context})

    # SSL profiles
    if 'lbaas_cssl_profile' in esd:
        profiles.append({'name': esd['lbaas_cssl_profile'],
                         'partition': 'Common',
                         'context': 'clientside'})
    if 'lbaas_sssl_profile' in esd:
        profiles.append({'name': esd['lbaas_sssl_profile'],
                         'partition': 'Common',
                         'context': 'serverside'})

    # persistence
    if 'lbaas_persist' in esd:
        if vip.get('persist', None):
            LOG.warning("Overwriting the existing VIP persist profile: %s",
                        vip['persist'])
        vip['persist'] = [{'name': esd['lbaas_persist']}]

    if 'lbaas_fallback_persist' in esd and vip.get('persist'):
        if vip.get('fallbackPersistence', None):
            LOG.warning(
                "Overwriting the existing VIP fallback persist "
                "profile: %s", vip['fallbackPersistence'])
        vip['fallbackPersistence'] = esd['lbaas_fallback_persist']

    # iRules
    vip['rules'] = list()
    if 'lbaas_irule' in esd:
        irules = []
        for irule in esd['lbaas_irule']:
            irules.append('/Common/' + irule)
        vip['rules'] = irules

    # L7 policies
    if 'lbaas_policy' in esd:
        if vip.get('policies'):
            LOG.warning(
                "LBaaS L7 policies and rules will be overridden "
                "by ESD policies")
            vip['policies'] = list()

        policies = list()
        for policy in esd['lbaas_policy']:
            policies.append({'name': policy, 'partition': 'Common'})
        vip['policies'] = policies
