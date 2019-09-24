# Copyright 2018 SAP SE
# Copyright (c) 2014-2018, F5 Networks, Inc.
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

from oslo_log import log as logging

from octavia_f5.utils.exceptions import PolicyHasNoRules
from octavia_f5.utils.exceptions import NoActionFoundForPolicy

LOG = logging.getLogger(__name__)


class Action(object):
    """Describes a single action for a rule."""

    def __init__(
            self, action, action_name, partition, env_prefix, action_val=None):
        action_map = {
            'REDIRECT_TO_POOL': {'forward': True,
                                 'pool': self._get_pool_name(
                                     partition, env_prefix, action_val)},
            'REDIRECT_TO_URL': {
                'redirect': True, 'location': action_val, 'httpReply': True},
            'REJECT': {'reset': True, 'forward': True}
        }
        self.request = True
        self.name = action_name
        self.__dict__.update(action_map[action])

    def _get_pool_name(self, partition, env_prefix, action_value):
        """Construct pool name from partition and OpenStack pool name."""
        return '/{0}/{1}{2}'.format(partition, env_prefix, action_value)


class Condition(object):
    """Describes a single condition for a rule."""

    cond_comp_type_map = {
        'STARTS_WITH': 'startsWith',
        'ENDS_WITH': 'endsWith',
        'CONTAINS': 'contains',
        'EQUAL_TO': 'equals'
    }

    def __init__(self, condition, cond_name):
        key = condition['key']
        val = condition['value']
        self.request = True
        self.name = cond_name
        cond_type_map = {
            'HOST_NAME': {'httpHost': True, 'values': [val], 'host': True},
            'PATH': {'httpUri': True, 'path': True, 'values': [val]},
            'FILE_TYPE': {'httpUri': True, 'extension': True, 'values': [val]},
            'HEADER': {'httpHeader': True, 'tmName': key, 'values': [val]},
            'COOKIE': {'httpCookie': True, 'tmName': key, 'values': [val]}
        }
        if condition['invert']:
            setattr(self, 'not', condition['invert'])
        self.__dict__.update(cond_type_map[condition['type']])
        setattr(self, self.cond_comp_type_map[condition['compare_type']], True)


class Rule(object):
    """Describes a single rule for a policy."""

    def __init__(self, policy):
        self._set_name(policy)
        self.ordinal = policy['position']
        self.actions = []
        self.conditions = []
        self._adapt_rule_to_conditions_and_actions(
            policy)

    def _adapt_rule_to_conditions_and_actions(
            self, policy):
        """Adapt OpenStack rules into conditions and actions."""
        for idx, os_rule_dict in enumerate(policy.l7rules):
            os_rule = self._get_l7rule(os_rule_dict.id)
            if os_rule.enabled:
                cond = Condition(os_rule, str(idx))
                self.conditions.append(cond.__dict__)
        act_type, act_val = self._get_action_and_value(policy.id)
        action = Action(act_type, '0', act_val)
        self.actions.append(action.__dict__)

    def _get_l7rule(self, rule_id, l7policy):
        """Get rule dict from service list."""
        for rule in l7policy.l7rules:
            if rule.id == rule_id:
                return rule

    def _set_name(self, policy):
        """Set name of rule to something intelligent."""
        if not policy.name:
            self.name = policy.action.lower()
            self.name += '_' + str(policy.position)
        else:
            self.name = policy.name

    def _get_action_and_value(self, policy_id, listener):
        """Get the action and action value associated with a policy."""
        for pol in listener.l7policies:
            if pol['id'] == policy_id:
                action = pol['action']
                action_val = None
                if action == 'REDIRECT_TO_POOL':
                    action_val = pol['redirect_pool_id']
                if action == 'REDIRECT_TO_URL':
                    action_val = pol['redirect_url']
                return action, action_val
        msg = "Could not find action for the following policy id: {}".format(
            policy_id)
        raise NoActionFoundForPolicy(msg)



"""Map OpenStack policies and rules to policy and rules on device."""
def _adapt_policies_to_rules(listener):
    """OS Policies are translated into Rules on the device."""
    policy_dict = {}
    for policy in listener.l7policies:
        if not policy.enabled:
            continue

        bigip_rule = Rule(policy)
        policy_dict['rules'].append(bigip_rule.__dict__)
    if not policy_dict['rules']:
        msg = 'All policies were in a PENDING_DELETE or admin_state ' \
            'DOWN.  Deleting wrapper_policy.'
        raise PolicyHasNoRules(msg)
    _check_if_adapted_rules_empty()


def _check_if_adapted_rules_empty():
    policy_dict = {}
    """Delete wrapper policy if all rules in PENDING_DELETE state."""
    delete_wrapper_policy = True
    for os_rule in policy_dict['rules']:
        if os_rule['conditions']:
            delete_wrapper_policy = False
            break
    if delete_wrapper_policy:
        msg = 'All rules were in a PENDING_DELETE state. Deleting ' \
            'wrapper_policy.'
        raise PolicyHasNoRules(msg)


def _adapt_policy(listener):
    """Setup the wrapper policy, which will contain rules."""
    policy_dict = {}
    policy_dict['name'] = 'wrapper_policy_' + listener.id

    policy_dict['strategy'] = 'first-match'
    policy_dict['rules'] = list()
    policy_dict['legacy'] = True
    policy_dict['requires'] = ['http']
    policy_dict['controls'] = ['forwarding']

    l7rules = sum([len(l7policy.l7rules) for
                   l7policy in listener.l7policies])
    if not l7rules:
        msg = 'No Rules given to implement. A Policy cannot be attached ' \
            'to a Virtual until it has one or more Rules.'
        raise PolicyHasNoRules(msg)
    _adapt_policies_to_rules(listener)

def translate(listener):
    policy_dict = {}
    try:
        _adapt_policy(listener)
    except (PolicyHasNoRules, NoActionFoundForPolicy) as error:
        LOG.debug(error.message)
        policy_dict['rules'] = list()

    return policy_dict

def translate_name(l7policy):
    return {'name': 'wrapper_policy'}
