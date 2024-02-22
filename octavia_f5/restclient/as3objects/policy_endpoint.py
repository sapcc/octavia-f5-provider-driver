# Copyright 2019 SAP SE
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

from octavia_lib.common import constants

from octavia_f5.common import constants as f5_const
from octavia_f5.restclient import as3types
from octavia_f5.restclient.as3classes import Policy_Compare_String, Policy_Condition, Policy_Action, \
    Endpoint_Policy_Rule, Endpoint_Policy
from octavia_f5.restclient.as3objects import pool
from octavia_f5.utils.exceptions import PolicyTypeNotSupported, CompareTypeNotSupported, PolicyActionNotSupported

COMPARE_TYPE_MAP = {
    'STARTS_WITH': 'starts-with',
    'ENDS_WITH': 'ends-with',
    'CONTAINS': 'contains',
    'EQUAL_TO': 'equals'
}
COMPARE_TYPE_INVERT_MAP = {
    'STARTS_WITH': 'does-not-start-with',
    'ENDS_WITH': 'does-not-end-with',
    'CONTAINS': 'does-not-contain',
    'EQUAL_TO': 'does-not-equal'
}
COND_TYPE_MAP = {
    # constants.L7RULE_TYPE_HOST_NAME: {'match_key': 'host', 'type': 'httpUri'},
    # Workaround for https://github.com/F5Networks/f5-appsvcs-extension/issues/229, match Host in httpHeader
    constants.L7RULE_TYPE_HOST_NAME: {'match_key': 'all', 'type': 'httpHeader', 'key_name': 'name',
                                      'override_key': 'Host'},
    constants.L7RULE_TYPE_PATH: {'match_key': 'path', 'type': 'httpUri'},
    constants.L7RULE_TYPE_FILE_TYPE: {'match_key': 'extension', 'type': 'httpUri'},
    constants.L7RULE_TYPE_HEADER: {'match_key': 'all', 'type': 'httpHeader', 'key_name': 'name'},
    constants.L7RULE_TYPE_SSL_DN_FIELD: {'match_key': 'serverName', 'type': 'sslExtension'},
    constants.L7RULE_TYPE_COOKIE: {'match_key': 'all', 'type': 'httpCookie', 'key_name': 'name'},
}
SUPPORTED_ACTION_TYPE = [
    constants.L7POLICY_ACTION_REDIRECT_TO_POOL,
    constants.L7POLICY_ACTION_REDIRECT_TO_URL,
    constants.L7POLICY_ACTION_REDIRECT_PREFIX,
    constants.L7POLICY_ACTION_REJECT
]


def get_name(policy_id):
    return "{}{}".format(f5_const.PREFIX_POLICY, policy_id)


def get_wrapper_name(listener_id):
    return "{}{}".format(f5_const.PREFIX_WRAPPER_POLICY, listener_id)


def _get_condition(l7rule):
    if l7rule.type not in COND_TYPE_MAP:
        raise PolicyTypeNotSupported(
            "l7policy-id={}, l7rule-id={}, type={}".format(
                l7rule.l7policy_id, l7rule.id, l7rule.type))
    if l7rule.compare_type not in COMPARE_TYPE_MAP:
        raise CompareTypeNotSupported(
            "l7policy-id={}, l7rule-id={}, type={}".format(
                l7rule.l7policy_id, l7rule.id, l7rule.compare_type))

    args = dict()
    if l7rule.invert:
        operand = COMPARE_TYPE_INVERT_MAP[l7rule.compare_type]
    else:
        operand = COMPARE_TYPE_MAP[l7rule.compare_type]
    condition = COND_TYPE_MAP[l7rule.type]
    values = [l7rule.value]
    compare_string = Policy_Compare_String(operand=operand, values=values)
    args[condition['match_key']] = compare_string
    args['type'] = condition['type']
    if 'key_name' in condition:
        if 'override_key' in condition:
            args[condition['key_name']] = condition['override_key']
        else:
            args[condition['key_name']] = l7rule.key
    return Policy_Condition(**args)


def _get_action(l7policy):
    if l7policy.action not in SUPPORTED_ACTION_TYPE:
        raise PolicyActionNotSupported()

    args = dict()
    if l7policy.action == constants.L7POLICY_ACTION_REDIRECT_TO_POOL:
        args['type'] = 'forward'
        pool_name = pool.get_name(l7policy.redirect_pool_id)
        args['select'] = {'pool': {'use': pool_name}}
        args['event'] = 'request'
    elif l7policy.action == constants.L7POLICY_ACTION_REDIRECT_TO_URL:
        args['type'] = 'httpRedirect'
        args['location'] = l7policy.redirect_url
        args['event'] = 'request'
        if l7policy.redirect_http_code:
            args['code'] = l7policy.redirect_http_code
    elif l7policy.action == constants.L7POLICY_ACTION_REDIRECT_PREFIX:
        args['type'] = 'httpRedirect'
        args['location'] = 'tcl:{}[HTTP::uri]'.format(l7policy.redirect_prefix)
        args['event'] = 'request'
    elif l7policy.action == constants.L7POLICY_ACTION_REJECT:
        args['type'] = 'drop'
        args['event'] = 'request'
    return Policy_Action(**args)


def get_endpoint_policy(l7policies):
    wrapper_name = ', '.join([l7policy.name for l7policy in l7policies if l7policy.name])
    wrapper_desc = ', '.join([l7policy.description for l7policy in l7policies if l7policy.description])

    args = dict()
    args['label'] = as3types.f5label(wrapper_name or wrapper_desc)
    args['remark'] = as3types.f5remark(wrapper_desc or wrapper_name)
    args['rules'] = [Endpoint_Policy_Rule(
        name=get_name(l7policy.id),
        label=as3types.f5label(l7policy.name or l7policy.description),
        remark=as3types.f5remark(l7policy.description or l7policy.name),
        conditions=[_get_condition(l7rule) for l7rule in l7policy.l7rules],
        actions=[_get_action(l7policy)]
    ) for l7policy in l7policies]
    args['strategy'] = 'first-match'
    return Endpoint_Policy(**args)
