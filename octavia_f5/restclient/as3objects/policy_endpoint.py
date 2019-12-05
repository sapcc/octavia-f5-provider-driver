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

from octavia_f5.restclient.as3classes import *
from octavia_f5.utils.exceptions import *
from octavia_f5.restclient.as3objects import pool


def get_name(policy_id):
    return constants.PREFIX_POLICY + \
           policy_id.replace('/', '').replace('-','_')


def _get_condition(l7rule):
    COMPARE_TYPE_MAP = {
        'STARTS_WITH': 'startsWith',
        'ENDS_WITH': 'endsWith',
        'CONTAINS': 'contains',
        'EQUAL_TO': 'equals'
    }
    COND_TYPE_MAP = {
        'HOST_NAME': {'match_key': 'host', 'type': 'httpUri'},
        'PATH': {'match_key': 'path', 'type': 'httpUri'},
        'FILE_TYPE': {'match_key': 'extension', 'type': 'httpUri'},
        'HEADER': {'match_key': 'all', 'type': 'httpHeader'},
        'SSL_DN_FIELD': {'match_key': 'serverName', 'type': 'sslExtension'}
    }

    if l7rule.type not in COND_TYPE_MAP:
        raise PolicyTypeNotSupported()
    if l7rule.compare_type not in COMPARE_TYPE_MAP:
        raise CompareTypeNotSupported()
    if l7rule.invert:
        raise PolicyRuleInvertNotSupported()

    args = dict()
    operand = COMPARE_TYPE_MAP[l7rule.compare_type]
    condition = COND_TYPE_MAP[l7rule.type]
    compare_string = Policy_Compare_String(operand=operand, values=[l7rule.value])
    args[condition['match_key']] = compare_string
    args['type'] = condition['type']
    return Policy_Condition(**args)

def _get_action(l7policy):
    # TODO(Andrew Karpow) REDIRECT_PREFIX (http://abc.de -> https://abc.de)
    SUPPORTED_ACTION_TYPE = ['REDIRECT_TO_POOL', 'REDIRECT_TO_URL', 'REJECT']
    if l7policy.action not in SUPPORTED_ACTION_TYPE:
        raise PolicyActionNotSupported()

    args = dict()
    if l7policy.action == 'REDIRECT_TO_POOL':
        args['type'] = 'forward'
        pool_name = pool.get_name(l7policy.redirect_pool_id)
        args['select'] = {'pool': {'use': pool_name}}
        args['event'] = 'request'
    elif l7policy.action == 'REDIRECT_TO_URL':
        args['type'] = 'httpRedirect'
        args['location'] = l7policy.redirect_url
        args['event'] = 'request'
    elif l7policy.action == 'REJECT':
        args['type'] = 'drop'
        args['event'] = 'request'
    return Policy_Action(**args)


def get_endpoint_policy(l7policy):
    args = dict()
    args['label'] = l7policy.name
    args['name'] = l7policy.id.replace('-', '_')
    args['remark'] = l7policy.description
    args['conditions'] = [_get_condition(l7rule) for l7rule in l7policy.l7rules]
    args['actions'] = [_get_action(l7policy)]
    args['strategy'] = 'all-match'
    return Endpoint_Policy(**args)
