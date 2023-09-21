# Copyright 2023 SAP SE
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

from octavia.common import validate
from octavia_f5.common import constants
from octavia_f5.restclient.as3classes import Cipher_Rule, Cipher_Group

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def get_cipher_rule_name(object_id, object_type):
    """Returns AS3 object name for Cipher Rule related to a listener or a pool

    :param object_id: octavia listener or pool id
    :return: AS3 object name
    """
    return "{}{}_{}".format(constants.PREFIX_CIPHER_RULE, object_type.lower(), object_id)


def get_cipher_group_name(object_id, object_type):
    """Returns AS3 object name for Cipher Group related to a listener or a pool

    :param object_id: octavia listener or pool id
    :return: AS3 object name
    """
    return "{}{}_{}".format(constants.PREFIX_CIPHER_GROUP, object_type.lower(), object_id)


def filter_cipher_suites(cipher_suites, object_print_name, object_id):
    """Filter out cipher suites according to blocklist and allowlist.

    This is necessary, because there can be invalid cipher suites if e.g. a
    previously allowed cipher suite was added to the blocklist recently and
    listeners/pools using the cipher suite already existed.

    :param cipher_suites: String containing colon-separated list of cipher suites.
    :param object_print_name: A printable representation of the object to be logged, e.g. "Listener" or "Pool".
    :param object_id: ID of the object the cipher suites belong to. This is used for logging, so it should be a string.
    :return String containing colon-separated list of non-blocked/allowed cipher suites.
    """

    blocked_cipher_suites = validate.check_cipher_prohibit_list(cipher_suites)
    disallowed_cipher_suites = validate.check_cipher_allow_list(cipher_suites)
    rejected_cipher_suites = list(set(blocked_cipher_suites + disallowed_cipher_suites))

    cipher_suites_list = cipher_suites.split(':')
    if rejected_cipher_suites:
        LOG.error("{} object with ID {} has invalid cipher suites which won't be provisioned: {}"
                  .format(object_print_name, object_id, ', '.join(rejected_cipher_suites)))
        for c in rejected_cipher_suites:
            cipher_suites_list.remove(c)

    return cipher_suites_list


def get_cipher_rule(ciphers, parent_obj, parent_id):
    rule_name = get_cipher_rule_name(parent_id, parent_obj)
    group_name = get_cipher_group_name(parent_id, parent_obj)
    rule_args = {
        'cipherSuites': filter_cipher_suites(ciphers, parent_obj, parent_id)
    }
    group_args = {
        'allowCipherRules': [{'use': rule_name}]
    }
    return group_name, [
        (rule_name, Cipher_Rule(**rule_args)),
        (group_name, Cipher_Group(**group_args))
    ]
