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
import math

from octavia_f5.common import constants
from octavia_f5.restclient import as3types
from octavia_f5.restclient.as3classes import Member


def get_name(member_id):
    return "{}{}".format(constants.PREFIX_MEMBER, member_id)


def normalize_weight(weight):
    """AS3 accepts ratios between 0 and 100 whereas Octavia
    allows ratios in a range of 0 and 256, so we normalize
    the Octavia value for AS3 consumption.

    We also round up the result since we want avoid having a 0
    (no traffic received at all) when setting a weight of 1
    """
    ratio = int(math.ceil((weight / 256.) * 100.))
    return ratio

def get_member(member):
    args = dict()
    args['servicePort'] = member.protocol_port
    args['serverAddresses'] = [member.ip_address]

    if member.enabled:
        args['adminState'] = 'enable'
    else:
        args['adminState'] = 'disable'

    if member.weight == 0:
        args['ratio'] = 1
        args['adminState'] = 'disable'
    else:
        args['ratio'] = normalize_weight(member.weight)

    args['remark'] = as3types.f5remark(member.id)
    return Member(**args)