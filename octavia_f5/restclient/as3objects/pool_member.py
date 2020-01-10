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
from octavia_f5.restclient.as3classes import Member


def get_name(member_id):
    return constants.PREFIX_MEMBER + \
           member_id.replace('/', '').replace('-', '_')


def get_member(member):
    args = dict()
    args['servicePort'] = member.protocol_port
    args['serverAddresses'] = [member.ip_address]

    if hasattr(member, 'admin_state_up'):
        if member.admin_state_up:
            args['adminState'] = 'enable'
        else:
            args['adminState'] = 'disable'

    if member.weight == 0:
        args['ratio'] = 1
        args['adminState'] = "disable"
    else:
        args['ratio'] = member.weight

    return Member(**args)