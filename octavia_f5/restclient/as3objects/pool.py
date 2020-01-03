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

from octavia_f5.common import constants
from oslo_log import log as logging

from octavia_f5.restclient.as3classes import Pool, Pointer
from octavia_f5.restclient.as3objects import monitor as m_monitor
from octavia_f5.restclient.as3objects import application as m_app

LOG = logging.getLogger(__name__)


def get_name(pool_id):
    return constants.PREFIX_POOL + \
           pool_id.replace('/', '').replace('-', '_')


def get_path(pool):
    return m_app.get_path(pool.load_balancer) + \
           '/' + get_name(pool.id)


def get_pool(pool):
    lbmode = 'round-robin'
    if pool.lb_algorithm is constants.LB_ALGORITHM_LEAST_CONNECTIONS:
        lbmode = 'least-connections-member'
    # SOURCE_IP algo not supported by BigIP

    args = {
        'label': pool.name or pool.id,
        'remark': pool.description or pool.id,
        'loadBalancingMode': lbmode,
    }
    if pool.health_monitor:
        args['monitors'] = [Pointer(use=m_monitor.get_name(pool.health_monitor.id))]

    return Pool(**args)


# from service_adpater.py f5_driver-agent
def _get_lb_method(method):
    lb_method = method.upper()

    if lb_method == 'LEAST_CONNECTIONS':
        return 'least-connections-member'
    elif lb_method == 'RATIO_LEAST_CONNECTIONS':
        return 'ratio-least-connections-member'
    elif lb_method == 'SOURCE_IP':
        return 'least-connections-node'
    elif lb_method == 'OBSERVED_MEMBER':
        return 'observed-member'
    elif lb_method == 'PREDICTIVE_MEMBER':
        return 'predictive-member'
    elif lb_method == 'RATIO':
        return 'ratio-member'
    else:
        return 'round-robin'


# from service_adpater.py f5_driver-agent
def _set_lb_method(self, lb_method, members):
    """Set pool lb method depending on member attributes."""
    lb_method = self._get_lb_method(lb_method)

    if lb_method == 'SOURCE_IP':
        return lb_method

    member_has_weight = False
    for member in members:
        if hasattr(member, 'weight') and member.weight > 1 and \
                member['provisioning_status'] != 'PENDING_DELETE':
            member_has_weight = True
            break

    if member_has_weight:
        if lb_method == 'LEAST_CONNECTIONS':
            return self._get_lb_method('RATIO_LEAST_CONNECTIONS')
        return self._get_lb_method('RATIO')
    return lb_method


def _map_member(self, member):
    obj = {}
    port = member.protocol_port
    ip_address = member.address

    if member.admin_state_up:
        obj["session"] = "user-enabled"
    else:
        obj["session"] = "user-disabled"

    if member.weight == 0:
        obj["ratio"] = 1
        obj["session"] = "user-disabled"
    else:
        obj["ratio"] = member.weight

    if ':' in ip_address:
        obj['name'] = ip_address + '.' + str(port)
    else:
        obj['name'] = ip_address + ':' + str(port)

    obj["partition"] = self.get_partition_name(member.project_id)
    obj["address"] = ip_address
    return obj
