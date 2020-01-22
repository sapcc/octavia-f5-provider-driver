# Copyright 2018, 2019, 2020 SAP SE
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
from octavia_f5.restclient.as3objects import pool_member as m_member
from octavia_f5.utils import driver_utils as utils

LOG = logging.getLogger(__name__)


def get_name(pool_id):
    """Return AS3 object name for type pool

    :param pool_id: pool id
    :return: AS3 object name
    """
    return constants.PREFIX_POOL + \
           pool_id.replace('/', '').replace('-', '_')


def get_pool(pool):
    """Map Octavia Pool -> AS3 Pool object

    :param pool: octavia pool object
    :return: AS3 pool
    """
    entities = []
    lbaas_lb_method = pool.lb_algorithm.upper()
    lbmode = _set_lb_method(lbaas_lb_method, pool.members)

    service_args = {
        'label': (pool.name or pool.id)[:64],
        'remark': (pool.description or pool.id)[:64],
        'loadBalancingMode': lbmode,
        'members': [],
    }

    for member in pool.members:
        if not utils.pending_delete(member):
            service_args['members'].append(
                m_member.get_member(member))

    if pool.health_monitor and not utils.pending_delete(
            pool.health_monitor):
        name = m_monitor.get_name(pool.health_monitor.id)
        hm = m_monitor.get_monitor(pool.health_monitor)
        entities.append((name, hm))
        service_args['monitors'] = [Pointer(use=name)]

        for member in pool.members:
            # Custom member address
            if member.monitor_address or member.monitor_port:
                member_hm = m_monitor.get_monitor(pool.health_monitor)
                if member.monitor_address:
                    member_hm.set_target_address(member.monitor_address)
                if member.monitor_port:
                    member_hm.set_target_port(member.monitor_port)
                name = m_member.get_name(member.id)
                entities.append((name, member_hm))

    entities.append((get_name(pool.id), Pool(**service_args)))
    return entities


# from service_adpater.py f5_driver-agent
def _get_lb_method(method):
    """ Returns F5 load balancing mode for octavia pool lb-algorithm

    :param method: Octavia lb-algorithm
    :return: F5 load balancing mode
    """
    lb_method = method.upper()

    if lb_method == constants.LB_ALGORITHM_LEAST_CONNECTIONS:
        return 'least-connections-member'
    elif lb_method == 'RATIO_LEAST_CONNECTIONS':
        return 'ratio-least-connections-member'
    elif lb_method == constants.LB_ALGORITHM_SOURCE_IP:
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
def _set_lb_method(lbaas_lb_method, members):
    """Set pool lb method depending on member attributes.

    :param lbaas_lb_method: octavia loadbalancing method
    :param members: octavia members
    :return: F5 load balancing method
    """
    lb_method = _get_lb_method(lbaas_lb_method)

    if lb_method == 'SOURCE_IP':
        return lb_method

    member_has_weight = False
    for member in members:
        if not utils.pending_delete(member) and member.weight > 1:
            member_has_weight = True
            break

    if member_has_weight:
        if lb_method == 'LEAST_CONNECTIONS':
            return _get_lb_method('RATIO_LEAST_CONNECTIONS')
        return _get_lb_method('RATIO')
    return lb_method
