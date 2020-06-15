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

from octavia_f5.restclient import as3types
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
    return "{}{}".format(constants.PREFIX_POOL, pool_id)


def get_pool(pool):
    """Map Octavia Pool -> AS3 Pool object

    :param pool: octavia pool object
    :return: AS3 pool
    """

    # Entities is a list of tuples, which each describe AS3 objects
    # which may reference each other but do not form a hierarchy.
    entities = []
    lbaas_lb_method = pool.lb_algorithm.upper()
    lbmode = _set_lb_method(lbaas_lb_method, pool.members)

    service_args = {
        'label': as3types.f5label(pool.name or pool.description),
        'remark': as3types.f5remark(pool.description or pool.name),
        'loadBalancingMode': lbmode,
        'members': [],
    }

    for member in pool.members:
        # Ignore backup members, will be handled by service
        if not utils.pending_delete(member) and not member.backup:
            service_args['members'].append(
                m_member.get_member(member))

    #if pool.health_monitor and not utils.pending_delete(
    #        pool.health_monitor):
    # Workaround for Monitor deletion bug in AS3, dereference but remain HM
    if pool.health_monitor:
        hms = m_monitor.get_monitors(pool.health_monitor, pool.members)
        entities.extend(hms)

        # Part of the workaround
        if not utils.pending_delete(pool.health_monitor):
            service_args['monitors'] = [Pointer(use=name) for name, _ in hms]

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
