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
from octavia_f5.utils.mapper import partition
from octavia_f5.utils.mapper import monitor

LOG = logging.getLogger(__name__)

class PoolMapper(partition.PartitionMapper):
    def __init__(self):
        self.hm = monitor.MonitorMapper()

    def get_pool_path(self, loadbalancer, pool):
        name = constants.PREFIX_POOL + pool.id if pool else ''
        partition = self.get_partition_name(loadbalancer.project_id)

        return dict(name=name, partition=partition)

    # from service_adpater.py f5_driver-agent
    def map_pool(self, pool, loadbalancer, members, health_monitor):
        obj = self.get_pool_path(loadbalancer, pool)
        obj["description"] = self.get_resource_description(pool)

        if hasattr(pool, 'lb_algorithm'):
            lbaas_lb_method = pool.lb_algorithm.upper()
            obj['loadBalancingMode'] = \
                self._set_lb_method(lbaas_lb_method, members)

            # If source_ip lb method, add SOURCE_IP persistence to ensure
            # source IP loadbalancing. See issue #344 for details.
            if pool.lb_algorithm.upper() == 'SOURCE_IP':
                persist = getattr(pool, 'session_persistence', None)
                if not persist:
                    obj['session_persistence'] = {'type': 'SOURCE_IP'}

        if pool.health_monitor:
            hm = self.hm.get_health_monitor_path(loadbalancer, pool.health_monitor)
            obj["monitor"] = hm.name

        obj_members = list()
        for member in members:
            provisioning_status = member.get('provisioning_status', "")
            if provisioning_status != "PENDING_DELETE":
                obj_members.append(self._map_member(member))

            obj["members"] = obj_members

        return obj

    # from service_adpater.py f5_driver-agent
    @staticmethod
    def _get_lb_method( method):
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
