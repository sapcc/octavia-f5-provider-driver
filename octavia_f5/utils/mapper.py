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
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

def get_partition_name(project_id):
    if project_id is not None:
        name = constants.PREFIX_PROJECT + \
               project_id.replace('/', '')
    else:
        name = "Common"

    return name


def get_folder(loadbalancer):
    folder = None

    if hasattr(loadbalancer, 'project_id'):
        project_id = loadbalancer.project_id
        folder_name = get_partition_name(project_id)
        folder = {"name": folder_name,
                  "subPath": "/",
                  "fullPath": "/" + folder_name,
                  "hidden": False,
                  "inheritedDevicegroup": True}
        if hasattr(loadbalancer, 'traffic_group'):
            folder['trafficGroup'] = loadbalancer.traffic_group
            folder['inheritedTrafficGroup'] = False
        else:
            folder['inheritedTrafficGroup'] = True

    return folder


def get_virtual_name(listener):
    name = constants.PREFIX_LISTENER + listener.id
    partition = get_partition_name(listener.project_id)

    return dict(name=name, partition=partition)


def get_vip_default_pool(listener):
    if listener.default_pool:
        return listener.default_pool

    return None


def get_virtual(listener):

    #listener["use_snat"] = self.snat_mode()
    #if listener["use_snat"] and self.snat_count() > 0:
    #    listener["snat_pool_name"] = self.get_folder_name(
    #        loadbalancer["tenant_id"])

    pool = get_vip_default_pool(listener)

    #if hasattr(pool, 'session_persistence'):
    #    listener["session_persistence"] = pool.session_persistence

    listener_policies = None # self.get_listener_policies(service)

    vip = _map_virtual(listener, pool=pool,
                            policies=listener_policies)

    return vip


def _map_virtual(listener, pool=None, policies=None):
    loadbalancer = listener.load_balancer
    vip = get_virtual_name(listener)

    vip["description"] = getattr(listener, 'description', '')

    if pool:
        pool_name = get_pool_name(loadbalancer, pool)
        vip['pool'] = getattr(pool_name, 'name', '')

    vip["connectionLimit"] = max(0, getattr(listener, 'connection_limit', 0))

    port = getattr(listener, "protocol_port", None)
    lb_vip = getattr(loadbalancer, "vip", None)

    if lb_vip.ip_address and port:
        if str(lb_vip.ip_address).endswith('%0'):
            ip_address = lb_vip.ip_address[:-2]

        if ':' in ip_address:
            vip['destination'] = ip_address + "." + str(port)
        else:
            vip['destination'] = ip_address + ":" + str(port)
    else:
        pass
        #LOG.error("No VIP address or port specified")

    vip["mask"] = '255.255.255.255'

    if hasattr(listener, 'admin_state_up'):
        if listener.admin_state_up:
            vip["enabled"] = True
        else:
            vip["disabled"] = True

    #self._add_vlan_and_snat(listener, vip)
    #self._add_profiles_session_persistence(listener, pool, vip)

    vip['rules'] = list()
    vip['policies'] = list()
    #if policies:
    #    self._apply_l7_and_esd_policies(listener, policies, vip)

    return vip


def get_pool_name(loadbalancer, pool):
    """Return a barebones pool object with name and partition."""
    partition = get_partition_name(loadbalancer.project_id)
    name = constants.PREFIX_POOL + pool.id if pool else ''

    return {"name": name,
            "partition": partition}