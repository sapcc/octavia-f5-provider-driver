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
from octavia_f5.restclient.as3objects import tenant as m_partition
from octavia_f5.restclient.as3objects import pool as m_pool

LOG = logging.getLogger(__name__)


def get_path(listener_id):
    return constants.PREFIX_LISTENER + \
           listener_id.replace('/', '').replace('-', '')


def to_dict(listener):
    name = get_path(listener.id)
    partition = m_partition.get_path(
        listener.project_id)

    return dict(name=name, partition=partition)


def get_vip_default_pool(listener):
    if listener.default_pool:
        return listener.default_pool

    return None


def get_virtual(listener):
    # listener["use_snat"] = self.snat_mode()
    # if listener["use_snat"] and self.snat_count() > 0:
    #    listener["snat_pool_name"] = self.get_folder_name(
    #        loadbalancer["tenant_id"])

    pool = get_vip_default_pool(listener)

    # if hasattr(pool, 'session_persistence'):
    #    listener["session_persistence"] = pool.session_persistence

    listener_policies = None  # self.get_listener_policies(service)

    vip = _map_virtual(listener, pool=pool,
                       policies=listener_policies)

    return vip


def _map_virtual(listener, pool=None, policies=None):
    loadbalancer = listener.load_balancer
    virtual = to_dict(listener)

    virtual["description"] = m_partition.get_resource_description(pool)

    if pool:
        pool_name = m_pool.to_dict(loadbalancer, pool)
        virtual['pool'] = getattr(pool_name, 'name', '')

    virtual["connectionLimit"] = \
        max(0, getattr(listener, 'connection_limit', 0))

    port = getattr(listener, "protocol_port", None)
    vip = getattr(loadbalancer, "vip", None)

    if vip and port:
        ip_address = vip.ip_address
        if str(vip.ip_address).endswith('%0'):
            ip_address = vip.ip_address[:-2]

        if ':' in ip_address:
            virtual['destination'] = ip_address + "." + str(port)
        else:
            virtual['destination'] = ip_address + ":" + str(port)

        virtual["mask"] = '255.255.255.255'

    if hasattr(listener, 'admin_state_up'):
        if listener.admin_state_up:
            virtual["enabled"] = True
        else:
            virtual["disabled"] = True

        # self._add_vlan_and_snat(listener, vip)
        # self._add_profiles_session_persistence(listener, pool, vip)

        virtual['rules'] = list()
        virtual['policies'] = list()
    # if policies:
    #    self._apply_l7_and_esd_policies(listener, policies, vip)

    return virtual


def _add_profiles_session_persistence(self, listener, pool, vip):
    protocol = listener.get('protocol', "")
    if protocol not in ["HTTP", "HTTPS", "TCP", "TERMINATED_HTTPS"]:
        LOG.warning("Listener protocol unrecognized: %s",
                    listener["protocol"])
    vip["ipProtocol"] = "tcp"

    if protocol == 'TCP':
        virtual_type = 'fastl4'
    else:
        virtual_type = 'standard'

    if virtual_type == 'fastl4':
        vip['profiles'] = ['/Common/fastL4']
    else:
        # add profiles for HTTP, HTTPS, TERMINATED_HTTPS protocols
        vip['profiles'] = ['/Common/http', '/Common/oneconnect']

    vip['fallbackPersistence'] = ''
    vip['persist'] = []

    persistence = None
    if pool:
        persistence = pool.get('session_persistence', None)
        lb_algorithm = pool.get('lb_algorithm', 'ROUND_ROBIN')

    valid_persist_types = ['SOURCE_IP', 'APP_COOKIE', 'HTTP_COOKIE']
    if persistence:
        persistence_type = persistence.get('type', "")
        if persistence_type not in valid_persist_types:
            LOG.warning("Invalid peristence type: %s",
                        persistence_type)
            return

        if persistence_type == 'APP_COOKIE':
            vip['persist'] = [{'name': 'app_cookie_' + vip['name']}]

        elif persistence_type == 'SOURCE_IP':
            vip['persist'] = [{'name': '/Common/source_addr'}]

        elif persistence_type == 'HTTP_COOKIE':
            vip['persist'] = [{'name': '/Common/cookie'}]

        if persistence_type != 'SOURCE_IP':
            if lb_algorithm == 'SOURCE_IP':
                vip['fallbackPersistence'] = '/Common/source_addr'

        if persistence_type in ['HTTP_COOKIE', 'APP_COOKIE']:
            if protocol == "TCP":
                vip['profiles'] = [p for p in vip['profiles']
                                   if p != 'fastL4']
            vip['profiles'] = ['/Common/http', '/Common/oneconnect']
