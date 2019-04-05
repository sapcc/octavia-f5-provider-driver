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
from octavia_f5.restclient.as3classes import Service
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import application as m_app

""" Maps listener to AS3 service """


def get_name(listener_id):
    return constants.PREFIX_LISTENER + \
           listener_id.replace('/', '').replace('-', '')


def get_path(listener):
    return m_app.get_path(listener.load_balancer) + \
            '/' + get_name(listener.id)


def get_service(listener):
    servicetype = constants.SERVICE_GENERIC
    if listener.protocol == constants.PROTOCOL_TCP:
        servicetype = constants.SERVICE_TCP
    # UDP
    elif listener.protocol == constants.PROTOCOL_UDP:
        servicetype = constants.SERVICE_UDP
    # HTTP
    elif listener.protocol == constants.PROTOCOL_HTTP:
        servicetype = constants.SERVICE_HTTP
    # HTTPS
    elif listener.protocol == constants.PROTOCOL_HTTPS:
        servicetype = constants.SERVICE_HTTPS

    service_args = {
        '_servicetype': servicetype,
        'virtualPort': listener.protocol_port,
        'virtualAddresses': ['1.2.3.4']  # TODO: port.ip
    }

    if listener.default_pool_id:
        service_args['pool'] = m_pool.get_name(listener.default_pool_id)

    return Service(**service_args)
"""
    app = Application(constants.APPLICATION_GENERIC, label=listener.id)
    app.add_service(m_virtual.get_path(listener.id), service)
    for pool in listener.pools:
        f5_pool = self._get_f5_pool(pool)
        for member in pool.members:
            f5_member = self._get_f5_member(member)
            f5_pool.add_member(f5_member)

        if pool.health_monitor:
            (f5_hm_name, f5_hm_obj) = self.get_f5_monitor(
                pool.health_monitor
            )
            if f5_hm_obj:
                app.add_monitor(f5_hm_name, f5_hm_obj)
                f5_pool.add_monitor({'use': f5_hm_name})
            else:
                f5_pool.add_monitor(f5_hm_name)

        app.add_pool(m_pool.get_path(pool.id), f5_pool)

    return app
"""