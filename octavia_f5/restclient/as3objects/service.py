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
from octavia_f5.restclient.as3classes import Service, Service_Generic_iRules
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import application as m_app

""" Maps listener to AS3 service """


def get_name(listener_id):
    return constants.PREFIX_LISTENER + \
           listener_id.replace('/', '').replace('-', '')


def get_path(listener):
    return m_app.get_path(listener.load_balancer) + \
            '/' + get_name(listener.id)


def get_service(listener, irules):
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

    vip = listener.load_balancer.vip

    service_args = {
        '_servicetype': servicetype,
        'virtualPort': listener.protocol_port,
        'virtualAddresses': [vip.ip_address]
    }

    if listener.connection_limit > 0:
        service_args['maxConnections'] = listener.connection_limit

    if listener.default_pool_id:
        service_args['pool'] = m_pool.get_name(listener.default_pool_id)

    service_args['iRules'] = [
        Service_Generic_iRules('/Common/' + rule) for
        rule in irules
    ]

    return Service(**service_args)
