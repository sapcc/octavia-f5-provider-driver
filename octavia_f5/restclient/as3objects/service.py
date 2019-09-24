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

from octavia_f5.common import constants as con
from oslo_config import cfg
from octavia_f5.restclient.as3classes import Service, BigIP, Service_Generic_profileTCP, Persist
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import application as m_app

CONF = cfg.CONF

""" Maps listener to AS3 service """


def get_name(listener_id):
    return con.PREFIX_LISTENER + \
           listener_id.replace('/', '').replace('-', '')


def get_path(listener):
    return m_app.get_path(listener.load_balancer) + \
            '/' + get_name(listener.id)


def process_esd(servicetype, esd):
    service_args = {}
    irules = esd.get('lbaas_irule', None)
    if irules:
        service_args['iRules'] = [
            BigIP('/Common/' + rule) for
            rule in irules
        ]

    # client / server tcp profiles
    if servicetype in [con.SERVICE_HTTP, con.SERVICE_HTTPS,
                       con.SERVICE_TCP]:
        ctcp = esd.get('lbaas_ctcp', None)
        stcp = esd.get('lbaas_stcp', None)
        if stcp and ctcp:
            # Server and Clientside profile defined
            service_args['profileTCP'] = Service_Generic_profileTCP(
                ingress=BigIP('/Common/' + ctcp),
                egress=BigIP('/Common/' + stcp)
            )
        elif ctcp:
            service_args['profileTCP'] = BigIP('/Common/' + ctcp)
        else:
            service_args['profileTCP'] = 'normal'

    if servicetype in [con.SERVICE_HTTP, con.SERVICE_HTTPS]:
        # OneConnect (Multiplex) Profile
        oneconnect = esd.get('lbaas_one_connect', None)
        if oneconnect:
            service_args['profileMultiplex'] = BigIP(
                '/Common/' + oneconnect)

        # HTTP Compression Profile
        compression = esd.get('lbaas_http_compression', None)
        if compression:
            service_args['profileHTTPCompression'] = BigIP(
                '/Common/' + compression)

    return service_args


def get_service(listener):
    # Determine service type
    servicetype = con.SERVICE_GENERIC
    if listener.protocol == con.PROTOCOL_TCP:
        servicetype = CONF.f5_agent.tcp_service_type
    # UDP
    elif listener.protocol == con.PROTOCOL_UDP:
        servicetype = con.SERVICE_UDP
    # HTTP
    elif listener.protocol == con.PROTOCOL_HTTP:
        servicetype = con.SERVICE_HTTP
    # HTTPS
    elif listener.protocol == con.PROTOCOL_HTTPS:
        servicetype = con.SERVICE_HTTPS

    vip = listener.load_balancer.vip

    service_args = {
        '_servicetype': servicetype,
        'virtualPort': listener.protocol_port,
        'virtualAddresses': [vip.ip_address]
    }

    if listener.connection_limit > 0:
        service_args['maxConnections'] = listener.connection_limit

    # Add default pool and session persistence
    if listener.default_pool_id:
        default_pool = m_pool.get_name(listener.default_pool_id)
        persistence = listener.default_pool.session_persistence
        #lb_algorithm = listener.default_pool.lb_algorith
        lb_algorithm = 'SOURCE_IP'

        service_args['pool'] = default_pool

        # lb algorithm rules them all
        if lb_algorithm == 'SOURCE_IP':
            service_args['persistenceMethods'] = ['source-address']
        elif persistence.type == 'HTTP_COOKIE':
            service_args['persistenceMethods'] = ['cookie']
        elif persistence.type == 'SOURCE_IP':
            # TODO: add persistence_timeout and/or persistence_granularity
            service_args['persistenceMethods'] = ['source-address']
        elif persistence.type == 'APP_COOKIE':
            service_args['persistenceMethods'] = Persist(
                persistenceMethod='cookie',
                cookieName=persistence.cookie_name
            )

    return Service(**service_args)

def get_service_profiles(l7policy):
    pass