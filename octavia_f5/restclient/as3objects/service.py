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
from oslo_config import cfg

from octavia_f5.common import constants as const
from octavia_f5.restclient.as3classes import Service, BigIP, Service_Generic_profileTCP, Persist, Pointer
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import policy_endpoint as m_policy
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import tls as m_tls
from octavia_f5.restclient.as3objects import persist as m_persist
from octavia_lib.common import constants as lib_consts

CONF = cfg.CONF

""" Maps listener to AS3 service """


def get_name(listener_id):
    return const.PREFIX_LISTENER + \
           listener_id.replace('/', '').replace('-', '_')


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
    if servicetype in [const.SERVICE_HTTP, const.SERVICE_HTTPS,
                       const.SERVICE_TCP]:
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

    if servicetype in [const.SERVICE_HTTP, const.SERVICE_HTTPS]:
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
    entities = []
    vip = listener.load_balancer.vip
    service_args = {
        'virtualPort': listener.protocol_port,
        'virtualAddresses': [vip.ip_address],
        'persistenceMethods': [],
    }

    if listener.description:
        service_args['label'] = listener.description

    # Determine service type
    if listener.protocol == const.PROTOCOL_TCP:
        service_args['_servicetype'] = CONF.f5_agent.tcp_service_type
    # UDP
    elif listener.protocol == const.PROTOCOL_UDP:
        service_args['_servicetype'] = const.SERVICE_UDP
    # HTTP
    elif listener.protocol == const.PROTOCOL_HTTP:
        service_args['_servicetype'] = const.SERVICE_HTTP
    # HTTPS (non-terminated)
    elif listener.protocol == const.PROTOCOL_HTTPS:
        service_args['_servicetype'] = const.SERVICE_GENERIC
    elif listener.protocol == const.PROTOCOL_TERMINATED_HTTPS:
        service_args['_servicetype'] = const.SERVICE_HTTPS
        service_args['serverTLS'] = m_tls.get_name(listener.id)
        service_args['redirect80'] = False

    if CONF.f5_agent.profile_l4:
        service_args['profileL4'] = BigIP(CONF.f5_agent.profile_l4)
    if CONF.f5_agent.profile_multiplex:
        service_args['profileMultiplex'] = BigIP(CONF.f5_agent.profile_multiplex)

    if listener.connection_limit > 0:
        service_args['maxConnections'] = listener.connection_limit

    # Add default pool
    if listener.default_pool_id:
        default_pool = m_pool.get_name(listener.default_pool_id)
        service_args['pool'] = default_pool

    #  session persistence
    if listener.default_pool_id and listener.default_pool.session_persistence:
        persistence = listener.default_pool.session_persistence
        lb_algorithm = listener.default_pool.lb_algorithm

        if persistence.type == 'APP_COOKIE':
            name, obj_persist = m_persist.get_app_cookie(persistence.cookie_name)
            service_args['persistenceMethods'] = [Pointer(name)]
            entities.append((name, obj_persist))
            if lb_algorithm == 'SOURCE_IP':
                service_args['fallbackPersistenceMethod'] = 'source-address'

        elif persistence.type == 'SOURCE_IP':
            if not persistence.persistence_timeout and not persistence.persistence_granularity:
                service_args['persistenceMethods'] = ['source-address']
            else:
                name, obj_persist = m_persist.get_source_ip(
                    persistence.persistence_timeout,
                    persistence.persistence_granularity
                )
                service_args['persistenceMethods'] = [Pointer(name)]
                entities.append((name, obj_persist))

        elif persistence.type == 'HTTP_COOKIE':
            service_args['persistenceMethods'] = ['cookie']
            if lb_algorithm == 'SOURCE_IP':
                service_args['fallbackPersistenceMethod'] = 'source-address'

    if listener.l7policies:
        service_args['policyEndpoint'] = [
            m_policy.get_name(l7policy.id) for l7policy in listener.l7policies
            if l7policy.provisioning_status != lib_consts.PENDING_DELETE
        ]

    service = Service(**service_args)
    entities.append((get_name(listener.id), service))
    return entities
