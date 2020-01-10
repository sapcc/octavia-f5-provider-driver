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
from oslo_log import log as logging

from octavia.common import exceptions
from octavia_f5.common import constants as const
from octavia_f5.restclient.as3classes import Service, BigIP, Service_Generic_profileTCP, Pointer
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import certificate as m_cert
from octavia_f5.restclient.as3objects import irule as m_irule
from octavia_f5.restclient.as3objects import persist as m_persist
from octavia_f5.restclient.as3objects import policy_endpoint as m_policy
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import tls as m_tls
from octavia_lib.common import constants as lib_consts

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

""" Maps listener to AS3 service """


def get_name(listener_id):
    return const.PREFIX_LISTENER + \
           listener_id.replace('/', '').replace('-', '_')


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


def get_service(listener, cert_manager):
    entities = []
    vip = listener.load_balancer.vip
    service_args = {
        'virtualPort': listener.protocol_port,
        'virtualAddresses': [vip.ip_address],
        'persistenceMethods': [],
        'iRules': []
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
    # Proxy
    elif listener.protocol == const.PROTOCOL_PROXY:
        service_args['_servicetype'] = const.SERVICE_HTTP
        name, irule = m_irule.get_proxy_irule()
        service_args['iRules'].append(name)
        entities.append((name, irule))
    # Terminated HTTPS
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
        pool = listener.default_pool
        if pool.provisioning_status != lib_consts.PENDING_DELETE:
            default_pool = m_pool.get_name(listener.default_pool_id)
            service_args['pool'] = default_pool

            if pool.protocol == const.PROTOCOL_PROXY:
                name, irule = m_irule.get_proxy_irule()
                service_args['iRules'].append(name)
                entities.append((name, irule))
            elif pool.protocol == const.PROTOCOL_HTTPS:
                # TODO: Implement Client_TLS profile for lb -> member TLS connection
                pass

    # Insert header irules
    for name, irule in m_irule.get_header_irules(listener.insert_headers):
        service_args['iRules'].append(name)
        entities.append((name, irule))

    if listener.tls_certificate_id:
        auth_name = None
        certificates = m_cert.get_certificates(listener, cert_manager)
        if listener.client_ca_tls_certificate_id and listener.client_authentication != 'NONE':
            try:
                auth_name, secret = m_cert.load_secret(listener, cert_manager, listener.client_ca_tls_certificate_id)
                entities.append((auth_name, m_cert.get_ca_bundle(secret, auth_name, auth_name)))
            except exceptions.CertificateRetrievalException as e:
                LOG.error("Error fetching certificate: %s", e)

        entities.append((
            m_tls.get_name(listener.id),
            m_tls.get_tls_server([cert['id'] for cert in certificates], auth_name, listener.client_authentication)
        ))
        entities.extend([(cert['id'], cert['as3']) for cert in certificates])

    # session persistence
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
