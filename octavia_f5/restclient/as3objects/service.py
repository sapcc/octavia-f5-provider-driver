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

from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import exceptions
from octavia_f5.common import constants as const
from octavia_f5.restclient import as3classes as as3, as3types
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import certificate as m_cert
from octavia_f5.restclient.as3objects import irule as m_irule
from octavia_f5.restclient.as3objects import persist as m_persist
from octavia_f5.restclient.as3objects import policy_endpoint as m_policy
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import tls as m_tls

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

""" Maps listener to AS3 service """


def get_name(listener_id):
    """Return AS3 object name for type listener

    :param listener_id: listener id
    :return: AS3 object name
    """
    return "{}{}".format(const.PREFIX_LISTENER, listener_id)


def get_esd_entities(servicetype, esd):
    """
    Map F5 ESD (Enhanced Service Definition) to service components.

    :param servicetype: as3 service type
    :param esd: parsed ESD repository
    :return: AS3 service flags according to ESD definition
    """
    service_args = {}
    irules = esd.get('lbaas_irule', None)
    if irules:
        service_args['iRules'] = [as3.BigIP(rule) for rule in irules]

    # client / server tcp profiles
    if servicetype in [const.SERVICE_HTTP, const.SERVICE_HTTPS,
                       const.SERVICE_TCP, const.SERVICE_L4]:
        ctcp = esd.get('lbaas_ctcp', None)
        stcp = esd.get('lbaas_stcp', None)
        if stcp and ctcp:
            # Server and Clientside profile defined
            service_args['profileTCP'] = as3.Service_Generic_profileTCP(
                ingress=as3.BigIP(ctcp),
                egress=as3.BigIP(stcp)
            )
        elif ctcp:
            service_args['profileTCP'] = as3.BigIP(ctcp)
        else:
            service_args['profileTCP'] = 'normal'

    if servicetype in [const.SERVICE_HTTP, const.SERVICE_HTTPS]:
        # OneConnect (Multiplex) Profile
        oneconnect = esd.get('lbaas_one_connect', None)
        if oneconnect:
            service_args['profileMultiplex'] = as3.BigIP(oneconnect)

        # HTTP Compression Profile
        compression = esd.get('lbaas_http_compression', None)
        if compression:
            service_args['profileHTTPCompression'] = as3.BigIP(compression)

    return service_args


def get_service(listener, cert_manager, esd_repository):
    """ Map Octavia listener -> AS3 Service

    :param listener: Octavia listener
    :param cert_manager: cert_manager wrapper instance
    :return: AS3 Service + additional AS3 application objects
    """

    # Entities is a list of tuples, which each describe AS3 objects
    # which may reference each other but do not form a hierarchy.
    entities = []
    vip = listener.load_balancer.vip
    project_id = listener.load_balancer.project_id
    label = as3types.f5label(listener.name or listener.description)
    virtual_address = '{}/32'.format(vip.ip_address)
    service_args = {
        'virtualPort': listener.protocol_port,
        'persistenceMethods': [],
        'iRules': [],
        'policyEndpoint': [],
        'label': label
    }

    # Custom virtual address settings
    if CONF.f5_agent.service_address_icmp_echo:
        service_address = as3.ServiceAddress(virtualAddress=virtual_address,
                                             icmpEcho=CONF.f5_agent.service_address_icmp_echo)
        entities.append((m_app.get_name(listener.load_balancer.id), service_address))
        service_args['virtualAddresses'] = [[as3.Pointer(m_app.get_name(listener.load_balancer.id)), virtual_address]]
    else:
        service_args['virtualAddresses'] = [virtual_address]

    # Determine service type
    if listener.protocol == const.PROTOCOL_TCP:
        service_args['_servicetype'] = CONF.f5_agent.tcp_service_type
    # UDP
    elif listener.protocol == const.PROTOCOL_UDP:
        service_args['_servicetype'] = const.SERVICE_UDP
    # HTTP
    elif listener.protocol == const.PROTOCOL_HTTP:
        service_args['_servicetype'] = const.SERVICE_HTTP
    # HTTPS (non-terminated, forward TCP traffic)
    elif listener.protocol == const.PROTOCOL_HTTPS:
        service_args['_servicetype'] = CONF.f5_agent.tcp_service_type
    # Proxy
    elif listener.protocol == const.PROTOCOL_PROXY:
        service_args['_servicetype'] = const.SERVICE_TCP
        name, irule = m_irule.get_proxy_irule()
        service_args['iRules'].append(name)
        entities.append((name, irule))
    # Terminated HTTPS
    elif listener.protocol == const.PROTOCOL_TERMINATED_HTTPS:
        service_args['_servicetype'] = const.SERVICE_HTTPS
        service_args['serverTLS'] = m_tls.get_listener_name(listener.id)
        service_args['redirect80'] = False

        # Certificate Handling
        auth_name = None
        certificates = cert_manager.get_certificates(listener)
        if listener.client_ca_tls_certificate_id and listener.client_authentication != 'NONE':
            # Client Side Certificates
            try:
                auth_name, secret = cert_manager.load_secret(project_id, listener.client_ca_tls_certificate_id)
                entities.append((auth_name, m_cert.get_ca_bundle(secret, auth_name, auth_name)))
            except exceptions.CertificateRetrievalException as e:
                LOG.error("Error fetching certificate: %s", e)

        entities.append((
            m_tls.get_listener_name(listener.id),
            m_tls.get_tls_server([cert['id'] for cert in certificates], auth_name, listener.client_authentication)
        ))
        entities.extend([(cert['id'], cert['as3']) for cert in certificates])

    if listener.connection_limit > 0:
        service_args['maxConnections'] = listener.connection_limit

    # Add default pool
    if listener.default_pool_id:
        pool = listener.default_pool
        if pool.provisioning_status != lib_consts.PENDING_DELETE:
            default_pool = m_pool.get_name(listener.default_pool_id)
            service_args['pool'] = default_pool

            # only consider Proxy pool, everything else is determined by listener type
            if pool.protocol == const.PROTOCOL_PROXY:
                name, irule = m_irule.get_proxy_irule()
                service_args['iRules'].append(name)
                entities.append((name, irule))

        # Pool member certificate handling (TLS backends)
        if pool.tls_enabled and listener.protocol in \
                [ const.PROTOCOL_PROXY, const.PROTOCOL_HTTP, const.PROTOCOL_TERMINATED_HTTPS ]:
            client_cert = None
            trust_ca = None
            crl_file = None

            service_args['clientTLS'] = m_tls.get_pool_name(pool.id)
            certificates = cert_manager.get_certificates(pool)
            if len(certificates) == 1:
                cert = certificates.pop()
                entities.append((cert['id'], cert['as3']))
                client_cert = cert['id']

            if pool.ca_tls_certificate_id:
                trust_ca, secret = cert_manager.load_secret(
                    project_id, pool.ca_tls_certificate_id)
                entities.append((trust_ca, m_cert.get_ca_bundle(
                    secret, trust_ca, trust_ca)))

            if pool.crl_container_id:
                # TODO: CRL currently not supported
                pass

            entities.append((
                m_tls.get_pool_name(pool.id),
                m_tls.get_tls_client(
                    trust_ca=trust_ca,
                    client_cert=client_cert,
                    crl_file=crl_file
                )
            ))

    # Insert header irules
    if service_args['_servicetype'] in const.SERVICE_HTTP_TYPES:
        # HTTP profiles only
        for name, irule in m_irule.get_header_irules(listener.insert_headers):
            service_args['iRules'].append(name)
            entities.append((name, irule))

    # session persistence
    if listener.default_pool_id and listener.default_pool.session_persistence:
        persistence = listener.default_pool.session_persistence
        lb_algorithm = listener.default_pool.lb_algorithm

        if service_args['_servicetype'] in const.SERVICE_HTTP_TYPES:
            # Add APP_COOKIE / HTTP_COOKIE persistance only in HTTP profiles
            if persistence.type == 'APP_COOKIE' and persistence.cookie_name:
                # generate iRule for cookie_name
                escaped_cookie = persistence.cookie_name
                escaped_cookie.replace("\"", "")
                irule_name, irule = m_irule.get_app_cookie_irule(escaped_cookie)
                entities.append((irule_name, irule))

                # add iRule to universal persistance profile
                name, obj_persist = m_persist.get_app_cookie(escaped_cookie)
                service_args['persistenceMethods'] = [as3.Pointer(name)]
                entities.append((name, obj_persist))
                if lb_algorithm == 'SOURCE_IP':
                    service_args['fallbackPersistenceMethod'] = 'source-address'

            elif persistence.type == 'HTTP_COOKIE':
                service_args['persistenceMethods'] = ['cookie']
                if lb_algorithm == 'SOURCE_IP':
                    service_args['fallbackPersistenceMethod'] = 'source-address'

        if persistence.type == 'SOURCE_IP':
            if not persistence.persistence_timeout and not persistence.persistence_granularity:
                service_args['persistenceMethods'] = ['source-address']
            else:
                name, obj_persist = m_persist.get_source_ip(
                    persistence.persistence_timeout,
                    persistence.persistence_granularity
                )
                service_args['persistenceMethods'] = [as3.Pointer(name)]
                entities.append((name, obj_persist))


    # Map listener tags to ESDs
    for tag in listener.tags:

        # get ESD of same name
        esd = esd_repository.get_esd(tag)
        if esd is None:
            continue

        # enrich service with iRules and other things defined in ESD
        esd_entities = get_esd_entities(service_args['_servicetype'], esd)
        for entity_name in esd_entities:
            if entity_name == 'iRules':
                service_args['iRules'].extend(esd_entities['iRules'])
            else:
                service_args[entity_name] = esd_entities[entity_name]

    endpoint_policies = []
    # Map special L7policies to ESDs
    # TODO: Remove this as soon as all customers have migrated their scripts.
    # Triggering ESDs via L7policies is considered deprecated. Tags should be used instead. See the code above.
    for policy in listener.l7policies:
        # get ESD of same name
        esd = esd_repository.get_esd(policy.name)

        # Add ESD or regular endpoint policy
        if esd:
            # enrich service with iRules and other things defined in ESD
            esd_entities = get_esd_entities(service_args['_servicetype'], esd)
            for entity_name in esd_entities:
                if entity_name == 'iRules':
                    service_args['iRules'].extend(esd_entities['iRules'])
                else:
                    service_args[entity_name] = esd_entities[entity_name]
        elif policy.provisioning_status != lib_consts.PENDING_DELETE:
            endpoint_policies.append(policy)

    # UDP listener won't support policies
    if endpoint_policies and not service_args['_servicetype'] == const.SERVICE_UDP:
        # add a regular endpoint policy
        policy_name = m_policy.get_wrapper_name(listener.id)

        # make endpoint policy object
        endpoint_policy = (policy_name, m_policy.get_endpoint_policy(endpoint_policies))
        entities.append(endpoint_policy)

        # reference endpoint policy object in service
        service_args['policyEndpoint'].append(policy_name)

    # Ensure no duplicate iRules
    service_args['iRules'] = list(set(service_args['iRules']))

    # fastL4 profile doesn't support iRules or custom TCP profiles,
    # fallback to TCP Service when iRules/Profiles detected
    if service_args['_servicetype'] == const.SERVICE_L4 and (
            len(service_args['iRules']) > 0 or 'profileTCP' in service_args):
        service_args['_servicetype'] = const.SERVICE_TCP

    # add default profiles to supported listeners
    if CONF.f5_agent.profile_http and service_args['_servicetype'] in const.SERVICE_HTTP_TYPES:
        if 'profileHTTP' not in service_args:
            service_args['profileHTTP'] = as3.BigIP(CONF.f5_agent.profile_http)
    if CONF.f5_agent.profile_l4 and service_args['_servicetype'] == const.SERVICE_L4:
        if 'profileL4' not in service_args:
            service_args['profileL4'] = as3.BigIP(CONF.f5_agent.profile_l4)
    if CONF.f5_agent.profile_tcp and service_args['_servicetype'] in const.SERVICE_TCP_TYPES:
        if 'profileTCP' not in service_args:
            service_args['profileTCP'] = as3.BigIP(CONF.f5_agent.profile_tcp)
    if CONF.f5_agent.profile_udp and service_args['_servicetype'] == const.SERVICE_UDP:
        if 'profileUDP' not in service_args:
            service_args['profileUDP'] = as3.BigIP(CONF.f5_agent.profile_udp)

    # Use the virtual-server address as SNAT address
    if CONF.f5_agent.snat_virtual:
        service_args['snat'] = 'self'

    # create service object and fill in additional fields
    service = as3.Service(**service_args)

    # add service to entities and return
    entities.append((get_name(listener.id), service))
    return entities
