# Copyright 2019 SAP SE
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
from octavia_f5.restclient.as3classes import TLS_Server, TLS_Client, Pointer
from oslo_config import cfg

CONF = cfg.CONF


def get_listener_name(listener_id):
    """Returns AS3 object name for TLS profiles related to listeners

    :param listener_id: octavia listener id
    :return: AS3 object name
    """
    return "{}{}".format(constants.PREFIX_TLS_LISTENER, listener_id)


def get_pool_name(pool_id):
    """Returns AS3 object name for TLS profiles related to pools

    :param pool_id: octavia pool id
    :return: AS3 object name
    """
    return "{}{}".format(constants.PREFIX_TLS_POOL, pool_id)


def get_tls_server(certificate_ids, authentication_ca=None, authentication_mode='NONE'):
    """ returns AS3 TLS_Server

    :param certificate_ids: reference ids to AS3 certificate objs
    :param authentication_ca: reference id to AS3 auth-ca obj
    :param authentication_mode: reference id to AS3 auth-mode
    :return: TLS_Server
    """
    mode_map = {
        'NONE': 'ignore',
        'OPTIONAL': 'request',
        'MANDATORY': 'require'
    }

    service_args = {
        'certificates': [{'certificate': cert_id} for cert_id in set(certificate_ids)]
    }

    if authentication_ca:
        service_args['authenticationTrustCA'] = authentication_ca
        service_args['authenticationInviteCA'] = authentication_ca
        service_args['authenticationMode'] = mode_map[authentication_mode]

    if CONF.f5_tls_server.default_ciphers:
        service_args['ciphers'] = CONF.f5_tls_server.default_ciphers

    if CONF.f5_tls_server.forward_proxy_bypass is not None:
        service_args['forwardProxyBypassEnabled'] = CONF.f5_tls_server.forward_proxy_bypass
    if CONF.f5_tls_server.forward_proxy is not None:
        service_args['forwardProxyEnabled'] = CONF.f5_tls_server.forward_proxy
    if CONF.f5_tls_server.insert_empty_fragments is not None:
        service_args['insertEmptyFragmentsEnabled'] = CONF.f5_tls_server.insert_empty_fragments
    if CONF.f5_tls_server.single_use_dh is not None:
        service_args['singleUseDhEnabled'] = CONF.f5_tls_server.single_use_dh
    if CONF.f5_tls_server.tls_1_0 is not None:
        service_args['tls1_0Enabled'] = CONF.f5_tls_server.tls_1_0
    if CONF.f5_tls_server.tls_1_1 is not None:
        service_args['tls1_1Enabled'] = CONF.f5_tls_server.tls_1_1
    if CONF.f5_tls_server.tls_1_2 is not None:
        service_args['tls1_2Enabled'] = CONF.f5_tls_server.tls_1_2
    if CONF.f5_tls_server.tls_1_3 is not None:
        service_args['tls1_3Enabled'] = CONF.f5_tls_server.tls_1_3
    if CONF.f5_tls_server.cache_certificate is not None:
        service_args['cacheCertificateEnabled'] = CONF.f5_tls_server.cache_certificate
    if CONF.f5_tls_server.stapler_ocsp is not None:
        service_args['staplerOCSPEnabled'] = CONF.f5_tls_server.stapler_ocsp

    return TLS_Server(**service_args)


def get_tls_client(trust_ca=None, client_cert=None, crl_file=None):
    """ returns AS3 TLS_Client

    :param trust_ca: reference to AS3 trust_ca obj
    :param client_cert: reference to AS3 client_cert
    :param crl_file: reference to AS3 crl_file
    :return: TLS_Client
    """
    service_args = dict()
    if trust_ca:
        service_args['trustCA'] = Pointer(trust_ca)
        service_args['validateCertificate'] = True
    if client_cert:
        service_args['clientCertificate'] = client_cert
    if crl_file:
        service_args['crlFile'] = crl_file

    if CONF.f5_tls_client.default_ciphers:
        service_args['ciphers'] = CONF.f5_tls_client.default_ciphers

    if CONF.f5_tls_client.forward_proxy_bypass is not None:
        service_args['forwardProxyBypassEnabled'] = CONF.f5_tls_client.forward_proxy_bypass
    if CONF.f5_tls_client.forward_proxy is not None:
        service_args['forwardProxyEnabled'] = CONF.f5_tls_client.forward_proxy
    if CONF.f5_tls_client.insert_empty_fragments is not None:
        service_args['insertEmptyFragmentsEnabled'] = CONF.f5_tls_client.insert_empty_fragments
    if CONF.f5_tls_client.single_use_dh is not None:
        service_args['singleUseDhEnabled'] = CONF.f5_tls_client.single_use_dh
    if CONF.f5_tls_client.tls_1_0 is not None:
        service_args['tls1_0Enabled'] = CONF.f5_tls_client.tls_1_0
    if CONF.f5_tls_client.tls_1_1 is not None:
        service_args['tls1_1Enabled'] = CONF.f5_tls_client.tls_1_1
    if CONF.f5_tls_client.tls_1_2 is not None:
        service_args['tls1_2Enabled'] = CONF.f5_tls_client.tls_1_2
    if CONF.f5_tls_client.tls_1_3 is not None:
        service_args['tls1_3Enabled'] = CONF.f5_tls_client.tls_1_3

    return TLS_Client(**service_args)
