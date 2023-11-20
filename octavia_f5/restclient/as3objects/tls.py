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

from oslo_config import cfg
from oslo_log import log as logging

from octavia_lib.common import constants as lib_consts
from octavia.common import validate
from octavia_f5.common import constants
from octavia_f5.restclient.as3classes import TLS_Server, TLS_Client, Pointer

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


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


def filter_cipher_suites(cipher_suites, object_print_name, object_id):
    """Filter out cipher suites according to blocklist and allowlist.

    This is necessary, because there can be invalid cipher suites if e.g. a
    previously allowed cipher suite was added to the blocklist recently and
    listeners/pools using the cipher suite already existed.

    :param cipher_suites: String containing colon-separated list of cipher suites.
    :param object_print_name: A printable representation of the object to be logged, e.g. "Listener" or "Pool".
    :param object_id: ID of the object the cipher suites belong to. This is used for logging, so it should be a string.
    :return String containing colon-separated list of non-blocked/allowed cipher suites.
    """

    blocked_cipher_suites = validate.check_cipher_prohibit_list(cipher_suites)
    disallowed_cipher_suites = validate.check_cipher_allow_list(cipher_suites)
    rejected_cipher_suites = list(set(blocked_cipher_suites + disallowed_cipher_suites))

    cipher_suites_list = cipher_suites.split(':')
    if rejected_cipher_suites:
        LOG.error("{} object with ID {} has invalid cipher suites which won't be provisioned: {}"
                  .format(object_print_name, object_id, ', '.join(rejected_cipher_suites)))
        for c in rejected_cipher_suites:
            cipher_suites_list.remove(c)

    return ':'.join(cipher_suites_list)


def get_tls_server(certificate_ids, listener, authentication_ca=None, allow_renegotiation=True, cipher_group=None):
    """ returns AS3 TLS_Server

    :param certificate_ids: reference ids to AS3 certificate objs
    :param listener: Listener object
    :param authentication_ca: reference id to AS3 auth-ca obj
    :param allow_renegotiation: Whether to allow TLS renegotiation. Has to be False when HTTP2 is used.
    :param cipher_group: name of Cipher Group has to be used for this listener
    :return: TLS_Server
    """
    mode_map = {
        'NONE': 'ignore',
        'OPTIONAL': 'request',
        'MANDATORY': 'require'
    }

    service_args = {
        'certificates': [{'certificate': cert_id} for cert_id in set(certificate_ids)],
    }

    if cipher_group:
        service_args['cipherGroup'] = {'use': cipher_group}

    if authentication_ca:
        service_args['authenticationTrustCA'] = authentication_ca
        service_args['authenticationInviteCA'] = authentication_ca
        service_args['authenticationMode'] = mode_map[listener.client_authentication]

    if CONF.f5_tls_server.forward_proxy_bypass is not None:
        service_args['forwardProxyBypassEnabled'] = CONF.f5_tls_server.forward_proxy_bypass
    if CONF.f5_tls_server.forward_proxy is not None:
        service_args['forwardProxyEnabled'] = CONF.f5_tls_server.forward_proxy
    if CONF.f5_tls_server.insert_empty_fragments is not None:
        service_args['insertEmptyFragmentsEnabled'] = CONF.f5_tls_server.insert_empty_fragments
    if CONF.f5_tls_server.single_use_dh is not None:
        service_args['singleUseDhEnabled'] = CONF.f5_tls_server.single_use_dh
    if CONF.f5_tls_server.cache_certificate is not None:
        service_args['cacheCertificateEnabled'] = CONF.f5_tls_server.cache_certificate
    if CONF.f5_tls_server.stapler_ocsp is not None:
        service_args['staplerOCSPEnabled'] = CONF.f5_tls_server.stapler_ocsp

    # LBs created before Ussuri may have TLS-enabled listeners with no tls_versions specified
    tls_versions = listener.tls_versions or CONF.api_settings.default_listener_tls_versions

    # Set TLS versions
    # Enable/Disable all SSL versions at once
    service_args['sslEnabled'] = lib_consts.SSL_VERSION_3 in tls_versions
    service_args['tls1_0Enabled'] = lib_consts.TLS_VERSION_1 in tls_versions
    # Note: tls_1_1 is only supported in tmos version 14.0+
    service_args['tls1_1Enabled'] = lib_consts.TLS_VERSION_1_1 in tls_versions
    service_args['tls1_2Enabled'] = lib_consts.TLS_VERSION_1_2 in tls_versions
    service_args['tls1_3Enabled'] = lib_consts.TLS_VERSION_1_3 in tls_versions
    # Control Renegotiation depends on HTTP2
    service_args['renegotiationEnabled'] = allow_renegotiation

    return TLS_Server(**service_args)


def get_tls_client(pool, trust_ca=None, client_cert=None, crl_file=None, allow_renegotiation=True, cipher_group=None):
    """ returns AS3 TLS_Client

    :param pool: The pool for which to create the TLS client
    :param trust_ca: reference to AS3 trust_ca obj
    :param client_cert: reference to AS3 client_cert
    :param crl_file: reference to AS3 crl_file
    :param allow_renegotiation: Whether to allow TLS renegotiation. Has to be False when HTTP2 is used.
    :param cipher_group: name of Cipher Group has to be used for this pool
    :return: TLS_Client
    """

    service_args = {}

    if cipher_group:
        service_args['cipherGroup'] = {'use': cipher_group}

    if trust_ca:
        service_args['trustCA'] = Pointer(trust_ca)
        service_args['validateCertificate'] = True
    if client_cert:
        service_args['clientCertificate'] = client_cert
    if crl_file:
        service_args['crlFile'] = crl_file

    if CONF.f5_tls_client.forward_proxy_bypass is not None:
        service_args['forwardProxyBypassEnabled'] = CONF.f5_tls_client.forward_proxy_bypass
    if CONF.f5_tls_client.forward_proxy is not None:
        service_args['forwardProxyEnabled'] = CONF.f5_tls_client.forward_proxy
    if CONF.f5_tls_client.insert_empty_fragments is not None:
        service_args['insertEmptyFragmentsEnabled'] = CONF.f5_tls_client.insert_empty_fragments
    if CONF.f5_tls_client.single_use_dh is not None:
        service_args['singleUseDhEnabled'] = CONF.f5_tls_client.single_use_dh

    # LBs created before Ussuri may have TLS-enabled pools with no tls_versions specified
    tls_versions = pool.tls_versions or CONF.api_settings.default_pool_tls_versions

    # Set TLS versions
    # Enable/Disable all SSL versions at once
    service_args['sslEnabled'] = lib_consts.SSL_VERSION_3 in tls_versions
    service_args['tls1_0Enabled'] = lib_consts.TLS_VERSION_1 in tls_versions
    # Note: tls_1_1 is only supported in tmos version 14.0+
    service_args['tls1_1Enabled'] = lib_consts.TLS_VERSION_1_1 in tls_versions
    service_args['tls1_2Enabled'] = lib_consts.TLS_VERSION_1_2 in tls_versions
    service_args['tls1_3Enabled'] = lib_consts.TLS_VERSION_1_3 in tls_versions
    # Control Renegotiation depends on HTTP2
    service_args['renegotiationEnabled'] = allow_renegotiation

    return TLS_Client(**service_args)
