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
import base64
import hashlib

from octavia_f5.common import constants
from octavia_f5.restclient.as3classes import Certificate, CA_Bundle
from octavia.common.tls_utils import cert_parser
from oslo_context import context as oslo_context


def get_name(container_id):
    return "{}{}".format(constants.PREFIX_CONTAINER,
                         container_id.replace('-', '_'))


def get_container_id(listener):
    return listener.tls_certificate_id.split('/')[-1]


def _process_tls_certificates(self, listener):
    tls_cert = None
    sni_certs = []
    certs = []

    if data['tls_cert'] is not None:
        # Note, the first cert is the TLS default cert
        certs.append(tls_cert)
    if data['sni_certs']:
        certs.extend(sni_certs)

    return certs


def _get_secret(self, listener, secret_ref):
    if not secret_ref:
        return None
    context = oslo_context.RequestContext(project_id=listener.project_id)
    secret = self.cert_manager.get_secret(context, secret_ref)
    return secret.encode('utf-8')


def _get_certificate(remark, tlscontainer):
    service_args = {
        'remark': remark,
        'certificate': tlscontainer.certificate.decode('utf-8')
    }

    if tlscontainer.private_key:
        service_args['privateKey'] = tlscontainer.private_key.decode('utf-8')

    # TODO: support for intermediates
    # if tlscontainer.intermediates:

    if tlscontainer.passphrase:
        service_args['passphrase'] = {
            'ciphertext': base64.urlsafe_b64encode(tlscontainer.passphrase)
        }

    return Certificate(**service_args)


def get_certificates(listener, cert_manager):
    certificates = []
    data = cert_parser.load_certificates_data(cert_manager, listener)
    container_id = get_container_id(listener)

    # Note, the first cert is the TLS default cert
    if data['tls_cert'] is not None:
        certificates.append({
            'id': '{}{}'.format(constants.PREFIX_CERTIFICATE, data['tls_cert'].id),
            'as3': _get_certificate(
                'Container {}'.format(container_id),
                data['tls_cert'])
        })

    for sni_cert in data['sni_certs']:
        certificates.append({
            'id': '{}{}'.format(constants.PREFIX_CERTIFICATE, sni_cert.id),
            'as3': _get_certificate(
                'Container {}'.format(container_id),
                sni_cert)
        })

    return certificates


def load_secret(listener, cert_manager, secret_ref):
    if not secret_ref:
        return None
    context = oslo_context.RequestContext(project_id=listener.project_id)
    secret = cert_manager.get_secret(context, secret_ref)
    try:
        secret = secret.encode('utf-8')
    except AttributeError:
        pass
    id = hashlib.sha1(secret).hexdigest()  # nosec

    return 'secret_{}'.format(id), secret


def get_ca_bundle(bundle, remark='', label=''):
    service_args = {
        'remark': remark,
        'label': label,
        'bundle': bundle.decode('utf-8').replace('\r',  '')
    }
    return CA_Bundle(**service_args)
