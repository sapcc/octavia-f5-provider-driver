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

from octavia_f5.common import constants
from octavia_f5.restclient import as3types
from octavia_f5.restclient.as3classes import Certificate, CA_Bundle


def get_name(container_id):
    """Return AS3 object name for type certificate

    :param container_id: container_id of barbican container
    :return: AS3 object name
    """
    return "{}{}".format(constants.PREFIX_CONTAINER, container_id)


def get_certificate(remark, tlscontainer):
    """Get AS3 Certificate object.

    :param remark: comment
    :param tlscontainer: tls container to create certificate object from
    :return: AS3 Certificate
    """
    def _decode(pem):
        try:
            return pem.decode('utf-8').replace('\r', '')
        except AttributeError:
            return pem.replace('\r', '')


    # TLS certificate is always the first one
    certificates = [_decode(tlscontainer.certificate)]

    for intermediate in tlscontainer.intermediates:
        intermediate = _decode(intermediate)
        if intermediate not in certificates:
            certificates.append(intermediate)

    service_args = {
        'remark': as3types.f5remark(remark),
        'certificate': '\n'.join(certificates)
    }

    if tlscontainer.private_key:
        service_args['privateKey'] = _decode(tlscontainer.private_key)

    if tlscontainer.passphrase:
        service_args['passphrase'] = {
            'ciphertext': base64.urlsafe_b64encode(tlscontainer.passphrase)
        }

    return Certificate(**service_args)


def get_ca_bundle(bundle, remark='', label=''):
    """AS3 Certificate Authority Bundle object.

    :param bundle: the CA certificate bundle as PEM encoded bytes
    :param remark: comment
    :param label: label
    :return: AS3 CA_Bundle
    """
    service_args = {
        'remark': as3types.f5remark(remark),
        'label': as3types.f5label(label),
        'bundle': bundle.decode('utf-8').replace('\r',  '')
    }
    return CA_Bundle(**service_args)
