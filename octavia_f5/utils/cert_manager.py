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

import hashlib

from oslo_config import cfg
from oslo_context import context as oslo_context
from stevedore import driver as stevedore_driver

from octavia.common.tls_utils import cert_parser
from octavia_f5.common import constants
from octavia_f5.restclient.as3objects import certificate as m_cert

CONF = cfg.CONF


class CertManagerWrapper(object):
    def __init__(self):
        self.cert_manager = stevedore_driver.DriverManager(
            namespace='octavia.cert_manager',
            name=CONF.certificates.cert_manager,
            invoke_on_load=True,
        ).driver

    def get_certificates(self, obj, context=None):
        """Fetches certificates and creates dict out of octavia objects

        :param obj: octavia listener or pool object
        :param context: optional oslo_context
        :return: certificate dict
        """
        certificates = []
        cert_dict = cert_parser.load_certificates_data(self.cert_manager, obj, context)
        cert_dict['container_id'] = []
        if obj.tls_certificate_id:
            cert_dict['container_id'].append(obj.tls_certificate_id.split('/')[-1])
        if hasattr(obj, 'sni_containers') and obj.sni_containers:
            cert_dict['container_id'].extend([sni.tls_container_id.split('/')[-1]
                                              for sni in obj.sni_containers])

        # Note, the first cert is the TLS default cert
        if cert_dict['tls_cert'] is not None:
            certificates.append({
                'id': '{}{}'.format(constants.PREFIX_CERTIFICATE, cert_dict['tls_cert'].id),
                'as3': m_cert.get_certificate(
                    'Container {}'.format(', '.join(cert_dict['container_id'])),
                    cert_dict['tls_cert'])
            })

        for sni_cert in cert_dict['sni_certs']:
            certificates.append({
                'id': '{}{}'.format(constants.PREFIX_CERTIFICATE, sni_cert.id),
                'as3': m_cert.get_certificate(
                    'Container {}'.format(', '.join(cert_dict['container_id'])),
                    sni_cert)
            })

        return certificates

    def load_secret(self, project_id, secret_ref):
        """Loads secrets from secret store

        :param project_id: project_id used for request context
        :param secret_ref: secret reference to secret store
        :return: tuple of secret name and secret itself
        """
        if not secret_ref:
            return None
        context = oslo_context.RequestContext(project_id=project_id)
        secret = self.cert_manager.get_secret(context, secret_ref)
        try:
            secret = secret.encode('utf-8')
        except AttributeError:
            pass
        id = hashlib.sha1(secret).hexdigest()  # nosec

        return '{}{}'.format(constants.PREFIX_SECRET, id), secret
