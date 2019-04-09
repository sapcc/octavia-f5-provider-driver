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
import json

import requests
from requests.auth import HTTPBasicAuth
from six.moves.urllib import parse
from octavia_f5.restclient.as3exceptions import UnprocessableEntityException
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class BigipAS3RestClient(object):
    def __init__(self, bigip_url, enable_verify=True, enable_token=True,
                 physical_network=None, esd=None):
        self.bigip = parse.urlsplit(bigip_url, allow_fragments=False)
        self.enable_verify = enable_verify
        self.enable_token = enable_token
        self.token = None
        self.s = self._create_session()
        self.reauthorize()
        self.physical_network = physical_network
        self.esd = esd

    def reauthorize(self):
        # Login
        login = '/mgmt/shared/authn/login'
        credentials = {
            "username": self.bigip.username,
            "password": self.bigip.password,
            "loginProviderName": "tmos"
        }
        basicauth = HTTPBasicAuth(self.bigip.username, self.bigip.password)
        r = self.s.post(self._url(login),
                        json=credentials, auth=basicauth)
        r.raise_for_status()
        print(json.dumps(r.json(), indent=4, sort_keys=True))
        self.token = r.json()['token']['token']

        self.s.headers.update({'X-F5-Auth-Token': self.token})

        url = '/mgmt/shared/authz/tokens/{}'
        patch_timeout = {
            "timeout": "36000"
        }
        r = self.s.patch(self._url(url.format(self.token)), json=patch_timeout)
        print(json.dumps(r.json(), indent=4, sort_keys=True))

    def _url(self, path):
        return parse.urlunsplit(
            parse.SplitResult(scheme=self.bigip.scheme,
                              netloc=self.bigip.hostname,
                              path=path,
                              query='',
                              fragment='')
        )

    def _create_session(self):
        session = requests.Session()
        session.verify = self.enable_verify
        return session

    def post(self, **kwargs):
        url = '/mgmt/shared/appsvcs/declare'
        print(kwargs.get('json'))
        response = self.s.post(self._url(url), **kwargs)
        print json.dumps(json.loads(response.text), indent=4, sort_keys=True)
        if response.status_code == 422:
            raise UnprocessableEntityException(response.text)
        return response

    def patch(self, operation, path, **kwargs):
        url = '/mgmt/shared/appsvcs/declare'

        LOG.debug("Calling PATCH %s with path %s", operation, path)
        params = kwargs.copy()

        params.update({'op': operation, 'path': path})
        response = self.s.patch(self._url(url), json=[params])
        print json.dumps(json.loads(response.text), indent=4, sort_keys=True)
        #if response.status_code == 422:
        #    raise UnprocessableEntityException(response.text)

        #response.raise_for_status()
        return response

