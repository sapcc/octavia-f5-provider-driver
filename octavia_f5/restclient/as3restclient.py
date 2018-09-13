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

import requests
from requests.auth import HTTPBasicAuth
from six.moves.urllib import parse

class BigipAS3RestClient(object):
    def __init__(self, bigip_url, enable_verify=True, enable_token=True):
        self.bigip = parse.urlparse(bigip_url)
        self.enable_verify = enable_verify
        self.enable_token = enable_token
        self.token = None
        self.s = self._createSession()

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

        self.s.headers.update({'X-F5-Auth-Token': '12345'})

        url = '/mgmt/shared/authz/tokens/{}'
        patch_timeout = {
            "timeout": "36000"
        }
        r = self.s.patch(self._url(url, self.token), json=patch_timeout)

    def _url(self, path, params=None):
        if not params:
            return parse.urljoin(self.bigip, path)
        else:
            return parse.urljoin(self.bigip, path.format(**params))

    def _createSession(self):
        session = requests.Session()
        session.verify = self.enable_verify
        return session