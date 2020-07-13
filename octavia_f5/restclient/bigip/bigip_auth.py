# Copyright 2020 SAP SE
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
from requests.auth import HTTPBasicAuth, AuthBase
from six.moves.urllib import parse
from tenacity import *

BIGIP_TOKEN_HEADER = 'X-F5-Auth-Token'
BIGIP_TOKEN_MAX_TIMEOUT = '36000'
BIGIP_TOKENS_PATH = '/mgmt/shared/authz/tokens'
BIGIP_LOGIN_PATH = '/mgmt/shared/authn/login'


class BigIPBasicAuth(HTTPBasicAuth):
    """ A requests custom BasicAuth provider that just parses username
        and password from URL for HTTP basic authentication """
    def __init__(self, url):
        self.url = url
        parse_result = parse.urlparse(url, allow_fragments=False)
        super(BigIPBasicAuth, self).__init__(parse_result.username, parse_result.password)


class BigIPTokenAuth(AuthBase):
    """ A requests custom Auth provider that installs a response hook to detect authentication
        responses and acquires a BigIP authentication token for follow up http requests. """
    def __init__(self, url):
        self.url = url
        parse_result = parse.urlparse(url, allow_fragments=False)
        self.username = parse_result.username
        self.password = parse_result.password
        self.token = self.get_token()

    def __call__(self, r):
        def response_hook(r, *args, **kwargs):
            # This response hook will fetch a fresh token if encountered an 401
            if r.status_code == 401 or BIGIP_TOKEN_HEADER not in r.headers:
                # Requests session will auto-retry on 401
                self._token = self.get_token()

        # modify and return the request
        r.headers[BIGIP_TOKEN_HEADER] = self.token
        r.hooks['response'] = [response_hook]
        return r

    @retry(
        wait=wait_incrementing(3, 5, 10),
        stop=stop_after_attempt(3)
    )
    def get_token(self):
        """ Get F5-Auth-Token
            https://clouddocs.f5.com/products/extensions/f5-declarative-onboarding/latest/authentication.html
        """
        credentials = {
            "username": self.username,
            "password": self.password,
            "loginProviderName": "tmos"
        }
        auth = (self.username, self.password)

        r = requests.post(parse.urljoin(self.url, BIGIP_LOGIN_PATH),
                          json=credentials, auth=auth, timeout=10, verify=False)

        # Handle maximum active login tokens condition
        if r.status_code == 400 and 'maximum active login tokens' in r.text:
            # Delete all existing tokens
            requests.delete(parse.urljoin(self.url, BIGIP_TOKENS_PATH), auth=auth, timeout=10, verify=False)
            r = requests.post(parse.urljoin(self.url, BIGIP_LOGIN_PATH), json=credentials,
                              auth=auth, timeout=10, verify=False)

        r.raise_for_status()
        token = r.json()['token']['token']

        # Increase timeout to max of 10 hours
        patch_timeout = {"timeout": BIGIP_TOKEN_MAX_TIMEOUT}
        requests.patch("{}/{}".format(parse.urljoin(self.url, BIGIP_TOKENS_PATH), token),
                       auth=auth, json=patch_timeout, timeout=10, verify=False)
        return token