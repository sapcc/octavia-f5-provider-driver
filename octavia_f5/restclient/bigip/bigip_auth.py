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

from urllib import parse

import requests
import tenacity
from requests.auth import HTTPBasicAuth, AuthBase

BIGIP_TOKEN_HEADER = 'X-F5-Auth-Token'
BIGIP_TOKEN_HEADER_F5OS_A = 'X-Auth-Token'
BIGIP_TOKEN_MAX_TIMEOUT = '36000'
BIGIP_TOKENS_PATH = '/mgmt/shared/authz/tokens'
BIGIP_LOGIN_PATH = '/mgmt/shared/authn/login'
BIGIP_LOGIN_PATH_F5OS_A = '/api/data/openconfig-system:system/aaa'


class BigIPBasicAuth(HTTPBasicAuth):
    """ A requests custom BasicAuth provider that just parses username
        and password from URL for HTTP basic authentication """
    def __init__(self, url):
        self.url = url
        parse_result = parse.urlparse(url, allow_fragments=False)
        super().__init__(parse_result.username, parse.unquote(parse_result.password))


class BigIPTokenAuth(AuthBase):
    """ A requests custom Auth provider that installs a response hook to detect authentication
        responses and acquires a BigIP authentication token for follow up http requests. """

    def __init__(self, url, f5os_a=False):
        """The f5os_a parameter defines whether we're talking to a F5OS-A API, which is used on rSeries devices. It
        must be supplied by the caller, because this class is instantiated for both, communication with BigIP guests
        and hosts, and they might use different APIs."""
        self.url = url
        parse_result = parse.urlparse(url, allow_fragments=False)
        self.username = parse_result.username
        self.password = parse.unquote(parse_result.password)
        self.f5os_a = f5os_a
        # Use single global token
        self.token = None
        self._token_endpoint = BIGIP_LOGIN_PATH if not f5os_a else BIGIP_LOGIN_PATH_F5OS_A
        self._token_header = BIGIP_TOKEN_HEADER if not f5os_a else BIGIP_TOKEN_HEADER_F5OS_A

    def handle_401(self, r, **kwargs):
        """ This response hook will fetch a fresh token if encountered an 401 response code.
            It's loosely based on requests digest auth.

        :return: requests.Response
        """
        if r.status_code != 401:
            return r

        # Consume content and release the original connection
        # to allow our new request to reuse the same one.
        # pylint: disable=pointless-statement
        # noinspection PyStatementEffect
        r.content
        r.raw.release_conn()
        prep = r.request.copy()
        prep.headers[self._token_header] = self.get_token()

        _r = r.connection.send(prep, **kwargs)
        _r.history.append(r)
        _r.request = prep

        return _r

    def __call__(self, r):
        # No token, no fun
        if self.token:
            r.headers[self._token_header] = self.token

        # handle 401 case
        r.register_hook('response', self.handle_401)
        return r

    @tenacity.retry(
        wait=tenacity.wait_incrementing(3, 5, 10),
        stop=tenacity.stop_after_attempt(3)
    )
    def get_token(self):
        """ Get F5-Auth-Token
            https://clouddocs.f5.com/products/extensions/f5-declarative-onboarding/latest/authentication.html
        """

        credentials = {
            "username": self.username,
            "password": self.password,
        }
        if not self.f5os_a:
            credentials["loginProviderName"] = "tmos"
        auth = (self.username, self.password)

        token_request_args = [parse.urljoin(self.url, self._token_endpoint)]
        token_request_kwargs = {"json": credentials, "auth": auth, "timeout": 10, "verify": False}
        if self.f5os_a:
            r = requests.head(*token_request_args, **token_request_kwargs)
        else:
            r = requests.post(*token_request_args, **token_request_kwargs)

        # Handle maximum active login tokens condition
        if not self.f5os_a and r.status_code == 400 and 'maximum active login tokens' in r.text:
            # Delete all existing tokens
            requests.delete(parse.urljoin(self.url, BIGIP_TOKENS_PATH), auth=auth, timeout=10, verify=False)
            r = requests.post(parse.urljoin(self.url, self._token_endpoint), json=credentials,
                              auth=auth, timeout=10, verify=False)

        # Check response code
        r.raise_for_status()

        # extract token from response
        if self.f5os_a:
            token = r.headers[self._token_header]
        else:
            token = r.json()['token']['token']

        # Increase timeout to max of 10 hours
        if not self.f5os_a:
            patch_timeout = {"timeout": BIGIP_TOKEN_MAX_TIMEOUT}
            requests.patch(f"{parse.urljoin(self.url, BIGIP_TOKENS_PATH)}/{token}",
                           auth=auth, json=patch_timeout, timeout=10, verify=False)

        # Store and return token
        self.token = token
        return token
