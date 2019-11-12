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

import functools
import requests
from oslo_log import log as logging
from requests import HTTPError
from requests.auth import HTTPBasicAuth
from six.moves.urllib import parse
from tenacity import *

LOG = logging.getLogger(__name__)
RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5

AS3_LOGIN_PATH = '/mgmt/shared/authn/login'
AS3_TOKENS_PATH = '/mgmt/shared/authz/tokens/{}'
AS3_DECLARE_PATH = '/mgmt/shared/appsvcs/declare'


class BigipAS3RestClient(object):
    def __init__(self, bigip_url, enable_verify=True, enable_token=True,
                 physical_network=None, esd=None):
        self.bigip = parse.urlsplit(bigip_url, allow_fragments=False)
        self.enable_verify = enable_verify
        self.enable_token = enable_token
        self.token = None
        self.s = self._create_session()
        self.physical_network = physical_network
        self.esd = esd

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

    def _authorized(self, response):
        if response.status_code == 401:
            self.reauthorize()

    def authorized(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except HTTPError as e:
                if e.response.status_code == 401:
                    self.reauthorize()
                    return func(self, *args, **kwargs)
                else:
                    raise(e)
        return wrapper

    @retry(
        retry=retry_if_exception_type(HTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS),
    )
    def reauthorize(self):
        # Login
        credentials = {
            "username": self.bigip.username,
            "password": self.bigip.password,
            "loginProviderName": "tmos"
        }
        basicauth = HTTPBasicAuth(self.bigip.username, self.bigip.password)
        r = self.s.post(self._url(AS3_LOGIN_PATH),
                        json=credentials, auth=basicauth)
        r.raise_for_status()
        self.token = r.json()['token']['token']

        self.s.headers.update({'X-F5-Auth-Token': self.token})

        patch_timeout = {
            "timeout": "36000"
        }
        r = self.s.patch(self._url(AS3_TOKENS_PATH.format(self.token)), json=patch_timeout)
        LOG.debug("Reauthorized!")

    @retry(
        retry=retry_if_exception_type(HTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    @authorized
    def post(self, **kwargs):
        LOG.debug("Calling POST with JSON %s", kwargs.get('json'))
        response = self.s.post(self._url(AS3_DECLARE_PATH), **kwargs)
        response.raise_for_status()
        LOG.debug("POST finished with %d", response.status_code)
        print json.dumps(json.loads(response.text), indent=4, sort_keys=True)
        return response

    @retry(
        retry=retry_if_exception_type(HTTPError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS))
    @authorized
    def patch(self, operation, path, **kwargs):
        LOG.debug("Calling PATCH %s with path %s", operation, path)
        params = kwargs.copy()

        params.update({'op': operation, 'path': path})
        response = self.s.patch(self._url(AS3_DECLARE_PATH), json=[params])
        response.raise_for_status()
        print json.dumps(json.loads(response.text), indent=4, sort_keys=True)
        return response
