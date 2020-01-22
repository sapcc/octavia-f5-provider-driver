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

import functools
import json

import requests
from oslo_log import log as logging
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from six.moves.urllib import parse
from urllib3.util.retry import Retry

LOG = logging.getLogger(__name__)

AS3_LOGIN_PATH = '/mgmt/shared/authn/login'
AS3_TOKENS_PATH = '/mgmt/shared/authz/tokens/{}'
AS3_DECLARE_PATH = '/mgmt/shared/appsvcs/declare'


def authorized(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code == 401:
            self.reauthorize()
            return func(self, *args, **kwargs)
        else:
            return response

    return wrapper


class BigipAS3RestClient(object):
    def __init__(self, bigip_url, enable_verify=True, enable_token=True,
                 esd=None):
        self.bigip = parse.urlsplit(bigip_url, allow_fragments=False)
        self.enable_verify = enable_verify
        self.enable_token = enable_token
        self.token = None
        self.session = self._create_session()
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
        retry = Retry(
            total=5,
            backoff_factor=0.3,
            status_forcelist=(500, 502, 503, 504),
        )
        session.mount('https://', HTTPAdapter(max_retries=retry))
        session.verify = self.enable_verify
        return session

    def reauthorize(self):
        # Login
        credentials = {
            "username": self.bigip.username,
            "password": self.bigip.password,
            "loginProviderName": "tmos"
        }
        basicauth = HTTPBasicAuth(self.bigip.username, self.bigip.password)
        r = self.session.post(self._url(AS3_LOGIN_PATH),
                              json=credentials, auth=basicauth)
        self.token = r.json()['token']['token']

        self.session.headers.update({'X-F5-Auth-Token': self.token})

        patch_timeout = {
            "timeout": "36000"
        }
        r = self.session.patch(self._url(AS3_TOKENS_PATH.format(self.token)), json=patch_timeout)
        LOG.debug("Reauthorized!")

    @authorized
    def post(self, **kwargs):
        LOG.debug("Calling POST with JSON %s", kwargs.get('json'))
        response = self.session.post(self._url(AS3_DECLARE_PATH), **kwargs)
        LOG.debug("POST finished with %d", response.status_code)
        if response.headers.get('Content-Type') == 'application/json':
            LOG.debug(json.dumps(json.loads(response.text)['results'], indent=4, sort_keys=True))
        else:
            LOG.debug(response.text)
        return response

    @authorized
    def patch(self, operation, path, **kwargs):
        LOG.debug("Calling PATCH %s with path %s", operation, path)
        if 'value' in kwargs:
            LOG.debug(json.dumps(kwargs['value'], indent=4, sort_keys=True))
        params = kwargs.copy()
        params.update({'op': operation, 'path': path})
        response = self.session.patch(self._url(AS3_DECLARE_PATH), json=[params])
        if response.headers.get('Content-Type') == 'application/json':
            LOG.debug(json.dumps(json.loads(response.text), indent=4, sort_keys=True))
        else:
            LOG.debug(response.text)
        return response

    @authorized
    def delete(self, **kwargs):
        tenants = kwargs.get('tenants', None)
        if not tenants:
            LOG.error("Delete called without tenant, would wipe all AS3 Declaration, ignoring!")
            return None

        LOG.debug("Calling DELETE for tenants %s", tenants)
        response = self.session.delete(self._url('{}/{}'.format(AS3_DECLARE_PATH, ','.join(tenants))))
        LOG.debug("DELETE finished with %d", response.status_code)
        if response.headers.get('Content-Type') == 'application/json':
            LOG.debug(json.dumps(json.loads(response.text)['results'], indent=4, sort_keys=True))
        else:
            LOG.debug(response.text)
        return response
