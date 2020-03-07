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
import os
import signal

import prometheus_client as prometheus
import requests
from oslo_log import log as logging
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from six.moves.urllib import parse
from urllib3.util.retry import Retry

from octavia_f5.utils import exceptions

LOG = logging.getLogger(__name__)

AS3_LOGIN_PATH = '/mgmt/shared/authn/login'
AS3_TOKENS_PATH = '/mgmt/shared/authz/tokens/{}'
AS3_DECLARE_PATH = '/mgmt/shared/appsvcs/declare'
AS3_INFO_PATH = '/mgmt/shared/appsvcs/info'


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
        try:
            info = self.info()
            info.raise_for_status()
        except requests.exceptions.HTTPError as e:
            # Failed connecting to AS3 endpoint, gracefully terminate
            LOG.error('Could not connect to AS3 endpoint: %s', e)
            os.kill(os.getpid(), signal.SIGTERM)

    _metric_httpstatus = prometheus.metrics.Counter(
        'octavia_as3_httpstatus', 'Number of HTTP statuses in responses to AS3 requests', ['method', 'statuscode'])
    _metric_post = prometheus.metrics.Counter(
        'octavia_as3_post', 'Amount of POST requests sent to AS3')
    _metric_post_duration = prometheus.metrics.Summary(
        'octavia_as3_post_duration', 'Time it needs to send a POST request to AS3')
    _metric_post_exceptions = prometheus.metrics.Counter(
        'octavia_as3_post_exceptions', 'Number of exceptions at POST requests sent to AS3')
    _metric_patch = prometheus.metrics.Counter(
        'octavia_as3_patch', 'Amount of PATCH requests sent to AS3')
    _metric_patch_duration = prometheus.metrics.Summary(
        'octavia_as3_patch_duration', 'Time it needs to send a PATCH request to AS3')
    _metric_patch_exceptions = prometheus.metrics.Counter(
        'octavia_as3_patch_exceptions', 'Number of exceptions at PATCH request sent to AS3')
    _metric_delete = prometheus.metrics.Counter(
        'octavia_as3_delete', 'Amount of DELETE requests  sent to AS3')
    _metric_delete_duration = prometheus.metrics.Summary(
        'octavia_as3_delete_duration', 'Time it needs to send a DELETE request to AS3')
    _metric_delete_exceptions = prometheus.metrics.Counter(
        'octavia_as3_delete_exceptions', 'Number of exceptions at DELETE request sent to AS3')
    _metric_authorization = prometheus.metrics.Counter(
        'octavia_as3_authorization',
        'How often the F5 provider driver had to (re)authorize before performing an AS3 request')
    _metric_authorization_duration = prometheus.metrics.Summary(
        'octavia_as3_authorization_duration', 'Time it needs to (re)authorize')
    _metric_authorization_exceptions = prometheus.metrics.Counter(
        'octavia_as3_authorization_exceptions', 'Number of exceptions at (re)authorization')

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

    @staticmethod
    def _check_response(response):
        def _check_for_errors(text):
            if 'errors' in text:
                raise exceptions.AS3Exception(text['errors'])
            if 'message' in text:
                if 'please try again' in text['message']:
                    # BigIP busy, just throw retry-exception
                    raise exceptions.RetryException(text['message'])
                if 'the requested route-domain' in text.get('response', ''):
                    # Self-IP not created yet, retry
                    raise exceptions.RetryException(text['message'])
                err = '{}: {}'.format(text['message'], text.get('response'))
                raise exceptions.AS3Exception(err)

        if response.headers.get('Content-Type') == 'application/json':
            text = response.json()
            if not response.ok:
                _check_for_errors(text)
                if 'results' in text:
                    _check_for_errors(text['results'][0])
            else:
                LOG.debug(json.dumps(text.get('results'), indent=4, sort_keys=True))
        else:
            LOG.debug(response.text)

    @_metric_authorization_exceptions.count_exceptions()
    @_metric_authorization_duration.time()
    def reauthorize(self):
        self._metric_authorization.inc()
        # Login
        credentials = {
            "username": self.bigip.username,
            "password": self.bigip.password,
            "loginProviderName": "tmos"
        }

        self.session.headers.pop('X-F5-Auth-Token', None)
        r = self.session.post(self._url(AS3_LOGIN_PATH), json=credentials)
        self._metric_httpstatus.labels(method='post', statuscode=r.status_code).inc()
        r.raise_for_status()
        self.token = r.json()['token']['token']

        self.session.headers.update({'X-F5-Auth-Token': self.token})

        patch_timeout = {
            "timeout": "36000"
        }
        r = self.session.patch(self._url(AS3_TOKENS_PATH.format(self.token)), json=patch_timeout)
        self._metric_httpstatus.labels(method='patch', statuscode=r.status_code).inc()
        LOG.debug("Reauthorized!")

    @_metric_post_exceptions.count_exceptions()
    @authorized
    @_metric_post_duration.time()
    def post(self, **kwargs):
        self._metric_post.inc()
        LOG.debug("Calling POST with JSON %s", kwargs.get('json'))
        response = self.session.post(self._url(AS3_DECLARE_PATH), **kwargs)
        self._metric_httpstatus.labels(method='post', statuscode=response.status_code).inc()
        LOG.debug("POST finished with %d", response.status_code)
        self._check_response(response)
        return response

    @_metric_patch_exceptions.count_exceptions()
    @authorized
    @_metric_patch_duration.time()
    def patch(self, operation, path, **kwargs):
        self._metric_patch.inc()
        LOG.debug("Calling PATCH %s with path %s", operation, path)
        if 'value' in kwargs:
            LOG.debug(json.dumps(kwargs['value'], indent=4, sort_keys=True))
        params = kwargs.copy()
        params.update({'op': operation, 'path': path})
        response = self.session.patch(self._url(AS3_DECLARE_PATH), json=[params])
        self._metric_httpstatus.labels(method='patch', statuscode=response.status_code).inc()
        self._check_response(response)
        return response

    @_metric_delete_exceptions.count_exceptions()
    @authorized
    @_metric_delete_duration.time()
    def delete(self, **kwargs):
        self._metric_delete.inc()
        tenants = kwargs.get('tenants', None)
        if not tenants:
            LOG.error("Delete called without tenant, would wipe all AS3 Declaration, ignoring!")
            return None

        LOG.debug("Calling DELETE for tenants %s", tenants)
        response = self.session.delete(self._url('{}/{}'.format(AS3_DECLARE_PATH, ','.join(tenants))))
        self._metric_httpstatus.labels(method='delete', statuscode=response.status_code).inc()
        LOG.debug("DELETE finished with %d", response.status_code)
        self._check_response(response)
        return response

    @authorized
    def info(self):
        return self.session.get(self._url(AS3_INFO_PATH))
        pass
