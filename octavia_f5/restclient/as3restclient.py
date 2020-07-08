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
import re
import signal

import prometheus_client as prometheus
import requests
from oslo_log import log as logging
from requests.adapters import HTTPAdapter
from six.moves.urllib import parse
from urllib3.util.retry import Retry

from octavia_f5.utils import exceptions

LOG = logging.getLogger(__name__)

AS3_LOGIN_PATH = '/mgmt/shared/authn/login'
AS3_TOKENS_PATH = '/mgmt/shared/authz/tokens'
AS3_DECLARE_PATH = '/mgmt/shared/appsvcs/declare'
AS3_INFO_PATH = '/mgmt/shared/appsvcs/info'
F5_DEVICE_PATH = '/mgmt/tm/cm/device'


def check_response(func):
    def _check_for_errors(text):
        if 'errors' in text:
            raise exceptions.AS3Exception(text['errors'])
        if 'message' in text:
            if 'please try again' in text['message']:
                # BigIP busy, just throw retry-exception
                raise exceptions.RetryException(text['message'])
            if 'requested route-domain' in text.get('response', ''):
                # Self-IP not created yet, retry
                raise exceptions.RetryException(text['message'])
            if 'declaration failed' in text['message']:
                # Workaround for Monitor deletion bug
                m = re.search('Monitor /(.*)/(.*)/(.*) is in use', text['response'])
                if m:
                    raise exceptions.MonitorDeletionException(*m.groups())
            err = '{}: {}'.format(text['message'], text.get('response'))
            raise exceptions.AS3Exception(err)

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if 'application/json' in response.headers.get('Content-Type'):
            try:
                text = response.json()
            except ValueError as e:
                # AS3 returns malformed json, failover
                LOG.error(e)
                raise exceptions.FailoverException(e)

            if not response.ok:
                _check_for_errors(text)
                if 'results' in text:
                    _check_for_errors(text['results'][0])
            else:
                if 'results' in text:
                    LOG.debug(json.dumps(text.get('results'), indent=4, sort_keys=True))
        else:
            LOG.debug(response.text)
        return response

    return wrapper


def authorized(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if not self.auth:
            return response
        if response.status_code == 401 or 'X-F5-Auth-Token' not in self.session.headers:
            self.reauthorize()
            return func(self, *args, **kwargs)
        else:
            return response

    return wrapper


class BigipAS3RestClient(object):
    _metric_httpstatus = prometheus.metrics.Counter(
        'octavia_as3_httpstatus', 'Number of HTTP statuses in responses to AS3 requests', ['method', 'statuscode'])
    _metric_post_duration = prometheus.metrics.Summary(
        'octavia_as3_post_duration', 'Time it needs to send a POST request to AS3')
    _metric_post_exceptions = prometheus.metrics.Counter(
        'octavia_as3_post_exceptions', 'Number of exceptions at POST requests sent to AS3')
    _metric_patch_duration = prometheus.metrics.Summary(
        'octavia_as3_patch_duration', 'Time it needs to send a PATCH request to AS3')
    _metric_patch_exceptions = prometheus.metrics.Counter(
        'octavia_as3_patch_exceptions', 'Number of exceptions at PATCH request sent to AS3')
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
        'octavia_as3_authorization_exceptions', 'Number of exceptions during (re)authorization')
    _metric_version = prometheus.Info(
        'octavia_as3_version', 'AS3 Version')

    def __init__(self, url, enable_verify=True, enable_token=True, auth=True):
        self.bigip = parse.urlsplit(url, allow_fragments=False)
        # Use the first BigIP device by default
        self.enable_verify = enable_verify
        self.enable_token = enable_token
        self.auth = auth
        self.token = None
        self.session = self._create_session()
        try:
            info_dict = self.info()
            self._metric_version.info(info_dict)
        except requests.exceptions.HTTPError as e:
            # Failed connecting to AS3 endpoint, gracefully terminate
            LOG.error('Could not connect to AS3 endpoint: %s', e)
            os.kill(os.getpid(), signal.SIGTERM)

    def _url(self, path):
        return parse.urlunsplit(
            parse.SplitResult(scheme=self.bigip.scheme,
                              netloc=self.bigip.netloc,
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

    @check_response
    @authorized
    def _call_method(self, method, url, **kwargs):
        meth = getattr(self.session, method)
        response = meth(url, **kwargs)
        self._metric_httpstatus.labels(method=method, statuscode=response.status_code).inc()
        LOG.debug("%s to %s finished with %d", method, self.bigip.hostname, response.status_code)
        return response

    @property
    def hostname(self):
        return self.bigip.hostname

    @property
    def scheme(self):
        return self.bigip.scheme

    @property
    def is_active(self):
        try:
            r = self.get(path=F5_DEVICE_PATH, timeout=3)
        except requests.exceptions.Timeout:
            return False

        return any([device['name'] == self.bigip.hostname and
                    device['failoverState'] == 'active'
                    for device in r.json().get('items', [])])

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

        self.session = self._create_session()
        r = self.session.post(self._url(AS3_LOGIN_PATH), json=credentials)
        self._metric_httpstatus.labels(method='post', statuscode=r.status_code).inc()
        if r.status_code == 400 and 'maximum active login tokens' in r.text:
            self.session.delete(self._url(AS3_TOKENS_PATH), auth=(
                self.bigip.username, self.bigip.password))
            r = self.session.post(self._url(AS3_LOGIN_PATH), json=credentials)

        r.raise_for_status()
        self.token = r.json()['token']['token']

        self.session.headers.update({'X-F5-Auth-Token': self.token})

        patch_timeout = {
            "timeout": "36000"
        }
        r = self.session.patch(self._url(AS3_TOKENS_PATH + "/{}".format(self.token)), json=patch_timeout)
        self._metric_httpstatus.labels(method='patch', statuscode=r.status_code).inc()
        LOG.debug("Reauthorized!")

    def get(self, path, **kwargs):
        path = self._url(path)
        LOG.debug("Calling GET '%s'", path)
        return self._call_method('get', path)

    @_metric_post_exceptions.count_exceptions()
    @_metric_post_duration.time()
    def post(self, **kwargs):
        LOG.debug("Calling POST with JSON %s", kwargs.get('json'))
        return self._call_method('post', self._url(AS3_DECLARE_PATH), **kwargs)

    @_metric_patch_exceptions.count_exceptions()
    @_metric_patch_duration.time()
    def patch(self, operation, path, **kwargs):
        LOG.debug("Calling PATCH %s with path %s", operation, path)
        if 'value' in kwargs:
            LOG.debug(json.dumps(kwargs['value'], indent=4, sort_keys=True))
        params = kwargs.copy()
        params.update({'op': operation, 'path': path})
        return self._call_method('patch', self._url(AS3_DECLARE_PATH), json=[params])

    @_metric_delete_exceptions.count_exceptions()
    @_metric_delete_duration.time()
    def delete(self, **kwargs):
        tenants = kwargs.get('tenants', None)
        if not tenants:
            LOG.error("Delete called without tenant, would wipe all AS3 Declaration, ignoring!")
            return None

        LOG.debug("Calling DELETE for tenants %s", tenants)
        url = self._url('{}/{}'.format(AS3_DECLARE_PATH, ','.join(tenants)))
        return self._call_method('delete', url)

    def info(self):
        info = self.get(AS3_INFO_PATH)
        info.raise_for_status()
        return dict(device=self.bigip.hostname, **info.json())
