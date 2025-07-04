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

import prometheus_client as prometheus
import requests
from oslo_log import log as logging
from urllib3.util.retry import Retry

from octavia_f5.restclient.bigip.timeout_http_adapter import TimeoutHTTPAdapter

LOG = logging.getLogger(__name__)

BIGIP_DEVICE_PATH = '/mgmt/tm/cm/device'
BIGIP_CM_PATH = '/mgmt/tm/cm'


class BigIPRestClient(requests.Session):
    _metric_get_exceptions = prometheus.metrics.Counter(
        'octavia_bigip_get_exceptions', 'Number of exceptions at GET requests sent to Big IP')
    _metric_post_exceptions = prometheus.metrics.Counter(
        'octavia_bigip_post_exceptions', 'Number of exceptions at POST requests sent to Big IP')
    _metric_put_exceptions = prometheus.metrics.Counter(
        'octavia_bigip_put_exceptions', 'Number of exceptions at PUT request sent to Big IP')
    _metric_patch_exceptions = prometheus.metrics.Counter(
        'octavia_bigip_patch_exceptions', 'Number of exceptions at PATCH request sent to Big IP')
    _metric_delete_exceptions = prometheus.metrics.Counter(
        'octavia_bigip_delete_exceptions', 'Number of exceptions at DELETE request sent to Big IP')

    def __init__(self, bigip_url, verify=True, auth=None, f5os_a=False):
        super().__init__()
        self.url = parse.urlparse(bigip_url, allow_fragments=False)

        # Remove any user/pw, since it's been already configured via auth
        self.url = self.url._replace(netloc=self.url.hostname)
        retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
        adapter = TimeoutHTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=2)

        self.mount('https://', adapter)
        self.mount("http://", adapter)
        self.verify = verify
        self.auth = auth
        self._active = None
        self.f5os_a = f5os_a

    def get_url(self, url):
        """Create the URL based off this partial path."""
        url_tuple = parse.SplitResult(
            scheme=self.url.scheme, netloc=self.url.netloc,
            path=url, query='', fragment='')
        return parse.urlunsplit(url_tuple)

    @property
    def hostname(self):
        return self.url.hostname

    @property
    def scheme(self):
        return self.url.scheme

    @property
    def is_active(self):
        """
        Get active device which is active device in F5 devices pair.
        """
        self.update_status()
        return self._active

    def is_available(self, timeout: int):
        """
        Check if BigIP device is available for communications.
        """
        available = True
        try:
            requests.get(self.url.scheme + '://' + self.url.hostname, timeout=timeout, verify=False)
            LOG.info(f'Found device with URL {self.url.hostname}')
        except requests.exceptions.Timeout:
            LOG.info(f'Device timed out, considering it unavailable. Timeout: {timeout}s Hostname: {self.url.hostname}')
            available = False
        return available

    def update_status(self):
        """ Update status if device is active or not

        :rtype: bool
        """
        try:
            r = self.get(self.get_url(BIGIP_DEVICE_PATH), timeout=3)
        except requests.exceptions.RequestException as err:
            LOG.error("getting status from F5 device failed with error: %s", err)
            return self._active or False

        statuses = r.json().get('items', [])
        if not statuses:
            LOG.error("F5 status response is empty, return cached status")
            return self._active or False
        if len(statuses) < 2:
            LOG.error("F5 status response contain less than 2 devices: %s", statuses)
        statuses = {d['name']: d['failoverState'] == 'active' for d in statuses}
        LOG.debug("got F5 devices statuses: %s", statuses)
        if not any(statuses.values()):
            LOG.error("both F5 devices are not active! return cached status")
            return self._active or False
        self._active = statuses[self.hostname]
        return self._active

    @_metric_get_exceptions.count_exceptions()
    def get(self, url=None, **kwargs):
        """ Override get for baseurl compatbility
        """
        if 'path' in kwargs:
            url = self.get_url(kwargs.pop('path'))

        # add F5OS-A headers if needed
        if self.f5os_a:
            headers = kwargs.get('headers', {})
            headers['Content-Type'] = 'application/yang-data+json'
            headers['Accept'] = 'application/yang-data+json'
            kwargs['headers'] = headers

        return super().get(url, **kwargs)

    @_metric_post_exceptions.count_exceptions()
    def post(self, url=None, **kwargs):
        """ Override get for baseurl compatbility
        """
        if 'path' in kwargs:
            url = self.get_url(kwargs.pop('path'))

        # add F5OS-A headers if needed
        if self.f5os_a:
            headers = kwargs.get('headers', {})
            headers['Content-Type'] = 'application/yang-data+json'
            headers['Accept'] = 'application/yang-data+json'
            kwargs['headers'] = headers

        return super().post(url, **kwargs)

    @_metric_delete_exceptions.count_exceptions()
    def delete(self, url=None, **kwargs):
        """ Override get for baseurl compatbility
        """
        if 'path' in kwargs:
            url = self.get_url(kwargs.pop('path'))

        # add F5OS-A headers if needed
        if self.f5os_a:
            headers = kwargs.get('headers', {})
            headers['Content-Type'] = 'application/yang-data+json'
            headers['Accept'] = 'application/yang-data+json'
            kwargs['headers'] = headers

        return super().delete(url, **kwargs)

    @_metric_patch_exceptions.count_exceptions()
    def patch(self, url=None, **kwargs):
        """ Override get for baseurl compatbility
        """
        if 'path' in kwargs:
            url = self.get_url(kwargs.pop('path'))

        # add F5OS-A headers if needed
        if self.f5os_a:
            headers = kwargs.get('headers', {})
            headers['Content-Type'] = 'application/yang-data+json'
            headers['Accept'] = 'application/yang-data+json'
            kwargs['headers'] = headers

        return super().patch(url, **kwargs)

    @_metric_put_exceptions.count_exceptions()
    def put(self, url=None, **kwargs):
        """ Override get for baseurl compatbility
        """
        if 'path' in kwargs:
            url = self.get_url(kwargs.pop('path'))

        # add F5OS-A headers if needed
        if self.f5os_a:
            headers = kwargs.get('headers', {})
            headers['Content-Type'] = 'application/yang-data+json'
            headers['Accept'] = 'application/yang-data+json'
            kwargs['headers'] = headers

        return super().put(url, **kwargs)

    def config_sync(self, device_group):
        """ Performing a ConfigSync

            Impact of procedure: The following command synchronizes the local BIG-IP device to the device group.
        """

        cmd = {
            'command': 'run',
            'utilCmdArgs': f'config-sync to-group {device_group}'
        }
        return super().post(self.get_url(BIGIP_CM_PATH), json=cmd)
