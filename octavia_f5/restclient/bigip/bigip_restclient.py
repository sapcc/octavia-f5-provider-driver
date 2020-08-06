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
from oslo_log import log as logging
from six.moves.urllib import parse
from urllib3.util.retry import Retry

from octavia_f5.restclient.bigip.timeout_http_adapter import TimeoutHTTPAdapter

LOG = logging.getLogger(__name__)

BIGIP_DEVICE_PATH = '/mgmt/tm/cm/device'
BIGIP_CM_PATH = '/mgmt/tm/cm'


class BigIPRestClient(requests.Session):
    def __init__(self, bigip_url, verify=True, auth=None):
        super(BigIPRestClient, self).__init__()
        self.url = parse.urlsplit(bigip_url, allow_fragments=False)
        retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504))
        adapter = TimeoutHTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=2)

        self.mount('https://', adapter)
        self.mount("http://", adapter)
        self.verify = verify
        self.auth = auth

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
        try:
            r = self.get(self.get_url(BIGIP_DEVICE_PATH), timeout=3)
        except requests.exceptions.Timeout:
            return False

        return any([device['name'] == self.hostname and
                    device['failoverState'] == 'active'
                    for device in r.json().get('items', [])])

    def get(self, url=None, **kwargs):
        """ Override get for baseurl compatbility
        """
        if 'path' in kwargs:
            url = self.get_url(kwargs.pop('path'))

        return super(BigIPRestClient, self).get(url, **kwargs)

    def config_sync(self, device_group):
        """ Performing a ConfigSync

            Impact of procedure: The following command synchronizes the local BIG-IP device to the device group.
        """

        cmd = {
            'command': 'run',
            'utilCmdArgs': 'config-sync to-group {}'.format(device_group)
        }
        return super(BigIPRestClient, self).post(self.get_url(BIGIP_CM_PATH), json=cmd)