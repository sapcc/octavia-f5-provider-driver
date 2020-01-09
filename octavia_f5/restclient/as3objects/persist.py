# Copyright 2019 SAP SE
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
from octavia_f5.restclient.as3classes import Persist
import hashlib
from octavia_f5.common import constants as const


def get_source_ip(timeout, granularity):
    m = hashlib.md5()
    persist = {'persistenceMethod': 'source-address'}
    if timeout:
        persist['duration'] = timeout
        m.update(str(timeout).encode('utf-8'))
    if granularity:
        persist['addressMask'] = granularity
        m.update(granularity.encode('utf-8'))
    name = 'persist_{}'.format(m.hexdigest())
    persist = Persist(**persist)
    return name, persist


def get_app_cookie(cookie_name):
    m = hashlib.md5()
    persist = Persist(
        persistenceMethod='cookie',
        cookieName=cookie_name
    )
    m.update(cookie_name.encode('utf-8'))
    name = 'persist_{}'.format(m.hexdigest())
    return name, persist
