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
from octavia_f5.common import constants
from octavia_f5.restclient.as3exceptions import *
import six
import json

class BaseDescription(object):
    def __init__(self, data):
        data = data.copy()
        if 'self' in data:
             del data['self']
        if 'kwargs' in data:
            self.__dict__.update(data['kwargs'])
            del data['kwargs']
        self.__dict__.update(data)

    def require(self, key):
        if getattr(self, key, None) is None:
            raise RequiredKeyMissingException(key)

    def to_dict(self):
        data = self.__dict__.copy()
        for key, value in six.iteritems(data):
            if isinstance(value, BaseDescription):
                data[key] = value.to_dict()
            elif isinstance(value, list):
                data[key] = []
                for item in self.__dict__[key]:
                    if isinstance(item, BaseDescription):
                        print(item.to_dict())
                        data[key].append(item.to_dict())
                    else:
                        print(item)
                        data[key].append(item)
        return data

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True,
                          indent=4, separators=(',', ': '))

class AS3(BaseDescription):
    ACTIONS = ['deploy', 'dry-run', 'patch', 'redeploy', 'retrieve', 'remove']

    def __init__(self, persist=True, action='deploy'):
        if action not in self.ACTIONS:
            raise TypeNotSupportedException

        super(AS3, self).__init__(locals())
        setattr(self, 'class', 'AS3')

    def setADC(self, adc):
        setattr(self, 'declaration', adc)


class ADC(BaseDescription):
    def __init__(self, schemaVersion='3.0.0', updateMode='selective', **kwargs):
        super(ADC, self).__init__(locals())
        setattr(self, 'class', 'ADC')

        self.require('id')
        self.require('label')

    def setTenant(self, name, tenant):
        setattr(self, name, tenant)

    def getOrCreateTenant(self, name):
        if not hasattr(self, name):
            self.setTenant(name, Tenant())

        return getattr(self, name)


class Tenant(BaseDescription):
    def __init__(self, **kwargs):
        super(Tenant, self).__init__(locals())
        setattr(self, 'class', 'Tenant')

    def add_application(self, name, application):
        setattr(self, name, application)


class Application(BaseDescription):
    def __init__(self, template, **kwargs):
        if template not in constants.SUPPORTED_APPLICATION_TEMPLATES:
            raise TypeNotSupportedException

        super(Application, self).__init__(locals())
        setattr(self, 'class', 'Application')

    def set_service_main(self, service):
        self.serviceMain = service

    def add_pool(self, name, pool):
        if hasattr(self, name):
            raise DuplicatedKeyException

        setattr(self, name, pool)

    def add_service(self, name):
        if hasattr(self, name):
            return getattr(self, name)
        else:
            setattr(self, name, Service('Service_Generic'))

    def add_monitor(self, name, monitor):
        if hasattr(self, name):
            raise DuplicatedKeyException

        setattr(self, name, monitor)


class Service(BaseDescription):

    def __init__(self, servicetype, virtualAddresses = None,
                 pool = None, virtualPort = None, **kwargs):
        if servicetype not in constants.SUPPORTED_SERVICES:
            raise TypeNotSupportedException

        super(Service, self).__init__(locals())
        setattr(self, 'class', servicetype)


class Pool(BaseDescription):
    def __init__(self, enable=True, **kwargs):
        super(Pool, self).__init__(locals())
        setattr(self, 'class', 'Pool')

        self.members = []
        self.monitors = []

    def add_member(self, member):
        self.members.append(member)

    def add_monitor(self, monitor):
        self.monitors.append(monitor)

class Member(BaseDescription):
    def __init__(self, enable=True, **kwargs):
        super(Member, self).__init__(locals())

        self.require('servicePort')
        self.require('serverAddresses')


class Monitor(BaseDescription):
    def __init__(self, **kwargs):
        super(Monitor, self).__init__(locals())
        setattr(self, 'class', 'Monitor')

