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
from octavia_f5.restclient.as3classes import Pool, Application, Member, Monitor, Service
from octavia_f5.restclient.as3objects import monitor as m_monitor


class As3Convert(object):

    @staticmethod
    def get_f5_monitor(monitor):
        http = monitor.type is constants.HEALTH_MONITOR_HTTP
        icmp = monitor.type is constants.HEALTH_MONITOR_PING
        https = monitor.type is constants.HEALTH_MONITOR_HTTPS
        tcp = monitor.type is constants.HEALTH_MONITOR_TCP
        udp = monitor.type is constants.HEALTH_MONITOR_UDP_CONNECT
        http_get = monitor.http_method is constants.HEALTH_MONITOR_HTTP_METHOD_GET
        root = monitor.url_path == '/'
        code200 = monitor.expected_codes = '200'
        enabled = monitor.enabled

        # check for predefined profiles
        if http and http_get and root and code200 and enabled:
            return None, ['http']
        elif https and http_get and root and code200 and enabled:
            return None, ['https']
        elif icmp and enabled:
            return None, ['icmp']
        elif tcp and enabled:
            return None, ['tcp']

        # Create custom health monitor
        monitor_type = 'tcp'
        if http:
            monitor_type = 'http'
        elif https:
            monitor_type = 'https'
        elif udp:
            monitor_type = 'udp'

        if http or https:
            send = 'HEAD {}\r\nHTTP/1.0\r\n\r\n'.format(monitor.url_path)
            receive = 'HTTP {} OK'.format(monitor.expected_codes)
            return monitor.monitor(monitor.id), Monitor(
                interval=monitor.delay,
                label=monitor.name,
                timeout=monitor.timeout,
                monitorType=monitor_type,
                send=send,
                receive=receive
            )
        else:
            return m_monitor.get_path(monitor.id), Monitor(
                interval=monitor.delay,
                label=monitor.name,
                timeout=monitor.timeout,
                monitorType=type
            )

