# Copyright 2018 SAP SE
# Copyright (c) 2014-2018, F5 Networks, Inc.
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
from oslo_log import log as logging
import octavia_f5.restclient.as3objects.pool as m_pool
from octavia_f5.restclient.as3classes import Monitor

LOG = logging.getLogger(__name__)


def get_name(healthmonitor_id):
    return constants.PREFIX_HEALTH_MONITOR + \
           healthmonitor_id.replace('/', '').replace('-', '')


def get_path(health_monitor):
    return m_pool.get_path(health_monitor.pool) \
           + '/' + get_name(health_monitor.id)


def get_monitor(health_monitor):
    args = dict()

    # Standard Octavia monitor types
    if health_monitor.type == 'HTTP':
        args['monitorType'] = 'http'
    elif health_monitor.type == 'HTTPS':
        args['monitorType'] = 'https'
    elif health_monitor.type == 'PING':
        args['monitorType'] = 'icmp'
    elif health_monitor.type == 'TCP':
        args['monitorType'] = 'tcp'
    elif health_monitor.type == 'TLS-HELLO':
        args['monitorType'] = 'tcp'
    elif health_monitor.type == 'UDP-CONNECT':
        args['monitorType'] = 'udp'

    # F5 specific monitory types
    elif health_monitor.type == 'SIP':
        args['monitorType'] = 'sip'
    elif health_monitor.type == 'SMTP':
        args['monitorType'] = 'smtp'
    elif health_monitor.type == 'TCP-HALF_OPEN':
        args['monitorType'] = 'tcp-half-open'
    elif health_monitor.type == 'LDAP':
        args['monitorType'] = 'ldap'
    elif health_monitor.type == 'DNS':
        args['monitorType'] = 'dns'
        args['queryName'] = health_monitor.domain_name
    # No Health monitor type available
    else:
        return {}

    if health_monitor.type == 'HTTP' or health_monitor.type == 'HTTPS':
        send = "{} {} HTTP/{}\\r\\n".format(
            health_monitor.http_method,
            health_monitor.url_path,
            health_monitor.http_version)
        if hasattr(health_monitor, 'domain_name'):
            send += "Host: {}\\r\\n\\r\\n".format(
                health_monitor.domain_name)
        else:
            send += "\\r\\n"

        args['send'] = send
        args['receive'] = _get_recv_text(health_monitor)

    if hasattr(health_monitor, 'delay'):
        args["interval"] = health_monitor.delay
    if hasattr(health_monitor, 'timeout'):
        timeout = (int(health_monitor.fall_threshold) *
                   int(health_monitor.timeout))
        args["timeout"] = timeout
    if hasattr(health_monitor, 'rise_threshold'):
        time_until_up = (int(health_monitor.rise_threshold) *
                         int(health_monitor.timeout))
        args["timeUntilUp"] = time_until_up

    return Monitor(**args)


def _get_recv_text(healthmonitor):
    if hasattr(healthmonitor, 'expected_codes'):
        try:
            if healthmonitor.expected_codes.find(",") > 0:
                status_codes = (
                    healthmonitor.expected_codes.split(','))
                recv_text = "HTTP/{:1.1f} (".format(
                    healthmonitor.http_version)
                for status in status_codes:
                    int(status)
                    recv_text += status + "|"
                recv_text = recv_text[:-1]
                recv_text += ")"
            elif healthmonitor.expected_codes.find("-") > 0:
                status_range = (
                    healthmonitor.expected_codes.split('-'))
                start_range = status_range[0]
                stop_range = status_range[1]
                recv_text = (
                        "HTTP/{:1.1f} [{}-{}]".format(
                            healthmonitor.http_version,
                            start_range,
                            stop_range
                        )
                )
            else:
                recv_text = "HTTP/{:1.1f} {}".format(
                    healthmonitor.http_version,
                    healthmonitor.expected_codes)
        except Exception as exc:
            LOG.error(
                "invalid monitor expected_codes={}, http_version={}, defaulting to 'HTTP/1.0 200': {}".format(
                healthmonitor.expected_codes, healthmonitor.http_version, exc))
            recv_text = "HTTP/1.0 200"
    else:
        recv_text = "HTTP/1.0 200"

    return recv_text


