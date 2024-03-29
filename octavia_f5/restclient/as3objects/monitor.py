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

from oslo_config import cfg
from oslo_log import log as logging

from octavia_f5.common import constants
from octavia_f5.restclient import as3classes as as3
from octavia_f5.restclient import as3types

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
TEMPLATE = """#!/bin/sh
me=$(basename $0)

pidfile="/var/run/$me-$1:$2.pid"

if [ -f "$pidfile" ]; then
   kill -9 $(cat $pidfile) > /dev/null 2>&1
fi

echo "$$" > $pidfile

node_ip=$(echo $1 | sed 's/::ffff://')
pm_port="$2"

{}

if [ $? -eq 0 ]
then
    rm -f $PIDFILE
    echo "UP"
else
    rm -f $PIDFILE
    exit
fi"""

# Source: https://devcentral.f5.com/s/articles/https-monitor-ssl-handshake
TLS_HELLO_CHECK = TEMPLATE.format("echo 'QUIT'|openssl s_client -verify 1 -connect $node_ip:$pm_port >/dev/null 2>&1")


def get_name(healthmonitor_id):
    return "{}{}".format(constants.PREFIX_HEALTH_MONITOR, healthmonitor_id)


def get_monitor(health_monitor, target_address=None, target_port=None):
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
        args['send'] = ''
        args['receive'] = ''
    elif health_monitor.type == 'TLS-HELLO':
        args['monitorType'] = 'external'
        args['script'] = TLS_HELLO_CHECK
        args['receive'] = 'UP'
    elif health_monitor.type == 'UDP-CONNECT':
        args['monitorType'] = 'udp'
        args['receive'] = ''
        args['send'] = ''

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
        http_version = '1.0'
        if health_monitor.http_version:
            http_version = health_monitor.http_version
        send = "{} {} HTTP/{}\\r\\n".format(
            health_monitor.http_method,
            health_monitor.url_path,
            http_version
            )
        if health_monitor.domain_name:
            send += "Host: {}\\r\\n\\r\\n".format(
                health_monitor.domain_name)
        else:
            send += "\\r\\n"

        args['send'] = send
        args['receive'] = _get_recv_text(health_monitor)

    # BigIP does not have a semantic equivalent to the max_retries_down API parameter; The only available parameters
    # are interval (corresponding to 'delay' in the Octavia API) and timeout, both measured in seconds. So instead of
    # having an amount of probes (specified by max_retries_down) fail and each timing out after a number of seconds
    # (specified by the timeout API parameter) before setting a member to offline, we use max_retries_down together
    # with delay to calculate the timeout that we provision to the BigIP.
    args["interval"] = health_monitor.delay
    # This timeout must not be confused with the 'timeout' API parameter, which we ignore, because it denotes the
    # timeout of one probe, while the timeout AS3 parameter denotes the overall timeout over all probes!
    # The max_retries_down API parameter is called fall_threshold in the database
    timeout = int(health_monitor.fall_threshold) * int(health_monitor.delay) + 1

    # BigIP LTM (TMOS v15.1.3) maximum health monitor timeout seems to be 86400 seconds, at least on the GUI, but that
    # value is undocumented, so we're staying on the safe side with a lower value, until customer demand is present.
    args["timeout"] = min(timeout, 900)
    if target_address:
        args["targetAddress"] = target_address
    if target_port:
        args["targetPort"] = target_port

    if CONF.f5_agent.profile_healthmonitor_tls and health_monitor.type == 'HTTPS':
        args["clientTLS"] = as3.BigIP(CONF.f5_agent.profile_healthmonitor_tls)

    args['label'] = as3types.f5label(health_monitor.name or health_monitor.id)

    return as3.Monitor(**args)


def _get_recv_text(healthmonitor):
    http_version = "1.(0|1)"
    if healthmonitor.http_version:
        http_version = "{:1.1f}".format(healthmonitor.http_version)

    try:
        if healthmonitor.expected_codes.find(",") > 0:
            status_codes = healthmonitor.expected_codes.split(',')
            recv_text = "HTTP/{} ({})".format(
                http_version, "|".join(status_codes))
        elif healthmonitor.expected_codes.find("-") > 0:
            status_range = healthmonitor.expected_codes.split('-')
            start_range = status_range[0]
            stop_range = status_range[1]
            recv_text = "HTTP/{} [{}-{}]".format(
                        http_version, start_range, stop_range
            )
        else:
            recv_text = "HTTP/{} {}".format(
                http_version, healthmonitor.expected_codes)
    except Exception as exc:
        LOG.error(
            "invalid monitor expected_codes=%s, http_version=%s, defaulting to '%s': %s",
            healthmonitor.expected_codes, healthmonitor.http_version,
            CONF.f5_agent.healthmonitor_receive, exc)
        recv_text = CONF.f5_agent.healthmonitor_receive
    return recv_text
