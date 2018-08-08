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
from octavia_f5.utils.mapper import partition

LOG = logging.getLogger(__name__)

class MonitorMapper(partition.PartitionMapper):
    def get_health_monitor_path(self, loadbalancer, healthmonitor):
        name = constants.PREFIX_HEALTH_MONITOR + healthmonitor.id
        partition = self.get_partition_name(loadbalancer.project_id)

        return dict(name=name, partition=partition)

    def map_healthmonitor(self, loadbalancer, health_monitor):
        obj = self.get_health_monitor_path(loadbalancer, health_monitor)

        obj["description"] = self.get_resource_description(
            health_monitor)

        # type
        if hasattr(health_monitor, 'type'):
            # obj["type"] = lbaas_healthmonitor["type"].lower()
            if (health_monitor.type == "HTTP" or
                    health_monitor.type == "HTTPS"):

                # url path
                if hasattr(health_monitor, 'url_path'):
                    obj["send"] = ("GET " +
                                   health_monitor.url_path +
                                             " HTTP/1.0\\r\\n\\r\\n")
                else:
                    obj["send"] = "GET / HTTP/1.0\\r\\n\\r\\n"

                # expected codes
                obj["recv"] = self._get_recv_text(
                    health_monitor)

        # interval - delay
        if hasattr(health_monitor, 'delay'):
            obj["interval"] = health_monitor.delay

        # timeout
        if hasattr(health_monitor, 'timeout'):
            if hasattr(health_monitor, 'max_retries'):
                timeout = (int(health_monitor.max_retries) *
                           int(health_monitor.timeout))
                obj["timeout"] = timeout

        return obj

    @staticmethod
    def _get_recv_text(healthmonitor):
        if hasattr(healthmonitor, 'expected_codes'):
            try:
                if healthmonitor.expected_codes.find(",") > 0:
                    status_codes = (
                        healthmonitor.expected_codes.split(','))
                    recv_text = "HTTP/1.(0|1) ("
                    for status in status_codes:
                        int(status)
                        recv_text += status + "|"
                    recv_text = recv_text[:-1]
                    recv_text += ")"
                elif healthmonitor.expected_codes.find("-") > 0:
                    status_range = (
                        healthmonitor.expected_codes.split('-'))
                    start_range = status_range[0]
                    int(start_range)
                    stop_range = status_range[1]
                    int(stop_range)
                    recv_text = (
                            "HTTP/1.(0|1) [" +
                            start_range + "-" +
                            stop_range + "]"
                    )
                else:
                    int(healthmonitor.expected_codes)
                    recv_text = "HTTP/1.(0|1) " + \
                                healthmonitor.expected_codes
            except Exception as exc:
                LOG.error(
                    "invalid monitor: %s, expected_codes %s, setting to 200"
                    % (exc, healthmonitor.expected_codes))
                recv_text = "HTTP/1.(0|1) 200"
        else:
            recv_text = "HTTP/1.(0|1) 200"

        return recv_text
