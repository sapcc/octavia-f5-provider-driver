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
import as3mapper as map


class As3Convert(object):
    @staticmethod
    def _get_f5_pool(pool):
        lbmode = 'round-robin'
        if pool.lb_algorithm is constants.LB_ALGORITHM_LEAST_CONNECTIONS:
            lbmode = 'least-connections-member'
        # SOURCE_IP algo not supported by BigIP

        return Pool(
            enable=pool.enabled,
            label=pool.name,
            remark=pool.description,
            loadBalancingMode=lbmode
        )

    @staticmethod
    def _get_f5_member(member):
        return Member(
            enable=member.enabled,
            servicePort=member.protocol_port,
            serverAddresses=[member.ip_address],
            priorityGroup=member.weight
        )

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
        type = 'tcp'
        if http:
            type = 'http'
        elif https:
            type = 'https'
        elif udp:
            type = 'udp'

        if http or https:
            send = 'HEAD {}\r\nHTTP/1.0\r\n\r\n'.format(monitor.url_path)
            receive = 'HTTP {} OK'.format(monitor.expected_codes)
            return map.monitor(monitor.id), Monitor(
                interval=monitor.delay,
                label=monitor.name,
                timeout=monitor.timeout,
                monitorType=type,
                send=send,
                receive=receive
            )
        else:
            return map.monitor(monitor.id), Monitor(
                interval=monitor.delay,
                label=monitor.name,
                timeout=monitor.timeout,
                monitorType=type
            )


    def create_application(self, listener):
        prot = constants.APPLICATION_GENERIC
        servicetype = constants.SERVICE_GENERIC
        if listener.protocol is constants.PROTOCOL_TCP:
            prot = constants.APPLICATION_TCP
            servicetype = constants.SERVICE_TCP
        elif listener.protocol is constants.PROTOCOL_UDP:
            prot = constants.APPLICATION_UDP
            servicetype = constants.SERVICE_UDP
        elif listener.protocol is constants.PROTOCOL_HTTP:
            prot = constants.APPLICATION_HTTP
            servicetype = constants.SERVICE_HTTP
        elif listener.protocol is constants.PROTOCOL_HTTPS:
            prot = constants.APPLICATION_HTTPS
            servicetype = constants.SERVICE_HTTPS

        app = Application(prot)
        service = Service(
            servicetype=servicetype,
            pool=map.pool(listener.default_pool_id),
            virtualPort=listener.protocol_port,
            virtualAddresses=['1.2.3.4']  # TODO: port.ip
        )
        app.set_service_main(service)
        for pool in listener.pools:
            f5_pool = self._get_f5_pool(pool)
            for member in pool.members:
                f5_member = self._get_f5_member(member)
                f5_pool.add_member(f5_member)

            if pool.health_monitor:
                (f5_hm_name, f5_hm_obj) = self.get_f5_monitor(
                    pool.health_monitor
                )
                if f5_hm_obj:
                    app.add_monitor(f5_hm_name, f5_hm_obj)
                    f5_pool.add_monitor({'use': f5_hm_name})
                else:
                    f5_pool.add_monitor(f5_hm_name)

            app.add_pool(map.pool(pool.id), f5_pool)

        return app



