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

from octavia_f5.restclient.as3classes import IRule
from octavia_f5.common import constants

PROXY_PROTOCOL_INITIATIOR = """when CLIENT_ACCEPTED {
    set proxyheader "PROXY TCP[IP::version] [IP::remote_addr] [IP::local_addr] [TCP::remote_port] [TCP::local_port]\\r\\n"
}
 
when SERVER_CONNECTED {
    TCP::respond $proxyheader
}"""


def get_proxy_irule():
    irule = IRule(PROXY_PROTOCOL_INITIATIOR,
                  remark="Insert Proxy Protocol Header V1")
    name = '{}proxy_protocol_initiator'.format(constants.PREFIX_IRULE)
    return name, irule
