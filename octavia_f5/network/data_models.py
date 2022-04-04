#  Copyright 2021 SAP SE
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from oslo_log import log as logging

from octavia.common.data_models import BaseDataModel
from octavia.network import base
from octavia_f5.utils import driver_utils

LOG = logging.getLogger(__name__)


class Network(BaseDataModel):
    """ This is a helper class what can provide vlan tag and
        default gateway """
    def __init__(self, id=None, name=None, subnets=None,
                 project_id=None, admin_state_up=None, mtu=None,
                 provider_network_type=None,
                 provider_physical_network=None,
                 provider_segmentation_id=None,
                 router_external=None,
                 port_security_enabled=None,
                 segments=None):
        self.id = id
        self.name = name
        self.subnets = subnets
        self.project_id = project_id
        self.admin_state_up = admin_state_up
        self.provider_network_type = provider_network_type
        self.provider_physical_network = provider_physical_network
        self.provider_segmentation_id = provider_segmentation_id
        self.router_external = router_external
        self.mtu = mtu
        self.port_security_enabled = port_security_enabled
        self.segments = segments or []
        self._network_driver = driver_utils.get_network_driver()

    def default_gateway_ip(self, subnet_id):
        subnet = self._network_driver.get_subnet(subnet_id)
        return subnet.gateway_ip

    def has_bound_segment(self):
        for segment in self.segments:
            if segment['provider:physical_network'] == self._network_driver.physical_network:
                return True
        return False

    @property
    def vlan_id(self):
        for segment in self.segments:
            if segment['provider:physical_network'] == self._network_driver.physical_network:
                return segment['provider:segmentation_id']

        err = 'Error retrieving segment id for physical network {} of network {}'.format(
                  self._network_driver.physical_network, self.id)
        raise base.NetworkException(err)
