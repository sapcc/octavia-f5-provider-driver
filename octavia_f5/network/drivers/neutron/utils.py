#  Copyright 2022 SAP SE
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

from octavia.common import constants
from octavia_f5.network import data_models as network_models


def convert_network_dict_to_model(network_dict):
    nw = network_dict.get('network', network_dict)

    return network_models.Network(
        id=nw.get(constants.ID),
        name=nw.get(constants.NAME),
        subnets=nw.get('subnets'),
        project_id=nw.get(constants.TENANT_ID),
        admin_state_up=nw.get('admin_state_up'),
        mtu=nw.get('mtu'),
        provider_network_type=nw.get('provider:network_type'),
        provider_physical_network=nw.get('provider:physical_network'),
        provider_segmentation_id=nw.get('provider:segmentation_id'),
        router_external=nw.get('router:external'),
        port_security_enabled=nw.get('port_security_enabled'),
        segments=nw.get('segments')
    )
