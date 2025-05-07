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

from octavia_f5.network import data_models as network_models


def convert_network_to_model(nw):
    return network_models.Network(
        id=nw.id,
        name=nw.name,
        subnets=nw.subnet_ids,
        project_id=nw.project_id,
        admin_state_up=nw.is_admin_state_up,
        mtu=nw.mtu,
        provider_network_type=nw.provider_network_type,
        provider_physical_network=nw.provider_physical_network,
        provider_segmentation_id=nw.provider_segmentation_id,
        router_external=nw.is_router_external,
        port_security_enabled=nw.is_port_security_enabled,
        segments=nw.segments
    )
