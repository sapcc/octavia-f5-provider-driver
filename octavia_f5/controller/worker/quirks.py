# Copyright 2020 SAP SE
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

from octavia_f5.utils import driver_utils, exceptions
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import tenant as m_tenant
from octavia_f5.restclient.as3objects import application as m_app

F5_POOL_PATH = '/mgmt/tm/ltm/pool'


def workaround_autotool_1469(network_id, loadbalancer_id, pool, bigips):
    """ This is a workaround for F5 TMSH / AS3 Bug tracked as 527004 / AUTOTOOL-1469.
    -> Custom Monitor noted as in-use and cannot be removed

    Workaround tries to unassociate monitor manually and without transactions
    via iControl REST API.

    :param loadbalancers: loadbalancers
    :param bigips: bigips
    """
    if pool.health_monitor and driver_utils.pending_delete(pool.health_monitor):
        for bigip in bigips:
            try:
                pool_resource_path = '{pool_path}/~{net_id}~{lb_id}~{pool_id}'.format(
                    pool_path=F5_POOL_PATH, net_id=m_tenant.get_name(network_id),
                    lb_id=m_app.get_name(loadbalancer_id), pool_id=m_pool.get_name(pool.id)
                )
                pool_json = bigip.get(pool_resource_path)

                if pool_json.ok:
                    pool_dict = pool_json.json()
                    if 'monitor' in pool_dict:
                        pool_dict['monitor'] = None
                        bigip.put(pool_resource_path, json=pool_dict)
            except exceptions.AS3Exception:
                pass