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

from stevedore import driver
from oslo_config import cfg
from oslo_log import log as logging

from octavia_f5.common import constants
from octavia_lib.api.drivers import data_models

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


def pending_delete(obj):
    return obj.provisioning_status == constants.PENDING_DELETE


def get_network_driver():
    CONF.import_group('controller_worker', 'octavia.common.config')
    return driver.DriverManager(
        namespace='octavia.network.drivers',
        name=CONF.controller_worker.network_driver,
        invoke_on_load=True
    ).driver


def lb_to_vip_obj(lb):
    vip_obj = data_models.VIP()
    if lb.vip_address:
        vip_obj.ip_address = lb.vip_address
    if lb.vip_network_id:
        vip_obj.network_id = lb.vip_network_id
    if lb.vip_port_id:
        vip_obj.port_id = lb.vip_port_id
    if lb.vip_subnet_id:
        vip_obj.subnet_id = lb.vip_subnet_id
    if lb.vip_qos_policy_id:
        vip_obj.qos_policy_id = lb.vip_qos_policy_id
    vip_obj.load_balancer = lb
    return vip_obj
