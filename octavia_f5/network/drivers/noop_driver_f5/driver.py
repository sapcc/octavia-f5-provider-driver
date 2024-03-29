# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

from octavia.network.drivers.noop_driver import driver
from octavia_f5.network import data_models

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class NoopNetworkDriverF5(driver.NoopNetworkDriver):
    def __init__(self):
        self.physical_network = 'physnet'
        self.physical_interface = 'portchannel1'
        super(NoopNetworkDriverF5, self).__init__()

    def allocate_vip(self, load_balancer):
        return super(NoopNetworkDriverF5, self).allocate_vip(load_balancer)

    def get_scheduled_host(self, port_id):
        return CONF.host

    def get_segmentation_id(self, network_id, host=None):
        return 1234

    def get_network(self, network_id, context=None):
        return data_models.Network()

    def ensure_selfips(self, load_balancers, agent=None, cleanup_orphans=False):
        return ([], [])

    def cleanup_selfips(self, selfips):
        return

    def create_vip(self, load_balancer, candidate):
        return self.driver.create_port(load_balancer.vip.network_id)

    def invalidate_cache(self, hard=True):
        pass
