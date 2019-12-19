#    Copyright 2018 SAP SE
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
from oslo_log import log as logging

from octavia.api.drivers.amphora_driver import driver
from octavia_lib.api.drivers import exceptions

CONF = cfg.CONF
CONF.import_group('oslo_messaging', 'octavia.common.config')
LOG = logging.getLogger(__name__)


class F5ProviderDriver(driver.AmphoraProviderDriver):
    """Octavia plugin for the F5 driver."""
    def __init__(self):
        super(F5ProviderDriver, self).__init__()

    def create_vip_port(self, loadbalancer_id, project_id, vip_dictionary):
        # Let Octavia create the port
        raise exceptions.NotImplementedError()

    def loadbalancer_failover(self, loadbalancer_id):
        raise exceptions.NotImplementedError()

    def get_supported_flavor_metadata(self):
        raise exceptions.NotImplementedError()

    def validate_flavor(self, flavor_metadata):
        raise exceptions.NotImplementedError()
