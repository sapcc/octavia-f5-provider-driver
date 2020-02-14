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

from jsonschema import exceptions as js_exceptions
from jsonschema import validate
from oslo_config import cfg
from oslo_log import log as logging

from octavia.api.drivers.amphora_driver import driver
from octavia_f5.api.drivers.f5_driver import flavor_schema
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
        """Performs a fail over of a load balancer.

        :param loadbalancer_id (string): ID of the load balancer to failover.
        :return: Nothing if the failover request was accepted.
        :raises DriverError: An unexpected error occurred in the driver.
        :raises: NotImplementedError if driver does not support request.
        """
        raise exceptions.NotImplementedError()

    # Same as the super method, but it had to be copied, because of
    # the reference to flavor_schema.SUPPORTED_FLAVOR_SCHEMA
    def get_supported_flavor_metadata(self):
        """Returns the valid flavor metadata keys and descriptions.

        This extracts the valid flavor metadata keys and descriptions
        from the JSON validation schema and returns it as a dictionary.

        :return: Dictionary of flavor metadata keys and descriptions.
        :raises DriverError: An unexpected error occurred.
        """
        try:
            props = flavor_schema.SUPPORTED_FLAVOR_SCHEMA['properties']
            return {k: v.get('description', '') for k, v in props.items()}
        except Exception as e:
            raise exceptions.DriverError(
                user_fault_string='Failed to get the supported flavor '
                                  'metadata due to: {}'.format(str(e)),
                operator_fault_string='Failed to get the supported flavor '
                                      'metadata due to: {}'.format(str(e)))

    # Mostly same as the super method, but it had to be copied, because of
    # the reference to flavor_schema.SUPPORTED_FLAVOR_SCHEMA
    def validate_flavor(self, flavor_dict):
        """Validates if driver can support flavor as defined in flavor_metadata.

        :param flavor_metadata (dict): Dictionary with flavor metadata.
        :return: Nothing if the flavor is valid and supported.
        :raises DriverError: An unexpected error occurred in the driver.
        :raises NotImplementedError: The driver does not support flavors.
        :raises UnsupportedOptionError: if driver does not
              support one of the configuration options.
        """
        try:
            validate(flavor_dict, flavor_schema.SUPPORTED_FLAVOR_SCHEMA)
        except js_exceptions.ValidationError as e:
            error_object = ''
            if e.relative_path:
                error_object = '{} '.format(e.relative_path[0])
            raise exceptions.UnsupportedOptionError(
                user_fault_string='{0}{1}'.format(error_object, e.message),
                operator_fault_string=str(e))
        except Exception as e:
            raise exceptions.DriverError(
                user_fault_string='Failed to validate the flavor metadata '
                                  'due to: {}'.format(str(e)),
                operator_fault_string='Failed to validate the flavor metadata '
                                      'due to: {}'.format(str(e)))