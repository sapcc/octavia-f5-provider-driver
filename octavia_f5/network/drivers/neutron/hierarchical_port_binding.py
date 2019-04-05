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

from neutronclient.common import exceptions as neutron_client_exceptions
from oslo_config import cfg
from oslo_log import log as logging
import six
from stevedore import driver as stevedore_driver

from octavia_f5.common import constants
from octavia.common import exceptions
from octavia.i18n import _
from octavia.network import base
from octavia.network.drivers.neutron import base as neutron_base
from octavia.network.drivers.neutron import utils

LOG = logging.getLogger(__name__)

PROJECT_ID_ALIAS = 'project-id'
VIP_SECURITY_GRP_PREFIX = 'lb-'
LBAASV2_OWNER = 'network:f5lbaasv2'

CONF = cfg.CONF


class HierachicalPortBindingDriver(neutron_base.BaseNeutronDriver):

    def __init__(self):
        super(HierachicalPortBindingDriver, self).__init__()

    def allocate_vip(self, load_balancer):
        if load_balancer.vip.port_id:
            LOG.info('Port %s already exists. Nothing to be done.',
                     load_balancer.vip.port_id)
            port = self.get_port(load_balancer.vip.port_id)
            return self._port_to_vip(port, load_balancer)

        fixed_ip = {}
        if load_balancer.vip.subnet_id:
            fixed_ip['subnet_id'] = load_balancer.vip.subnet_id
        if load_balancer.vip.ip_address:
            fixed_ip['ip_address'] = load_balancer.vip.ip_address

        # Make sure we are backward compatible with older neutron
        if self._check_extension_enabled(PROJECT_ID_ALIAS):
            project_id_key = 'project_id'
        else:
            project_id_key = 'tenant_id'

        # It can be assumed that network_id exists
        port = {'port': {'name': 'octavia-lb-' + load_balancer.id,
                         'network_id': load_balancer.vip.network_id,
                         'admin_state_up': False,
                         'device_id': 'lb-{0}'.format(load_balancer.id),
                         'device_owner': LBAASV2_OWNER,
                         'binding:host_id': 'f512-03',
                         project_id_key: load_balancer.project_id}}

        if fixed_ip:
            port['port']['fixed_ips'] = [fixed_ip]
        try:
            new_port = self.neutron_client.create_port(port)
        except Exception as e:
            message = _('Error creating neutron port on network '
                        '{network_id}.').format(
                network_id=load_balancer.vip.network_id)
            LOG.exception(message)
            raise base.AllocateVIPException(
                message,
                orig_msg=getattr(e, 'message', None),
                orig_code=getattr(e, 'status_code', None),
            )
        new_port = utils.convert_port_dict_to_model(new_port)
        return self._port_to_vip(new_port, load_balancer)

    def deallocate_vip(self, vip):
        try:
            port = self.get_port(vip.port_id)
        except base.PortNotFound:
            LOG.warning("Can't deallocate VIP because the vip port {0} "
                        "cannot be found in neutron. "
                        "Continuing cleanup.".format(vip.port_id))
            port = None

        self._delete_security_group(vip, port)

        if port and port.device_owner == LBAASV2_OWNER:
            try:
                self.neutron_client.delete_port(vip.port_id)
            except (neutron_client_exceptions.NotFound,
                    neutron_client_exceptions.PortNotFoundClient):
                LOG.debug('VIP port %s already deleted. Skipping.',
                          vip.port_id)
            except Exception:
                message = _('Error deleting VIP port_id {port_id} from '
                            'neutron').format(port_id=vip.port_id)
                LOG.exception(message)
                raise base.DeallocateVIPException(message)
        elif port:
            LOG.info("Port %s will not be deleted by Octavia as it was "
                     "not created by Octavia.", vip.port_id)

    def update_vip(self, load_balancer, for_delete=False):
        pass

    def plug_vip(self, load_balancer, vip):
        pass

    def unplug_vip(self, load_balancer, vip):
        pass

    def plug_network(self, compute_id, network_id, ip_address=None):
        pass

    def unplug_network(self, compute_id, network_id, ip_address=None):
        pass

    def failover_preparation(self, amphora):
        pass

    def plug_port(self, amphora, port):
        pass

    def get_network_configs(self, load_balancer, amphora=None):
        pass

    def wait_for_port_detach(self, amphora):
        pass

    def update_vip_sg(self, load_balancer, vip):
        """ Not supported yet """
        pass

    def plug_aap_port(self, load_balancer, vip, amphora, subnet):
        pass

    def unplug_aap_port(self, vip, amphora, subnet):
        pass

    def _delete_security_group(self, vip, port):
        """ Not implemented yet """
        pass