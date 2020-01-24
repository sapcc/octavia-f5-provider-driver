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
from oslo_cache import core as cache
from oslo_config import cfg
from oslo_log import log as logging

from octavia.db import api as db_apis
from octavia.i18n import _
from octavia.network import base
from octavia.network.drivers.neutron import allowed_address_pairs as aap
from octavia.network.drivers.neutron import utils
from octavia_f5.common import constants
from octavia_f5.db import repositories

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
PROJECT_ID_ALIAS = 'project-id'

cache.configure(CONF)
cache_region = cache.create_region()
MEMOIZE = cache.get_memoization_decorator(
    CONF, cache_region, "networking")
cache.configure_cache_region(CONF, cache_region)


class HierachicalPortBindingDriver(aap.AllowedAddressPairsDriver):
    def __init__(self):
        super(HierachicalPortBindingDriver, self).__init__()
        self.amp_repo = repositories.AmphoraRepository()

    def allocate_vip(self, load_balancer):
        port_id = load_balancer.vip.port_id
        if port_id:
            LOG.info('Port %s already exists. Nothing to be done.', port_id)
            port = self.get_port(port_id)
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

        # select a candidate to schedule to
        try:
            session = db_apis.get_session()
            candidate = self.amp_repo.get_candidates(session)[0]
        except ValueError as e:
            message = _('Scheduling failed, no ready candidates found')
            LOG.exception(message)
            raise base.AllocateVIPException(
                message,
                orig_msg=getattr(e, 'message', None),
                orig_code=getattr(e, 'status_code', None),
            )
        LOG.debug("Found candidates for new LB %s: %s", load_balancer.id, candidate)

        # It can be assumed that network_id exists
        port = {'port': {'name': 'octavia-lb-{}'.format(load_balancer.id),
                         'network_id': load_balancer.vip.network_id,
                         'admin_state_up': False,
                         'device_id': 'lb-{0}'.format(load_balancer.id),
                         'device_owner': constants.DEVICE_OWNER_LISTENER,
                         # TODO: needs to be auto-scheduled by agent
                         'binding:host_id': 'f512-01',
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

        if port and port.device_owner == constants.DEVICE_OWNER_LISTENER:
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

    @MEMOIZE
    def get_scheduled_host(self, port_id):
        """ Returns binding host port has been scheduled

        :param port_id: the neutron port id
        :return: hostname of the binding host
        """
        res = self.neutron_client.show_port(port_id)
        return res['port']['binding:host_id']

    @MEMOIZE
    def get_segmentation_id(self, network_id):
        physical_network = CONF.networking.f5_network_segment_physical_network
        # List neutron ports associated with the Amphora
        try:
            network = self.neutron_client.show_network(network_id)
            for segment in network['network']['segments']:
                if segment['provider:physical_network'] == physical_network:
                    return segment['provider:segmentation_id']
        except Exception as e:
            LOG.error('Error retrieving segmentation id for network "%s": %s', network_id, e)
        return 0
