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

from urllib import parse

import ipaddress
import re
import requests.exceptions
import tenacity
from neutronclient.common import exceptions as neutron_client_exceptions
from oslo_cache import core as cache
from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import data_models as octavia_models, exceptions
from octavia.db import api as db_apis
from octavia.i18n import _
from octavia.network import base
from octavia.network import data_models as network_models
from octavia.network.drivers.neutron import base as neutron_base
from octavia.network.drivers.neutron import utils
from octavia_f5.common import constants
from octavia_f5.db import repositories
from octavia_f5.db import scheduler
from octavia_f5.network.drivers.neutron import utils as f5_utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
CONF.import_group('networking', 'octavia_f5.common.config')
PROJECT_ID_ALIAS = 'project-id'

cache.configure(CONF)
cache_region = cache.create_region()
MEMOIZE = cache.get_memoization_decorator(
    CONF, cache_region, "networking")
cache.configure_cache_region(CONF, cache_region)


class NeutronClient(neutron_base.BaseNeutronDriver):
    """ The networking-f5 octavia driver is a octavia-only version of the
        networking-f5 driver for neutron. Octavia worker will provision L2 Routes,
        Routedomains, Self-IPs and VLANs by it's own and update the corresponding
        Neutron port via Neutrons API.

        This driver is preferred to the legacy neutron networking-f5 driver and just needs a
        dummy ml2 binding driver on neutron side.
    """

    def __init__(self):
        LOG.info("Initializing Neutron Client")
        super(NeutronClient, self).__init__()
        self.scheduler = scheduler.Scheduler()
        self.amphora_repo = repositories.AmphoraRepository()
        self.physical_network = None
        self.physical_interface = None
        self.parse_mapping(CONF.networking.physical_interface_mapping)
        LOG.info("Initialized Neutron Client")

    def _validate_fixed_ip(self, fixed_ips, subnet_id, ip_address):
        """Validate an IP address exists in a fixed_ips dict

        :param fixed_ips: A port fixed_ups dict
        :param subnet_id: The subnet that should contain the IP
        :param ip_address: The IP address to validate
        :returns: True if the ip address is in the dict, False if not
        """
        for fixed_ip in fixed_ips:
            normalized_fixed_ip = ipaddress.ip_address(
                fixed_ip.ip_address).compressed
            normalized_ip = ipaddress.ip_address(ip_address).compressed
            if (fixed_ip.subnet_id == subnet_id and
                    normalized_fixed_ip == normalized_ip):
                return True
        return False

    @staticmethod
    def _fixed_ips_to_list_of_dicts(fixed_ips):
        list_of_dicts = []
        for fixed_ip in fixed_ips:
            list_of_dicts.append(fixed_ip.to_dict())
        return list_of_dicts

    def allocate_vip(self, load_balancer: octavia_models.LoadBalancer):
        if load_balancer.vip.port_id:
            try:
                port = self.get_port(load_balancer.vip.port_id)
                fixed_ip_found = self._validate_fixed_ip(
                    port.fixed_ips, load_balancer.vip.subnet_id,
                    load_balancer.vip.ip_address)
                if (port.network_id == load_balancer.vip.network_id and
                        fixed_ip_found):
                    LOG.info('Port %s already exists. Nothing to be done.',
                             load_balancer.vip.port_id)
                    return self._port_to_vip(port, load_balancer)
                LOG.error('Neutron VIP mis-match. Expected ip %s on '
                          'subnet %s in network %s. Neutron has fixed_ips %s '
                          'in network %s. Deleting and recreating the VIP '
                          'port.', load_balancer.vip.ip_address,
                          load_balancer.vip.subnet_id,
                          load_balancer.vip.network_id,
                          self._fixed_ips_to_list_of_dicts(port.fixed_ips),
                          port.network_id)
                if load_balancer.vip.octavia_owned:
                    self.delete_port(load_balancer.vip.port_id)
                else:
                    raise base.AllocateVIPException(
                        'VIP port {0} is broken, but is owned by project {1} '
                        'so will not be recreated. Aborting VIP allocation.'
                            .format(port.id, port.project_id))
            except base.AllocateVIPException as e:
                # Catch this explicitly because otherwise we blame Neutron
                LOG.error(getattr(e, 'message', None))
                raise
            except base.PortNotFound:
                LOG.warning('VIP port %s is missing from neutron. Rebuilding.',
                            load_balancer.vip.port_id)
            except Exception as e:
                message = _('Neutron is failing to service requests due to: '
                            '{}. Aborting.').format(str(e))
                LOG.error(message)
                raise base.AllocateVIPException(
                    message,
                    orig_msg=getattr(e, 'message', None),
                    orig_code=getattr(e, 'status_code', None), )

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
            candidate = self.scheduler.get_candidates(session, load_balancer.availability_zone)[0]
        except (ValueError, IndexError) as e:
            message = _('Scheduling failed, no ready candidates found')
            LOG.exception(message)
            raise base.AllocateVIPException(
                message,
                orig_msg=getattr(e, 'message', None),
                orig_code=getattr(e, 'status_code', None),
            )
        LOG.debug("Found candidates for new LB %s: %s", load_balancer.id, candidate)

        # It can be assumed that network_id exists
        vip_port = {'port': {'name': 'loadbalancer-{}'.format(load_balancer.id),
                             'network_id': load_balancer.vip.network_id,
                             'admin_state_up': True,
                             'device_id': load_balancer.id,
                             'device_owner': constants.DEVICE_OWNER_LISTENER,
                             'binding:host_id': candidate,
                             project_id_key: load_balancer.project_id}}

        if fixed_ip:
            vip_port['port']['fixed_ips'] = [fixed_ip]
        try:
            new_port = self.neutron_client.create_port(vip_port)
        except Exception as e:
            message = _('Error creating neutron port for network '
                        '{network_id}.').format(
                network_id=load_balancer.vip.network_id)
            LOG.exception(message)
            raise base.AllocateVIPException(
                message,
                orig_msg=getattr(e, 'message', None),
                orig_code=getattr(e, 'status_code', None),
            )

        try:
            selfips = self.ensure_selfips([load_balancer], candidate)
        except Exception as e:
            message = _('Error creating selfips for network '
                        '{network_id}: {err}.').format(
                network_id=load_balancer.vip.network_id,
                err=e
            )
            LOG.exception(message)
            raise base.AllocateVIPException(
                message,
                orig_msg=getattr(e, 'message', None),
                orig_code=getattr(e, 'status_code', None),
            )

        # Convert to octavia objects
        new_port = utils.convert_port_dict_to_model(new_port)

        # Update allowed address pairs
        self.update_aap(new_port, selfips)
        LOG.debug(f"Ensured SelfIPs {[selfip.id for selfip in selfips]} for VIP {new_port.id}")

        return self._port_to_vip(new_port, load_balancer)

    def deallocate_vip(self, vip):
        try:
            port = self.get_port(vip.port_id)
        except base.PortNotFound:
            LOG.warning("Can't deallocate VIP because the vip port {0} "
                        "cannot be found in neutron. "
                        "Continuing cleanup.".format(vip.port_id))
            port = None

        if port and port.device_owner in [constants.DEVICE_OWNER_LISTENER, constants.DEVICE_OWNER_LEGACY]:
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
            LOG.warning("Port %s will not be deleted by Octavia as it was "
                        "not created by Octavia.", vip.port_id)

    @MEMOIZE
    def get_scheduled_host(self, port_id):
        """ Returns binding host port has been scheduled

        :param port_id: the neutron port id
        :return: hostname of the binding host
        """
        res = self.neutron_client.show_port(port_id)
        return res['port']['binding:host_id']

    def get_network(self, network_id, context=None):
        """ Overrides get_network to use a customized version that holds this segment id.

        :rtype: octavia_f5 network object
        """
        try:
            network_dict = self.neutron_client.show_network(network_id)
        except neutron_client_exceptions.NotFound:
            message = _(f"Network not found (network id: {network_id}).")
            raise base.NetworkNotFound(message)
        except Exception:
            message = _(f"Error retrieving network (network id: {network_id}.")
            LOG.exception(message)
            raise base.NetworkException(message)
        return f5_utils.convert_network_dict_to_model(network_dict)

    @MEMOIZE
    def get_segmentation_id(self, network_id, host):
        try:
            network = self.neutron_client.show_network(network_id)
            for segment in network['network']['segments']:
                if segment['provider:physical_network'] == self.physical_network:
                    return segment['provider:segmentation_id']
        except Exception as e:
            LOG.error('Error retrieving segmentation id for network "%s": %s', network_id, e)
            raise e
        raise base.NetworkException('No segmentation id for network "{}" found'.format(network_id))

    def parse_mapping(self, mapping):
        if not mapping:
            return
        mapping = mapping.strip()
        split_result = mapping.split(':')
        physical_network = split_result[0].strip()
        if not physical_network:
            raise ValueError(_("Missing physical_network in mapping: '%s'") % mapping)
        self.physical_network = physical_network

        if len(split_result) != 2:
            self.physical_interface = constants.DEFAULT_PHYSICAL_INTERFACE
            return
        physical_interface = split_result[1].strip()
        if not physical_interface:
            raise ValueError(_("Missing physical_interface in mapping: '%s'") % mapping)
        self.physical_interface = physical_interface

    @staticmethod
    def _make_selfip_dict(project_id: str, network_id: str, subnet_id: str, f5host: str, agent: str):
        return {
            'port': {
                'tenant_id': project_id,
                'binding:host_id': agent,
                'name': 'local-{}-{}'.format(f5host, subnet_id),
                'network_id': network_id,
                'device_owner': constants.DEVICE_OWNER_SELFIP,
                'device_id': subnet_id,
                'description': f5host,
                'admin_state_up': True,
                'fixed_ips': [{'subnet_id': subnet_id}]
            }
        }

    def _get_f5_hostnames(self, host: str) -> [str]:
        """ Returns f5 device hostnames of a specific agent host.

        :param host: agent hostname
        :return: array of hostnames
        """
        # If this is a worker, we can just parse it from config
        if CONF.f5_agent.bigip_urls:
            return [parse.urlsplit(url, allow_fragments=False).hostname
                    for url in CONF.f5_agent.bigip_urls]

        # Fetch from database
        if host:
            session = db_apis.get_session()
            return self.amphora_repo.get_devices_for_host(session, host)

        raise Exception(f"Hostname not found for host {host}")

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(
            (neutron_client_exceptions.Conflict,
             neutron_client_exceptions.InternalServerError,
             neutron_client_exceptions.ServiceUnavailable,
             requests.exceptions.ConnectionError)),
        wait=tenacity.wait_incrementing(1, 1, 5),
        stop=tenacity.stop_after_attempt(15))
    def ensure_selfips(self, load_balancers: [octavia_models.LoadBalancer],
                       agent: str = None,
                       cleanup_orphans: bool = False) -> [network_models.Port]:
        """ Ensures, that for a specific Neutron Load-Balancer VIP port,
            SelfIP ports in Neutron are existing and returns them.

        :param load_balancers: Octavia Load Balancers
        :param agent: Optional agent host, if null will be discovered from load_balancer db
        :param cleanup_orphans: Remove orphaned selfips (requires all load_balancers of this agent)
        :return: Array of SelfIP Ports
        """

        if not load_balancers:
            return []

        if not agent:
            # get the hosted agent, only expect one
            hosts_id = list(set(lb.server_group_id for lb in load_balancers if lb.server_group_id is not None))
            if len(hosts_id) != 1:
                raise Exception("Could not identify single host: {}".format(hosts_id))
        else:
            hosts_id = [agent]

        requested_subnets = set(lb.vip.subnet_id for lb in load_balancers)
        filter = {'device_owner': [constants.DEVICE_OWNER_SELFIP,
                                   constants.DEVICE_OWNER_LEGACY],
                  'binding:host_id': hosts_id,
                  'fixed_ips': [f'subnet_id={subnet}' for subnet in requested_subnets]}
        selfips = self.neutron_client.list_ports(**filter).get('ports', [])

        # For every subnet and f5host, we expect a selfip
        f5hosts = {host: set() for host in self._get_f5_hostnames(hosts_id[0])}
        for selfip in list(selfips):
            m = re.match('local-(.*)-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',
                         selfip.get('name', ''))
            if not m:
                continue

            host, subnet = m.group(1, 2)
            # only accepts existing selfip if it's assigned to a valid host, unique and uses an expected subnet
            if host in f5hosts and subnet in requested_subnets and subnet not in f5hosts[host]:
                f5hosts[m.group(1)].add(m.group(2))
            elif cleanup_orphans:
                # Not a valid selfip, delete and remove from original list
                LOG.info("Orphaned SelfIP for Network %s found, deleting port %s",
                         selfip['network_id'], selfip['id'])
                try:
                    self.neutron_client.delete_port(selfip['id'])
                except neutron_client_exceptions.NetworkNotFoundClient:
                    pass
                selfips.remove(selfip)

        # create missing selfips
        project_id = load_balancers[0].project_id
        network_id = load_balancers[0].vip.network_id
        for f5host, existing_selfip_subnets in f5hosts.items():
            # iterate over missing subnet selfips per device
            for subnet_id in requested_subnets.difference(existing_selfip_subnets):
                if subnet_id is None:
                    continue
                # Create SelfIP Port for device
                try:
                    selfip_dict = self._make_selfip_dict(project_id, network_id, subnet_id, f5host, hosts_id[0])
                    selfips.append(self.neutron_client.create_port(selfip_dict))
                except neutron_client_exceptions.NetworkNotFoundClient:
                    pass

        return [utils.convert_port_dict_to_model(selfip) for selfip in selfips]

    def update_aap(self, vip: network_models.Port, selfips: [network_models.Port]):
        """ Tries to update a VIP ports allowed_address_pairs with SelfIPs ip addresses

        :param vip: Network VIP port
        :param selfips: SelfIP ports
        """
        if not selfips:
            return

        aap = {
            'port': {
                'allowed_address_pairs': [
                    {'ip_address': selfip.fixed_ips[0].ip_address} for selfip in selfips
                ]
            }
        }
        try:
            self.neutron_client.update_port(vip.id, aap)
        except Exception as e:
            LOG.warning("Failed updating VIPs allowed_address_pairs %s: %s", vip.id, e)

    def cleanup_selfips(self, selfips: [network_models.Port]):
        for port in selfips:
            self.delete_port(port.id)

    def create_port(self, network_id, name=None, fixed_ips=(),
                    secondary_ips=(), security_group_ids=(),
                    admin_state_up=True, qos_policy_id=None):
        pass

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(
            (exceptions.NetworkServiceError)),
        wait=tenacity.wait_incrementing(1, 1, 5),
        stop=tenacity.stop_after_attempt(15))
    def delete_port(self, port_id):
        """delete a neutron port.

        :param port_id: The port ID to delete.
        :returns: None
        """
        try:
            self.neutron_client.delete_port(port_id)
        except (neutron_client_exceptions.NotFound,
                neutron_client_exceptions.PortNotFoundClient):
            LOG.debug('Port %s already deleted. Skipping.',
                      port_id)
        except Exception as e:
            raise exceptions.NetworkServiceError(net_error=str(e))

    def plug_vip(self, load_balancer, vip):
        pass

    def unplug_vip(self, load_balancer, vip):
        pass

    def plug_network(self, compute_id, network_id, ip_address=None):
        pass

    def unplug_network(self, compute_id, network_id, ip_address=None):
        pass

    def get_security_group(self, sg_name):
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
        pass

    def plug_aap_port(self, load_balancer, vip, amphora, subnet):
        pass

    def unplug_aap_port(self, vip, amphora, subnet):
        pass

    def set_port_admin_state_up(self, port_id, state):
        pass
