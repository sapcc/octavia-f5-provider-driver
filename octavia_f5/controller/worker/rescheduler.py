# Copyright 2021 SAP SE
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

import tenacity
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from six.moves.urllib import parse

from octavia.common import clients
from octavia.common import constants as api_consts
from octavia.db import repositories as repo
from octavia_f5.api.drivers.f5_driver.driver import F5ProviderDriver
from octavia_f5.common import constants
from octavia_f5.db import api as db_apis
from octavia_f5.db import repositories as f5_repos
from octavia_f5.utils import driver_utils

CONF = cfg.CONF
CONF.import_group('f5_agent', 'octavia_f5.common.config')
LOG = logging.getLogger(__name__)


class Rescheduler(object):

    def __init__(self):
        self.neutron_client = clients.NeutronAuth.get_neutron_client(
            endpoint=CONF.neutron.endpoint,
            region=CONF.neutron.region_name,
            endpoint_type=CONF.neutron.endpoint_type,
            service_name=CONF.neutron.service_name,
            insecure=CONF.neutron.insecure,
            ca_cert=CONF.neutron.ca_certificates_file
        )
        self.driver = F5ProviderDriver()
        self.network_driver = driver_utils.get_network_driver()
        self._amphora_repo = repo.AmphoraRepository()
        self._loadbalancer_repo = f5_repos.LoadBalancerRepository()
        self.locks = lockutils.FairLocks()

    def reschedule_loadbalancer(self, load_balancer_id, target_host):
        """Fail over one single load balancer from its host to another (target_host)"""

        load_balancer = self._loadbalancer_repo.get(db_apis.get_session(), id=load_balancer_id)

        # only reschedule LBs on this host
        if load_balancer.server_group_id == CONF.host:
            self._reschedule([load_balancer], target_host)

    def reschedule_loadbalancers(self, target_host):
        """Reschedule all load balancers from this host to target_host."""

        load_balancers = self._loadbalancer_repo.get_all_from_host(db_apis.get_session())
        self._reschedule(load_balancers, target_host)

    def _reschedule(self, load_balancers, target_host):
        """Reschedule all load balancers in list load_balancers to new host target_host.

        This is an internal function. It does not check whether the LBs are all on the same host.
        Use reschedule_loadbalancers if you want to reschedule multiple LBs from the same host.
        """

        # check target host
        if target_host is None:
            LOG.error("LB migration: Cannot move load balancer(s): No target host specified")
            return

        # create missing self IP ports
        # we need to create selfIP ports for every subnet that does not have any already on the target device
        LOG.info("Creating missing self IPs, if needed")

        # get all self IP ports
        try:
            query_filter = {
                'device_owner': 'network:f5selfip',
                'binding:host_id': target_host,
            }
            target_host_selfip_ports = self.neutron_client.list_ports(**query_filter).get('ports')
        except Exception as e:
            LOG.error("Cannot get ports from Neutron: {}".format(e))
            raise e

        # map to subnets that have selfIP ports on target host
        subnets_with_selfips_on_target_host = []
        for port in target_host_selfip_ports:
            for ip in port['fixed_ips']:
                subnet_id = ip['subnet_id']
                if subnet_id not in subnets_with_selfips_on_target_host:
                    subnets_with_selfips_on_target_host.append(subnet_id.replace('_', '-'))

        # get all subnets of load balancers to migrate
        lb_subnets = []
        for lb in load_balancers:
            lb_networking = {
                'project': lb.project_id,
                'network': lb.vip.network_id,
                'subnet': lb.vip.subnet_id,
            }
            if lb_networking not in lb_subnets:
                lb_subnets.append(lb_networking)

        # due to unreliable naming conventions we derive the target host name directly from the current one
        source_host_domain = parse.urlparse(CONF.f5_agent.bigip_urls[0]).hostname
        target_host_domain = source_host_domain.replace(CONF.host, target_host)

        # find subnets that don't have self IP ports on the target device yet and create needed ports
        for lb_networking in lb_subnets:
            subnet = lb_networking['subnet'].replace('_', '-')
            if subnet not in subnets_with_selfips_on_target_host:
                # we only need to create the port for one side, f5 agent creates it for the other side
                port_name = "local-{}-{}".format(target_host_domain, subnet)
                LOG.info("Creating self IP port with name {}, binding:host_id {}"
                         .format(port_name, target_host))
                port = {'port': {'name': port_name,
                                 'admin_state_up': False, # SelfIP port will be activated later
                                 'device_owner': constants.DEVICE_OWNER_SELF_IP,
                                 'binding:host_id': target_host,
                                 'network_id': lb_networking['network'],
                                 'description': target_host_domain,
                                 'project_id': lb_networking['project'],
                                 }}
                self.neutron_client.create_port(port)

        # now that all selfIP ports exist we can start moving load balancers
        LOG.info("Acquiring sync lock")
        with self.locks.get('sync_lbs').write_lock():

            # set new host in database
            # We are doing this for all LBs at once _before_ their VIP ports are switched over. This is so that the
            # worker of the target host can start working on all of them at once, else we might have to wait a long time
            # for each LB to be synced.
            for lb in load_balancers:
                LOG.info("LB/Amphora {}: Changing host '{}' to '{}'."
                         .format(lb.id, lb.server_group_id, target_host))
                self._amphora_repo.update(db_apis.get_session(), lb.id, compute_flavor=target_host)
                self._loadbalancer_repo.update(db_apis.get_session(), lb.id, server_group_id=target_host,
                                               provisioning_status=constants.PENDING_CREATE)

            # Retrying without limit is okay, since this process is always invoked manually and thus observed by a
            # human. When said human sees a load balancer being stuck, they can then fix it without having to invoke
            # this rescheduling call again
            @tenacity.retry()
            def wait_for_active_lb(lb_id):
                lb = self._loadbalancer_repo.get(db_apis.get_session(), id=lb_id)
                assert (lb.provisioning_status == constants.ACTIVE)

            # Wait for load balancers to be created, then rebind their port. Note that some load balancers will be
            # created before others and thus will stay dormant until this loop tends to them. That should not pose a
            # problem however, since the old load balancers are still in place, still routing traffic.
            for lb in load_balancers:
                # we must reimplement api.drivers.f5_driver.driver.F5ProviderDriver.loadbalancer_create because it
                # selects the wrong host to schedule to and needs another LB instance object than we have
                LOG.info("Telling worker of target host to create load balancer {} on host {}"
                         .format(lb.id, target_host))
                payload = {api_consts.LOAD_BALANCER_ID: lb.id, api_consts.FLAVOR: lb.flavor_id}
                client = self.driver.client.prepare(server=target_host)
                client.cast({}, 'create_load_balancer', **payload)

                # wait
                LOG.info("Waiting for load balancer {} to be created on new host {}..."
                         .format(lb.id, target_host))
                wait_for_active_lb(lb.id)
                LOG.info("Load balancer {} is ACTIVE on new host {}.".format(lb.id, target_host))

                # invalidate cache and rebind port
                LOG.info("Rebinding VIP port of load balancer {} to host {}".format(lb.id, target_host))
                port_update = {'port': {'binding:host_id': target_host}}
                self.network_driver.invalidate_cache()
                self.neutron_client.update_port(lb.vip.port_id, port_update)

                # since this method can take a very long time, log when it's done
                LOG.info("Done migrating load balancer {}".format(lb.id))

        # TODO mark created self IP ports as admin_state_up:True
        # TODO delete LB on old device

        LOG.info("Done. Sync lock released.")
