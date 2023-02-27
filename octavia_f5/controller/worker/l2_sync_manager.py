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

from concurrent import futures
from itertools import chain

import prometheus_client as prometheus
import requests
from oslo_config import cfg
from oslo_log import log as logging
from taskflow.listeners import logging as tf_logging

from octavia.common import data_models as octavia_models
from octavia.common.base_taskflow import BaseTaskFlowEngine
from octavia.network import base
from octavia.network import data_models as network_models
from octavia_f5.controller.worker.flows import f5_flows
from octavia_f5.controller.worker.tasks import f5_tasks
from octavia_f5.restclient.bigip import bigip_auth
from octavia_f5.restclient.bigip.bigip_restclient import BigIPRestClient
from octavia_f5.utils import driver_utils, decorators

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class L2SyncManager(BaseTaskFlowEngine):
    """Manager class maintaining connection to BigIPs for L2 configuration"""

    _metric_failed_futures = prometheus.metrics.Counter(
        'octavia_l2_failed_futures', 'Failed l2 task futures', ['device', 'task'])

    def __init__(self):
        super(L2SyncManager).__init__()
        self._bigips = list(self.initialize_bigips(CONF.f5_agent.bigip_urls))
        self._vcmps = list(self.initialize_bigips(CONF.networking.vcmp_urls))
        self._f5flows = f5_flows.F5Flows()
        self._network_driver = driver_utils.get_network_driver()
        self.executor = futures.ThreadPoolExecutor(max_workers=CONF.networking.max_workers)

    def initialize_bigips(self, bigip_urls: [str]):
        if CONF.f5_agent.dry_run:
            return []

        instances = []
        for bigip_url in bigip_urls:
            # Create iControlREST client for every bigip

            kwargs = {'bigip_url': bigip_url,
                      'verify': CONF.f5_agent.bigip_verify}

            if CONF.f5_agent.bigip_token:
                kwargs['auth'] = bigip_auth.BigIPTokenAuth(bigip_url)
            else:
                kwargs['auth'] = bigip_auth.BigIPBasicAuth(bigip_url)

            instance = BigIPRestClient(**kwargs)
            instances.append(instance)
        return instances

    def bigips(self):
        """ :returns all BigIP instances """
        return self._bigips

    def vcmps(self):
        """ :returns all BigIP instances """
        return self._vcmps

    def failover(self):
        """ Failover callback for updating the active/passive property """
        for bigip in self._bigips:
            bigip.update_status()

    def _do_ensure_l2_flow(self, selfips: [network_models.Port], store: dict):
        e = self.taskflow_load(self._f5flows.ensure_l2(selfips), store=store)
        with tf_logging.DynamicLoggingListener(e, log=LOG):
            e.run()

    def _do_ensure_vcmp_l2_flow(self, store: dict):
        e = self.taskflow_load(self._f5flows.ensure_vcmp_l2(), store=store)
        with tf_logging.DynamicLoggingListener(e, log=LOG):
            e.run()

    def _do_remove_l2_flow(self, store: dict):
        e = self.taskflow_load(self._f5flows.get_selfips_from_device_for_vlan(), store=store)
        with tf_logging.LoggingListener(e, log=LOG):
            e.run()

        selfips = e.storage.get('all-selfips')

        e = self.taskflow_load(self._f5flows.remove_l2(selfips), store=store)
        with tf_logging.LoggingListener(e, log=LOG):
            e.run()

    def _do_sync_l2_selfips_flow(self, expected_selfips: [network_models.Port], store: dict):
        e = self.taskflow_load(self._f5flows.get_selfips_from_device_for_vlan(), store=store)
        with tf_logging.LoggingListener(e, log=LOG):
            e.run()

        device_selfips = e.storage.get('all-selfips')
        selfips = {
            'add': [port for port in expected_selfips if port.id not in [p.id for p in device_selfips]],
            'remove': [port for port in device_selfips if port.id not in [p.id for p in expected_selfips]]
        }

        LOG.debug("%s: L2 SelfIP sync diff for network %s: %s",
                  store['bigip'].hostname, store['network'].id, {'add': [p.id for p in selfips['add']],
                                                                 'remove': [p.id for p in selfips['remove']]})

        e = self.taskflow_load(self._f5flows.sync_l2_selfips(selfips), store=store)
        with tf_logging.LoggingListener(e, log=LOG):
            e.run()

    def _do_sync_l2_static_routes_flow(self, selfips: [network_models.Port], store: dict):
        ensure_static_routes = f5_tasks.SyncSubnetRoutes(inject={'selfips': selfips})
        e = self.taskflow_load(ensure_static_routes, store=store)
        with tf_logging.LoggingListener(e, log=LOG):
            e.run()

    def _do_remove_vcmp_l2_flow(self, store: dict):
        e = self.taskflow_load(self._f5flows.remove_vcmp_l2(), store=store)
        with tf_logging.DynamicLoggingListener(e, log=LOG):
            e.run()

    def ensure_l2_flow(self, selfips: [network_models.Port], network_id: str, device=None):
        """ Runs the taskflows for ensuring correct l2 configuration on all bigip devices in parallel

        :param selfips: Neutron SelfIP ports
        :param network_id: Neutron Network ID
        :param device: optional device host to sync, defaults to all devices to sync
        """
        if not selfips:
            return

        network = self._network_driver.get_network(network_id)
        if not network.has_bound_segment():
            raise Exception(f"Failed ensure_l2_flow for network_id={network_id}: No segment bound")

        fs = {}
        for bigip in self._bigips:
            if device and bigip.hostname != device:
                continue

            selfips_for_host = [selfip for selfip in selfips if bigip.hostname in selfip.name]
            subnet_ids = set(sip.fixed_ips[0].subnet_id for sip in selfips_for_host)
            store = {'bigip': bigip, 'network': network, 'subnet_id': subnet_ids.pop()}
            fs[self.executor.submit(self._do_ensure_l2_flow, selfips=selfips_for_host, store=store)] = bigip

        if CONF.networking.override_vcmp_guest_names:
            guest_names = CONF.networking.override_vcmp_guest_names
        else:
            guest_names = [bigip.hostname for bigip in self._bigips]

        for vcmp in self._vcmps:
            store = {'bigip': vcmp, 'network': network, 'bigip_guest_names': guest_names}
            fs[self.executor.submit(self._do_ensure_vcmp_l2_flow, store=store)] = vcmp

        failed_bigips = []
        done, not_done = futures.wait(fs, timeout=CONF.networking.l2_timeout)
        for f in done | not_done:
            bigip = fs[f]
            try:
                f.result(0)
            except Exception as e:
                self._metric_failed_futures.labels(bigip.hostname, 'ensure_l2_flow').inc()
                LOG.error("Failed running ensure_l2_flow for host %s: %s", bigip.hostname, e)
                failed_bigips.append(bigip)

        # We raise error only if all pairs failed
        if self._bigips and all(bigip in failed_bigips for bigip in self._bigips):
            raise Exception(f"Failed ensure_l2_flow for all bigip devices of network_id={network_id}")

        if self._vcmps and all(vcmp in failed_bigips for vcmp in self._vcmps):
            raise Exception(f"Failed ensure_l2_flow for all vcmp devices of network_id={network_id}")

    def remove_l2_flow(self, network_id: str, device=None):
        """ Runs the taskflows for cleanup of l2 configuration on all bigip devices in parallel

        :param network_id: Neutron Network ID
        :param device: optional device host to sync, defaults to all devices to sync
        """

        try:
            network = self._network_driver.get_network(network_id)
        except base.NetworkNotFound:
            LOG.warning("remove_l2_flow: Network %s not found, skipping", network_id)
            return

        if not network.has_bound_segment():
            LOG.debug("remove_l2_flow: Network %s has no existing segment binding, skipping",
                      network_id)
            return

        fs = {}
        for bigip in self._bigips:
            if device and bigip.hostname != device:
                continue

            store = {'bigip': bigip, 'network': network}
            fs[self.executor.submit(self._do_remove_l2_flow, store=store)] = bigip

        if CONF.networking.override_vcmp_guest_names:
            guest_names = CONF.networking.override_vcmp_guest_names
        else:
            guest_names = [bigip.hostname for bigip in self._bigips]

        for vcmp in self._vcmps:
            store = {'bigip': vcmp, 'bigip_guest_names': guest_names, 'network': network}
            fs[self.executor.submit(self._do_remove_vcmp_l2_flow, store=store)] = vcmp

        done, not_done = futures.wait(fs, timeout=CONF.networking.l2_timeout)
        for f in done | not_done:
            bigip = fs[f]
            try:
                f.result(0)
            except Exception as e:
                self._metric_failed_futures.labels(bigip.hostname, 'remove_l2_flow').inc()
                LOG.error("Failed running remove_l2_flow for host %s: %s", bigip.hostname, e)

    def sync_l2_selfips_flow(self, selfips: [network_models.Port], network_id: str, device=None):
        """ Runs the taskflows to sync selfips (add/remove) on all bigip devices in parallel

        :param selfips: Neutron SelfIP ports expected
        :param network_id: Neutron Network ID
        :param device: optional device host to sync, defaults to all devices to sync
        """
        if not selfips:
            return

        network = self._network_driver.get_network(network_id)
        if not network.has_bound_segment():
            raise Exception(f"Failed sync_l2_selfips_flow for network_id={network_id}: No segment bound")

        fs = {}
        for bigip in self._bigips:
            if device and bigip.hostname != device:
                continue

            store = {'bigip': bigip, 'network': network}
            selfips_for_host = [selfip for selfip in selfips if bigip.hostname in selfip.name]
            fs[self.executor.submit(self._do_sync_l2_selfips_flow,
                                    expected_selfips=selfips_for_host,
                                    store=store)] = bigip
            fs[self.executor.submit(self._do_sync_l2_static_routes_flow,
                                    selfips=selfips_for_host, store=store)] = bigip

        done, not_done = futures.wait(fs, timeout=10)
        for f in done | not_done:
            bigip = fs[f]
            try:
                f.result(0)
            except Exception as e:
                self._metric_failed_futures.labels(bigip.hostname, 'sync_l2_selfips_flow').inc()
                LOG.error("Failed running sync_l2_selfips_flow for host %s: %s", bigip.hostname, e)

    @decorators.RaisesIControlRestError()
    def full_sync(self, loadbalancers: [octavia_models.LoadBalancer]):
        """ Initiates a full sync for all L2 entities, this is a very api-heavy function. """
        network_ids = set(lb.vip.network_id for lb in loadbalancers)
        networks = {net.id: net for net in
                    self.executor.map(self._network_driver.get_network, network_ids, timeout=60)}
        selfip_ports = list(chain.from_iterable(
            self._network_driver.ensure_selfips(loadbalancers, cleanup_orphans=True)))

        LOG.info("Running l2 full-sync [#loadbalancers=%d, #networks=%d, #selfips=%d]",
                 len(loadbalancers), len(network_ids), len(selfip_ports))

        # Use dedicated executor to ensure serial deletion
        executor = futures.ThreadPoolExecutor(max_workers=1)
        fs = []
        for bigip in self._bigips:
            """ 1. Delete all orphaned routes """
            res = bigip.get(path='/mgmt/tm/net/route')
            res.raise_for_status()
            for route in res.json().get('items', []):
                # Check if route name is a legacy route net-{network_id}
                if route['name'] in [f"net-{id}" for id in network_ids]:
                    net_id = route['name'][len('net-'):]
                    # Consider route with unexpected vlan to be obsoloted
                    if net_id in networks and route['network'].endswith(str(networks[net_id].vlan_id)):
                        continue

                if route['name'] in [f"vlan-{network.vlan_id}" for network in networks.values()]:
                    continue

                # Skip unmanaged routes
                if not (route['name'].startswith('net-') or route['name'].startswith('vlan-')):
                    continue

                # Cleanup
                path = f"/mgmt/tm/net/route/{route['fullPath'].replace('/', '~')}"
                fs.append(executor.submit(bigip.delete, path=path))

            """ 2. Delete all orphaned selfips """
            res = bigip.get(path='/mgmt/tm/net/self')
            res.raise_for_status()
            for selfip in res.json().get('items', []):
                if selfip['name'] in [f"port-{sip.id}" for sip in selfip_ports]:
                    continue

                # Skip unmanaged selfips
                if not selfip['name'].startswith('port-'):
                    continue

                # Cleanup SelfIP
                path = f"/mgmt/tm/net/self/{selfip['fullPath'].replace('/', '~')}"
                fs.append(executor.submit(bigip.delete, path=path))

            """ 3. Delete all orphaned route domains """
            res = bigip.get(path='/mgmt/tm/net/route-domain')
            res.raise_for_status()
            for route_domain in res.json().get('items', []):
                if route_domain['name'] in [f"net-{id}" for id in network_ids]:
                    net_id = route_domain['name'][len('net-'):]
                    # Consider routedomain with unexpected vlan to be obsoloted
                    if net_id in networks and route_domain['id'] == networks[net_id].vlan_id:
                        continue

                if route_domain['name'] in [f"vlan-{network.vlan_id}" for network in networks.values()]:
                    continue

                # Skip unmanaged route domains
                if not (route_domain['name'].startswith('net-') or route_domain['name'].startswith('vlan-')):
                    continue

                # Cleanup Route-Domain
                path = f"/mgmt/tm/net/route-domain/{route_domain['fullPath'].replace('/', '~')}"
                fs.append(executor.submit(bigip.delete, path=path))

            """ 4. Delete all orphaned vlans """
            res = bigip.get(path='/mgmt/tm/net/vlan')
            res.raise_for_status()
            for vlan in res.json().get('items', []):
                if vlan['name'] in [f"vlan-{network.vlan_id}" for network in networks.values()]:
                    continue

                # Skip unmanaged vlans
                if not vlan['name'].startswith('vlan'):
                    continue

                # Cleanup Route-Domain
                path = f"/mgmt/tm/net/vlan/{vlan['fullPath'].replace('/', '~')}"
                fs.append(executor.submit(bigip.delete, path=path))

        """ 5. Full sync """
        for network in networks.values():
            selfips = [sip for sip in selfip_ports if sip.network_id == network.id]
            fs.append(executor.submit(self.ensure_l2_flow, selfips=selfips, network_id=network.id))

        """ 6. Execute cleanup and full-sync and collect any errors """
        done, not_done = futures.wait(fs, timeout=CONF.networking.l2_timeout * len(networks))
        for f in done | not_done:
            try:
                res = f.result(0)
                if isinstance(res, requests.Response):
                    with decorators.RaisesIControlRestError():
                        res.raise_for_status()
            except Exception as e:
                LOG.exception(e)

        LOG.info("Finished l2 full-sync")
