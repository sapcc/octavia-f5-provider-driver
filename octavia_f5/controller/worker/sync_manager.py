# Copyright 2019 SAP SE
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

import prometheus_client as prometheus
import tenacity
from oslo_config import cfg
from oslo_log import log as logging
from requests import ConnectionError, Timeout

from octavia_f5.db import api as db_apis
from octavia_f5.restclient import as3declaration
from octavia_f5.restclient.as3objects import tenant as m_part
from octavia_f5.restclient.as3restclient import AS3ExternalContainerRestClient, AS3RestClient
from octavia_f5.restclient.bigip import bigip_auth
from octavia_f5.utils import exceptions
from octavia_f5.utils.decorators import RunHookOnException

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


class FakeOK(object):
    def ok(self):
        return True


class FakeError(object):
    def ok(self):
        return False


class SyncManager(object):
    """Manager class maintaining connection to BigIPs and transparently controls failover case"""

    _metric_failover = prometheus.metrics.Counter(
        'octavia_as3_failover', 'How often the F5 provider driver switched to another BigIP device')
    _metric_version = prometheus.metrics.Gauge(
        'octavia_as3_version_info', 'AS3 Version', ['device', 'release', 'schemaCurrent', 'schemaMinimum', 'version'])
    _metric_target = prometheus.metrics.Gauge(
        'octavia_as3_targeted_device', 'AS3 targeted device', ['device'])

    def __init__(self, status_manager, loadbalancer_repo):
        self._bigip = None
        self._bigips = list(self.initialize_bigips())
        self._declaration_manager = as3declaration.AS3DeclarationManager(status_manager)
        self._loadbalancer_repo = loadbalancer_repo

        if CONF.f5_agent.migration:
            self.failover(active_device=False)
            LOG.warning("[Migration Mode] using passive device %s", self.bigip().hostname)
        else:
            self.failover()

    def initialize_bigips(self):
        instances = []
        for bigip_url in CONF.f5_agent.bigip_urls:
            # Create REST client for every bigip

            kwargs = {'bigip_url': bigip_url}

            if CONF.f5_agent.bigip_token:
                kwargs['auth'] = bigip_auth.BigIPTokenAuth(bigip_url)
            else:
                kwargs['auth'] = bigip_auth.BigIPBasicAuth(bigip_url)

            if CONF.f5_agent.as3_endpoint:
                kwargs['as3_url'] = CONF.f5_agent.as3_endpoint
                instance = AS3ExternalContainerRestClient(**kwargs)
            else:
                instance = AS3RestClient(**kwargs)

            if CONF.debug:
                # Install debug request logs
                instance.debug_enable()

            # Fetch as3 version info
            try:
                info_dict = instance.info()
                self._metric_version.labels(**info_dict).set(1)
            except Exception:
                # Failed connecting to AS3 endpoint, gracefully terminate
                LOG.error('Could not connect to AS3 endpoint: %s', instance.hostname)

            instances.append(instance)
        return instances

    def bigips(self):
        """ :returns all BigIP instances """
        return self._bigips

    def bigip(self, device=None):
        """ :returns the (active/specific) BigIP device, e.g.:
        - active BigIP device (device = None)
        - specific BigIP device (device != None)

        :param device: specify BigIP device
        :return: as3 restclient of the requested device
        """
        for bigip in self._bigips:
            if bigip.hostname == device:
                return bigip

        self._metric_target.labels(device=self._bigip.hostname).set(1)
        return self._bigip

    def devices(self):
        """ :returns list of device hostnames managed by sync_manager

        """
        return [bigip.hostname for bigip in self._bigips]

    def passive(self):
        """ :returns not active/targeted device """
        for bigip in self._bigips:
            if bigip != self._bigip:
                return bigip
        return None

    def failover(self, active_device=True):
        if len(self._bigips) == 1:
            # Always use same BigIP
            self._bigip = self._bigips[0]
        else:
            # Failover to bigip which is active (if active_device == True) or passive (if active_device == False)
            active_devices = [bigip for bigip in self._bigips if bigip.update_status() == active_device]
            if not active_devices:
                raise exceptions.FailoverException("Cannot failover: No device found that's in desired state.")
            self._bigip = next(iter(active_devices))
        LOG.info("failover() triggered, target device is %s", self._bigip.hostname)

    def force_failover(self, *args, **kwargs):
        # If not in migration mode: force fail-over
        if not CONF.f5_agent.migration:
            self._bigip = next(iter([bigip for bigip in self._bigips if bigip != self._bigip]))

            self._metric_failover.inc()
            LOG.warning("Force failover to device %s due to connection/response error", self._bigip.hostname)

    @RunHookOnException(
        hook=force_failover,
        exceptions=(ConnectionError, Timeout, exceptions.FailoverException)
    )
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(ConnectionError),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS)
    )
    def tenant_update(self, network_id, device=None, selfips=None):
        """ Synchronous call to update F5s with all loadbalancers of a tenant (network_id).

           :param network_id: the as3 tenant
           :param device: hostname of the bigip device, if none use active device
           :param selfips: list of selfips related to this tenant
           :return: True if success, else False

        """

        if selfips is None:
            self_ips = []
        else:
            self_ips = [fixed_ip.ip_address for selfip in selfips for fixed_ip in selfip.fixed_ips]
        loadbalancers = self._loadbalancer_repo.get_all_by_network(
            db_apis.get_session(), network_id=network_id, show_deleted=False)
        if not loadbalancers:
            return False

        decl = self._declaration_manager.get_declaration({network_id: loadbalancers}, self_ips)
        if CONF.f5_agent.dry_run:
            decl.set_action('dry-run')

        # No config syncing if we are in migration mode or specifically syncing one device
        if not CONF.f5_agent.migration and not device and CONF.f5_agent.sync_to_group:
            decl.set_sync_to_group(CONF.f5_agent.sync_to_group)

        return self.bigip(device).post(tenants=[m_part.get_name(network_id)], payload=decl)

    @RunHookOnException(
        hook=force_failover,
        exceptions=(ConnectionError, Timeout, exceptions.FailoverException)
    )
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(ConnectionError),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS)
    )
    def tenant_delete(self, network_id, device=None):
        """ Delete a Tenant.
        Instead of HTTP DELETE we POST an empty tenant declaration.
        It works just as well, but additionally leaves us control over declaration persistency.

        :param network_id: network id
        :return: True if success, else False
        """
        decl = self._declaration_manager.get_declaration({network_id: []}, [])

        if CONF.f5_agent.dry_run:
            decl.set_action('dry-run')

        # No config syncing if we are in migration mode or specificly syncing one device
        if not CONF.f5_agent.migration and not device and CONF.f5_agent.sync_to_group:
            decl.set_sync_to_group(CONF.f5_agent.sync_to_group)

        return self.bigip(device).post(tenants=[m_part.get_name(network_id)], payload=decl)

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(ConnectionError),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS)
    )
    def get_tenants(self, device=None):
        return self.bigip(device).get_tenants()
