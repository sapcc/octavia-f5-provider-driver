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

import time
import uuid

import prometheus_client as prometheus
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from requests import ConnectionError
from tenacity import *

from octavia.common import exceptions as o_exceptions
from octavia.db import repositories as repo
from octavia_f5.common import constants
# from octavia_f5.controller.worker import quirks
from octavia_f5.db import repositories as f5_repos
from octavia_f5.restclient.as3classes import ADC, AS3, Application
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import pool_member as m_member
from octavia_f5.restclient.as3objects import service as m_service
from octavia_f5.restclient.as3objects import tenant as m_part
from octavia_f5.restclient.as3restclient import AS3ExternalContainerRestClient, AS3RestClient
from octavia_f5.restclient.bigip import bigip_auth
from octavia_f5.utils import driver_utils, exceptions, cert_manager, esd_repo
from octavia_f5.utils.decorators import RunHookOnException

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


# Workaround for Monitor deletion, fake successfull deletion
class FakeOK(object):
    def ok(self):
        return True


class SyncManager(object):
    """Manager class maintaining connection to BigIPs and transparently controls failover case"""

    _metric_failover = prometheus.metrics.Counter(
        'octavia_as3_failover', 'How often the F5 provider driver switched to another BigIP device')
    _metric_version = prometheus.metrics.Gauge(
        'octavia_as3_version_info', 'AS3 Version', ['device', 'release', 'schemaCurrent', 'schemaMinimum', 'version'])

    def __init__(self):
        self._amphora_repo = repo.AmphoraRepository()
        self._esd_repo = esd_repo.EsdRepository()
        self._loadbalancer_repo = f5_repos.LoadBalancerRepository()
        self.network_driver = driver_utils.get_network_driver()
        self.cert_manager = cert_manager.CertManagerWrapper()
        self._bigip = None
        self._bigips = [bigip for bigip in self.initialize_bigips()]
        self._last_persist = 0

        if CONF.f5_agent.migration:
            self.failover(active_device=False)
            LOG.warning("[Migration Mode] using passive device %s", self.bigip().hostname)
        else:
            self.failover()

    def initialize_bigips(self):
        for bigip_url in CONF.f5_agent.bigip_urls:
            # Create REST client for every bigip

            kwargs = {
                'bigip_url': bigip_url,
                'verify': CONF.f5_agent.bigip_verify,
                'async_mode': CONF.f5_agent.async_mode,
            }

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

            yield(instance)

    def bigip(self, device=None):
        """ Returns the (active/specific) BigIP device, e.g.:
        - active BigIP device (device = None)
        - specific BigIP device (device != None)

        :param device: specify BigIP device
        :return: as3 restclient of the requested device
        """
        for bigip in self._bigips:
            if bigip.hostname == device:
                return bigip

        return self._bigip

    def failover(self, active_device=True):
        if len(self._bigips) == 1:
            # Always use same BigIP
            self._bigip = self._bigips[0]
        else:
            # Failover to bigip which is active (if active_device == True) or passive (if active_device == False)
            self._bigip = next(iter([bigip for bigip in self._bigips if bigip.is_active == active_device]))

    def force_failover(self, *args, **kwargs):
        # If not in migration mode: force fail-over
        if not CONF.f5_agent.migration:
            self._bigip = next(iter([bigip for bigip in self._bigips if bigip != self._bigip]))

            self._metric_failover.inc()
            LOG.warning("Force failover to device %s due to connection/response error", self._bigip.hostname)

    @RunHookOnException(hook=force_failover, exceptions=(ConnectionError, exceptions.FailoverException))
    @retry(
        retry=retry_if_exception_type(ConnectionError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    def tenant_update(self, network_id, loadbalancers, device=None, status=None):
        """Task to update F5s with all specified loadbalancers' configurations
           of a tenant (network_id).

           :param network_id: the as3 tenant
           :param loadbalancers: loadbalancer to update
           :param device: hostname of the bigip device, if none use active device
           :param status: (optionally) status manager
           :return: requests post result

        """

        action = 'deploy'
        persist = False

        if CONF.f5_agent.dry_run:
            action = 'dry-run'
        if CONF.f5_agent.persist_every == 0:
            persist = True
        elif CONF.f5_agent.persist_every > 0:
            persist = time.time() - CONF.f5_agent.persist_every > self._last_persist
            if persist:
                self._last_persist = time.time()

        decl = AS3(
            persist=persist,
            action=action,
            historyLimit=2,
            _log_level=LOG.logger.level)
        adc = ADC(
            id="urn:uuid:{}".format(uuid.uuid4()),
            label="F5 BigIP Octavia Provider")
        decl.set_adc(adc)

        if not CONF.f5_agent.migration and not device:
            # No config syncing if we are in migration mode or specificly syncing one device
            if CONF.f5_agent.sync_to_group:
                decl.set_sync_to_group(CONF.f5_agent.sync_to_group)

        project_id = None
        if loadbalancers:
            project_id = loadbalancers[-1].project_id

        segmentation_id = self.network_driver.get_segmentation_id(network_id)
        tenant = adc.get_or_create_tenant(
            m_part.get_name(network_id),
            defaultRouteDomain=segmentation_id,
            label='{}{}'.format(constants.PREFIX_PROJECT, project_id or 'none')
        )

        for loadbalancer in loadbalancers:
            # Skip load balancer in (pending) deletion
            if loadbalancer.provisioning_status in [constants.PENDING_DELETE]:
                continue

            # Create generic application
            app = Application(constants.APPLICATION_GENERIC, label=loadbalancer.id)

            # Attach Octavia listeners as AS3 service objects
            for listener in loadbalancer.listeners:
                if not driver_utils.pending_delete(listener):
                    try:
                        service_entities = m_service.get_service(listener, self.cert_manager, self._esd_repo)
                        app.add_entities(service_entities)
                    except o_exceptions.CertificateRetrievalException as e:
                        LOG.error("Could not retrieve certificate, skipping listener '%s': %s", listener.id, e)
                        if status:
                            status.set_error(listener)

            # Attach pools
            for pool in loadbalancer.pools:
                # quirks.workaround_autotool_1469(network_id, loadbalancer.id, pool, self._bigips)
                if not driver_utils.pending_delete(pool):
                    app.add_entities(m_pool.get_pool(pool))

            # Attach newly created application
            tenant.add_application(m_app.get_name(loadbalancer.id), app)

        return self.bigip(device).post(tenants=[m_part.get_name(network_id)], payload=decl)

    @RunHookOnException(hook=force_failover, exceptions=(ConnectionError, exceptions.FailoverException))
    @retry(
        retry=retry_if_exception_type(ConnectionError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    def tenant_delete(self, network_id):
        """ Delete a Tenant

        :param network_id: network id
        :return: requests delete result
        """
        if CONF.f5_agent.dry_run:
            return FakeOK()

        tenant = m_part.get_name(network_id)
        ret = self.bigip().delete(tenants=[tenant])
        if CONF.f5_agent.sync_to_group and not CONF.f5_agent.migration and ret.ok:
            self.bigip().config_sync(CONF.f5_agent.sync_to_group)
        return ret

    @RunHookOnException(hook=force_failover, exceptions=(ConnectionError, exceptions.FailoverException))
    @retry(
        retry=retry_if_exception_type(ConnectionError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    def member_create(self, member):
        """Patches new member into existing pool

        :param member: octavia member object
        """
        if CONF.f5_agent.dry_run:
            return FakeOK()

        patch_body = [
            {
                'op': 'add',
                'path': '{}/{}/{}/members/-'.format(
                    m_part.get_name(member.pool.load_balancer.vip.network_id),
                    m_app.get_name(member.pool.load_balancer.id),
                    m_pool.get_name(member.pool.id)),
                'value': m_member.get_member(member).to_dict()
            }
        ]
        tenants = [member.pool.load_balancer.vip.network_id]
        return self.bigip().patch(tenants=tenants, patch_body=patch_body)
