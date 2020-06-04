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

import uuid

import prometheus_client as prometheus
from oslo_config import cfg
from oslo_log import log as logging
from requests import ConnectionError
from tenacity import *

from octavia.db import repositories as repo
import prometheus_client as prometheus
from octavia_f5.common import constants
from octavia_f5.db import repositories as f5_repos
from octavia_f5.restclient import as3restclient
from octavia_f5.restclient.as3classes import ADC, AS3, Application, Monitor
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import pool_member as m_member
from octavia_f5.restclient.as3objects import service as m_service
from octavia_f5.restclient.as3objects import tenant as m_part
from octavia_f5.utils import driver_utils, exceptions, cert_manager, esd_repo
from octavia_f5.utils.decorators import RunHookOnException

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


class SyncManager(object):
    """Manager class maintaining connection to BigIPs and transparently controls failover case"""

    _metric_failover = prometheus.metrics.Counter(
        'octavia_as3_failover', 'How often the F5 provider driver switched to another BigIP device')

    def __init__(self):
        self._amphora_repo = repo.AmphoraRepository()
        self._esd_repo = esd_repo.EsdRepository()
        self._loadbalancer_repo = f5_repos.LoadBalancerRepository()
        self._bigips = [as3restclient.BigipAS3RestClient(
            url=bigip_url,
            enable_verify=CONF.f5_agent.bigip_verify,
            enable_token=CONF.f5_agent.bigip_token)
            for bigip_url in CONF.f5_agent.bigip_urls
        ]
        self.network_driver = driver_utils.get_network_driver()
        self.cert_manager = cert_manager.CertManagerWrapper()
        self.bigip = None
        if CONF.f5_agent.migration:
            self.failover(active_device=False)
            LOG.warning("[Migration Mode] using passive device %s", self.bigip.hostname)
        else:
            self.failover()

    def failover(self, active_device=True):
        # Failover to bigip which is active (if active_device == True) or passive (if active_device == False)
        self.bigip = next(iter([bigip for bigip in self._bigips if bigip.is_active == active_device]))

    def force_failover(self, *args, **kwargs):
        # If not in migration mode: force fail-over
        if not CONF.f5_agent.migration:
            self.bigip = next(iter([bigip for bigip in self._bigips if bigip != self.bigip]))

            self._metric_failover.inc()
            LOG.warning("Force failover to device %s due to connection/response error", self.bigip.hostname)

    @RunHookOnException(hook=force_failover, exceptions=(ConnectionError, exceptions.FailoverException))
    @retry(
        retry=retry_if_exception_type(ConnectionError),
        wait=wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=stop_after_attempt(RETRY_ATTEMPTS)
    )
    def tenant_update(self, network_id, loadbalancers, device=None):
        """Task to update F5s with all specified loadbalancers' configurations
           of a tenant (network_id).

           :param network_id: the as3 tenant
           :param loadbalancers: loadbalancer to update
           :param device: hostname of the bigip device, if none use active device
           :return: requests post result

        """

        action = 'deploy'
        if CONF.f5_agent.dry_run:
            action = 'dry-run'
        decl = AS3(
            persist=True,
            action=action,
            _log_level=LOG.logger.level)
        adc = ADC(
            id="urn:uuid:{}".format(uuid.uuid4()),
            label="F5 BigIP Octavia Provider")
        decl.set_adc(adc)

        if not CONF.f5_agent.migration and CONF.f5_agent.sync_to_group:
            # No group syncing if we are in migration mode
            decl.set_sync_to_group(CONF.f5_agent.sync_to_group)

        segmentation_id = self.network_driver.get_segmentation_id(network_id)
        tenant = adc.get_or_create_tenant(
            m_part.get_name(network_id),
            defaultRouteDomain=segmentation_id
        )

        for loadbalancer in loadbalancers:
            # Skip load balancer in pending deletion
            if driver_utils.pending_delete(loadbalancer):
                continue

            # Create generic application
            app = Application(constants.APPLICATION_GENERIC, label=loadbalancer.id)

            # Attach Octavia listeners as AS3 service objects
            for listener in loadbalancer.listeners:
                if not driver_utils.pending_delete(listener):
                    service_entities = m_service.get_service(listener, self.cert_manager, self._esd_repo)
                    app.add_entities(service_entities)

            # Attach pools
            for pool in loadbalancer.pools:
                if not driver_utils.pending_delete(pool):
                    app.add_entities(m_pool.get_pool(pool))

            # Attach newly created application
            tenant.add_application(m_app.get_name(loadbalancer.id), app)

        # Optionally temporarly select BigIP
        bigip = self.bigip
        if device:
            for b in self._bigips:
                if b.hostname == device:
                    bigip = b

        # Workaround for Monitor deletion bug, inject no-op Monitor
        # tracked https://github.com/F5Networks/f5-appsvcs-extension/issues/110
        while True:
            try:
                return bigip.post(json=decl.to_json())
            except exceptions.MonitorDeletionException as e:
                tenant = getattr(decl.declaration, e.tenant)
                application = getattr(tenant, e.application, None)
                if not application:
                    # create fake application
                    application = Application(constants.APPLICATION_GENERIC, label='HM Workaround App')
                    tenant.add_application(e.application, application)
                application.add_entities([(e.monitor, Monitor(monitorType='icmp', interval=0))])

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
        tenant = m_part.get_name(network_id)

        # Workaround for Monitor deletion, fake successfull deletion
        class FakeOK(object):
            def ok(self):
                return True

        try:
            return self.bigip.delete(tenants=[tenant])
        except exceptions.MonitorDeletionException:
            return FakeOK()

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
        path = '{}/{}/{}/members/-'.format(
            m_part.get_name(member.pool.load_balancer.vip.network_id),
            m_app.get_name(member.pool.load_balancer.id),
            m_pool.get_name(member.pool.id)
        )
        return self.bigip.patch(operation='add', path=path,
                                value=m_member.get_member(member).to_dict())