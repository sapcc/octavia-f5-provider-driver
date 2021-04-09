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

from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import exceptions as o_exceptions
from octavia_f5.common import constants
from octavia_f5.restclient import as3classes as as3
from octavia_f5.restclient.as3classes import Application
from octavia_f5.restclient.as3objects import application as m_app
from octavia_f5.restclient.as3objects import pool as m_pool
from octavia_f5.restclient.as3objects import service as m_service
from octavia_f5.utils import driver_utils

CONF = cfg.CONF
LAST_PERSIST = 0
LOG = logging.getLogger(__name__)

def get_name(network_id):
    return "{}{}".format(constants.PREFIX_NETWORK,
                         network_id.replace('-', '_'))


def get_tenant(segmentation_id, loadbalancers, status, cert_manager, esd_repo):

    project_id = None
    if loadbalancers:
        project_id = loadbalancers[-1].project_id

    tenant = as3.Tenant(
        defaultRouteDomain=segmentation_id,
        label='{}{}'.format(constants.PREFIX_PROJECT, project_id or 'none')
    )

    # Skip members that re-use load balancer vips
    loadbalancer_ips = [load_balancer.vip.ip_address for load_balancer in loadbalancers
                        if not driver_utils.pending_delete(load_balancer)]

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
                    service_entities = m_service.get_service(listener, cert_manager, esd_repo)
                    app.add_entities(service_entities)
                except o_exceptions.CertificateRetrievalException as e:
                    if getattr(e, 'status_code', 0) != 400:
                        # Error connecting to keystore, skip tenant update
                        raise e

                    LOG.error("Could not retrieve certificate, assuming it is deleted, skipping listener '%s': %s", listener.id, e)
                    if status:
                        # Key / Container not found in keystore
                        status.set_error(listener)

        # Attach pools
        for pool in loadbalancer.pools:
            if not driver_utils.pending_delete(pool):
                app.add_entities(m_pool.get_pool(pool, loadbalancer_ips, status))

        # Attach newly created application
        tenant.add_application(m_app.get_name(loadbalancer.id), app)

    return tenant
