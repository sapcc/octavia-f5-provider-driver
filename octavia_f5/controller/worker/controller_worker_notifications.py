# Copyright 2019, 2020 SAP SE
# Copyright 2015 Hewlett-Packard Development Company, L.P.
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
import oslo_messaging as messaging

from octavia.common import constants as octavia_consts
from octavia.common import rpc
from octavia.db import repositories as repo
from octavia.db import models as db_models
from octavia_f5.db import api as db_apis
from octavia_f5.db import repositories as f5_repos
from octavia_f5.utils import driver_utils

CONF = cfg.CONF
CONF.import_group('f5_agent', 'octavia_f5.common.config')
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


class ControllerWorkerNotifications(object):

    def __init__(self):
        self._loadbalancer_repo = f5_repos.LoadBalancerRepository()
        self._vip_repo = repo.VipRepository()

        # instantiate managers/drivers
        self.network_driver = driver_utils.get_network_driver()

        # RPC client to send notifications to another workers
        self.target = messaging.Target(
            namespace=octavia_consts.RPC_NAMESPACE_CONTROLLER_AGENT,
            topic=octavia_consts.TOPIC_AMPHORA_V2, version="2.0", fanout=False)
        self.rpc_client = rpc.get_client(self.target)

        super().__init__()

    def _get_scheduled_host(self, loadbalancer):
        """ Get scheduled host of the loadbalancer.
        :param loadbalancer: loadbalancer data
        :return: scheduled host
        """
        if loadbalancer.server_group_id:
            return loadbalancer.server_group_id
        # fetch scheduled server from VIP port
        return self.network_driver.get_scheduled_host(loadbalancer.vip.port_id)

    def _get_sgs_recursively(self, security_group):
        found_sgs = [security_group]
        rules = list(tuple(self.network_driver.network_proxy.security_group_rules(
            security_group_id=security_group)))
        for rule in rules:
            if rule.get('remote_group_id'):
                found_sgs += self._get_sgs_recursively(rule['remote_group_id'])
        return found_sgs

    def process_security_group_update_notification(self, security_group_id, action):
        notifications = {}
        with db_apis.session().begin() as session:
            loadbalancers = self._loadbalancer_repo.get_all_by_security_group(
                session, security_group_id=security_group_id)
            if not loadbalancers:
                LOG.debug("No loadbalancers using Security Group "
                          f"{security_group_id}, notification will be ignored")
                return
            for lb in loadbalancers:
                db_groups = list(lb.vip.sg_ids)
                # If security group was deleted we have to update database
                # before load_balancer update notification
                if action == 'deleted':
                    LOG.debug(f"Security Group {security_group_id} attached to "
                              f"LoadBalancer {lb.id} will be removed from the "
                              f"list {','.join(db_groups)}")
                    db_groups.remove(security_group_id)
                    self._vip_repo.update(session, lb.id, sg_ids=db_groups)
                else:
                    found_sgs = []
                    for sg in db_groups:
                        found_sgs += self._get_sgs_recursively(sg)
                    # Check if there remote SGs that we have to watch
                    if set(found_sgs) != set(db_groups):
                        for vip_sg_id in set(found_sgs) - set(db_groups):
                            vip_sg = db_models.VipSecurityGroup(
                                load_balancer_id=lb.id,
                                sg_id=vip_sg_id)
                            session.add(vip_sg)
                            session.flush()
                            LOG.debug(f"Remote Security group {vip_sg_id} was added to Loadbalancer {lb.id}")
                # Send notification that LoadBalancer updated
                worker = self._get_scheduled_host(lb)
                notifications[lb.id] = worker
                LOG.debug(f"Notify worker {worker} about {action} Security Group "
                          f"{security_group_id} attached to LoadBalancer {lb.id}")

        # We have to notify workers about updates outside database
        # transaction to be sure that database already updated
        # that's why we are do it outside context manager which commited data
        for lb_id, worker in notifications.items():
            # notify correct worker about loadbalancer changes
            payload = {
                octavia_consts.ORIGINAL_LOADBALANCER: {
                    octavia_consts.LOADBALANCER_ID: lb_id
                },
                octavia_consts.LOAD_BALANCER_UPDATES: {}
            }
            client = self.rpc_client.prepare(server=worker)
            client.cast({}, 'update_load_balancer', **payload)
