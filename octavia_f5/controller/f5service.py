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

import cotyledon
import oslo_messaging as messaging
from oslo_log import log as logging
from oslo_messaging.rpc import dispatcher

from octavia_f5.common import constants
from octavia_f5.controller.worker import controller_worker

LOG = logging.getLogger(__name__)


class F5Service(cotyledon.Service):
    """Service running in cotyledon service manager. Starts F5 driver workers."""
    def __init__(self, worker_id, conf):
        super(F5Service, self).__init__(worker_id)
        self.conf = conf
        self.topic = conf.oslo_messaging.topic
        self.server = conf.host
        self.endpoints = [controller_worker.ControllerWorker()]
        self.access_policy = dispatcher.DefaultRPCAccessPolicy
        self.message_listener = None

    def run(self):
        LOG.info('Starting consumer...')
        transport = messaging.get_rpc_transport(self.conf)
        target = messaging.Target(topic=self.topic, server=self.server,
                                  fanout=False, namespace=constants.RPC_NAMESPACE_CONTROLLER_AGENT)
        self.message_listener = messaging.get_rpc_server(
            transport, target, self.endpoints,
            executor='threading',
            access_policy=self.access_policy
        )
        self.message_listener.start()

    def terminate(self, graceful=False):
        if self.message_listener:
            LOG.info('Stopping consumer...')
            self.message_listener.stop()
            if graceful:
                LOG.info('Consumer successfully stopped.  Waiting for final '
                         'messages to be processed...')
                self.message_listener.wait()
        if self.endpoints:
            LOG.info('Shutting down endpoint worker executors...')
            for e in self.endpoints:
                try:
                    e.worker.executor.shutdown()
                except AttributeError:
                    pass
        super(F5Service, self).terminate()
