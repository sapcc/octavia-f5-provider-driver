# Copyright 2020 SAP SE
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

from oslo_config import cfg
from oslo_log import log as logging

from octavia_f5.restclient.as3classes import AS3

CONF = cfg.CONF
LAST_PERSIST = 0
LOG = logging.getLogger(__name__)


def get_as3():
    action = 'deploy'
    persist = False
    global LAST_PERSIST

    if CONF.f5_agent.persist_every == 0:
        persist = True
    elif CONF.f5_agent.persist_every > 0:
        persist = time.time() - CONF.f5_agent.persist_every > LAST_PERSIST
        if persist:
            LAST_PERSIST = time.time()

    return AS3(
        persist=persist,
        action=action,
        historyLimit=2,
        _log_level=LOG.logger.level
    )
