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

import sys

import cotyledon
from cotyledon import oslo_config_glue
from oslo_config import cfg
from oslo_log import log

from octavia_f5.common import config
from octavia_f5.controller.f5service import F5Service

CONF = cfg.CONF

def main():
    """Entry point of the F5 agent process. Starts the F5 cotyledon service."""
    argv = sys.argv or []
    config.init(argv[1:])
    log.set_defaults()
    config.setup_logging(CONF)

    sm = cotyledon.ServiceManager()
    sm.add(F5Service, workers=CONF.controller_worker.workers,
           args=(CONF,))
    oslo_config_glue.setup(sm, CONF, reload_method="mutate")
    sm.run()


if __name__ == "__main__":
    main()
