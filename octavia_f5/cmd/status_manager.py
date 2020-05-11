# Copyright 2015 Hewlett-Packard Development Company, L.P.
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

import os
import signal
import sys
import threading

from futurist import periodics
from oslo_config import cfg
from oslo_log import log as logging
from oslo_reports import guru_meditation_report as gmr

from octavia import version
from octavia.common import rpc
from octavia_f5.common import config
from octavia_f5.controller.statusmanager import status_manager

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _mutate_config(*args, **kwargs):
    CONF.mutate_config_files()


def _handle_mutate_config(listener_proc_pid, check_proc_pid, *args, **kwargs):
    LOG.info("Status Manager recieved HUP signal, mutating config.")
    _mutate_config()
    os.kill(listener_proc_pid, signal.SIGHUP)
    os.kill(check_proc_pid, signal.SIGHUP)


def _prepare_service(argv=None):
    argv = sys.argv or []
    config.init(argv[1:])
    logging.set_defaults()
    config.setup_logging(cfg.CONF)
    rpc.init()


def main():
    _prepare_service(sys.argv)
    gmr.TextGuruMeditation.setup_autorun(version)
    sm = status_manager.StatusManager()
    signal.signal(signal.SIGHUP, _mutate_config)

    @periodics.periodic(CONF.status_manager.health_check_interval,
                        run_immediately=True)
    def periodic_status():
        sm.heartbeat()

    status_check = periodics.PeriodicWorker(
        [(periodic_status, None, None)],
        schedule_strategy='aligned_last_finished')

    hm_status_thread = threading.Thread(target=status_check.start)
    hm_status_thread.daemon = True
    LOG.info("Status Manager process starts")
    hm_status_thread.start()

    def hm_exit(*args, **kwargs):
        status_check.stop()
        status_check.wait()
        sm.stats_executor.shutdown()
        sm.health_executor.shutdown()
        LOG.info("Status Manager executors terminated")
    signal.signal(signal.SIGINT, hm_exit)

    hm_status_thread.join()
    LOG.info("Status Manager terminated")


if __name__ == "__main__":
    main()
