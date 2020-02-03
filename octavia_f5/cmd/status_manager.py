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

import multiprocessing
import os
import signal
import sys
from functools import partial

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


def sm_status_check(exit_event):
    sm = status_manager.StatusManager(exit_event)
    signal.signal(signal.SIGHUP, _mutate_config)

    @periodics.periodic(CONF.health_manager.health_check_interval,
                        run_immediately=True)
    def periodic_status():
        sm.heartbeat()

    status = periodics.PeriodicWorker(
        [(periodic_status, None, None)],
        schedule_strategy='aligned_last_finished')

    def sm_exit(*args, **kwargs):
        status.stop()

    signal.signal(signal.SIGINT, sm_exit)
    status.start()


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

    processes = []
    exit_event = multiprocessing.Event()

    hm_status_proc = multiprocessing.Process(name='SM_status_check',
                                             target=sm_status_check,
                                             args=(exit_event,))
    processes.append(hm_status_proc)

    LOG.info("Status Manager process starts:")
    hm_status_proc.start()

    def process_cleanup(*args, **kwargs):
        LOG.info("Status Manager exiting due to signal")
        exit_event.set()
        os.kill(hm_status_proc.pid, signal.SIGINT)
        hm_status_proc.join()

    signal.signal(signal.SIGTERM, process_cleanup)
    signal.signal(signal.SIGHUP, partial(
        _handle_mutate_config, hm_status_proc.pid))

    try:
        for process in processes:
            process.join()
    except KeyboardInterrupt:
        process_cleanup()


if __name__ == "__main__":
    main()
