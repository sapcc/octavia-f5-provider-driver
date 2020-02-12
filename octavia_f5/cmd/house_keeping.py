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
#

import datetime
import signal
import sys
import time

import prometheus_client as prometheus
from oslo_config import cfg
from oslo_log import log as logging
from oslo_reports import guru_meditation_report as gmr

from octavia import version
from octavia.common import service
from octavia.controller.housekeeping import house_keeping

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
PROMETHEUS_PORT = 8000

_metric_housekeeping = prometheus.Counter('octavia_housekeeping', 'How often housekeeping has been run.')
_metric_housekeeping_exceptions = prometheus.Counter('octavia_housekeeping_exceptions', 'How often housekeeping failed.')


def _mutate_config():
    LOG.info("Housekeeping recieved HUP signal, mutating config.")
    CONF.mutate_config_files()


def main():
    """Perform db cleanup for old resources.

    Remove load balancers from database, which have been deleted have since expired.
    """

    # perform the rituals
    service.prepare_service(sys.argv)
    gmr.TextGuruMeditation.setup_autorun(version)
    signal.signal(signal.SIGHUP, _mutate_config)

    # Read configuration
    interval = CONF.house_keeping.cleanup_interval
    lb_expiry = CONF.house_keeping.load_balancer_expiry_age

    # initialize
    prometheus.start_http_server(PROMETHEUS_PORT)
    db_cleanup = house_keeping.DatabaseCleanup()
    LOG.info("Starting house keeping at %s", str(datetime.datetime.utcnow()))

    # start cleanup cycle
    while True:
        LOG.debug("Housekeeping")
        _metric_housekeeping.inc()
        try:
            db_cleanup.cleanup_load_balancers()
        except Exception as e:
            LOG.error('Housekeeping caught the following exception: {}'.format(e))
            _metric_housekeeping_exceptions.inc()
        time.sleep(interval)
