#  Copyright 2022 SAP SE
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from oslo_log import log as logging
from octavia_f5.controller.worker.flows import f5_flows_iseries
from octavia_f5.controller.worker.tasks import f5_tasks_rseries

LOG = logging.getLogger(__name__)


class F5Flows(f5_flows_iseries.F5Flows):
    """Class that configures flows to use tasks specific to rSeries devices."""

    def __init__(self):
        super(F5Flows, self).__init__(tasks=f5_tasks_rseries)
