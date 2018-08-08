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

import json

from oslo_log import log as logging
from taskflow import task

from octavia.controller.worker import task_utils as task_utilities
from octavia.db import api as db_apis
from octavia.db import repositories as repo
from octavia_f5.utils.l7policy_adapter import L7PolicyServiceAdapter

LOG = logging.getLogger(__name__)

class PolicyBuild(task.Task):
    """Base task to load drivers common to the tasks."""

    def __init__(self, **kwargs):
        super(PolicyBuild, self).__init__(**kwargs)
        self.l7policy_repo = repo.L7PolicyRepository()
        self.l7rule_repo = repo.L7RuleRepository()
        self.l7policy_adapter = L7PolicyServiceAdapter(self.conf)

    def build_policy(self, l7policies, listener, l7rule):
        # build data structure for service adapter input
        os_policies = {'l7rules': [], 'l7policies': [], 'f5_policy': {}}

        # get all policies and rules for listener referenced by this policy
        for policy_id in listener.l7_policies:
            policy = self.l7policy_repo.get(
                db_apis.get_session(), id=policy_id.id)
            if policy:
                os_policies['l7policies'].append(policy)
                for rule in policy.rules:
                    l7rule = self.l7rule_repo.get(
                        db_apis.get_session(), id=rule.id)

                    if l7rule:
                        os_policies['l7rules'].append(l7rule)

        if os_policies['l7policies']:
            os_policies['f5_policy'] = self.l7policy_adapter.translate(
                os_policies)

        LOG.debug(json.dumps(os_policies, indent=4, sort_keys=True))
        return os_policies
