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

import tenacity
from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import data_models
from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions as driver_exceptions
from octavia_lib.common import constants as lib_consts

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class Status(object):
    STATUS_MAPPING = {
        'LoadBalancer': lib_consts.LOADBALANCERS,
        'Listener': lib_consts.LISTENERS,
        'Pool': lib_consts.POOLS,
        'Member': lib_consts.MEMBERS,
        'HealthMonitor': lib_consts.HEALTHMONITORS,
        'L7Policy': lib_consts.L7POLICIES,
        'L7Rule': lib_consts.L7RULES,
    }

    def __init__(self):
        self.status = dict()

    def update(self, obj, recursive=True, provisioning_status=None):
        status_type = self.STATUS_MAPPING[type(obj).__name__]

        # get existing status objects for givin status type
        status_objs = self.status.get(status_type, [])

        if recursive:
            # also transit status of all children objects
            if status_type == lib_consts.LOADBALANCERS:
                for listener in obj.listeners:
                    self.update(listener)
                for pool in obj.pools:
                    self.update(pool)
            if status_type == lib_consts.LISTENERS:
                for l7policy in obj.l7policies:
                    self.update(l7policy)
            if status_type == lib_consts.L7POLICIES:
                for l7rule in obj.l7rules:
                    self.update(l7rule)
            if status_type == lib_consts.POOLS:
                for member in obj.members:
                    self.update(member)
                if obj.health_monitor:
                    self.update(obj.health_monitor)

        current_prov_status = getattr(obj, 'provisioning_status', None)
        if not current_prov_status:
            # No prov-status found, skip
            return

        if not provisioning_status:
            # Auto select transition
            if current_prov_status == lib_consts.PENDING_DELETE:
                # Transition to deleted
                provisioning_status = lib_consts.DELETED
            elif current_prov_status == lib_consts.PENDING_UPDATE:
                # Transition to active
                provisioning_status = lib_consts.ACTIVE
            elif current_prov_status == lib_consts.PENDING_CREATE:
                # Transition to active
                provisioning_status = lib_consts.ACTIVE
            else:
                # Skip
                return

        status_objs.append(self._status_obj(obj, provisioning_status))
        self.status.update({status_type: status_objs})

    @staticmethod
    def _status_obj(obj,
                    provisioning_status=lib_consts.ACTIVE):
        """Return status object for statup update api consumption

        :param obj: octavia object containing ID
        :param provisioning_status: provisioning status
        :return: status object
        """
        status_obj = {
            lib_consts.ID: obj.id,
            lib_consts.PROVISIONING_STATUS: provisioning_status
        }

        # Set operating state of loadbalancers by default to active
        if isinstance(obj, data_models.LoadBalancer) and provisioning_status == lib_consts.ACTIVE:
            status_obj[lib_consts.OPERATING_STATUS] = lib_consts.ONLINE

        return status_obj


class StatusManager(object):
    # long-lived instance for driver-agent communication

    def __init__(self):
        self._octavia_driver_lib = driver_lib.DriverLibrary(
            status_socket=CONF.driver_agent.status_socket_path,
            stats_socket=CONF.driver_agent.stats_socket_path
        )

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(),
        wait=tenacity.wait_incrementing(start=1, increment=10),
        stop=tenacity.stop_after_attempt(max_attempt_number=3))
    def _update_status_to_octavia(self, status):
        try:
            self._octavia_driver_lib.update_loadbalancer_status(status)
        except driver_exceptions.UpdateStatusError as e:
            msg = ("Error while updating status to octavia: "
                   "%s") % e.fault_string
            LOG.error(msg)
            raise driver_exceptions.UpdateStatusError(msg)

    def update_status(self, loadbalancers):
        status = Status()
        for loadbalancer in loadbalancers:
            status.update(loadbalancer)

        # upload status dict to octavia
        self._update_status_to_octavia(status.status)

    def _set_ancestor_status_to_active(self, obj, status):
        if isinstance(obj, data_models.L7Rule):
            l7policy = obj.l7policy
            status.update(l7policy, recursive=False, provisioning_status=lib_consts.ACTIVE)
            listener = l7policy.listener
            status.update(listener, recursive=False, provisioning_status=lib_consts.ACTIVE)
            load_balancer = l7policy.listener.load_balancer
            status.update(load_balancer, recursive=False, provisioning_status=lib_consts.ACTIVE)

        if isinstance(obj, data_models.L7Policy):
            listener = obj.listener
            status.update(listener, recursive=False, provisioning_status=lib_consts.ACTIVE)
            load_balancer = listener.load_balancer
            status.update(load_balancer, recursive=False, provisioning_status=lib_consts.ACTIVE)

        if isinstance(obj, data_models.Member):
            pool = obj.pool
            status.update(pool, recursive=False, provisioning_status=lib_consts.ACTIVE)
            listeners = pool.listeners
            for listener in listeners:
                status.update(listener, recursive=False, provisioning_status=lib_consts.ACTIVE)
            load_balancer = pool.load_balancer
            status.update(load_balancer, recursive=False, provisioning_status=lib_consts.ACTIVE)

        if isinstance(obj, data_models.Listener):
            load_balancer = obj.load_balancer
            status.update(load_balancer, recursive=False, provisioning_status=lib_consts.ACTIVE)

        if isinstance(obj, data_models.Pool):
            listeners = obj.listeners
            for listener in listeners:
                status.update(listener, recursive=False, provisioning_status=lib_consts.ACTIVE)
            load_balancer = obj.load_balancer
            status.update(load_balancer, recursive=False, provisioning_status=lib_consts.ACTIVE)

        if isinstance(obj, data_models.HealthMonitor):
            pool = obj.pool
            status.update(pool, recursive=False, provisioning_status=lib_consts.ACTIVE)
            listeners = pool.listeners
            for listener in listeners:
                status.update(listener, recursive=False, provisioning_status=lib_consts.ACTIVE)
            load_balancer = pool.load_balancer
            status.update(load_balancer, recursive=False, provisioning_status=lib_consts.ACTIVE)

    def set_active(self, obj):
        status = Status()

        # set ancestors to active
        self._set_ancestor_status_to_active(obj, status)

        # transition object itself to active
        status.update(obj, recursive=False, provisioning_status=lib_consts.ACTIVE)

        # upload status dict to octavia
        self._update_status_to_octavia(status.status)

    def set_error(self, obj):
        status = Status()

        # set ancestors to active
        self._set_ancestor_status_to_active(obj, status)

        # transition object itself to error
        status.update(obj, recursive=False, provisioning_status=lib_consts.ERROR)

        # upload status dict to octavia
        self._update_status_to_octavia(status.status)

    def set_deleted(self, obj):
        status = Status()

        # set ancestors to active
        self._set_ancestor_status_to_active(obj, status)

        # transition object itself to error
        status.update(obj, recursive=False, provisioning_status=lib_consts.DELETED)

        # upload status dict to octavia
        self._update_status_to_octavia(status.status)
