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
from octavia_f5.utils import driver_utils as utils
from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions as driver_exceptions
from octavia_lib.common import constants as lib_consts

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class StatusManager(object):
    def __init__(self, bigip):
        self.bigip = bigip
        self._octavia_driver_lib = driver_lib.DriverLibrary(
            status_socket=CONF.driver_agent.status_socket_path,
            stats_socket=CONF.driver_agent.stats_socket_path
        )

    def set_active(self, obj):
        """Set provisioning_state of octavia object and all ancestors to
        ACTIVE.

        :param obj: octavia object like loadbalancer, pools, etc.
        """
        self._set_obj_and_ancestors(obj)

    def set_deleted(self, obj):
        """Set provisioning_state of octavia object to DELETED and all
        ancestors to ACTIVE.

        :param obj: octavia object like loadbalancer, pools, etc.
        """
        self._set_obj_and_ancestors(obj, lib_consts.DELETED)

    def set_error(self, obj):
        """Set provisioning_state of octavia object to ERROR and all
        ancestors to ACTIVE.

        :param obj: octavia object like loadbalancer, pools, etc.
        """
        self._set_obj_and_ancestors(obj, lib_consts.ERROR)

    def update_status(self, loadbalancers):
        """Set provisioning_state of loadbalancers and all it's
        children to ACTIVE if PENDING_UPDATE or PENDING_CREATE, else
        DELETED for PENDING_DELETED.

        :param loadbalancers: octavia loadbalancers list
        """

        def _set_deleted_or_active(obj):
            """Sets octavia object to deleted if status was PENDING_DELETE

            :param obj: octavia object
            """
            if utils.pending_delete(obj):
                self.set_deleted(obj)
            else:
                self.set_active(obj)

        for loadbalancer in loadbalancers:
            _set_deleted_or_active(loadbalancer)

            for listener in loadbalancer.listeners:
                _set_deleted_or_active(listener)

                for l7policy in listener.l7policies:
                    _set_deleted_or_active(l7policy)

                    for l7rule in l7policy.l7rules:
                        _set_deleted_or_active(l7rule)

            for pool in loadbalancer.pools:
                _set_deleted_or_active(pool)

                for member in pool.members:
                    _set_deleted_or_active(member)

                if pool.health_monitor:
                    _set_deleted_or_active(pool.health_monitor)

    def _set_obj_and_ancestors(self, obj, state=lib_consts.ACTIVE):
        """Set provisioning_state of octavia object to state and set all ancestors
        to ACTIVE.

        :param obj: octavia object like loadbalancer, pools, etc.
        """
        obj_status = self._status_obj(obj, state)

        # Load Balancer
        if isinstance(obj, data_models.LoadBalancer):
            self._update_status_to_octavia({
                lib_consts.LOADBALANCERS: [obj_status]
            })

        # Listener
        if isinstance(obj, data_models.Listener):
            self._update_status_to_octavia({
                lib_consts.LISTENERS: [obj_status],
                lib_consts.LOADBALANCERS: [self._status_obj(obj.load_balancer)]
            })

        # Pool
        if isinstance(obj, data_models.Pool):
            self._update_status_to_octavia({
                lib_consts.POOLS: [obj_status],
                lib_consts.LOADBALANCERS: [self._status_obj(obj.load_balancer)]
            })

        # Member
        if isinstance(obj, data_models.Member):
            self._update_status_to_octavia({
                lib_consts.MEMBERS: [obj_status],
                lib_consts.POOLS: [self._status_obj(obj.pool)],
                lib_consts.LOADBALANCERS: [self._status_obj(obj.pool.load_balancer)]
            })

        # Health Monitor
        if isinstance(obj, data_models.HealthMonitor):
            self._update_status_to_octavia({
                lib_consts.HEALTHMONITORS: [obj_status],
                lib_consts.POOLS: [self._status_obj(obj.pool)],
                lib_consts.LOADBALANCERS: [self._status_obj(obj.pool.load_balancer)]
            })

        # L7Policy
        if isinstance(obj, data_models.L7Policy):
            self._update_status_to_octavia({
                lib_consts.L7POLICIES: [obj_status],
                lib_consts.LISTENERS: [self._status_obj(obj.listener)],
                lib_consts.LOADBALANCERS: [self._status_obj(obj.listener.load_balancer)]
            })

        # L7Rule
        if isinstance(obj, data_models.L7Rule):
            self._update_status_to_octavia({
                lib_consts.L7RULES: [obj_status],
                lib_consts.L7POLICIES: [self._status_obj(obj.l7policy)],
                lib_consts.LISTENERS: [self._status_obj(obj.l7policy.listener)],
                lib_consts.LOADBALANCERS: [self._status_obj(
                    obj.l7policy.listener.load_balancer)]
            })

    @staticmethod
    def _status_obj(obj,
                    provisioning_status=lib_consts.ACTIVE):
        """Return status object for statup update api consumption

        :param obj: octavia object containing ID
        :param provisioning_status: provisioning status
        :return: status object
        """
        return {
            lib_consts.ID: obj.id,
            lib_consts.PROVISIONING_STATUS: provisioning_status
        }

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
