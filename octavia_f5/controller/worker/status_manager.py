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

from collections import defaultdict

import tenacity
from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions as driver_exceptions
from octavia_lib.common import constants as lib_consts
from oslo_config import cfg
from oslo_log import log as logging

from octavia.common import data_models
from octavia.db import api as db_apis
from octavia.db.repositories import AmphoraRepository
from octavia_f5.utils import driver_utils as utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class StatusManager(object):

    def __init__(self):
        # On Stein we don't have the get_socket option yet. We can't just pass None though, because while
        # DriverLibrary.__init__() doesn't have a problem with it due to taking **kwargs, it passes **kwargs to its
        # super class, which is object, which does not take any arguments...
        try:
            self._octavia_driver_lib = driver_lib.DriverLibrary(
                status_socket=CONF.driver_agent.status_socket_path,
                stats_socket=CONF.driver_agent.stats_socket_path,
                get_socket=CONF.driver_agent.get_socket_path,
            )
        except cfg.NoSuchOptError as e:
            if e.opt_name != 'get_socket_path':
                raise e
            self._octavia_driver_lib = driver_lib.DriverLibrary(
                status_socket=CONF.driver_agent.status_socket_path,
                stats_socket=CONF.driver_agent.stats_socket_path,
            )

    def status_dict(self, obj, cascade=False):
        """ Returns status dict for octavia object,
         deleted if status was PENDING_DELETE, else active.
         Ignores error status.

        :param obj: octavia object
        """

        # Cascade Delete: force deleted
        if cascade:
            return [self._status_obj(obj, lib_consts.DELETED)]

        # Don't update errored objects
        if obj.provisioning_status == lib_consts.ERROR:
            return []

        # Don't update already active objects:
        if obj.provisioning_status == lib_consts.ACTIVE:
            return []

        if utils.pending_delete(obj):
            return [self._status_obj(obj, lib_consts.DELETED)]
        else:
            return [self._status_obj(obj, lib_consts.ACTIVE)]

    def update_status(self, loadbalancers):
        """For each load balancer set the provisioning_status of it and all its children to ACTIVE if it is
        PENDING_UPDATE or PENDING_CREATE, or to DELETED if it is PENDING_DELETE. Ignore ERROR status.

        :param loadbalancers: octavia loadbalancers list
        """

        status = defaultdict(list)

        # Load Balancers
        for loadbalancer in loadbalancers:
            cascade = False
            status[lib_consts.LOADBALANCERS].extend(self.status_dict(loadbalancer))

            # Cascade?
            if loadbalancer.provisioning_status == lib_consts.PENDING_DELETE:
                cascade = True

            # Listeners
            for listener in loadbalancer.listeners:
                status[lib_consts.LISTENERS].extend(self.status_dict(listener, cascade))

                # L7Policies
                for l7policy in listener.l7policies:
                    status[lib_consts.L7POLICIES].extend(self.status_dict(l7policy, cascade))

                    # L7Rules
                    for l7rule in l7policy.l7rules:
                        status[lib_consts.L7RULES].extend(self.status_dict(l7rule, cascade))

            # Pools
            for pool in loadbalancer.pools:
                status[lib_consts.POOLS].extend(self.status_dict(pool, cascade))

                # Members
                for member in pool.members:
                    status[lib_consts.MEMBERS].extend(self.status_dict(member, cascade))

                # Health Monitors
                if pool.health_monitor:
                    status[lib_consts.HEALTHMONITORS].extend(self.status_dict(pool.health_monitor, cascade))

        self._update_status_to_octavia(status)

    @staticmethod
    def _status_obj(obj, provisioning_status):
        """Return status object for statup update api consumption

        :param obj: octavia object containing ID
        :param provisioning_status: provisioning status
        :return: status object
        """
        status_obj = {
            lib_consts.ID: obj.id,
            lib_consts.PROVISIONING_STATUS: provisioning_status
        }

        if isinstance(obj, data_models.LoadBalancer) and provisioning_status == lib_consts.ACTIVE:
            status_obj[lib_consts.OPERATING_STATUS] = lib_consts.ONLINE
        if isinstance(obj, data_models.HealthMonitor) and provisioning_status == lib_consts.ACTIVE:
            status_obj[lib_consts.OPERATING_STATUS] = lib_consts.ONLINE
        if isinstance(obj, data_models.L7Policy) and provisioning_status == lib_consts.ACTIVE:
            status_obj[lib_consts.OPERATING_STATUS] = lib_consts.ONLINE
        if isinstance(obj, data_models.L7Rule) and provisioning_status == lib_consts.ACTIVE:
            status_obj[lib_consts.OPERATING_STATUS] = lib_consts.ONLINE

        return status_obj

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
        finally:
            # Update amphora to DELETED if LB is DELETED, so that they get cleaned up together
            amp_repo = AmphoraRepository()
            session = db_apis.get_session()
            for lb in status['loadbalancers']:
                if lb['provisioning_status'] == lib_consts.DELETED:
                    amp_repo.update(session, lb['id'], status=lib_consts.DELETED, force_provisioning_status=True)

    @staticmethod
    def get_obj_type(obj):
        if isinstance(obj, data_models.LoadBalancer):
            return lib_consts.LOADBALANCERS

        # Listener
        if isinstance(obj, data_models.Listener):
            return lib_consts.LISTENERS

        # Pool
        if isinstance(obj, data_models.Pool):
            return lib_consts.POOLS

        # Member
        if isinstance(obj, data_models.Member):
            return lib_consts.MEMBERS

        # Health Monitor
        if isinstance(obj, data_models.HealthMonitor):
            return lib_consts.HEALTHMONITORS

        # L7Policy
        if isinstance(obj, data_models.L7Policy):
            return lib_consts.L7POLICIES

        # L7Rule
        if isinstance(obj, data_models.L7Rule):
            return lib_consts.L7RULES

    def set_error(self, obj):
        """Set provisioning_state of octavia object to ERROR
        :param obj: octavia object like loadbalancer, pools, etc.
        """
        obj.provisioning_status = lib_consts.ERROR
        self._update_status_to_octavia({self.get_obj_type(obj): [self._status_obj(obj, lib_consts.ERROR)]})
