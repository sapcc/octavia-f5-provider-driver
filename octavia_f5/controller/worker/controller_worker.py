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
#
import tenacity
from f5.bigip import ManagementRoot
from mock import patch
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy.orm import exc as db_exceptions
from taskflow.listeners import logging as tf_logging

from octavia.common import base_taskflow
from octavia.controller.worker.flows import health_monitor_flows
from octavia.controller.worker.flows import l7policy_flows
from octavia.controller.worker.flows import l7rule_flows
from octavia.controller.worker.flows import member_flows
from octavia.db import api as db_apis
from octavia.db import repositories as repo
from octavia_f5.common import constants
from octavia_f5.controller.worker.flows import load_balancer_flows
from octavia_f5.controller.worker.flows import listener_flows
from octavia_f5.controller.worker.flows import pool_flows

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

RETRY_ATTEMPTS = 15
RETRY_INITIAL_DELAY = 1
RETRY_BACKOFF = 1
RETRY_MAX = 5


def _is_provisioning_status_pending_update(lb_obj):
    return not lb_obj.provisioning_status == constants.PENDING_UPDATE


class ControllerWorker(base_taskflow.BaseTaskFlowEngine):

    def __init__(self):
        # Need to patch signal code since not running in mainthread
        with patch('f5.bigip.HAS_SIGNAL', False):
            self.bigip = ManagementRoot()
            LOG.info("Connected to F5 Device %s running TMOS %s", self.bigip.hostname, self.bigip.tmos_version)
        self._health_monitor_flows = health_monitor_flows.HealthMonitorFlows()
        self._lb_flows = load_balancer_flows.LoadBalancerFlows()
        self._listener_flows = listener_flows.ListenerFlows()
        self._member_flows = member_flows.MemberFlows()
        self._pool_flows = pool_flows.PoolFlows()
        self._l7policy_flows = l7policy_flows.L7PolicyFlows()
        self._l7rule_flows = l7rule_flows.L7RuleFlows()

        self._health_mon_repo = repo.HealthMonitorRepository()
        self._lb_repo = repo.LoadBalancerRepository()
        self._listener_repo = repo.ListenerRepository()
        self._member_repo = repo.MemberRepository()
        self._pool_repo = repo.PoolRepository()
        self._l7policy_repo = repo.L7PolicyRepository()
        self._l7rule_repo = repo.L7RuleRepository()

        self._exclude_result_logging_tasks = (
            constants.ROLE_STANDALONE + '-' +
            constants.GENERATE_SERVER_PEM,
            constants.ROLE_BACKUP + '-' +
            constants.GENERATE_SERVER_PEM,
            constants.ROLE_MASTER + '-' +
            constants.GENERATE_SERVER_PEM,
            constants.GENERATE_SERVER_PEM_TASK)

        super(ControllerWorker, self).__init__()

        # Todo: make configurable


    @tenacity.retry(
        retry=(
            tenacity.retry_if_result(_is_provisioning_status_pending_update) |
            tenacity.retry_if_exception_type()),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def _get_db_obj_until_pending_update(self, repo, id):

        return repo.get(db_apis.get_session(), id=id)


    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_health_monitor(self, health_monitor_id):
        """Creates a health monitor.

        :param pool_id: ID of the pool to create a health monitor on
        :returns: None
        :raises NoResultFound: Unable to find the object
        """
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)
        if not health_mon:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'health_monitor', health_monitor_id)
            raise db_exceptions.NoResultFound

        pool = health_mon.pool
        listeners = pool.listeners
        pool.health_monitor = health_mon
        load_balancer = pool.load_balancer

        create_hm_tf = self._taskflow_load(
            self._health_monitor_flows.get_create_health_monitor_flow(),
            store={constants.HEALTH_MON: health_mon,
                   constants.POOL: pool,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer})
        with tf_logging.DynamicLoggingListener(create_hm_tf,
                                               log=LOG):
            create_hm_tf.run()

    def delete_health_monitor(self, health_monitor_id):
        """Deletes a health monitor.

        :param pool_id: ID of the pool to delete its health monitor
        :returns: None
        :raises HMNotFound: The referenced health monitor was not found
        """
        health_mon = self._health_mon_repo.get(db_apis.get_session(),
                                               id=health_monitor_id)

        pool = health_mon.pool
        listeners = pool.listeners
        load_balancer = pool.load_balancer

        delete_hm_tf = self._taskflow_load(
            self._health_monitor_flows.get_delete_health_monitor_flow(),
            store={constants.HEALTH_MON: health_mon,
                   constants.POOL: pool,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer})
        with tf_logging.DynamicLoggingListener(delete_hm_tf,
                                               log=LOG):
            delete_hm_tf.run()

    def update_health_monitor(self, health_monitor_id, health_monitor_updates):
        """Updates a health monitor.

        :param pool_id: ID of the pool to have it's health monitor updated
        :param health_monitor_updates: Dict containing updated health monitor
        :returns: None
        :raises HMNotFound: The referenced health monitor was not found
        """
        health_mon = None
        try:
            health_mon = self._get_db_obj_until_pending_update(
                self._health_mon_repo, health_monitor_id)
        except tenacity.RetryError as e:
            LOG.warning('Health monitor did not go into %s in 60 seconds. '
                        'This either due to an in-progress Octavia upgrade '
                        'or an overloaded and failing database. Assuming '
                        'an upgrade is in progress and continuing.',
                        constants.PENDING_UPDATE)
            health_mon = e.last_attempt.result()

        pool = health_mon.pool
        listeners = pool.listeners
        pool.health_monitor = health_mon
        load_balancer = pool.load_balancer

        update_hm_tf = self._taskflow_load(
            self._health_monitor_flows.get_update_health_monitor_flow(),
            store={constants.HEALTH_MON: health_mon,
                   constants.POOL: pool,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer,
                   constants.UPDATE_DICT: health_monitor_updates})
        with tf_logging.DynamicLoggingListener(update_hm_tf,
                                               log=LOG):
            update_hm_tf.run()

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_listener(self, listener_id):
        """Creates a listener.

        :param listener_id: ID of the listener to create
        :returns: None
        :raises NoResultFound: Unable to find the object
        """
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)
        if not listener:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'listener', listener_id)
            raise db_exceptions.NoResultFound

        store = {constants.LOADBALANCER: listener.load_balancer,
                 constants.LISTENERS: [listener],
                 constants.BIGIP: self.bigip}

        create_listener_tf = self._taskflow_load(self._listener_flows.
                                                 get_create_listener_flow(),
                                                 store=store)
        with tf_logging.DynamicLoggingListener(create_listener_tf,
                                               log=LOG):
            create_listener_tf.run()

    def delete_listener(self, listener_id):
        """Deletes a listener.

        :param listener_id: ID of the listener to delete
        :returns: None
        :raises ListenerNotFound: The referenced listener was not found
        """
        listener = self._listener_repo.get(db_apis.get_session(),
                                           id=listener_id)
        load_balancer = listener.load_balancer

        delete_listener_tf = self._taskflow_load(
            self._listener_flows.get_delete_listener_flow(),
            store={constants.LOADBALANCER: load_balancer,
                   constants.LISTENER: listener,
                   constants.BIGIP: self.bigip})
        with tf_logging.DynamicLoggingListener(delete_listener_tf,
                                               log=LOG):
            delete_listener_tf.run()

    def update_listener(self, listener_id, listener_updates):
        """Updates a listener.

        :param listener_id: ID of the listener to update
        :param listener_updates: Dict containing updated listener attributes
        :returns: None
        :raises ListenerNotFound: The referenced listener was not found
        """
        listener = None
        try:
            listener = self._get_db_obj_until_pending_update(
                self._listener_repo, listener_id)
        except tenacity.RetryError as e:
            LOG.warning('Listener did not go into %s in 60 seconds. '
                        'This either due to an in-progress Octavia upgrade '
                        'or an overloaded and failing database. Assuming '
                        'an upgrade is in progress and continuing.',
                        constants.PENDING_UPDATE)
            listener = e.last_attempt.result()

        store = {constants.LISTENER: listener,
                 constants.LOADBALANCER: listener.load_balancer,
                 constants.UPDATE_DICT:listener_updates,
                 constants.LISTENERS:[listener],
                 constants.BIGIP: self.bigip}

        update_listener_tf = self._taskflow_load(self._listener_flows.
                                                 get_update_listener_flow(),
                                                 store=store)
        with tf_logging.DynamicLoggingListener(update_listener_tf, log=LOG):
            update_listener_tf.run()

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_load_balancer(self, load_balancer_id):
        """Creates a load balancer by allocation a partition.

        :param load_balancer_id: ID of the load balancer to create
        :returns: None
        :raises NoResultFound: Unable to find the object
        """
        lb = self._lb_repo.get(db_apis.get_session(), id=load_balancer_id)
        if not lb:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'load_balancer', load_balancer_id)
            raise db_exceptions.NoResultFound

        store = {constants.LOADBALANCER: lb,
                 constants.BIGIP: self.bigip,
                 constants.BUILD_TYPE_PRIORITY:
                 constants.LB_CREATE_NORMAL_PRIORITY}

        create_lb_flow = self._lb_flows.get_create_load_balancer_flow()

        create_lb_tf = self._taskflow_load(create_lb_flow, store=store)
        with tf_logging.DynamicLoggingListener(
                create_lb_tf, log=LOG,
                hide_inputs_outputs_of=self._exclude_result_logging_tasks):
            create_lb_tf.run()

    def delete_load_balancer(self, load_balancer_id, cascade=False):
        """Deletes a load balancer by de-allocating Amphorae.

        :param load_balancer_id: ID of the load balancer to delete
        :returns: None
        :raises LBNotFound: The referenced load balancer was not found
        """
        lb = self._lb_repo.get(db_apis.get_session(),
                               id=load_balancer_id)

        if cascade:
            (flow,
             store) = self._lb_flows.get_cascade_delete_load_balancer_flow(lb)
        else:
            (flow, store) = self._lb_flows.get_delete_load_balancer_flow(lb)
        store.update({constants.LOADBALANCER: lb,
                      constants.SERVER_GROUP_ID: lb.server_group_id})
        delete_lb_tf = self._taskflow_load(flow, store=store)

        with tf_logging.DynamicLoggingListener(delete_lb_tf,
                                               log=LOG):
            delete_lb_tf.run()

    def update_load_balancer(self, load_balancer_id, load_balancer_updates):
        """Updates a load balancer.

        :param load_balancer_id: ID of the load balancer to update
        :param load_balancer_updates: Dict containing updated load balancer
        :returns: None
        :raises LBNotFound: The referenced load balancer was not found
        """
        lb = None
        try:
            lb = self._get_db_obj_until_pending_update(
                self._lb_repo, load_balancer_id)
        except tenacity.RetryError as e:
            LOG.warning('Load balancer did not go into %s in 60 seconds. '
                        'This either due to an in-progress Octavia upgrade '
                        'or an overloaded and failing database. Assuming '
                        'an upgrade is in progress and continuing.',
                        constants.PENDING_UPDATE)
            lb = e.last_attempt.result()

        listeners, _ = self._listener_repo.get_all(
            db_apis.get_session(),
            load_balancer_id=load_balancer_id)

        update_lb_tf = self._taskflow_load(
            self._lb_flows.get_update_load_balancer_flow(),
            store={constants.LOADBALANCER: lb,
                   constants.LISTENERS: listeners,
                   constants.UPDATE_DICT: load_balancer_updates})

        with tf_logging.DynamicLoggingListener(update_lb_tf,
                                               log=LOG):
            update_lb_tf.run()

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_member(self, member_id):
        """Creates a pool member.

        :param member_id: ID of the member to create
        :returns: None
        :raises NoSuitablePool: Unable to find the node pool
        """
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        if not member:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'member', member_id)
            raise db_exceptions.NoResultFound

        pool = member.pool
        listeners = pool.listeners
        load_balancer = pool.load_balancer

        create_member_tf = self._taskflow_load(self._member_flows.
                                               get_create_member_flow(),
                                               store={constants.MEMBER: member,
                                                      constants.LISTENERS:
                                                          listeners,
                                                      constants.LOADBALANCER:
                                                          load_balancer,
                                                      constants.POOL: pool})
        with tf_logging.DynamicLoggingListener(create_member_tf,
                                               log=LOG):
            create_member_tf.run()

    def delete_member(self, member_id):
        """Deletes a pool member.

        :param member_id: ID of the member to delete
        :returns: None
        :raises MemberNotFound: The referenced member was not found
        """
        member = self._member_repo.get(db_apis.get_session(),
                                       id=member_id)
        pool = member.pool
        listeners = pool.listeners
        load_balancer = pool.load_balancer

        delete_member_tf = self._taskflow_load(
            self._member_flows.get_delete_member_flow(),
            store={constants.MEMBER: member, constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer, constants.POOL: pool}
        )
        with tf_logging.DynamicLoggingListener(delete_member_tf,
                                               log=LOG):
            delete_member_tf.run()

    def batch_update_members(self, old_member_ids, new_member_ids,
                             updated_members):
        old_members = [self._member_repo.get(db_apis.get_session(), id=mid)
                       for mid in old_member_ids]
        new_members = [self._member_repo.get(db_apis.get_session(), id=mid)
                       for mid in new_member_ids]
        updated_members = [
            (self._member_repo.get(db_apis.get_session(), id=m.get('id')), m)
            for m in updated_members]
        if old_members:
            pool = old_members[0].pool
        elif new_members:
            pool = new_members[0].pool
        else:
            pool = updated_members[0][0].pool
        listeners = pool.listeners
        load_balancer = pool.load_balancer

        batch_update_members_tf = self._taskflow_load(
            self._member_flows.get_batch_update_members_flow(
                old_members, new_members, updated_members),
            store={constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer,
                   constants.POOL: pool})
        with tf_logging.DynamicLoggingListener(batch_update_members_tf,
                                               log=LOG):
            batch_update_members_tf.run()

    def update_member(self, member_id, member_updates):
        """Updates a pool member.

        :param member_id: ID of the member to update
        :param member_updates: Dict containing updated member attributes
        :returns: None
        :raises MemberNotFound: The referenced member was not found
        """
        member = None
        try:
            member = self._get_db_obj_until_pending_update(
                self._member_repo, member_id)
        except tenacity.RetryError as e:
            LOG.warning('Member did not go into %s in 60 seconds. '
                        'This either due to an in-progress Octavia upgrade '
                        'or an overloaded and failing database. Assuming '
                        'an upgrade is in progress and continuing.',
                        constants.PENDING_UPDATE)
            member = e.last_attempt.result()

        pool = member.pool
        listeners = pool.listeners
        load_balancer = pool.load_balancer

        update_member_tf = self._taskflow_load(self._member_flows.
                                               get_update_member_flow(),
                                               store={constants.MEMBER: member,
                                                      constants.LISTENERS:
                                                          listeners,
                                                      constants.LOADBALANCER:
                                                          load_balancer,
                                                      constants.POOL:
                                                          pool,
                                                      constants.UPDATE_DICT:
                                                          member_updates})
        with tf_logging.DynamicLoggingListener(update_member_tf,
                                               log=LOG):
            update_member_tf.run()

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_pool(self, pool_id):
        """Creates a node pool.

        :param pool_id: ID of the pool to create
        :returns: None
        :raises NoResultFound: Unable to find the object
        """
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)
        if not pool:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'pool', pool_id)
            raise db_exceptions.NoResultFound

        store = {constants.POOL: pool,
                 constants.LISTENERS: pool.listeners,
                 constants.LOADBALANCER:pool.load_balancer,
                 constants.BIGIP: self.bigip}

        create_pool_tf = self._taskflow_load(self._pool_flows.
                                             get_create_pool_flow(),
                                             store=store)
        with tf_logging.DynamicLoggingListener(create_pool_tf,
                                               log=LOG):
            create_pool_tf.run()

    def delete_pool(self, pool_id):
        """Deletes a node pool.

        :param pool_id: ID of the pool to delete
        :returns: None
        :raises PoolNotFound: The referenced pool was not found
        """
        pool = self._pool_repo.get(db_apis.get_session(),
                                   id=pool_id)

        load_balancer = pool.load_balancer
        listeners = pool.listeners

        delete_pool_tf = self._taskflow_load(
            self._pool_flows.get_delete_pool_flow(),
            store={constants.POOL: pool, constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer})
        with tf_logging.DynamicLoggingListener(delete_pool_tf,
                                               log=LOG):
            delete_pool_tf.run()

    def update_pool(self, pool_id, pool_updates):
        """Updates a node pool.

        :param pool_id: ID of the pool to update
        :param pool_updates: Dict containing updated pool attributes
        :returns: None
        :raises PoolNotFound: The referenced pool was not found
        """
        pool = None
        try:
            pool = self._get_db_obj_until_pending_update(
                self._pool_repo, pool_id)
        except tenacity.RetryError as e:
            LOG.warning('Pool did not go into %s in 60 seconds. '
                        'This either due to an in-progress Octavia upgrade '
                        'or an overloaded and failing database. Assuming '
                        'an upgrade is in progress and continuing.',
                        constants.PENDING_UPDATE)
            pool = e.last_attempt.result()

        listeners = pool.listeners
        load_balancer = pool.load_balancer

        update_pool_tf = self._taskflow_load(self._pool_flows.
                                             get_update_pool_flow(),
                                             store={constants.POOL: pool,
                                                    constants.LISTENERS:
                                                        listeners,
                                                    constants.LOADBALANCER:
                                                        load_balancer,
                                                    constants.UPDATE_DICT:
                                                        pool_updates})
        with tf_logging.DynamicLoggingListener(update_pool_tf,
                                               log=LOG):
            update_pool_tf.run()

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_l7policy(self, l7policy_id):
        """Creates an L7 Policy.

        :param l7policy_id: ID of the l7policy to create
        :returns: None
        :raises NoResultFound: Unable to find the object
        """
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)
        if not l7policy:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'l7policy', l7policy_id)
            raise db_exceptions.NoResultFound

        listeners = [l7policy.listener]
        load_balancer = l7policy.listener.load_balancer

        create_l7policy_tf = self._taskflow_load(
            self._l7policy_flows.get_create_l7policy_flow(),
            store={constants.L7POLICY: l7policy,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer})
        with tf_logging.DynamicLoggingListener(create_l7policy_tf,
                                               log=LOG):
            create_l7policy_tf.run()

    def delete_l7policy(self, l7policy_id):
        """Deletes an L7 policy.

        :param l7policy_id: ID of the l7policy to delete
        :returns: None
        :raises L7PolicyNotFound: The referenced l7policy was not found
        """
        l7policy = self._l7policy_repo.get(db_apis.get_session(),
                                           id=l7policy_id)

        load_balancer = l7policy.listener.load_balancer
        listeners = [l7policy.listener]

        delete_l7policy_tf = self._taskflow_load(
            self._l7policy_flows.get_delete_l7policy_flow(),
            store={constants.L7POLICY: l7policy,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer})
        with tf_logging.DynamicLoggingListener(delete_l7policy_tf,
                                               log=LOG):
            delete_l7policy_tf.run()

    def update_l7policy(self, l7policy_id, l7policy_updates):
        """Updates an L7 policy.

        :param l7policy_id: ID of the l7policy to update
        :param l7policy_updates: Dict containing updated l7policy attributes
        :returns: None
        :raises L7PolicyNotFound: The referenced l7policy was not found
        """
        l7policy = None
        try:
            l7policy = self._get_db_obj_until_pending_update(
                self._l7policy_repo, l7policy_id)
        except tenacity.RetryError as e:
            LOG.warning('L7 policy did not go into %s in 60 seconds. '
                        'This either due to an in-progress Octavia upgrade '
                        'or an overloaded and failing database. Assuming '
                        'an upgrade is in progress and continuing.',
                        constants.PENDING_UPDATE)
            l7policy = e.last_attempt.result()

        listeners = [l7policy.listener]
        load_balancer = l7policy.listener.load_balancer

        update_l7policy_tf = self._taskflow_load(
            self._l7policy_flows.get_update_l7policy_flow(),
            store={constants.L7POLICY: l7policy,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer,
                   constants.UPDATE_DICT: l7policy_updates})
        with tf_logging.DynamicLoggingListener(update_l7policy_tf,
                                               log=LOG):
            update_l7policy_tf.run()

    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(db_exceptions.NoResultFound),
        wait=tenacity.wait_incrementing(
            RETRY_INITIAL_DELAY, RETRY_BACKOFF, RETRY_MAX),
        stop=tenacity.stop_after_attempt(RETRY_ATTEMPTS))
    def create_l7rule(self, l7rule_id):
        """Creates an L7 Rule.

        :param l7rule_id: ID of the l7rule to create
        :returns: None
        :raises NoResultFound: Unable to find the object
        """
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        if not l7rule:
            LOG.warning('Failed to fetch %s %s from DB. Retrying for up to '
                        '60 seconds.', 'l7rule', l7rule_id)
            raise db_exceptions.NoResultFound

        l7policy = l7rule.l7policy
        listeners = [l7policy.listener]
        load_balancer = l7policy.listener.load_balancer

        create_l7rule_tf = self._taskflow_load(
            self._l7rule_flows.get_create_l7rule_flow(),
            store={constants.L7RULE: l7rule,
                   constants.L7POLICY: l7policy,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer})
        with tf_logging.DynamicLoggingListener(create_l7rule_tf,
                                               log=LOG):
            create_l7rule_tf.run()

    def delete_l7rule(self, l7rule_id):
        """Deletes an L7 rule.

        :param l7rule_id: ID of the l7rule to delete
        :returns: None
        :raises L7RuleNotFound: The referenced l7rule was not found
        """
        l7rule = self._l7rule_repo.get(db_apis.get_session(),
                                       id=l7rule_id)
        l7policy = l7rule.l7policy
        load_balancer = l7policy.listener.load_balancer
        listeners = [l7policy.listener]

        delete_l7rule_tf = self._taskflow_load(
            self._l7rule_flows.get_delete_l7rule_flow(),
            store={constants.L7RULE: l7rule,
                   constants.L7POLICY: l7policy,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer})
        with tf_logging.DynamicLoggingListener(delete_l7rule_tf,
                                               log=LOG):
            delete_l7rule_tf.run()

    def update_l7rule(self, l7rule_id, l7rule_updates):
        """Updates an L7 rule.

        :param l7rule_id: ID of the l7rule to update
        :param l7rule_updates: Dict containing updated l7rule attributes
        :returns: None
        :raises L7RuleNotFound: The referenced l7rule was not found
        """
        l7rule = None
        try:
            l7rule = self._get_db_obj_until_pending_update(
                self._l7rule_repo, l7rule_id)
        except tenacity.RetryError as e:
            LOG.warning('L7 rule did not go into %s in 60 seconds. '
                        'This either due to an in-progress Octavia upgrade '
                        'or an overloaded and failing database. Assuming '
                        'an upgrade is in progress and continuing.',
                        constants.PENDING_UPDATE)
            l7rule = e.last_attempt.result()

        l7policy = l7rule.l7policy
        listeners = [l7policy.listener]
        load_balancer = l7policy.listener.load_balancer

        update_l7rule_tf = self._taskflow_load(
            self._l7rule_flows.get_update_l7rule_flow(),
            store={constants.L7RULE: l7rule,
                   constants.L7POLICY: l7policy,
                   constants.LISTENERS: listeners,
                   constants.LOADBALANCER: load_balancer,
                   constants.UPDATE_DICT: l7rule_updates})
        with tf_logging.DynamicLoggingListener(update_l7rule_tf,
                                               log=LOG):
            update_l7rule_tf.run()
