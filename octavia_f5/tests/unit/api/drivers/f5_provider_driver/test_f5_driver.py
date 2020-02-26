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

import mock
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture

from octavia.common import constants as consts
from octavia.tests.unit import base
from octavia.tests.unit.api.drivers import sample_data_models
from octavia_f5.api.drivers.f5_driver import driver
from octavia_lib.api.drivers import data_models as driver_dm


class TestF5Driver(base.TestRpc):

    def setUp(self):
        super(TestF5Driver, self).setUp()
        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        self.patches = [
            mock.patch('octavia.db.repositories.AmphoraRepository.get'),
            mock.patch('octavia.db.api.get_session')
        ]
        conf.config(group="oslo_messaging", topic='foo_topic')
        conf.config(group="controller_worker", network_driver='network_noop_driver_f5')
        self.amp_driver = driver.F5ProviderDriver()
        self.sample_data = sample_data_models.SampleDriverDataModels()

        for patch in self.patches:
            patch.start()

    def tearDown(self):
        super(TestF5Driver, self).tearDown()
        for patch in self.patches:
            patch.stop()

    # Load Balancer
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_loadbalancer_create(self, mock_cast):
        provider_lb = driver_dm.LoadBalancer(
            loadbalancer_id=self.sample_data.lb_id)
        self.amp_driver.loadbalancer_create(provider_lb)
        payload = {consts.LOAD_BALANCER_ID: self.sample_data.lb_id,
                   consts.FLAVOR: None}
        mock_cast.assert_called_with({}, 'create_load_balancer', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_loadbalancer_delete(self, mock_cast):
        provider_lb = driver_dm.LoadBalancer(
            loadbalancer_id=self.sample_data.lb_id)
        self.amp_driver.loadbalancer_delete(provider_lb)
        payload = {consts.LOAD_BALANCER_ID: self.sample_data.lb_id,
                   'cascade': False}
        mock_cast.assert_called_with({}, 'delete_load_balancer', **payload)

    # Listener
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_listener_create(self, mock_cast):
        provider_listener = driver_dm.Listener(
            listener_id=self.sample_data.listener1_id)
        self.amp_driver.listener_create(provider_listener)
        payload = {consts.LISTENER_ID: self.sample_data.listener1_id}
        mock_cast.assert_called_with({}, 'create_listener', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_listener_delete(self, mock_cast):
        provider_listener = driver_dm.Listener(
            listener_id=self.sample_data.listener1_id)
        self.amp_driver.listener_delete(provider_listener)
        payload = {consts.LISTENER_ID: self.sample_data.listener1_id}
        mock_cast.assert_called_with({}, 'delete_listener', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_listener_update(self, mock_cast):
        old_provider_listener = driver_dm.Listener(
            listener_id=self.sample_data.listener1_id)
        provider_listener = driver_dm.Listener(
            listener_id=self.sample_data.listener1_id, admin_state_up=False)
        self.amp_driver.listener_update(old_provider_listener,
                                        provider_listener)
        payload = {consts.LISTENER_ID: self.sample_data.listener1_id,
                   consts.LISTENER_UPDATES: {}}
        mock_cast.assert_called_with({}, 'update_listener', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_listener_update_name(self, mock_cast):
        old_provider_listener = driver_dm.Listener(
            listener_id=self.sample_data.listener1_id)
        provider_listener = driver_dm.Listener(
            listener_id=self.sample_data.listener1_id, name='Great Listener')
        self.amp_driver.listener_update(old_provider_listener,
                                        provider_listener)
        payload = {consts.LISTENER_ID: self.sample_data.listener1_id,
                   consts.LISTENER_UPDATES: {}}
        mock_cast.assert_called_with({}, 'update_listener', **payload)

    # Pool
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_pool_create(self, mock_cast):
        provider_pool = driver_dm.Pool(
            pool_id=self.sample_data.pool1_id)
        self.amp_driver.pool_create(provider_pool)
        payload = {consts.POOL_ID: self.sample_data.pool1_id}
        mock_cast.assert_called_with({}, 'create_pool', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_pool_delete(self, mock_cast):
        provider_pool = driver_dm.Pool(
            pool_id=self.sample_data.pool1_id)
        self.amp_driver.pool_delete(provider_pool)
        payload = {consts.POOL_ID: self.sample_data.pool1_id}
        mock_cast.assert_called_with({}, 'delete_pool', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_pool_update(self, mock_cast):
        old_provider_pool = driver_dm.Pool(
            pool_id=self.sample_data.pool1_id)
        provider_pool = driver_dm.Pool(
            pool_id=self.sample_data.pool1_id, admin_state_up=True)
        self.amp_driver.pool_update(old_provider_pool, provider_pool)
        payload = {consts.POOL_ID: self.sample_data.pool1_id,
                   consts.POOL_UPDATES: {}}
        mock_cast.assert_called_with({}, 'update_pool', **payload)

    # Member
    @mock.patch('octavia.db.repositories.PoolRepository.get')
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_member_create(self, mock_cast, mock_pool_get):
        provider_member = driver_dm.Member(
            member_id=self.sample_data.member1_id)
        self.amp_driver.member_create(provider_member)
        payload = {consts.MEMBER_ID: self.sample_data.member1_id}
        mock_cast.assert_called_with({}, 'create_member', **payload)

    @mock.patch('octavia.db.repositories.PoolRepository.get')
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_member_create_udp_ipv4(self, mock_cast, mock_pool_get):
        mock_lb = mock.MagicMock()
        mock_lb.vip = mock.MagicMock()
        mock_lb.vip.ip_address = "192.0.1.1"
        mock_listener = mock.MagicMock()
        mock_listener.load_balancer = mock_lb
        mock_pool = mock.MagicMock()
        mock_pool.protocol = consts.PROTOCOL_UDP
        mock_pool.listeners = [mock_listener]
        mock_pool_get.return_value = mock_pool

        provider_member = driver_dm.Member(
            member_id=self.sample_data.member1_id,
            address="192.0.2.1")
        self.amp_driver.member_create(provider_member)
        payload = {consts.MEMBER_ID: self.sample_data.member1_id}
        mock_cast.assert_called_with({}, 'create_member', **payload)

    @mock.patch('octavia.db.repositories.PoolRepository.get')
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_member_create_udp_ipv4_ipv6(self, mock_cast, mock_pool_get):
        mock_lb = mock.MagicMock()
        mock_lb.vip = mock.MagicMock()
        mock_lb.vip.ip_address = "fe80::1"
        mock_listener = mock.MagicMock()
        mock_listener.load_balancer = mock_lb
        mock_pool = mock.MagicMock()
        mock_pool.protocol = consts.PROTOCOL_UDP
        mock_pool.listeners = [mock_listener]
        mock_pool_get.return_value = mock_pool

        provider_member = driver_dm.Member(
            member_id=self.sample_data.member1_id,
            address="192.0.2.1")
        self.amp_driver.member_create(provider_member)
        payload = {consts.MEMBER_ID: self.sample_data.member1_id}
        mock_cast.assert_called_with({}, 'create_member', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_member_delete(self, mock_cast):
        provider_member = driver_dm.Member(
            member_id=self.sample_data.member1_id)
        self.amp_driver.member_delete(provider_member)
        payload = {consts.MEMBER_ID: self.sample_data.member1_id}
        mock_cast.assert_called_with({}, 'delete_member', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_member_update(self, mock_cast):
        old_provider_member = driver_dm.Member(
            member_id=self.sample_data.member1_id)
        provider_member = driver_dm.Member(
            member_id=self.sample_data.member1_id, admin_state_up=True)
        self.amp_driver.member_update(old_provider_member, provider_member)
        payload = {consts.MEMBER_ID: self.sample_data.member1_id,
                   consts.MEMBER_UPDATES: {}}
        mock_cast.assert_called_with({}, 'update_member', **payload)

    # L7 Policy
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_l7policy_create(self, mock_cast):
        provider_l7policy = driver_dm.L7Policy(
            l7policy_id=self.sample_data.l7policy1_id)
        self.amp_driver.l7policy_create(provider_l7policy)
        payload = {consts.L7POLICY_ID: self.sample_data.l7policy1_id}
        mock_cast.assert_called_with({}, 'create_l7policy', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_l7policy_delete(self, mock_cast):
        provider_l7policy = driver_dm.L7Policy(
            l7policy_id=self.sample_data.l7policy1_id)
        self.amp_driver.l7policy_delete(provider_l7policy)
        payload = {consts.L7POLICY_ID: self.sample_data.l7policy1_id}
        mock_cast.assert_called_with({}, 'delete_l7policy', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_l7policy_update(self, mock_cast):
        old_provider_l7policy = driver_dm.L7Policy(
            l7policy_id=self.sample_data.l7policy1_id)
        provider_l7policy = driver_dm.L7Policy(
            l7policy_id=self.sample_data.l7policy1_id, admin_state_up=True)
        self.amp_driver.l7policy_update(old_provider_l7policy,
                                        provider_l7policy)
        payload = {consts.L7POLICY_ID: self.sample_data.l7policy1_id,
                   consts.L7POLICY_UPDATES: {}}
        mock_cast.assert_called_with({}, 'update_l7policy', **payload)

    # Health Monitor
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_health_monitor_create(self, mock_cast):
        provider_HM = driver_dm.HealthMonitor(
            healthmonitor_id=self.sample_data.hm1_id)
        self.amp_driver.health_monitor_create(provider_HM)
        payload = {consts.HEALTH_MONITOR_ID: self.sample_data.hm1_id}
        mock_cast.assert_called_with({}, 'create_health_monitor', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_health_monitor_delete(self, mock_cast):
        provider_HM = driver_dm.HealthMonitor(
            healthmonitor_id=self.sample_data.hm1_id)
        self.amp_driver.health_monitor_delete(provider_HM)
        payload = {consts.HEALTH_MONITOR_ID: self.sample_data.hm1_id}
        mock_cast.assert_called_with({}, 'delete_health_monitor', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_health_monitor_update(self, mock_cast):
        old_provider_hm = driver_dm.HealthMonitor(
            healthmonitor_id=self.sample_data.hm1_id)
        provider_hm = driver_dm.HealthMonitor(
            healthmonitor_id=self.sample_data.hm1_id, admin_state_up=True,
            max_retries=1, max_retries_down=2)
        self.amp_driver.health_monitor_update(old_provider_hm, provider_hm)
        payload = {consts.HEALTH_MONITOR_ID: self.sample_data.hm1_id,
                   consts.HEALTH_MONITOR_UPDATES: {}}
        mock_cast.assert_called_with({}, 'update_health_monitor', **payload)

    # L7 Rules
    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_l7rule_create(self, mock_cast):
        provider_l7rule = driver_dm.L7Rule(
            l7rule_id=self.sample_data.l7rule1_id)
        self.amp_driver.l7rule_create(provider_l7rule)
        payload = {consts.L7RULE_ID: self.sample_data.l7rule1_id}
        mock_cast.assert_called_with({}, 'create_l7rule', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_l7rule_delete(self, mock_cast):
        provider_l7rule = driver_dm.L7Rule(
            l7rule_id=self.sample_data.l7rule1_id)
        self.amp_driver.l7rule_delete(provider_l7rule)
        payload = {consts.L7RULE_ID: self.sample_data.l7rule1_id}
        mock_cast.assert_called_with({}, 'delete_l7rule', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_l7rule_update(self, mock_cast):
        old_provider_l7rule = driver_dm.L7Rule(
            l7rule_id=self.sample_data.l7rule1_id)
        provider_l7rule = driver_dm.L7Rule(
            l7rule_id=self.sample_data.l7rule1_id, admin_state_up=True)
        self.amp_driver.l7rule_update(old_provider_l7rule, provider_l7rule)
        payload = {consts.L7RULE_ID: self.sample_data.l7rule1_id,
                   consts.L7RULE_UPDATES: {}}
        mock_cast.assert_called_with({}, 'update_l7rule', **payload)

    @mock.patch('oslo_messaging.rpc.client._BaseCallContext.cast')
    def test_l7rule_update_invert(self, mock_cast):
        old_provider_l7rule = driver_dm.L7Rule(
            l7rule_id=self.sample_data.l7rule1_id)
        provider_l7rule = driver_dm.L7Rule(
            l7rule_id=self.sample_data.l7rule1_id, invert=True)
        self.amp_driver.l7rule_update(old_provider_l7rule, provider_l7rule)
        payload = {consts.L7RULE_ID: self.sample_data.l7rule1_id,
                   consts.L7RULE_UPDATES: {}}
        mock_cast.assert_called_with({}, 'update_l7rule', **payload)
