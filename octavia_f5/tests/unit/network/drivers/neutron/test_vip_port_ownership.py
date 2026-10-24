#  Copyright 2026 SAP SE
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
"""Ownership of VIP ports, see octavia-issues#66.

Caller-provided VIP ports (``--vip-port-id``) used to be taken as they are:
no device_owner, no device_id, no binding host. That allowed the project to
delete the port under a live load balancer (#66.1), several load balancers to
share one port (#66.2) and load balancers to land on a random agent (#66.3).

Now such a port is claimed while the load balancer exists and handed back
when it is deleted. Ports created by Octavia are marked octavia_owned=True.
"""

from unittest import mock

import openstack.exceptions as os_exceptions
from openstack.network.v2.port import Port

from octavia.common import data_models
from octavia.network import base as network_base
from octavia.tests.common import constants as t_constants

from octavia_f5.common import constants as f5_constants
from octavia_f5.tests.unit.network.drivers.neutron.test_neutron_client import (
    MOCK_CANDIDATE, MOCK_NEUTRON_PORT, MOCK_NEUTRON_SELFIP_PORTS,
    MOCK_SELFIP_IPADDRESS, MOCK_SUBNET_ID, NeutronClientTestCase)

LB_ID = 'lb-1'
REVISION = 7


def caller_port(**overrides):
    """A port as the project creates it: unowned, unbound, no device."""
    attrs = {
        'id': t_constants.MOCK_PORT_ID,
        'network_id': t_constants.MOCK_NETWORK_ID,
        'project_id': 'test-project',
        'device_id': '', 'device_owner': '', 'binding_host_id': '',
        'allowed_address_pairs': [], 'revision_number': REVISION,
        'fixed_ips': [{'ip_address': t_constants.MOCK_IP_ADDRESS,
                       'subnet_id': MOCK_SUBNET_ID}]}
    attrs.update(overrides)
    return Port(**attrs)


def claimed_port(**overrides):
    """The same port after claim_vip_port()."""
    attrs = {'device_id': LB_ID,
             'device_owner': f5_constants.DEVICE_OWNER_LISTENER,
             'binding_host_id': MOCK_CANDIDATE,
             'revision_number': REVISION + 1}
    attrs.update(overrides)
    return caller_port(**attrs)


def provided_port_lb(**lb_attrs):
    vip = data_models.Vip(port_id=t_constants.MOCK_PORT_ID,
                          subnet_id=MOCK_SUBNET_ID,
                          network_id=t_constants.MOCK_NETWORK_ID,
                          ip_address=t_constants.MOCK_IP_ADDRESS)
    return data_models.LoadBalancer(id=LB_ID, vip=vip, project_id='test-project',
                                    **lb_attrs)


def claim_calls(update_port):
    """update_port calls that claim the port (conditional on the revision)."""
    return [c for c in update_port.call_args_list if 'if_revision' in c.kwargs]


@mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
            return_value=[MOCK_CANDIDATE])
class TestClaimProvidedVipPort(NeutronClientTestCase):
    """allocate_vip() with a caller-provided port."""

    def setUp(self):
        super().setUp()
        # load balancers that use the port according to the Octavia DB
        self.port_users = mock.patch(
            'octavia_f5.db.repositories.LoadBalancerRepository.get_ids_by_vip_port',
            return_value=[]).start()
        proxy = self.driver.network_proxy
        proxy.get_port.return_value = caller_port()
        proxy.update_port.return_value = claimed_port()
        proxy.ports.return_value = MOCK_NEUTRON_SELFIP_PORTS

    def test_port_is_claimed_with_owner_device_and_binding(self, _sched):
        vip, _ = self.driver.allocate_vip(provided_port_lb())

        claims = claim_calls(self.driver.network_proxy.update_port)
        self.assertEqual(
            [mock.call(t_constants.MOCK_PORT_ID, if_revision=REVISION,
                       device_owner=f5_constants.DEVICE_OWNER_LISTENER,  # 66.1
                       device_id=LB_ID,                                  # 66.2
                       **{'binding:host_id': MOCK_CANDIDATE})],          # 66.3
            claims)
        # the caller's port is used, not replaced, and not owned by Octavia
        self.driver.network_proxy.create_port.assert_not_called()
        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertFalse(vip.octavia_owned)

    def test_binding_host_comes_from_scheduler_for_the_lb_az(self, get_candidates):
        # 66.3: the agent is chosen by the scheduler for the LB's AZ, not by
        # whichever worker happens to consume the create RPC
        get_candidates.return_value = ['agent-in-az-2']
        self.driver.allocate_vip(provided_port_lb(availability_zone='az-2'))

        get_candidates.assert_called_once_with(mock.ANY, 'az-2')
        claims = claim_calls(self.driver.network_proxy.update_port)
        self.assertEqual(1, len(claims))
        self.assertEqual('agent-in-az-2', claims[0].kwargs['binding:host_id'])

    def test_allowed_address_pairs_point_to_selfips(self, _sched):
        self.driver.allocate_vip(provided_port_lb())

        aap_calls = [c for c in self.driver.network_proxy.update_port.call_args_list
                     if 'allowed_address_pairs' in c.kwargs]
        self.assertEqual(
            [[{'ip_address': MOCK_SELFIP_IPADDRESS}]],
            [c.kwargs['allowed_address_pairs'] for c in aap_calls])

    def test_cached_host_is_invalidated(self, _sched):
        # get_scheduled_host() caches the binding per port; the create RPC
        # must see the host the port was just bound to
        with mock.patch.object(self.driver, 'invalidate_cache') as invalidate:
            self.driver.allocate_vip(provided_port_lb())
        invalidate.assert_called_once_with()

    def test_port_of_older_lb_is_refused(self, _sched):
        # 66.2 for load balancers created before ports were claimed: Neutron
        # doesn't show the port as used (no device_id), the Octavia DB does
        self.port_users.return_value = ['older-lb']

        exc = self.assertRaises(network_base.AllocateVIPException,
                                self.driver.allocate_vip, provided_port_lb())
        self.assertEqual(409, exc.orig_code)  # the API answers 409 Conflict
        self.port_users.assert_called_once_with(mock.ANY, t_constants.MOCK_PORT_ID)
        self.assertEqual([], claim_calls(self.driver.network_proxy.update_port))
        self.driver.network_proxy.create_port.assert_not_called()

    def test_lb_itself_does_not_count_as_other_user(self, _sched):
        self.port_users.return_value = [LB_ID]

        vip, _ = self.driver.allocate_vip(provided_port_lb())

        self.assertEqual(t_constants.MOCK_PORT_ID, vip.port_id)
        self.assertEqual(1, len(claim_calls(self.driver.network_proxy.update_port)))

    def test_port_claimed_by_other_lb_is_refused(self, _sched):
        # 66.2, second line of defence behind check_port_in_use() in the API
        self.driver.network_proxy.get_port.return_value = caller_port(
            device_id='another-lb')

        exc = self.assertRaises(network_base.AllocateVIPException,
                                self.driver.allocate_vip, provided_port_lb())
        self.assertEqual(409, exc.orig_code)
        self.assertEqual([], claim_calls(self.driver.network_proxy.update_port))

    def test_concurrent_claim_is_refused(self, _sched):
        # 66.2 race: two creates passed check_port_in_use() at the same time,
        # the other one updated the port first -> revision mismatch -> 412
        self.driver.network_proxy.update_port.side_effect = \
            os_exceptions.PreconditionFailedException()

        exc = self.assertRaises(network_base.AllocateVIPException,
                                self.driver.allocate_vip, provided_port_lb())
        self.assertEqual(409, exc.orig_code)

    def test_port_deleted_meanwhile_is_refused(self, _sched):
        # gone between the check in allocate_vip() and the claim
        self.driver.network_proxy.get_port.side_effect = [
            caller_port(), os_exceptions.NotFoundException()]

        exc = self.assertRaises(network_base.AllocateVIPException,
                                self.driver.allocate_vip, provided_port_lb())
        self.assertEqual(409, exc.orig_code)
        self.driver.network_proxy.create_port.assert_not_called()

    def test_neutron_refusal_is_passed_on(self, _sched):
        # e.g. a policy error: the API answers with Neutron's status code
        self.driver.network_proxy.update_port.side_effect = \
            os_exceptions.HttpException('forbidden', http_status=403)

        exc = self.assertRaises(network_base.AllocateVIPException,
                                self.driver.allocate_vip, provided_port_lb())
        self.assertEqual(403, exc.orig_code)

    def test_claim_is_reverted_when_allocation_fails(self, _sched):
        self.driver.network_proxy.get_port.return_value = caller_port(
            allowed_address_pairs=[{'ip_address': '10.9.9.9'}])
        # fail the last step of the flow, so the claim has certainly happened
        with mock.patch.object(self.driver, 'invalidate_cache',
                               side_effect=RuntimeError('boom')):
            self.assertRaises(RuntimeError,
                              self.driver.allocate_vip, provided_port_lb())

        # the port gets exactly its previous attributes back
        self.driver.network_proxy.update_port.assert_called_with(
            t_constants.MOCK_PORT_ID, device_owner='', device_id='',
            allowed_address_pairs=[{'ip_address': '10.9.9.9'}],
            **{'binding:host_id': ''})


@mock.patch('octavia_f5.db.scheduler.Scheduler.get_candidates',
            return_value=[MOCK_CANDIDATE])
class TestOctaviaOwnedFlag(NeutronClientTestCase):
    """Ports created by Octavia must come back with octavia_owned=True."""

    def setUp(self):
        super().setUp()
        self.driver.network_proxy.create_port.return_value = MOCK_NEUTRON_PORT
        self.driver.network_proxy.ports.return_value = MOCK_NEUTRON_SELFIP_PORTS

    def test_created_port_is_octavia_owned(self, _sched):
        vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                              network_id=t_constants.MOCK_NETWORK_ID)
        lb = data_models.LoadBalancer(id='1', vip=vip, project_id='test-project')

        created, _ = self.driver.allocate_vip(lb)

        self.assertTrue(created.octavia_owned)

    def test_rebuilt_port_is_octavia_owned(self, _sched):
        # A port was provided but is gone -> Octavia creates a new
        # loadbalancer-<id> port, so Octavia owns it. Before this change it
        # came back octavia_owned=False and was never deleted with the LB.
        self.driver.network_proxy.get_port.side_effect = \
            os_exceptions.NotFoundException()
        vip = data_models.Vip(subnet_id=MOCK_SUBNET_ID,
                              network_id=t_constants.MOCK_NETWORK_ID,
                              port_id=t_constants.MOCK_PORT_ID)
        lb = data_models.LoadBalancer(id='1', vip=vip, project_id='test-project')

        rebuilt, _ = self.driver.allocate_vip(lb)

        self.assertEqual(
            'loadbalancer-1',
            self.driver.network_proxy.create_port.call_args.kwargs['name'])
        self.assertTrue(rebuilt.octavia_owned)


class TestReleaseVip(NeutronClientTestCase):
    """release_vip(): the load balancer of a caller-owned port was deleted."""

    def vip(self):
        return data_models.Vip(port_id=t_constants.MOCK_PORT_ID,
                               network_id=t_constants.MOCK_NETWORK_ID,
                               load_balancer_id=LB_ID, octavia_owned=False)

    def test_claimed_port_is_handed_back(self):
        self.driver.network_proxy.get_port.return_value = claimed_port()

        self.driver.release_vip(self.vip())

        self.driver.network_proxy.update_port.assert_called_once_with(
            t_constants.MOCK_PORT_ID, device_owner='', device_id='',
            allowed_address_pairs=[], **{'binding:host_id': ''})
        self.driver.network_proxy.delete_port.assert_not_called()

    def test_unclaimed_legacy_port_is_left_alone(self):
        # LBs created before this change never claimed their port
        self.driver.network_proxy.get_port.return_value = caller_port()
        self.driver.release_vip(self.vip())
        self.driver.network_proxy.update_port.assert_not_called()

    def test_port_claimed_by_other_lb_is_left_alone(self):
        self.driver.network_proxy.get_port.return_value = claimed_port(
            device_id='another-lb')
        self.driver.release_vip(self.vip())
        self.driver.network_proxy.update_port.assert_not_called()

    def test_missing_port_is_fine(self):
        self.driver.network_proxy.get_port.side_effect = \
            os_exceptions.NotFoundException()
        self.driver.release_vip(self.vip())
        self.driver.network_proxy.update_port.assert_not_called()

    def test_neutron_error_on_update_is_raised(self):
        # the DriverUpdater keeps the LB in PENDING_DELETE then and
        # pending_sync retries (see test_status_manager)
        self.driver.network_proxy.get_port.return_value = claimed_port()
        self.driver.network_proxy.update_port.side_effect = \
            os_exceptions.HttpException('503')
        self.assertRaises(network_base.DeallocateVIPException,
                          self.driver.release_vip, self.vip())

    def test_neutron_error_on_lookup_is_raised(self):
        self.driver.network_proxy.get_port.side_effect = \
            os_exceptions.HttpException('503')
        self.assertRaises(network_base.DeallocateVIPException,
                          self.driver.release_vip, self.vip())
        self.driver.network_proxy.update_port.assert_not_called()


@mock.patch('octavia_f5.db.repositories.LoadBalancerRepository.'
            'get_all_by_network', return_value=[])
class TestDeallocateCallerOwnedVip(NeutronClientTestCase):
    """deallocate_vip() must never delete a port the caller owns.

    The SAP API calls deallocate_vip() when LB creation fails after the VIP
    was allocated. For a claimed caller port that used to be safe only
    because device_owner was empty; now we set it ourselves.
    """

    def vip(self, octavia_owned):
        return data_models.Vip(port_id=t_constants.MOCK_PORT_ID,
                               network_id=t_constants.MOCK_NETWORK_ID,
                               load_balancer_id=LB_ID,
                               octavia_owned=octavia_owned)

    def test_caller_port_is_released_not_deleted(self, _lbs):
        proxy = self.driver.network_proxy
        proxy.get_port.return_value = claimed_port()
        proxy.ports.return_value = [{'id': 'selfip-1'}]

        self.driver.deallocate_vip(self.vip(octavia_owned=False))

        # self-IPs created during the failed allocation are still cleaned up
        proxy.delete_port.assert_called_once_with('selfip-1')
        proxy.update_port.assert_called_once_with(
            t_constants.MOCK_PORT_ID, device_owner='', device_id='',
            allowed_address_pairs=[], **{'binding:host_id': ''})

    def test_octavia_port_is_deleted(self, _lbs):
        proxy = self.driver.network_proxy
        proxy.get_port.return_value = claimed_port()
        proxy.ports.return_value = []

        self.driver.deallocate_vip(self.vip(octavia_owned=True))

        proxy.delete_port.assert_called_once_with(t_constants.MOCK_PORT_ID)
        proxy.update_port.assert_not_called()
