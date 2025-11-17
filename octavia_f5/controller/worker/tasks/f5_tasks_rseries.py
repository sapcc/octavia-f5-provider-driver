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

import requests
import tenacity
from oslo_config import cfg
from oslo_log import log as logging
from taskflow import task

from octavia_f5.network import data_models as f5_network_models
from octavia_f5.restclient.bigip import bigip_restclient
from octavia_f5.utils import driver_utils, decorators

# import all tasks and override only those that are different for rSeries devices
from .f5_tasks_iseries import *  # noqa: F403,F401

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


class EnsureVLAN(task.Task):

    """ Task to create or update VLAN if needed """

    @decorators.RaisesF5osaError()
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(requests.HTTPError),
        wait=tenacity.wait_fixed(2),
        stop=tenacity.stop_after_attempt(3)
    )
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                existing_vlan: dict,
                network: f5_network_models.Network):
        vlan_id = network.vlan_id
        vlan_payload = {
            "vlan-id": vlan_id,
            "config": {
                "vlan-id": vlan_id,
                "name": f"vlan-{vlan_id}",
            }
        }
        payload = {'openconfig-vlan:vlan': [vlan_payload]}

        # return if VLAN already exists
        if existing_vlan:
            return existing_vlan

        # contrary to the EnsureVLAN task for iSeries devices, we don't need to patch the VLAN in this task,
        # because it only contains the VLAN ID. In fact, comparing the existing_vlan dictionary with the payload
        # would be misleading, since existing_vlan may also include the "members" key, which can change pretty
        # much arbitrarily.

        # create missing VLAN
        res = bigip.put(path=f"/api/data/openconfig-vlan:vlans/vlan={vlan_id}", json=payload)
        res.raise_for_status()

    @decorators.RaisesF5osaError()
    def revert(self, network: f5_network_models.Network,
               bigip: bigip_restclient.BigIPRestClient,
               existing_vlan, *args, **kwargs):
        vlan_id = network.vlan_id
        if existing_vlan is not None:
            LOG.warning(f"EnsureVLAN revert: Not deleting VLAN {vlan_id}, since it existed before "
                        f"the task was run: {existing_vlan}")
            return
        res = bigip.delete(path=f"/api/data/openconfig-vlan:vlans/vlan={vlan_id}")
        if not res.ok:
            LOG.warning("EnsureVLAN revert: Failed removing VLAN on the device %s for "
                        "vlan_id=%s: %s", bigip.hostname, vlan_id, res.content)
        res.raise_for_status()


class GetExistingVLAN(task.Task):
    default_provides = 'existing_vlan'

    @decorators.RaisesF5osaError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network):
        vlan_id = network.vlan_id
        res = bigip.get(path=f"/api/data/openconfig-vlan:vlans/vlan={vlan_id}")
        if res.status_code == 404:
            return None
        res.raise_for_status()

        # get and return VLAN dict from response json
        vlan_list = res.json()["openconfig-vlan:vlan"]
        if len(vlan_list) > 1:
            LOG.warning(f"GetExistingVLAN: Got multiple VLANs for ID {vlan_id}: {vlan_list} - only using the first one")
        return vlan_list[0]


class EnsureVLANInterface(task.Task):
    """ Task to create or update VLAN interface/LAG attachment if needed"""

    @decorators.RaisesF5osaError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                network: f5_network_models.Network):
        vlan_id = network.vlan_id
        network_driver = driver_utils.get_network_driver()
        lag_name = network_driver.physical_interface
        payload = {'openconfig-vlan:trunk-vlans': [vlan_id]}

        # Create VLAN interface if not existing or not correct
        path = f"/api/data/openconfig-interfaces:interfaces/interface={lag_name}" \
               f"/openconfig-if-aggregate:aggregation/openconfig-vlan:switched-vlan/config/trunk-vlans={vlan_id}"
        res = bigip.put(path=path, json=payload)
        res.raise_for_status()


class EnsureGuestVLAN(task.Task):
    """ Task to assign correct vlan to vcmp guest """

    @decorators.RaisesF5osaError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: [str],
                network: f5_network_models.Network):
        vlan_id = network.vlan_id

        # the guests are called tenant in the F5OS-A API
        device_response = bigip.get(path='/api/data/f5-tenants:tenants')
        device_response.raise_for_status()
        guests = device_response.json()["f5-tenants:tenants"]["tenant"]

        # assign the VLAN to each managed guest
        for guest in guests:
            guest_name = guest['name']

            # Check if it's a managed guest.
            # F5OS-A API only gives the host part of the name, so we have to check with startswith. We have to
            # check against the guest name with a dot appended, so that partial guest names don't match.
            if not any(name.startswith(guest_name + ".") for name in bigip_guest_names):
                continue

            # Check if the VLAN is already configured on the guest
            if vlan_id in guest['config']['vlans']:
                continue

            res = bigip.put(
                path=f"/api/data/f5-tenants:tenants/tenant={guest_name}/config/vlans={vlan_id}",
                json={'f5-tenants:vlans': [vlan_id]})
            res.raise_for_status()


class GetVCMPGuests(task.Task):
    default_provides = 'device_guests'

    """ Provides guests dict of a VCMP host """

    @decorators.RaisesF5osaError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient):
        device_response = bigip.get(path='/api/data/f5-tenants:tenants')
        device_response.raise_for_status()
        return device_response.json()["f5-tenants:tenants"]["tenant"]


class RemoveGuestVLAN(task.Task):
    """ Removes vlan assignment of a VCMP Guest """
    @decorators.RaisesF5osaError()
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: [str],
                device_guests: list,
                network: f5_network_models.Network):
        vlan_id = network.vlan_id
        for guest in device_guests:
            guest_name = guest['name']

            # Check if it's a managed guest.
            # F5OS-A API only gives the host part of the name, so we have to check with startswith. We have to
            # check against the guest name with a dot appended, so that partial guest names don't match.
            if not any(name.startswith(guest_name + ".") for name in bigip_guest_names):
                continue

            # Already removed?
            if vlan_id not in guest['config']['vlans']:
                return

            res = bigip.delete(
                path=f"/api/data/f5-tenants:tenants/tenant={guest_name}/config/vlans={vlan_id}")
            if not res.ok:
                LOG.warning("%s: Failed removing guest VLAN for vlan_id=%s: %s",
                            bigip.hostname, network.vlan_id, res.content)
            res.raise_for_status()


class RemoveVLANIfNotOwnedByGuest(task.Task):

    @decorators.RaisesF5osaError()
    # This backoff-retry mechanism is needed due to known F5 bug 1759761.
    # - KB article about the bug: https://my.f5.com/s/article/K000149152
    # - F5-internal case for SAP instance of the bug: 00888515
    # FIXME remove backoff-retry when bug is fixed (should be the case with F5OS 2.0).
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(requests.HTTPError),
        wait=tenacity.wait_exponential(),
        stop=tenacity.stop_after_attempt(3)
    )
    def execute(self,
                bigip: bigip_restclient.BigIPRestClient,
                bigip_guest_names: [str],
                device_guests: list,
                network: f5_network_models.Network):
        """ Task to delete VLAN on a VCMP Host  """
        vlan_id = network.vlan_id

        for guest in device_guests:
            # skip own guest
            # bigip_guest_names contain the whole domain, but the guest knows only its hostname
            if any(guest_name.startswith(guest['name'] + '.') for guest_name in bigip_guest_names):
                continue

            # if vlan is in use by other guest, don't delete it
            if vlan_id in guest['config']['vlans']:
                return

        res = bigip.delete(path=f"/api/data/openconfig-vlan:vlans/vlan={vlan_id}")
        if not res.ok:
            LOG.warning("%s: Failed RemoveVLANIfNotOwnedByGuest for vlan_id=%s: %s",
                        bigip.hostname, network.vlan_id, res.content)

        # There is another bug (not F5 bug 1759761 noted above, which is the
        # one for which we retry) - where VLAN detachment from the guest comes
        # back with HTTP 200 even though it's not finished yet. And if it then
        # ends up failing, because there are still objects on the guest that
        # depend on the VLAN, the vlan-listener object will still exist and
        # block VLAN deletion, even though the device config says the VLAN is
        # detached from the guest. vlan-listeners cannot be deleted.
        # The only fix is to attach and detach the VLAN to/from the guest
        # again. But since this incurs a performance penalty and the issue does
        # not impede LB configuration, we instead simply ignore failed VLAN
        # deletion. The VLAN can safely be reused later - a subsequent creation
        # request for it yields HTTP 201. This is the easiest option that
        # doesn't cause problems.
        # Note that this effectively disables the tenacity backoff-retry
        # mechanism on this method, since this method will never raise an
        # exception. That's okay, since orphaned VLANs are okay (see above).
        # But the retry code must not be removed, because when this bug is
        # fixed, bug 1759761 might still be around. They have to be treated
        # separately.
        # FIXME reenable raise_for_status when this bug is fixed or when guest
        # cleanup code is guaranteed to finish before host cleanup code.
        # res.raise_for_status()
