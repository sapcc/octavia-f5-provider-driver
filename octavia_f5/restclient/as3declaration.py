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

import uuid

from octavia_f5.restclient.as3classes import ADC
from octavia_f5.restclient.as3objects import as3 as m_as3
from octavia_f5.restclient.as3objects import tenant as m_tenant
from octavia_f5.utils import driver_utils, cert_manager, esd_repo


class AS3DeclarationManager(object):
    def __init__(self, status_manager):
        self._esd_repo = esd_repo.EsdRepository()
        self._network_driver = driver_utils.get_network_driver()
        self._cert_manager = cert_manager.CertManagerWrapper()
        self._status_manager = status_manager

    def get_declaration(self, tenants, skip_ips=[]):
        """ Returns complete AS3 declaration

        :param tenants: dict of network_id: loadbalancers, multiple tenants supported
        :param skip_ips: list of ip-addresses to remove from declaration (and print error).
        :param status: status manager instance (optional) for certifcate error callback

        :return: complete AS3 declaration
        """

        # AS3 wrapper class
        declaration = m_as3.get_as3()

        # PUT ADC (Application Delivery Controller)
        adc = ADC(
            id="urn:uuid:{}".format(uuid.uuid4()),
            label="F5 BigIP Octavia Provider")
        declaration.set_adc(adc)

        for network_id, loadbalancers in tenants.items():
            # Fetch segmentation id
            segmentation_id = None
            if loadbalancers:
                host = loadbalancers[0].server_group_id or loadbalancers[0].amphorae[0].compute_flavor
                segmentation_id = self._network_driver.get_segmentation_id(network_id, host)

            # get Tenant
            name = m_tenant.get_name(network_id)
            tenant = m_tenant.get_tenant(segmentation_id, loadbalancers, skip_ips,
                                         self._status_manager, self._cert_manager, self._esd_repo)
            adc.set_tenant(name, tenant)

        return declaration
