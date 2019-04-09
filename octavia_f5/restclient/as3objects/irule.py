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
from octavia_f5.restclient.as3classes import IRule


def get_irule(name):
    return IRule(
        BigIP('/Common/' + name))


def get_irule_names(l7policies, esd_repo):
    irules = []
    for l7policy in l7policies:
        esd = esd_repo.get_esd(l7policy.name)
        if esd:
            irules.extend(esd.get('lbaas_irule', []))

    return irules
