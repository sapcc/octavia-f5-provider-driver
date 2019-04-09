# Copyright (c) 2019 SAP SE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from octavia.common import constants
from octavia.common.data_models import BaseDataModel


class ESD(BaseDataModel):
    def __init__(self, id=None, name=None, attributes=None):
        self.id = id
        self.name = name
        self.attributes = attributes or []


class ESDAttributes(object):
    def __init__(self, esd_id=None, name=None, type=None):
        self.esd_id = esd_id
        self.type = type
        self.name = name
