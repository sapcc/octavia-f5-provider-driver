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

from octavia_f5.common import constants
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class PartitionMapper(object):
    @staticmethod
    def get_partition_name(project_id):
        if project_id is not None:
            name = constants.PREFIX_PROJECT + \
                   project_id.replace('/', '')
        else:
            name = "Common"

        return name

    def get_partition_path(self, project_id):
        partition = self.get_partition_name(project_id)

        return dict(partition=partition)

    @staticmethod
    def get_resource_description(resource):
        name = getattr(resource, 'name', '')
        description = getattr(resource, 'description', '')

        if name and description:
            return ':'.join((name, description))
        elif name:
            return name
        else:
            return description

    def get_folder(self, loadbalancer):
        folder = None

        if hasattr(loadbalancer, 'project_id'):
            project_id = loadbalancer.project_id
            folder_name = self.get_partition_name(project_id)
            folder = {"name": folder_name,
                      "subPath": "/",
                      "fullPath": "/" + folder_name,
                      "hidden": False,
                      "inheritedDevicegroup": True}
            if hasattr(loadbalancer, 'traffic_group'):
                folder['trafficGroup'] = loadbalancer.traffic_group
                folder['inheritedTrafficGroup'] = False
            else:
                folder['inheritedTrafficGroup'] = True

        return folder

