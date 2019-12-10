# Copyright 2018 SAP SE
# Copyright 2014-2017 F5 Networks Inc.
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

"""
Defines interface for ESD access that Resource or Octavia Controllers may
reference
"""

import glob
import json
import os
import six

from oslo_config import cfg
from octavia.common import exceptions
from oslo_log import log as logging

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


class EsdJSONValidation(object):
    """Class reads the json file(s)
    It checks and parses the content of json file(s) to a dictionary
    """

    def __init__(self, esddir):
        assert esddir != None
        self.esdJSONFileList = glob.glob(os.path.join(esddir, '*.json'))
        assert len(self.esdJSONFileList) > 0 # check that files have been found
        self.esdJSONDict = {}

    def read_json(self):
        for fileList in self.esdJSONFileList:
            try:
                with open(fileList) as json_file:
                    # Reading each file to a dictionary
                    file_json_dict = json.load(json_file)
                    # Combine all dictionaries to one
                    self.esdJSONDict.update(file_json_dict)

            except ValueError as err:
                LOG.error('ESD JSON File is invalid: %s', err)
                raise exceptions.InputFileError(
                    file_name=fileList,
                    reason=err
                )

        return self.esdJSONDict


class EsdRepository(EsdJSONValidation):
    """Class processes json dictionary
    It checks compares the tags from esdjson dictionary to list of valid tags
    """

    def __init__(self):
        self.esd_dict = {}
        self.validtags = []
        super(EsdRepository, self).__init__(CONF.f5_agent.esd_dir)
        self.process_esd()

    # this function will return intersection of known valid esd tags
    # and the ones that user provided
    def valid_tag_key_subset(self):
        self.validtags = list(set(self.esdJSONDict.keys()) &
                              set(self.valid_esd_tags.keys()))
        if not self.validtags:
            LOG.error("Intersect of valid esd tags and user esd tags is empty")

        if set(self.validtags) != set(self.esdJSONDict.keys()):
            LOG.error("invalid tags in the user esd tags")

    def process_esd(self):
        try:
            esd = self.read_json()
            self.esd_dict = self.verify_esd_dict(esd)
        except exceptions.InputFileError:
            self.esd_dict = {}
            raise

    def get_esd(self, name):
        return self.esd_dict.get(name, None)

    def is_valid_tag(self, tag):
        return self.valid_esd_tags.get(tag, None) is not None

    def verify_esd_dict(self, esd_dict):
        valid_esd_dict = {}
        for esd in esd_dict:
            # check that ESD is valid
            valid_esd = self.verify_esd(esd, esd_dict[esd])
            if not valid_esd:
                break

            # add non-empty valid ESD to return dict
            valid_esd_dict[esd] = valid_esd

        return valid_esd_dict

    def verify_esd(self, name, esd):
        valid_esd = {}
        for tag in esd:
            try:
                self.verify_tag(tag)
                self.verify_value(tag, esd[tag])

                # add tag to valid ESD
                valid_esd[tag] = esd[tag]
                LOG.debug("Tag {0} is valid for ESD {1}.".format(tag, name))
            except exceptions.InputFileError as err:
                LOG.info('Tag {0} failed validation for ESD {1} and was not '
                         'added to ESD. Error: {2}'.
                         format(tag, name, err.message))

        return valid_esd

    def verify_value(self, tag, value):
        tag_def = self.valid_esd_tags.get(tag)

        # verify value type
        value_type = tag_def['value_type']
        if not isinstance(value, value_type):
            msg = 'Invalid value {0} for tag {1}. ' \
                  'Type must be {2}.'.format(value, tag, value_type)
            raise exceptions.InputFileError(filename='', reason=msg)

    def verify_tag(self, tag):
        if not self.is_valid_tag(tag):
            msg = 'Tag {0} is not valid.'.format(tag)
            raise exceptions.InputFileError(filename='', reason=msg)

    # this dictionary contains all the tags
    # that are listed in the esd confluence page:
    # https://docs.f5net.com/display/F5OPENSTACKPROJ/Enhanced+Service+Definition
    # we are implementing the tags that can be applied only to listeners

    valid_esd_tags = {
        'lbaas_fastl4': {
            'value_type': six.string_types},
        'lbaas_ctcp': {
            'value_type': six.string_types},
        'lbaas_stcp': {
            'value_type': six.string_types},
        'lbaas_http': {
            'value_type': six.string_types},
        'lbaas_one_connect': {
            'value_type': six.string_types},
        'lbaas_http_compression': {
            'value_type': six.string_types},
        'lbaas_cssl_profile': {
            'value_type': six.string_types},
        'lbaas_sssl_profile': {
            'value_type': six.string_types},
        'lbaas_irule': {
            'value_type': list},
        'lbaas_policy': {
            'value_type': list},
        'lbaas_persist': {
            'value_type': six.string_types},
        'lbaas_fallback_persist': {
            'value_type': six.string_types}
    }
