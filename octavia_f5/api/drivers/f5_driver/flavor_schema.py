# Copyright 2018 Rackspace US Inc.  All rights reserved.
# Copyright 2020 SAP SE
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from octavia_f5.common import constants as consts

# This is a JSON schema validation dictionary
# https://json-schema.org/latest/json-schema-validation.html
#
# Note: This is used to generate the F5 driver "supported flavor
#       metadata" dictionary. Each property should include a description
#       for the user to understand what this flavor setting does.
#
# Where possible, the property name should match the configuration file name
# for the setting. The configuration file setting is the default when a
# setting is not defined in a flavor profile.

SUPPORTED_FLAVOR_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Octavia F5 Driver Flavor Metadata Schema",
    "description": "This schema is used to validate new flavor profiles "
                   "submitted for use in an F5 driver flavor profile.",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        consts.FLAVOR_COOKIE_ENCRYPTION: {
            "type": "boolean",
            "description": "Whether to use cookie encryption.",
        },
        consts.FLAVOR_HTTP_COMPRESSION: {
            "type": "boolean",
            "description": "Whether to use HTTP compression.",
        },
        consts.FLAVOR_ONE_CONNECT: {
            "type": "boolean",
            "description": "Whether to use F5 'One-Connect'. "
                           "TCP-Connections between LB and pool members are kept alive and "
                           "will be reused for further requests."
        },
        consts.FLAVOR_PROXY_PROTOCOL: {
            "type": "number",
            "description": "Proxy protocol version to use for a PROXY type pool.",
            "enum": list(consts.SUPPORTED_PROXY_PROTOCOL_VERSIONS)
        },
        consts.FLAVOR_SSO: {
            "type": "boolean",
            "description": "Whether to use single-sign-on.",
        },
        consts.FLAVOR_SSO_REQUIRED: {
            "type": "boolean",
            "description": "Whether to require single-sign-on. "
                           "Other client certs are accepted as well when single-sign-on is "
                           "active and " + consts.FLAVOR_SSO_REQUIRED + " is False."
        },
        consts.FLAVOR_STANDARD_TCP: {
            "type": "boolean",
            "description": "Whether to use F5 standard TCP variant instead of CCloud TCP variant.",
        },
    }
}