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

class TypeNotSupportedException(Exception):
    """Exception raised for not supported types.

    """
    pass


class RequiredKeyMissingException(Exception):
    """Exception raised for missing keys.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, key):
        self.message = 'Missing required key \'{}\'.'.format(key)


class IncompatibleSubTypeException(Exception):
    """Exception raised for wrong subtype.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, got, expected):
        self.message = 'Incompatible subtype \'{}\', expected \'{}\'.'.format(
            got, expected)


class DuplicatedKeyException(Exception):
    """Exception raised for duplicated keys.

    """
    pass


class UnprocessableEntityException(Exception):
    """Exception raised for generic F5 AS3 failure.
    
    """
    pass
