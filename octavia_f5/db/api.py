# Copyright 2014 Rackspace, 2019 SAP SE,
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

from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging

LOG = logging.getLogger(__name__)
_FACADE = None


def _create_facade_lazily():
    global _FACADE
    if _FACADE is None:
        _FACADE = True
        enginefacade.configure(sqlite_fk=True, expire_on_commit=True)


def _get_transaction_context(reader=False):
    _create_facade_lazily()
    # TODO(gthiemonge) Create and use new functions to get read-only sessions
    if reader:
        context = enginefacade.reader
    else:
        context = enginefacade.writer
    return context


def _get_sessionmaker(reader=False):
    context = _get_transaction_context(reader)
    return context.get_sessionmaker()


def get_engine():
    context = _get_transaction_context()
    return context.get_engine()


def get_session(reader=False):
    """Helper method to grab session."""
    return _get_sessionmaker(reader)()


def session(reader=False):
    return _get_sessionmaker(reader)
