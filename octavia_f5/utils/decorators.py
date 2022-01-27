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

import functools
from contextlib import ContextDecorator
from urllib.parse import urlparse

from requests import HTTPError

from octavia_f5.utils.exceptions import IControlRestException


class RunHookOnException(object):
    def __init__(self, hook, exceptions=Exception):
        self.hook = hook
        self.exceptions = exceptions

    def __call__(self, func):
        functools.update_wrapper(self, func)

        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except self.exceptions:
                self.hook(*args, **kwargs)
                return func(*args, **kwargs)
        return wrapper


class RaisesIControlRestError(ContextDecorator):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, traceback):
        if exc_type == HTTPError:
            parsed = urlparse(exc_val.request.url)
            redacted = parsed._replace(netloc="{}:{}@{}".format(parsed.username, "???", parsed.hostname))
            try:
                message = exc_val.response.json()
                if 'message' in message:
                    message = message['message']
            except Exception:
                message = exc_val.response.content
            raise IControlRestException(
                f"HTTP {exc_val.response.status_code} for {exc_val.request.method} {redacted.geturl()}: {message}"
            )
        return False
