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

from octavia_f5.utils.exceptions import IControlRestException, F5osaException


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


class RaisesApiError(ContextDecorator):

    def __init__(self):
        self.exception_class = Exception

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, traceback):
        if exc_type == HTTPError:
            parsed = urlparse(exc_val.request.url)

            # if a username is present, display it, but hide the password,
            # otherwise just display the hostname
            if parsed.username:
                redacted = parsed._replace(netloc=f"{parsed.username}:???@{parsed.hostname}").geturl()
            else:
                redacted = parsed.hostname

            # get error message from response
            try:
                err_msg = exc_val.response.json()
                if 'message' in err_msg:
                    err_msg = err_msg['message']
            except Exception:
                err_msg = exc_val.response.content

            # raise exception
            raise self.exception_class(
                f"HTTP {exc_val.response.status_code} for {exc_val.request.method} {redacted}: {err_msg}"
            )

        return False


class RaisesIControlRestError(RaisesApiError):
    def __init__(self):
        super().__init__()
        self.exception_class = IControlRestException


class RaisesF5osaError(RaisesApiError):
    def __init__(self):
        super().__init__()
        self.exception_class = F5osaException
