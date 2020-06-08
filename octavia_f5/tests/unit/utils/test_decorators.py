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

from octavia.tests.unit import base
from octavia_f5.utils.decorators import RunHookOnException


class ToMockedClass(object):
    def __init__(self):
        self.hooked_func_calls = 0
        self.hook_called = False

    def _hook_func(self):
        self.hook_called = True

    @RunHookOnException(hook=_hook_func)
    def hooked_func_raising_exception(self):
        self.hooked_func_calls += 1

        if self.hooked_func_calls <= 1:
            # Raise exception on first call
            raise Exception()


class TestRunHookOnException(base.TestCase):
    def test_run_hook(self):
        hooked_class = ToMockedClass()
        self.assertEqual(hooked_class.hooked_func_calls, 0)
        self.assertFalse(hooked_class.hook_called)

        hooked_class.hooked_func_raising_exception()
        self.assertEqual(hooked_class.hooked_func_calls, 2)
        self.assertTrue(hooked_class.hook_called)
