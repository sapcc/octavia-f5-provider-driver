# coding=utf-8
# Copyright 2019, 2020 SAP SE
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

import re
import string


def f5remark(remark):
    if not remark:
        return ""

    # Remove control characters.
    nstr = "".join(ch for ch in remark if ch in string.printable)

    # Remove double-quote ("), and backslash (\), limit to 64 characters.
    return re.sub('["\\\\]', '', nstr)[:64]


def f5label(label):
    if not label:
        return ""

    # Remove control characters and limit to 64 characters.
    nstr = "".join(ch for ch in label if ch in string.printable and ch != "&")
    return nstr[:64]
