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
import unicodedata


def f5remark(remark):
    # Remove control characters.
    nstr = "".join(ch for ch in remark
                   if unicodedata.category(ch)[0] != "C")

    # Remove double-quote (“), and backslash (\), limit to 64 characters.
    return re.sub('["\\\\]', '', nstr)[:64]


def f5label(label):
    # Remove control characters and limit to 64 characters.
    nstr = "".join(ch for ch in label
                   if unicodedata.category(ch)[0] != "C" and ch != "&")
    return nstr[:64]