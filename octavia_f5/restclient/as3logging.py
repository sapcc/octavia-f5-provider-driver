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

import json

from six.moves.urllib import parse


def get_response_log(response):
    """ Formats AS3 requests response and prints them pretty

    :param response: requests response
    :param error: boolean, true if log to error, else debug
    """

    request = response.request
    url = parse.urlparse(response.url)
    redacted_url = url._replace(netloc=url.hostname).geturl()
    msg = "{} {} finished with code {}:\n".format(
        request.method,
        redacted_url,
        response.status_code)

    # Format Request
    if request.body:
        try:
            parsed = json.loads(request.body)
            msg += json.dumps(parsed, sort_keys=True, indent=4)
        except ValueError:
            # No json, just dump
            msg += request.body

    # Format Response
    if 'application/json' in response.headers.get('Content-Type'):
        try:
            parsed = response.json()
            if 'results' in parsed:
                parsed = parsed['results']
            msg += json.dumps(parsed, sort_keys=True, indent=4)
        except ValueError:
            # No valid json
            msg += response.text
    else:
        msg += response.txt

    return msg.strip()