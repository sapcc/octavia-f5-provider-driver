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

from urllib import parse
import json

from octavia_f5.common import constants


def truncate_as3_secrets(as3_json_decl):
    """ Remove or truncate sensitive material from an AS3 declaration.
    Changes are made in-place.

    :param as3_json_decl: A parsed JSON object constructed with json.load or json.loads
    """

    for net in as3_json_decl:
        net_obj = as3_json_decl.get(net)
        for lb in net_obj:
            lb_obj = net_obj.get(lb)
            for lb_key in lb_obj:
                # remove private keys from certificate declarations
                if not lb_key.startswith(constants.PREFIX_CERTIFICATE):
                    continue
                cert_obj = lb_obj.get(lb_key)
                for cert_key in cert_obj:
                    if cert_key == 'privateKey':
                        cert_priv = cert_obj.get(cert_key)
                        # keep the first line so that the type of key is still
                        # recognizable
                        cert_obj[cert_key] = cert_priv.split("\n")[0] + "\n(...)"


def get_response_log(response):
    """ Formats AS3 requests response and prints them pretty

    :param response: requests response
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
            truncate_as3_secrets(parsed)
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
