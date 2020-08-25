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

import json
import time

import futurist
import prometheus_client as prometheus
from oslo_config import cfg
from oslo_log import log as logging
from six.moves.urllib import parse

from octavia_f5.restclient.as3classes import AS3
from octavia_f5.restclient.bigip import bigip_auth, bigip_restclient
from octavia_f5.utils import exceptions

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
AS3_PATH = '/mgmt/shared/appsvcs'
AS3_DECLARE_PATH = AS3_PATH + '/declare'
AS3_INFO_PATH = AS3_PATH + '/info'
AS3_TASKS_PATH = AS3_PATH + '/task/{}'

ASYNC_TIMEOUT = 90  # 90 seconds
AS3_TASK_POLL_INTERVAL = 5

class AS3RestClient(bigip_restclient.BigIPRestClient):
    """ AS3 rest client, implements POST, PATCH and DELETE operation for talking to F5 localhost AS3.
        Also supports BigIP rest calls to icontrol REST.

        See: https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/refguide/as3-api.html
    """
    _metric_httpstatus = prometheus.metrics.Counter(
        'octavia_as3_httpstatus', 'Number of HTTP statuses in responses to AS3 requests', ['method', 'statuscode'])
    _metric_post_duration = prometheus.metrics.Summary(
        'octavia_as3_post_duration', 'Time it needs to send a POST request to AS3')
    _metric_post_exceptions = prometheus.metrics.Counter(
        'octavia_as3_post_exceptions', 'Number of exceptions at POST requests sent to AS3')
    _metric_patch_duration = prometheus.metrics.Summary(
        'octavia_as3_patch_duration', 'Time it needs to send a PATCH request to AS3')
    _metric_patch_exceptions = prometheus.metrics.Counter(
        'octavia_as3_patch_exceptions', 'Number of exceptions at PATCH request sent to AS3')
    _metric_delete_duration = prometheus.metrics.Summary(
        'octavia_as3_delete_duration', 'Time it needs to send a DELETE request to AS3')
    _metric_delete_exceptions = prometheus.metrics.Counter(
        'octavia_as3_delete_exceptions', 'Number of exceptions at DELETE request sent to AS3')

    def __init__(self, bigip_url, auth=None):
        self.task_watcher = futurist.ThreadPoolExecutor(max_workers=1)
        verify = CONF.f5_agent.bigip_verify
        super(AS3RestClient, self).__init__(bigip_url, verify, auth)
        if CONF.f5_agent.prometheus:
            self.hooks['response'].append(self.metric_response_hook)
        self.hooks['response'].append(self.error_response_hook)

    def metric_response_hook(self, r, **kwargs):
        """ Metric hook for prometheus as3 http status"""
        self._metric_httpstatus.labels(method=r.request.method.lower(), statuscode=r.status_code).inc()

    def error_response_hook(self, r, **kwargs):
        """ Installs response hook that parses errors and throws """
        if 'application/json' in r.headers.get('Content-Type'):
            try:
                parsed = r.json()
                if 'results' in parsed:
                    parsed = parsed['results']

                if 'code' in parsed and parsed['code'] == 404:
                    if 'Public URI path not registered.' in parsed['message']:
                        # AS3 crashed, failover to backup device, leveraging auto-sync
                        raise exceptions.FailoverException()
            except ValueError:
                pass

    def debug_enable(self):
        """ Installs requests hook to enable debug logs of AS3 requests and responses. """

        def log_response(r, *args, **kwargs):
            # redact credentials from url
            url = parse.urlparse(r.url)
            redacted_url = url._replace(netloc=url.hostname)

            LOG.debug("%s %s finished with code %s", r.request.method, redacted_url.geturl(), r.status_code)
            if r.request.body:
                LOG.debug("Request Body")
                try:
                    parsed = json.loads(r.request.body)
                    LOG.debug("%s", json.dumps(parsed, sort_keys=True, indent=4))
                except ValueError:
                    LOG.debug("%s", r.request.body)

            LOG.debug("Response")
            if 'application/json' in r.headers.get('Content-Type'):
                try:
                    parsed = r.json()
                    if 'results' in parsed:
                        parsed = parsed['results']
                    LOG.debug("%s", json.dumps(parsed, sort_keys=True, indent=4))
                except ValueError:
                    LOG.error("Valid JSON expected: %s", r.text)
            else:
                LOG.debug("%s", r.text)

        LOG.debug("Installing AS3 debug hook for '%s'", self.hostname)
        self.hooks['response'].insert(0, log_response)

    def wait_for_task_finished(self, task_id):
        """ Waits for AS3 task to be finished successfully
        :param task_id: task id to be fetched
        :return: request result
        """
        LOG.info("ASync task '%s' being monitored...", task_id)
        while True:
            task = super(AS3RestClient, self).get(path=AS3_TASKS_PATH.format(task_id))
            if task.ok:
                results = task.json()['results']

                # Check for pending tasks
                if any(res['code'] == 0 for res in results):
                    time.sleep(AS3_TASK_POLL_INTERVAL)
                    continue

                # Check if all tasks successfully applied
                return all(200 <= res['code'] < 300 for res in results)

            time.sleep(AS3_TASK_POLL_INTERVAL)

    @_metric_post_exceptions.count_exceptions()
    @_metric_post_duration.time()
    def post(self, tenants, payload):
        url = '{}/{}'.format(self.get_url(AS3_DECLARE_PATH), ','.join(tenants))
        params = {}
        if CONF.f5_agent.async_mode:
            params['async'] = 'true'
        r = super(AS3RestClient, self).post(url, json=payload.to_dict(), params=params)

        if not r.ok:
            return False

        if r.status_code == 202:
            # ASYNC Task
            task_id = r.json()['id']
            fut = self.task_watcher.submit(self.wait_for_task_finished, task_id)
            return fut.result(timeout=ASYNC_TIMEOUT)

        return r.ok

    @_metric_patch_exceptions.count_exceptions()
    @_metric_patch_duration.time()
    def patch(self, tenants, patch_body):
        url = self.get_url(AS3_DECLARE_PATH)
        return super(AS3RestClient, self).patch(url, json=patch_body)

    @_metric_delete_exceptions.count_exceptions()
    @_metric_delete_duration.time()
    def delete(self, tenants):
        if not tenants:
            raise exceptions.DeleteAllTenenatsException()

        url = '{}/{}'.format(self.get_url(AS3_DECLARE_PATH), ','.join(tenants))
        return super(AS3RestClient, self).delete(url)

    def info(self):
        info = self.get(self.get_url(AS3_INFO_PATH), timeout=3)
        info.raise_for_status()
        return dict(device=self.hostname, **info.json())

    def get_tenants(self):
        tenants = self.get(self.get_url(AS3_DECLARE_PATH), params={'filterClass': 'Application'})
        tenants.raise_for_status()
        return tenants.json()


class AS3ExternalContainerRestClient(AS3RestClient):
    """ AS3 rest client that supports external containerized AS3 docker appliances. PATCH/DELETE requests
        are proxied via POST. iControlRest calls are directly called against the backend devices.

        See: https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/userguide/as3-container.html
    """
    def __init__(self, bigip_url, as3_url, auth=None):
        self.as3_url = parse.urlsplit(as3_url, allow_fragments=False)
        super(AS3ExternalContainerRestClient, self).__init__(bigip_url, auth)

    def get_url(self, url):
        """ Override host for AS3 declarations. """
        if url.startswith(AS3_PATH):
            # derive external as3 container url
            url_tuple = parse.SplitResult(
                scheme=self.as3_url.scheme, netloc=self.as3_url.netloc,
                path=url, query='', fragment='')
            return parse.urlunsplit(url_tuple)
        else:
            # derive regular bigip url
            return super(AS3ExternalContainerRestClient, self).get_url(url)

    def post(self, tenants, payload):
        if isinstance(payload, AS3):
            payload.set_bigip_target_host(self.hostname)
            if isinstance(self.auth, bigip_auth.BigIPTokenAuth):
                payload.set_target_tokens({bigip_auth.BIGIP_TOKEN_HEADER: self.auth.token})
            elif isinstance(self.auth, bigip_auth.BigIPBasicAuth):
                payload.set_target_username(self.auth.username)
                payload.set_target_passphrase(self.auth.password)
        return super(AS3ExternalContainerRestClient, self).post(tenants, payload)

    def patch(self, tenants, patch_body):
        # Patch is realized through post with action=patch
        payload = AS3(action='patch', patchBody=patch_body)
        return self.post(tenants or [], payload)

    def delete(self, tenants):
        # Delete is realized through post with action=delete
        if not tenants:
            raise exceptions.DeleteAllTenenatsException()

        payload = AS3(action='remove')
        return self.post(tenants, payload)
