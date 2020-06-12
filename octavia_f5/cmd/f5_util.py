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
#

import collections
import sys

from oslo_config import cfg
from oslo_log import log as logging

from octavia.db import repositories as repo
from octavia_f5.common import config
from octavia_f5.controller.worker import sync_manager, status_manager
from octavia_f5.db import api as db_apis
from octavia_f5.db import repositories as f5_repos

CONF = cfg.CONF


def main():
    if len(sys.argv) == 1:
        print('Error: Config file must be specified.')
        print('{} --config-file <filename>'.format(sys.argv[0]))
        return 1
    logging.register_options(cfg.CONF)
    cfg.CONF.register_cli_opts(config.f5_util_opts)
    argv = sys.argv or []
    config.init(argv[1:])
    logging.set_defaults()
    config.setup_logging(cfg.CONF)
    LOG = logging.getLogger('f5_util')
    CONF.log_opt_values(LOG, logging.DEBUG)

    if not CONF.all and not CONF.lb_id and not CONF.project_id and not CONF.agent_host:
        print('Error: One of --all, --lb_id, --project_id, --agent_host must be specified.')
        return 1

    _sync_manager = sync_manager.SyncManager()
    _status_manager = status_manager.StatusManager()
    _loadbalancer_repo = f5_repos.LoadBalancerRepository()
    _quota_repo = repo.QuotasRepository()
    _reset_dict = {
        'in_use_load_balancer': None,
        'in_use_listener': None,
        'in_use_pool': None,
        'in_use_health_monitor': None,
        'in_use_member': None,
    }

    session = db_apis.get_session()
    if CONF.lb_id:
        lbs = _loadbalancer_repo.get_all_from_host(session, id=CONF.lb_id)
        LOG.info('Starting manual sync for loadbalancer "{}" on host "{}".'.format(CONF.lb_id, CONF.host))
    elif CONF.project_id:
        lbs = _loadbalancer_repo.get_all_from_host(session, project_id=CONF.project_Id)
        LOG.info('Starting manual sync for loadbalancers "{}" on host "{}".'.format([
            lb.id for lb in lbs], CONF.host))
    elif CONF.agent_host:
        lbs = _loadbalancer_repo.get_all_from_host(session, host=CONF.agent_host)
    else:  # CONF.ALL
        lbs = _loadbalancer_repo.get_all_from_host(session)

    LOG.info('Starting manual sync for load balancers "{}" on host "{}".'.format(
        [lb.id for lb in lbs], CONF.agent_host or CONF.host))


    # deduplicate
    networks = collections.defaultdict(list)
    for lb in lbs:
        if lb not in networks[lb.vip.network_id]:
            networks[lb.vip.network_id].append(lb)

    # push configuration
    for network_id, loadbalancers in networks.items():
        try:
            if _sync_manager.tenant_update(network_id, loadbalancers).ok:
                _status_manager.update_status(loadbalancers)

            lock_session = db_apis.get_session(autocommit=False)
            for loadbalancer in loadbalancers:
                _quota_repo.update(lock_session, project_id=loadbalancer.project_id, quota=_reset_dict)
            lock_session.commit()
        except Exception as e:
            LOG.error("Exception while syncing loadbalancers %s: %s", [lb.id for lb in loadbalancers], e)

    return 0


if __name__ == "__main__":
    main()
