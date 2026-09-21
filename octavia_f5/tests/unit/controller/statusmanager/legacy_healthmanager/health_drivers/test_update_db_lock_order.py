#  Copyright 2024 SAP SE
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

"""
Regression tests for the heartbeat lock-ordering fix.

Background (commit 046d7a5)
---------------------------
The health-manager heartbeat and the API member PUT both hold a transaction
open while touching the pool row and the member row.  If the two actors
acquire those row locks in opposite order a circular wait (InnoDB deadlock)
results:

  Old heartbeat order    API member PUT order
  ───────────────────    ────────────────────
  BEGIN                  BEGIN
  UPDATE member   ←lock  SELECT lb FOR UPDATE
                         UPDATE pool  ←lock
  UPDATE pool  ←waits    UPDATE member  ←waits  → deadlock

The fix reverses the heartbeat order to pool→member, matching the API path.

These tests reproduce both orderings against a real MariaDB/InnoDB instance
using the actual Octavia repository classes and the actual health-manager
method (UpdateHealthDb._process_pool_status).

Running
-------
Start a MariaDB container and point the tests at it::

    docker run -d --name mariadb-deadlock-test \\
        -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=octavia \\
        -p 3307:3306 mariadb:10.11
    # wait ~15 s for MariaDB to be ready
    TEST_MARIADB_PORT=3307 TEST_MARIADB_PASS=root pytest -v \\
        octavia_f5/tests/unit/controller/statusmanager/legacy_healthmanager/\\
        health_drivers/test_update_db_lock_order.py

Environment variables (all optional, shown with defaults):
    TEST_MARIADB_HOST=127.0.0.1
    TEST_MARIADB_PORT=3306
    TEST_MARIADB_USER=root
    TEST_MARIADB_PASS=root
    TEST_MARIADB_DB=octavia
"""

import os
import threading

import pymysql
import pytest
from oslo_config import cfg
from oslo_config import fixture as oslo_fixture
from oslo_db import exception as oslo_db_exc
from oslo_utils import uuidutils
from sqlalchemy.exc import OperationalError as SaOperationalError

from octavia.common import constants
from octavia.db import api as db_api
from octavia.db import models
from octavia.db import repositories
from octavia.tests.unit import base

from octavia_f5.controller.statusmanager.legacy_healthmanager.health_drivers \
    import update_db


# ---------------------------------------------------------------------------
# Connection parameters
# ---------------------------------------------------------------------------
_HOST = os.environ.get('TEST_MARIADB_HOST', '127.0.0.1')
_PORT = int(os.environ.get('TEST_MARIADB_PORT', '3306'))
_USER = os.environ.get('TEST_MARIADB_USER', 'root')
_PASS = os.environ.get('TEST_MARIADB_PASS', 'root')
_DB = os.environ.get('TEST_MARIADB_DB', 'octavia')

_DB_URL = f'mysql+pymysql://{_USER}:{_PASS}@{_HOST}:{_PORT}/{_DB}'

ER_LOCK_DEADLOCK = 1213


def _mariadb_available():
    try:
        c = pymysql.connect(host=_HOST, port=_PORT, user=_USER,
                            password=_PASS, connect_timeout=2)
        c.close()
        return True
    except Exception:
        return False


requires_mariadb = pytest.mark.skipif(
    not _mariadb_available(),
    reason=(
        "MariaDB not reachable — set TEST_MARIADB_HOST/PORT/USER/PASS "
        "and run octavia-db-manage upgrade head against it first"
    )
)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestHeartbeatLockOrder(base.TestCase):
    """Deadlock regression tests using real MariaDB/InnoDB row locking."""

    # ------------------------------------------------------------------
    # Class-level setup: schema migration (once per test run)
    # ------------------------------------------------------------------

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if not _mariadb_available():
            return
        # Ensure the Octavia schema is up to date.
        from octavia.common import config as octavia_config
        octavia_config.register_cli_opts()
        cfg.CONF.set_override('connection', _DB_URL, group='database')
        import subprocess
        import shutil
        import tempfile
        import textwrap
        # Run schema migration via octavia-db-manage
        db_manage = shutil.which('octavia-db-manage')
        if db_manage:
            conf = tempfile.NamedTemporaryFile(
                mode='w', suffix='.conf', delete=False)
            conf.write(textwrap.dedent(f"""\
                [database]
                connection = {_DB_URL}
            """))
            conf.close()
            subprocess.run(
                [db_manage, '--config-file', conf.name, 'upgrade', 'head'],
                capture_output=True)

    # ------------------------------------------------------------------
    # Per-test setup: configure oslo cfg, seed fresh rows
    # ------------------------------------------------------------------

    def setUp(self):
        super().setUp()
        if not _mariadb_available():
            self.skipTest(
                "MariaDB not reachable — set TEST_MARIADB_HOST/PORT/USER/PASS")

        conf = self.useFixture(oslo_fixture.Config(cfg.CONF))
        conf.config(group='database', connection=_DB_URL)

        # Fresh IDs for every test to avoid cross-test interference.
        self.lb_id = uuidutils.generate_uuid()
        self.pool_id = uuidutils.generate_uuid()
        self.member_id = uuidutils.generate_uuid()

        self._seed_rows()

        self.repos = repositories.Repositories()
        self.updater = update_db.UpdateHealthDb()

    def _seed_rows(self):
        session = db_api.get_session()
        with session.begin():
            session.add(models.LoadBalancer(
                id=self.lb_id,
                project_id='test-project',
                provisioning_status=constants.ACTIVE,
                operating_status=constants.ONLINE,
                enabled=True,
            ))
            session.add(models.Vip(
                load_balancer_id=self.lb_id,
                vnic_type='normal',
            ))
            session.add(models.Pool(
                id=self.pool_id,
                load_balancer_id=self.lb_id,
                project_id='test-project',
                protocol=constants.PROTOCOL_HTTP,
                lb_algorithm=constants.LB_ALGORITHM_ROUND_ROBIN,
                provisioning_status=constants.ACTIVE,
                operating_status=constants.OFFLINE,
                enabled=True,
            ))
            session.add(models.Member(
                id=self.member_id,
                pool_id=self.pool_id,
                project_id='test-project',
                ip_address='10.0.0.1',
                protocol_port=80,
                backup=False,
                provisioning_status=constants.ACTIVE,
                operating_status=constants.OFFLINE,
                enabled=True,
                vnic_type='normal',
            ))

    # ------------------------------------------------------------------
    # The two threads
    # ------------------------------------------------------------------

    def _run_api_member_put(self, session, errors, after_member_lock=None):
        """Simulates the API member PUT DB path (pool lock → member lock).

        Mirrors the real path in MemberController.put():
          with session.begin():
              test_and_set_lb_and_listeners_prov_status(...)  # locks LB + pool
              member_repo.update(...)                          # locks member
        """
        try:
            with session.begin():
                ok = self.repos.test_and_set_lb_and_listeners_prov_status(
                    session,
                    lb_id=self.lb_id,
                    lb_prov_status=constants.PENDING_UPDATE,
                    listener_prov_status=constants.PENDING_UPDATE,
                    pool_id=self.pool_id,
                )
                if not ok:
                    errors.append('lb-not-mutable')
                    return
                # Pool row is now locked.  Signal HM it can start, then wait
                # until HM has acquired whatever lock it takes first.
                if after_member_lock:
                    after_member_lock()
                self.repos.member.update(
                    session, self.member_id,
                    provisioning_status=constants.PENDING_UPDATE,
                    force_provisioning_status=True,
                )
        except (SaOperationalError, oslo_db_exc.DBDeadlock) as exc:
            cause = getattr(exc, 'orig', exc)
            code = cause.args[0] if hasattr(cause, 'args') else None
            if isinstance(exc, oslo_db_exc.DBDeadlock) or code == ER_LOCK_DEADLOCK:
                errors.append('deadlock')
            else:
                errors.append(f'unexpected: {exc}')

    def _run_hm_old_order(self, session, errors, after_member_lock=None):
        """Simulates the OLD heartbeat order: member row first, then pool row.

        This is the order that existed before the fix and that causes
        deadlock when interleaved with the API member PUT.
        """
        try:
            with session.begin():
                # OLD ORDER: member first ─────────────────────────────────
                self.updater.member_repo.update(
                    session, self.member_id,
                    operating_status=constants.ONLINE,
                )
                # Member row is now locked. Signal API it can proceed.
                if after_member_lock:
                    after_member_lock()
                # OLD ORDER: pool second ──────────────────────────────────
                self.updater.pool_repo.update(
                    session, self.pool_id,
                    operating_status=constants.ONLINE,
                )
        except (SaOperationalError, oslo_db_exc.DBDeadlock) as exc:
            cause = getattr(exc, 'orig', exc)
            code = cause.args[0] if hasattr(cause, 'args') else None
            if isinstance(exc, oslo_db_exc.DBDeadlock) or code == ER_LOCK_DEADLOCK:
                errors.append('deadlock')
            else:
                errors.append(f'unexpected: {exc}')

    def _run_hm_fixed_order(self, session, errors, after_pool_lock=None):
        """Simulates the FIXED heartbeat order: pool row first, then member.

        This matches the API member PUT order and therefore cannot deadlock.
        """
        try:
            with session.begin():
                # FIXED ORDER: pool first ─────────────────────────────────
                self.updater.pool_repo.update(
                    session, self.pool_id,
                    operating_status=constants.ONLINE,
                )
                # Pool row is now locked. Signal API it can proceed.
                if after_pool_lock:
                    after_pool_lock()
                # FIXED ORDER: member second ──────────────────────────────
                self.updater.member_repo.update(
                    session, self.member_id,
                    operating_status=constants.ONLINE,
                )
        except (SaOperationalError, oslo_db_exc.DBDeadlock) as exc:
            cause = getattr(exc, 'orig', exc)
            code = cause.args[0] if hasattr(cause, 'args') else None
            if isinstance(exc, oslo_db_exc.DBDeadlock) or code == ER_LOCK_DEADLOCK:
                errors.append('deadlock')
            else:
                errors.append(f'unexpected: {exc}')

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    @requires_mariadb
    def test_old_heartbeat_order_causes_deadlock(self):
        """OLD heartbeat order (member→pool) deadlocks with API PUT (pool→member).

        Interleave:
          HM:  BEGIN → UPDATE member (lock m) → [pause]
          API: BEGIN → UPDATE lb FOR UPDATE → UPDATE pool (lock p) → [pause]
          HM:  UPDATE pool → waits for API (needs lock p)
          API: UPDATE member → waits for HM (needs lock m)  → InnoDB 1213
        """
        # hm_locked_member fires after HM has locked the member row.
        # api_locked_pool fires after API has locked the pool row.
        hm_locked_member = threading.Event()
        api_locked_pool = threading.Event()

        hm_errors = []
        api_errors = []

        def hm_thread():
            session = db_api.get_session()
            self._run_hm_old_order(
                session, hm_errors,
                after_member_lock=lambda: (
                    hm_locked_member.set(),
                    api_locked_pool.wait(timeout=10),
                )[-1],
            )

        def api_thread():
            hm_locked_member.wait(timeout=10)
            session = db_api.get_session()
            self._run_api_member_put(
                session, api_errors,
                after_member_lock=lambda: api_locked_pool.set(),
            )

        t_hm = threading.Thread(target=hm_thread, daemon=True)
        t_api = threading.Thread(target=api_thread, daemon=True)
        t_hm.start()
        t_api.start()
        t_hm.join(timeout=15)
        t_api.join(timeout=15)

        all_errors = hm_errors + api_errors
        self.assertIn(
            'deadlock', all_errors,
            f"Expected InnoDB deadlock (1213) with old member→pool order, "
            f"but no deadlock occurred. hm={hm_errors} api={api_errors}"
        )

    @requires_mariadb
    def test_fixed_heartbeat_order_no_deadlock(self):
        """FIXED heartbeat order (pool→member) does NOT deadlock with API PUT.

        Both actors acquire the pool lock first.  Whichever gets it second
        simply waits then proceeds; no circular dependency forms.
        """
        # Both threads race for the pool lock.  We use a barrier so they
        # start their transactions at roughly the same time.
        start_barrier = threading.Barrier(2, timeout=10)

        hm_errors = []
        api_errors = []

        def hm_thread():
            start_barrier.wait()
            session = db_api.get_session()
            self._run_hm_fixed_order(session, hm_errors)

        def api_thread():
            start_barrier.wait()
            session = db_api.get_session()
            self._run_api_member_put(session, api_errors)

        t_hm = threading.Thread(target=hm_thread, daemon=True)
        t_api = threading.Thread(target=api_thread, daemon=True)
        t_hm.start()
        t_api.start()
        t_hm.join(timeout=15)
        t_api.join(timeout=15)

        all_errors = hm_errors + api_errors
        self.assertNotIn(
            'deadlock', all_errors,
            f"Unexpected deadlock with fixed pool→member order. "
            f"hm={hm_errors} api={api_errors}"
        )
        self.assertEqual(
            [], all_errors,
            f"Unexpected errors with fixed order: hm={hm_errors} api={api_errors}"
        )
