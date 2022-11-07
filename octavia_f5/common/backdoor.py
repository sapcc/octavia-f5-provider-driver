# Copyright 2022 SAP SE
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from collections import Counter
import gc
import os
import sys
import time
import traceback

import manhole

from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def _find_objects_by_name(name):
    """Find all objects of the given class name"""
    objs = [o for o in gc.get_objects()
            if hasattr(o, "__class__") and o.__class__.__name__.startswith(name)
            ]
    objs.sort(key=lambda o: o.__class__.__name__)
    return objs


def _find_objects(cls):
    """Find all objects of the given class"""
    return [o for o in gc.get_objects()
            if hasattr(o, "__class__") and isinstance(o, cls)]


def _get_nativethreads():
    """Return tracebacks of all native threads as string"""
    lines = []
    for thread_id, stack in sys._current_frames().items():
        lines.append(str(thread_id))
        lines.extend(l.rstrip() for l in traceback.format_stack(stack))
        lines.append('')
    return '\n'.join(lines)


def _print_nativethreads():
    """Print tracebacks of all native threads"""
    print(_get_nativethreads())


def _print_semaphores():
    """Print all Semaphore objects used by oslo_concurrency.lockutils and
    their waiter count
    """
    # local import as we don't want to keep that local variable in global scope
    from oslo_concurrency.lockutils import _semaphores  # pylint: disable=C0415

    print('\n'.join(sorted([f"{name} - {len(s._cond._waiters)}"
                            for name, s in _semaphores._semaphores.items()])))


def _get_heap():
    # local imports as these are most likely never used anywhere
    from guppy import hpy  # pylint: disable=C0415
    hp = hpy()
    heap = hp.heap()
    print("Heap Size : ", heap.size, " bytes")
    return heap


def _time_it(fn, *args, **kwargs):
    """Call fn, measuring the time it takes with time.time()"""
    start = time.time()
    fn(*args, **kwargs)
    print(time.time() - start)


def _profile_it(fn, *args, return_stats=False, **kwargs):
    """Call fn with profiling enabled

    Optionally returns the pstats.Stats created while profiling.
    """
    # local imports as these are most likely never used anywhere
    import cProfile  # pylint: disable=C0415
    import pstats  # pylint: disable=C0415

    pr = cProfile.Profile()
    pr.runcall(fn, *args, **kwargs)
    pr.create_stats()
    ps = pstats.Stats(pr)

    if return_stats:
        return ps

    ps.sort_stats('tottime').print_stats(30)
    return None


def _count_object_types():
    """Return a collections.Counter containing class to count mapping
    of objects in gc
    """
    return Counter(o.__class__ for o in gc.get_objects()
                   if hasattr(o, '__class__'))


backdoor_opts = [
    cfg.StrOpt('backdoor_socket',
               help="Enable manhole backdoor, using the provided path"
                    " as a unix socket that can receive connections. "
                    "Inside the path {pid} will be replaced with"
                    " the PID of the current process.")
]


def install_backdoor():
    """Start a backdoor shell for debugging connectable via UNIX socket"""
    cfg.CONF.register_opts(backdoor_opts)

    if not cfg.CONF.backdoor_socket:
        return

    try:
        socket_path = cfg.CONF.backdoor_socket.format(pid=os.getpid())
    except (KeyError, IndexError, ValueError) as e:
        socket_path = cfg.CONF.backdoor_socket
        LOG.warning("Could not apply format string to backdoor socket"
                    f"path ({e}) - continuing with unformatted path")

    manhole.install(patch_fork=False, socket_path=socket_path,
                    daemon_connection=True,
                    locals={
                        'fo': _find_objects,
                        'fon': _find_objects_by_name,
                        'pnt': _print_nativethreads,
                        'gnt': _get_nativethreads,
                        'print_semaphores': _print_semaphores,
                        'time_it': _time_it,
                        'profile_it': _profile_it,
                        'count_object_types': _count_object_types,
                        'get_heap': _get_heap,
                    },
                    redirect_stderr=False)
