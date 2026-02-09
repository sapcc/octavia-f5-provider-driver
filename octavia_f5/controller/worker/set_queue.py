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

from queue import Queue, Full
import time


class SetQueue(Queue):
    """
    A thread-safe queue that stores unique items using sets and supports
    priority items.

    Inherits from `Queue` but overrides the internal storage to use sets,
    ensuring all items are unique.  Items added via `put_priority` are returned
    first when retrieving from the queue.
    """

    def _init(self, maxsize):
        self.maxsize = maxsize
        self.queue = []
        self.priority_queue = []

    def put_priority(self, item, block=True, timeout=None):
        """Add an item to the priority queue, respecting maxsize and blocking like
        Queue.put.
        """
        with self.not_full:
            # honor maxsize semantics from queue.Queue.put
            if self.maxsize > 0:
                if not block:
                    if self._qsize() >= self.maxsize:
                        raise Full
                elif timeout is None:
                    while self._qsize() >= self.maxsize:
                        self.not_full.wait()
                else:
                    endtime = time.time() + timeout
                    while self._qsize() >= self.maxsize:
                        remaining = endtime - time.time()
                        if remaining <= 0.0:
                            raise Full
                        self.not_full.wait(remaining)

            # insert the priority item if it's not already present
            if item not in self.priority_queue:
                self.priority_queue.append(item)
            if item in self.queue:
                self.queue.remove(item)

            # notify polling threads; notify() requires the lock to be held,
            # which it already is via self.not_full, so call notify() directly.
            self.not_empty.notify()

    def _put(self, item):
        if item not in self.priority_queue and item not in self.queue:
            self.queue.append(item)

    def _qsize(self):
        """Return the approximate size of the queue."""
        return len(self.queue) + len(self.priority_queue)

    def _get(self):
        if len(self.priority_queue) > 0:
            # If there are priority items, return one of them
            item = self.priority_queue.pop(0)
            if item in self.queue:
                self.queue.remove(item)
            return item
        return self.queue.pop(0)
