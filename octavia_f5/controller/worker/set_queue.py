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

from queue import Queue


# FIXME:
# - maxsize is only respected by put, not by put_priority
# - rename to something sensible like e. g. DeduplicatingPriorityQueue (or
#   DedupPrioQueue, though that doesn't fit with the stdlib PriorityQueue naming)
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

    def put_priority(self, item):
        """Add an item to the priority queue."""
        with self.not_full:
            if item not in self.priority_queue:
                self.priority_queue.append(item)
            if item in self.queue:
                self.queue.remove(item)
            # notify polling threads
            with self.not_empty:  # acquire self.mutex for self.not_empty
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
