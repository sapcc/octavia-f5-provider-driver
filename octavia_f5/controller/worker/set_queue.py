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


class SetQueue(Queue):
    """
    A thread-safe queue that stores unique items using sets and supports priority items.

    Inherits from `Queue` but overrides the internal storage to use sets, ensuring all items are unique.
    Items added via `put_priority` are returned first when retrieving from the queue.
    """
    def _init(self, maxsize):
        self.maxsize = maxsize
        self.queue = set()
        self.priority_queue = set()

    def put_priority(self, item):
        """Add an item to the priority queue."""
        self.priority_queue.add(item)
        self.queue.discard(item)
        # notify polling threads
        with self.not_empty: # acquire self.mutex for self.not_empty
            self.not_empty.notify()

    def _put(self, item):
        self.queue.add(item)

    def _qsize(self):
        """Return the approximate size of the queue."""
        return len(self.queue) + len(self.priority_queue)

    def _get(self):
        if len(self.priority_queue) > 0:
            # If there are priority items, return one of them
            item = self.priority_queue.pop()
            self.queue.discard(item)
            return item
        return self.queue.pop()
