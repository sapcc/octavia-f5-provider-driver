# Copyright 2025 SAP SE
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
import random

import octavia.tests.unit.base as base
from octavia_f5.controller.worker.set_queue import SetQueue


class TestSetQueue(base.TestCase):
    def test_set_queue(self):
        queue = SetQueue()
        # Add items to the queue
        queue.put('item1')
        queue.put('item2')
        # Check that items are in the queue
        self.assertFalse(queue.empty())

        rest = [queue.get(), queue.get()]
        self.assertTrue(queue.empty())
        self.assertIn('item1', rest)
        self.assertIn('item2', rest)

    def test_set_queue_priority(self):
        # Test priority items in SetQueue

        queue = SetQueue()
        queue.put('item1')
        queue.put_priority('priority_item1')
        queue.put('item2')

        # Check that priority item is returned first
        self.assertEqual(queue.get(), 'priority_item1')

        rest = [queue.get(), queue.get()]
        self.assertTrue(queue.empty())
        self.assertIn('item1', rest)
        self.assertIn('item2', rest)

    def test_set_queue_deduplication(self):
        """ Test that SetQueue only contains unique items """
        queue = SetQueue()
        queue.put('item1')
        queue.put('item1')
        queue.put('item2')
        queue.put_priority('priority_item1')
        queue.put_priority('priority_item1')
        queue.put_priority('priority_item2')

        # Check that only unique items are present
        self.assertEqual(queue.qsize(), 4)
        prio = [queue.get(), queue.get()]
        rest = [queue.get(), queue.get()]
        self.assertTrue(queue.empty())

        self.assertIn('priority_item1', prio)
        self.assertIn('priority_item2', prio)
        self.assertIn('item1', rest)
        self.assertIn('item2', rest)

    def test_set_queue_size(self):
        """ Test the size of the SetQueue """
        queue = SetQueue()
        self.assertEqual(queue.qsize(), 0)

        queue.put('item1')
        self.assertEqual(queue.qsize(), 1)

        queue.put('item2')
        self.assertEqual(queue.qsize(), 2)

        queue.put_priority('priority_item1')
        self.assertEqual(queue.qsize(), 3)

        queue.get()
        self.assertEqual(queue.qsize(), 2)

    def test_set_queue_empty(self):
        """ Test if the SetQueue is empty """

        queue = SetQueue()
        self.assertTrue(queue.empty())

        queue.put('item1')
        self.assertFalse(queue.empty())

        queue.get()
        self.assertTrue(queue.empty())

        queue.put_priority('priority_item1')
        self.assertFalse(queue.empty())

        queue.get()
        self.assertTrue(queue.empty())

    def test_set_queue_fifo(self):
        """ Test that the queue is FIFO (first in, first out) """
        queue = SetQueue()

        # Put items into queue.
        # - For simple order checking the values are strictly increasing.
        # - Exposing absence of FIFO doesn't work with integer numbers (even
        #   when they're of type float).
        # - `for i in range(...): queue.put(i + some_iota)` does expose absence
        #   of FIFO, but only after almost all items have been popped from the
        #   queue, shortly before the queue is empty.
        # Therefore we use a separate value which we increment by a random
        # amount with each step. This way, absence of FIFO is exposed reliably
        # and early - already after popping only a few items.
        val = 0
        for _ in range(10000):
            val += random.random()
            queue.put(val)

        # take items out of queue and check strict monoticity
        items_gotten = 0
        last_item = None
        while not queue.empty():
            item = queue.get()
            items_gotten += 1
            if last_item is not None:
                assert item > last_item, \
                    f"After getting {items_gotten} items: SetQueue is not FIFO"
            last_item = item
