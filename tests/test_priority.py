"""Priority on send: `priority` / `critical_volume` serialize onto the create
request, the deprecated `critical` flag maps to 5, and bad values are rejected
client-side.

Run: python3 -m unittest discover tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush.api import _priority_wire  # noqa: E402


class PriorityWireTest(unittest.TestCase):

    def test_nothing_set_sends_nothing(self):
        self.assertEqual(_priority_wire(None, False, None), {})

    def test_priority_and_volume_pass_through(self):
        self.assertEqual(_priority_wire(5, False, 0.4), {"priority": 5, "criticalVolume": 0.4})

    def test_critical_alias_is_level_5(self):
        self.assertEqual(_priority_wire(None, True, None), {"priority": 5})

    def test_priority_wins_over_critical(self):
        self.assertEqual(_priority_wire(2, True, None), {"priority": 2})

    def test_level_out_of_range_is_rejected(self):
        for bad in (0, 6, True, 2.5):
            with self.assertRaises(ValueError):
                _priority_wire(bad, False, None)

    def test_volume_needs_level_5(self):
        with self.assertRaises(ValueError):
            _priority_wire(4, False, 0.5)
        with self.assertRaises(ValueError):
            _priority_wire(None, False, 0.5)

    def test_volume_range(self):
        for bad in (0, 1.5, -0.1):
            with self.assertRaises(ValueError):
                _priority_wire(5, False, bad)
        self.assertEqual(_priority_wire(None, True, 1.0), {"priority": 5, "criticalVolume": 1.0})


if __name__ == "__main__":
    unittest.main()
