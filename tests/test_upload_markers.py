"""Per-answer encryption markers: an upload record's own marker (aggregate
completion events) wins over the caller's envelope marker (single-answer
events) — answers sealed after an org rotation carry newer keys than the task.

Run: python3 -m unittest discover tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush.client import Event, _wrap_input  # noqa: E402


class _MarkerEchoDecryptor:
    """Decrypts by echoing which marker was used — proves marker routing."""
    def try_decrypt_marker(self, value, marker):
        return f"dec[{marker.get('keyFingerprint') or marker.get('v')}]:{value}"


class UploadMarkerTest(unittest.TestCase):

    def test_aggregate_completion_uses_each_records_own_marker(self):
        ev = Event.from_raw({
            "eventType": "TaskCompleted",
            # Aggregate event: envelope EMPTY, per-record markers inside.
            "data": {"type": "taskCompleted", "taskId": "tsk-1", "inputsUploaded": [
                {"type": "textUploaded", "id": "inp-1", "value": "ct1",
                 "encryption": {"type": "personal", "keyFingerprint": "fp-v4"}},
                {"type": "textUploaded", "id": "inp-2", "value": "ct2",
                 "encryption": {"type": "personal", "keyFingerprint": "fp-v5"}},
            ]},
        })
        done = _wrap_input(ev, _MarkerEchoDecryptor(), None)
        self.assertEqual([u.value for u in done.uploads],
                         ["dec[fp-v4]:ct1", "dec[fp-v5]:ct2"])

    def test_single_answer_event_uses_the_envelope_marker(self):
        ev = Event.from_raw({
            "eventType": "TaskInputCompleted",
            "encryption": {"type": "personal", "keyFingerprint": "fp-answer"},
            "data": {"type": "taskInputCompleted", "taskId": "tsk-1",
                     "inputUploaded": {"type": "textUploaded", "id": "inp-1", "value": "ct"}},
        })
        item = _wrap_input(ev, _MarkerEchoDecryptor(), None)
        self.assertEqual(item.uploads[0].value, "dec[fp-answer]:ct")


if __name__ == "__main__":
    unittest.main()
