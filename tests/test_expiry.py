"""Expired markers: the collective `taskExpired` terminal ends streams
chain-wide (the clock's mirror of taskCanceled — no actor, no note), and
`expires_at` serializes onto the create request.

Run: python3 -m unittest discover tests
"""
import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import TaskExpired  # noqa: E402
from simplepush.api import _expires_at_wire  # noqa: E402
from simplepush.client import Event  # noqa: E402

from test_cancel import GROUP_RESPONSE, TASK_A, collect, make_group, make_client  # noqa: E402


def expired_event(task_id, version):
    return Event.from_raw({
        "eventType": "TaskExpired",
        "version": version,
        "createdAt": "2026-08-08T12:00:00Z",
        "data": {"type": "taskExpired", "taskId": task_id},
    })


class ExpiresAtWireTest(unittest.TestCase):

    def test_string_passes_through(self):
        self.assertEqual(_expires_at_wire("2026-08-09T10:00:00Z"), "2026-08-09T10:00:00Z")

    def test_aware_datetime_serializes_to_utc_iso(self):
        cest = datetime.timezone(datetime.timedelta(hours=2))
        value = datetime.datetime(2026, 8, 9, 12, 0, 0, tzinfo=cest)
        self.assertEqual(_expires_at_wire(value), "2026-08-09T10:00:00Z")

    def test_naive_datetime_is_rejected(self):
        with self.assertRaises(ValueError):
            _expires_at_wire(datetime.datetime(2026, 8, 9, 10, 0, 0))

    def test_send_task_carries_expires_at(self):
        calls = []
        client = make_client([GROUP_RESPONSE], calls)
        client.send_task(topic="alerts", content="hi",
                         expires_at="2026-08-09T10:00:00Z")
        _path, body, _headers = calls[-1]
        self.assertEqual(body["expiresAt"], "2026-08-09T10:00:00Z")

    def test_send_task_omits_expires_at_when_absent(self):
        calls = []
        client = make_client([GROUP_RESPONSE], calls)
        client.send_task(topic="alerts", content="hi")
        _path, body, _headers = calls[-1]
        self.assertNotIn("expiresAt", body)


class ExpiredStreamTest(unittest.IsolatedAsyncioTestCase):

    async def test_expired_ends_the_inputs_stream_as_collective_terminal(self):
        client, group, _calls = make_group([GROUP_RESPONSE])
        client._hub._dispatch(expired_event(TASK_A, 1))

        # No timeout: this only returns because taskExpired is terminal.
        items = await collect(group.instances[0].inputs(replay=True))
        self.assertEqual(len(items), 1)
        marker = items[0]
        self.assertIsInstance(marker, TaskExpired)
        self.assertEqual(marker.task_id, TASK_A)

    async def test_expired_root_ends_a_subtask_stream_too(self):
        # taskExpired is entity-wide terminal like taskCanceled: an expired
        # root closes every stream of the chain.
        client, group, _calls = make_group([
            GROUP_RESPONSE,
            {"subtaskId": "sub_00000000-0000-7000-8000-000000000010",
             "createdAt": "2026-08-08T10:00:30Z"},
        ])
        subtask = group.instances[0].append(content="follow-up")
        client._hub._dispatch(expired_event(TASK_A, 1))

        items = await collect(subtask.inputs(replay=True))
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0], TaskExpired)

    async def test_replies_stream_ends_on_expired_too(self):
        client, group, _calls = make_group([GROUP_RESPONSE])
        client._hub._dispatch(expired_event(TASK_A, 1))

        items = await collect(group.instances[0].replies(replay=True))
        self.assertEqual([type(i) for i in items], [TaskExpired])


if __name__ == "__main__":
    unittest.main()
