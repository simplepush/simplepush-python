"""Task/subtask/group cancellation: request shapes, validation, and the
canceled terminal markers ending streams.

Run: python3 -m unittest discover tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import CancelReason, Client, TaskGroup, TaskCanceled, SubtaskCanceled, GroupCancelResult  # noqa: E402
from simplepush.api import ApiError  # noqa: E402
from simplepush.client import Event  # noqa: E402

try:
    from simplepush.crypto import Decryptor, decrypt  # noqa: E402
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


GROUP_RESPONSE = {
    "groupId": "grptsk_00000000-0000-7000-8000-000000000001",
    "createdAt": "2026-08-04T10:00:00Z",
    "groupWaitToken": "wt_group",
    "groupAppendToken": "at_group",
    "instances": [
        {"taskId": "tsk_00000000-0000-7000-8000-00000000000a", "waitToken": "wt_a",
         "appendToken": "at_a", "recipient": {"publicId": "usr_a", "name": "Alice"}},
        {"taskId": "tsk_00000000-0000-7000-8000-00000000000b", "waitToken": "wt_b",
         "appendToken": "at_b", "recipient": {"publicId": "usr_b", "name": "Bob"}},
    ],
    "attachments": [],
}

TASK_A = GROUP_RESPONSE["instances"][0]["taskId"]
TASK_B = GROUP_RESPONSE["instances"][1]["taskId"]


def make_client(responses, calls):
    """A personal client whose `_post` pops canned responses and records
    (path, body, headers) — nothing touches the network."""
    client = Client("localhost", 8000, ssl=False, api_token="tok")
    queue = list(responses)

    def fake_post(path, body, headers=None):
        calls.append((path, body, headers))
        return queue.pop(0)

    client._post = fake_post
    return client


def make_group(responses):
    calls = []
    client = make_client(responses, calls)

    async def _noop():
        return None

    client._hub.ensure_running = _noop  # never open a real WS in a test
    return client, client.send_task(topic="alerts", content="hi"), calls


def canceled_event(task_id, version, *, reason="canceled", note=None, superseded_by=None):
    data = {"type": "taskCanceled", "taskId": task_id, "reason": reason}
    if note is not None:
        data["note"] = note
    if superseded_by is not None:
        data["supersededBy"] = superseded_by
    return Event.from_raw({
        "eventType": "TaskCanceled",
        "version": version,
        "createdAt": "2026-08-04T10:02:00Z",
        "data": data,
    })


def subtask_canceled_event(task_id, subtask_id, version, *, reason="superseded", superseded_by=None):
    data = {"type": "subtaskCanceled", "parentTaskId": task_id, "subtaskId": subtask_id, "reason": reason}
    if superseded_by is not None:
        data["supersededBy"] = superseded_by
    return Event.from_raw({
        "eventType": "SubtaskCanceled",
        "version": version,
        "createdAt": "2026-08-04T10:03:00Z",
        "data": data,
    })


def subtask_input_event(task_id, subtask_id, version):
    return Event.from_raw({
        "eventType": "SubtaskInputUploaded",
        "version": version,
        "createdAt": "2026-08-04T10:01:00Z",
        "data": {"type": "subtaskInputUploaded", "parentTaskId": task_id, "subtaskId": subtask_id},
    })


async def collect(stream):
    items = []
    async for item in stream:
        items.append(item)
    return items


class CancelRequestTest(unittest.TestCase):

    def test_task_cancel_posts_reason_and_note(self):
        client, group, calls = make_group([GROUP_RESPONSE, None])
        task = group.instances[0]
        task.cancel(reason="answered", note="already handled")

        path, body, headers = calls[-1]
        self.assertEqual(path, f"/tasks/{TASK_A}/cancel")
        self.assertEqual(body, {"reason": "answered", "note": "already handled"})
        self.assertEqual(headers, {"API-Token": "tok"})

    def test_reason_accepts_the_enum_and_serializes_its_wire_value(self):
        client, group, calls = make_group([GROUP_RESPONSE, None])
        group.instances[0].cancel(reason=CancelReason.ANSWERED)
        self.assertEqual(calls[-1][1], {"reason": "answered"})

    def test_task_cancel_defaults_to_plain_canceled(self):
        client, group, calls = make_group([GROUP_RESPONSE, None])
        group.instances[0].cancel()
        self.assertEqual(calls[-1][1], {"reason": "canceled"})

    def test_superseded_by_accepts_a_task_handle(self):
        client, group, calls = make_group([GROUP_RESPONSE, None])
        group.instances[0].cancel(reason="superseded", superseded_by=group.instances[1])
        self.assertEqual(calls[-1][1], {"reason": "superseded", "supersededBy": TASK_B})

    def test_superseded_by_without_superseded_reason_raises(self):
        client, group, calls = make_group([GROUP_RESPONSE])
        with self.assertRaises(ValueError):
            group.instances[0].cancel(reason="answered", superseded_by=TASK_B)
        self.assertEqual(len(calls), 1)  # only the send; nothing was posted

    def test_unknown_reason_raises(self):
        client, group, calls = make_group([GROUP_RESPONSE])
        with self.assertRaises(ValueError):
            group.instances[0].cancel(reason="bogus")

    def test_group_cancel_returns_counts_and_group_pointer(self):
        client, group, calls = make_group([GROUP_RESPONSE, {"canceled": 1, "skipped": 1}])
        replacement_id = "grptsk_00000000-0000-7000-8000-000000000002"
        result = group.cancel(reason="superseded", superseded_by=replacement_id)

        path, body, _headers = calls[-1]
        self.assertEqual(path, f"/task-groups/{group.group_id}/cancel")
        self.assertEqual(body, {"reason": "superseded", "supersededBy": replacement_id})
        self.assertEqual(result, GroupCancelResult(canceled=1, skipped=1))

    @unittest.skipUnless(HAVE_CRYPTO, "crypto extra not installed")
    def test_encrypted_send_cancel_encrypts_the_note_and_stamps_its_marker(self):
        calls = []
        client = make_client([GROUP_RESPONSE, None], calls)
        group = client.send_task(topic="alerts", content="hi", password="pw")
        group.instances[0].cancel(reason="answered", note="already handled")

        _path, body, _headers = calls[-1]
        # The note is sealed under the chain key and carries ITS OWN marker
        # (the send key's fingerprint) — not the task's marker.
        self.assertNotEqual(body["note"], "already handled")
        self.assertEqual(body["encryption"]["type"], "personal")
        self.assertEqual(body["encryption"]["keyFingerprint"], group._send_key.fingerprint)
        self.assertEqual(
            decrypt(body["note"], group._send_key.symmetric_key),
            "already handled",
        )

    def test_api_error_surfaces_the_backend_code(self):
        err = ApiError(409, '{"error": "task_canceled", "msg": "Task was canceled by its sender"}')
        self.assertEqual(err.code, "task_canceled")
        self.assertEqual(ApiError(500, "not json").code, None)


class CancelStreamTest(unittest.IsolatedAsyncioTestCase):

    async def test_task_canceled_ends_the_inputs_stream_with_a_marker(self):
        client, group, _calls = make_group([GROUP_RESPONSE])
        task = group.instances[0]
        client._hub._dispatch(canceled_event(TASK_A, 1, reason="answered", superseded_by=TASK_B))

        # No timeout: this only returns because the cancel is terminal.
        items = await collect(task.inputs(replay=True))
        self.assertEqual(len(items), 1)
        marker = items[0]
        self.assertIsInstance(marker, TaskCanceled)
        self.assertEqual(marker.task_id, TASK_A)
        self.assertEqual(marker.reason, "answered")
        self.assertEqual(marker.superseded_by, TASK_B)

    async def test_group_inputs_surface_each_members_cancel_then_end(self):
        client, group, _calls = make_group([GROUP_RESPONSE])
        client._hub._dispatch(canceled_event(TASK_A, 1))
        client._hub._dispatch(canceled_event(TASK_B, 1))

        items = await collect(group.inputs(replay=True))
        self.assertEqual(len(items), 2)
        self.assertTrue(all(isinstance(i.item, TaskCanceled) for i in items))
        self.assertEqual({i.item.task_id for i in items}, {TASK_A, TASK_B})

    async def test_root_cancel_ends_a_subtask_stream_too(self):
        # A canceled root closes the whole chain — the backend emits NO
        # per-subtask events, so the entity-wide taskCanceled must tear the
        # subtask stream down.
        client, group, calls = make_group([
            GROUP_RESPONSE,
            {"subtaskId": "sub_00000000-0000-7000-8000-000000000010",
             "createdAt": "2026-08-04T10:00:30Z"},
        ])
        subtask = group.instances[0].append(content="follow-up")
        client._hub._dispatch(canceled_event(TASK_A, 1))

        items = await collect(subtask.inputs(replay=True))
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0], TaskCanceled)

    async def test_subtask_cancel_is_scoped_to_its_own_stream(self):
        client, group, calls = make_group([
            GROUP_RESPONSE,
            {"subtaskId": "sub_00000000-0000-7000-8000-000000000010",
             "createdAt": "2026-08-04T10:00:30Z"},
        ])
        subtask = group.instances[0].append(content="follow-up")
        sub_id = subtask.subtask_id
        client._hub._dispatch(subtask_input_event(TASK_A, sub_id, 1))
        client._hub._dispatch(subtask_canceled_event(TASK_A, sub_id, 2, superseded_by="sub_replacement"))

        items = await collect(subtask.inputs(replay=True))
        self.assertEqual(len(items), 2)
        marker = items[1]
        self.assertIsInstance(marker, SubtaskCanceled)
        self.assertEqual(marker.subtask_id, sub_id)
        self.assertEqual(marker.superseded_by, "sub_replacement")

        # The ROOT task's stream is untouched by a scoped subtask cancel: it
        # times out (no terminal) rather than ending on a marker.
        root_items = await collect(group.instances[0].inputs(replay=True, timeout=0.05))
        self.assertEqual(root_items, [])


if __name__ == "__main__":
    unittest.main()
