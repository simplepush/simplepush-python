"""Unit tests for collecting input events over a whole task group
(`TaskGroup.inputs()`).

No network: the send is stubbed and events are fed straight into the client's
demux hub, so the merge over the members' shared `ws/v1/events` stream is
exercised without a socket. Run with

    python3 -m unittest discover tests

from python-library/.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import Client, Event, GroupInput, InputEvent, TaskCompleted, TaskDeleted  # noqa: E402


GROUP_RESPONSE = {
    "groupId": "grptsk_00000000-0000-7000-8000-000000000001",
    "createdAt": "2026-07-03T10:00:00Z",
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


def make_group(response=GROUP_RESPONSE):
    client = Client("localhost", 8000, ssl=False, api_token="tok")
    client._post = lambda path, body, headers=None: response

    async def _noop():
        return None

    client._hub.ensure_running = _noop  # never open a real WS in a test
    return client, client.send_task(topic="alerts", content="hi")


def input_event(task_id, version):
    return Event.from_raw({
        "eventType": "TaskInputUploaded",
        "version": version,
        "createdAt": "2026-07-03T10:01:00Z",
        "data": {"type": "taskInputUploaded", "taskId": task_id},
    })


def completed_event(task_id, version):
    return Event.from_raw({
        "eventType": "TaskCompleted",
        "version": version,
        "createdAt": "2026-07-03T10:01:30Z",
        "data": {"type": "taskCompleted", "taskId": task_id, "inputsUploaded": []},
    })


def deleted_event(task_id, version):
    return Event.from_raw({
        "eventType": "TaskDeleted",
        "version": version,
        "createdAt": "2026-07-03T10:02:00Z",
        "data": {"type": "taskDeleted", "taskId": task_id},
    })


async def collect(stream):
    items = []
    async for item in stream:
        items.append(item)
    return items


class GroupInputsTest(unittest.IsolatedAsyncioTestCase):

    async def test_merges_input_events_tagged_by_instance(self):
        client, group = make_group()
        client._hub._dispatch(input_event(TASK_A, 1))
        client._hub._dispatch(input_event(TASK_B, 2))

        items = await collect(group.inputs(replay=True, timeout=0.15))

        self.assertEqual(len(items), 2)
        self.assertTrue(all(isinstance(gi, GroupInput) for gi in items))
        by_task = {gi.instance.task_id: gi for gi in items}
        self.assertEqual(set(by_task), {TASK_A, TASK_B})
        self.assertIsInstance(by_task[TASK_A].item, InputEvent)
        self.assertEqual(by_task[TASK_A].item.type, "taskInputUploaded")
        self.assertEqual(by_task[TASK_A].recipient.name, "Alice")
        self.assertEqual(by_task[TASK_B].recipient.name, "Bob")

    async def test_terminal_completion_ends_the_group_without_a_timeout(self):
        client, group = make_group()
        client._hub._dispatch(completed_event(TASK_A, 1))
        client._hub._dispatch(completed_event(TASK_B, 2))

        # No timeout: this returns ONLY because every member's stream ends on its
        # own taskCompleted (it would hang forever otherwise).
        items = await collect(group.inputs(replay=True))

        self.assertEqual(len(items), 2)
        by_task = {gi.instance.task_id: gi for gi in items}
        self.assertIsInstance(by_task[TASK_A].item, TaskCompleted)
        self.assertIsInstance(by_task[TASK_B].item, TaskCompleted)

    async def test_member_deletion_surfaces_then_that_member_ends(self):
        client, group = make_group()
        client._hub._dispatch(input_event(TASK_A, 1))
        client._hub._dispatch(deleted_event(TASK_B, 2))

        items = await collect(group.inputs(replay=True, timeout=0.15))

        by_task = {gi.instance.task_id: gi for gi in items}
        self.assertIsInstance(by_task[TASK_A].item, InputEvent)
        self.assertIsInstance(by_task[TASK_B].item, TaskDeleted)

    async def test_empty_group_yields_nothing(self):
        empty = dict(GROUP_RESPONSE, instances=[])
        _client, group = make_group(empty)
        items = await collect(group.inputs(replay=True, timeout=0.15))
        self.assertEqual(items, [])


if __name__ == "__main__":
    unittest.main()
