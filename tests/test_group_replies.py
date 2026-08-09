"""Unit tests for collecting replies over a whole task group
(`TaskGroup.replies()`).

No network: the send is stubbed (canned group response) and events are fed
straight into the client's demux hub, so the merge over the members' shared
`ws/v1/events` stream is exercised without a socket. Run with

    python3 -m unittest discover tests

from python-library/.
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import Client, Event, GroupReply, Reply, TaskDeleted  # noqa: E402


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
    """A group handle whose hub never opens a socket: `_post` is canned and the
    hub runner is stubbed to a no-op so streams attach but nothing connects."""
    client = Client("localhost", 8000, ssl=False, api_token="tok")
    client._post = lambda path, body, headers=None, **kwargs: response

    async def _noop():
        return None

    client._hub.ensure_running = _noop  # never open a real WS in a test
    return client, client.send_task(topic="alerts", content="hi")


def reply_event(task_id, text, version, reply_id):
    return Event.from_raw({
        "eventType": "ReplyAppended",
        "entityId": "usr_x",
        "version": version,
        "createdAt": "2026-07-03T10:01:00Z",
        "data": {
            "type": "replyAppended",
            "taskId": task_id,
            "reply": {"id": reply_id, "body": {"type": "text", "value": text},
                      "createdAt": "2026-07-03T10:01:00Z"},
        },
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


class GroupRepliesTest(unittest.IsolatedAsyncioTestCase):

    async def test_merges_replies_from_every_member_tagged_by_instance(self):
        client, group = make_group()
        # A reply on each member's own instance (buffered before we iterate).
        client._hub._dispatch(reply_event(TASK_A, "from alice", 1, "rpl_a"))
        client._hub._dispatch(reply_event(TASK_B, "from bob", 2, "rpl_b"))

        items = await collect(group.replies(replay=True, timeout=0.15))

        self.assertEqual(len(items), 2)
        self.assertTrue(all(isinstance(gr, GroupReply) for gr in items))
        # Order across members is not guaranteed — key by originating instance.
        by_task = {gr.instance.task_id: gr for gr in items}
        self.assertEqual(set(by_task), {TASK_A, TASK_B})
        self.assertIsInstance(by_task[TASK_A].item, Reply)
        self.assertEqual(by_task[TASK_A].item.body.text, "from alice")
        self.assertEqual(by_task[TASK_B].item.body.text, "from bob")
        # `recipient` is the shortcut to which recipient replied.
        self.assertEqual(by_task[TASK_A].recipient.name, "Alice")
        self.assertEqual(by_task[TASK_B].recipient.name, "Bob")

    async def test_multiple_replies_from_one_member(self):
        client, group = make_group()
        client._hub._dispatch(reply_event(TASK_A, "one", 1, "rpl_1"))
        client._hub._dispatch(reply_event(TASK_A, "two", 2, "rpl_2"))

        items = await collect(group.replies(replay=True, timeout=0.15))

        self.assertEqual([gr.item.body.text for gr in items], ["one", "two"])
        self.assertTrue(all(gr.instance.task_id == TASK_A for gr in items))

    async def test_member_deletion_surfaces_then_that_member_ends(self):
        client, group = make_group()
        client._hub._dispatch(reply_event(TASK_A, "hi", 1, "rpl_a"))
        client._hub._dispatch(deleted_event(TASK_B, 2))

        items = await collect(group.replies(replay=True, timeout=0.15))

        by_task = {gr.instance.task_id: gr for gr in items}
        self.assertIsInstance(by_task[TASK_A].item, Reply)
        self.assertIsInstance(by_task[TASK_B].item, TaskDeleted)

    async def test_empty_group_yields_nothing(self):
        empty = dict(GROUP_RESPONSE, instances=[])
        _client, group = make_group(empty)
        items = await collect(group.replies(replay=True, timeout=0.15))
        self.assertEqual(items, [])


if __name__ == "__main__":
    unittest.main()
