"""Unit tests for collecting answers over a whole notification group
(`NotificationGroup.inputs()`).

Mirrors ``test_group_inputs.py`` (the task-groups precedent). No network: the
send is stubbed and events are fed straight into the client's demux hub, so the
merge over the members' shared `ws/v1/events` stream is exercised without a
socket. Run with

    python3 -m unittest discover tests

from python-library/.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import (  # noqa: E402
    Client, Event, GroupNotification, NotificationChoiceReply, NotificationCompleted,
)


GROUP_RESPONSE = {
    "groupId": "grpntf_00000000-0000-7000-8000-000000000001",
    "createdAt": "2026-07-05T10:00:00Z",
    "groupWaitToken": "wt_group",
    "instances": [
        {"notificationId": "ntf_00000000-0000-7000-8000-00000000000a", "waitToken": "wt_a",
         "recipient": {"publicId": "usr_a", "name": "Alice"}},
        {"notificationId": "ntf_00000000-0000-7000-8000-00000000000b", "waitToken": "wt_b",
         "recipient": {"publicId": "usr_b", "name": "Bob"}},
    ],
}

NTF_A = GROUP_RESPONSE["instances"][0]["notificationId"]
NTF_B = GROUP_RESPONSE["instances"][1]["notificationId"]


def make_group(response=GROUP_RESPONSE):
    client = Client("localhost", 8000, ssl=False, api_token="tok")
    client._post = lambda path, body, headers=None, **kwargs: response

    async def _noop():
        return None

    client._hub.ensure_running = _noop  # never open a real WS in a test
    return client, client.send_notification(topic="alerts", content="hi")


def completed_event(notification_id, version, reply=None):
    data = {"type": "notificationCompleted", "notificationId": notification_id}
    if reply is not None:
        data["reply"] = reply
    return Event.from_raw({
        "eventType": "NotificationCompleted",
        "version": version,
        "createdAt": "2026-07-05T10:01:00Z",
        "data": data,
    })


async def collect(stream):
    items = []
    async for item in stream:
        items.append(item)
    return items


class GroupNotificationInputsTest(unittest.IsolatedAsyncioTestCase):

    async def test_completions_end_the_group_without_a_timeout(self):
        client, group = make_group()
        client._hub._dispatch(completed_event(
            NTF_A, 1, reply={"type": "choice", "selectedIndex": 0, "selectedValue": "Yes"}))
        client._hub._dispatch(completed_event(NTF_B, 2))

        # No timeout: this returns ONLY because every member's stream ends on
        # its own notificationCompleted (it would hang forever otherwise).
        items = await collect(group.inputs(replay=True))

        self.assertEqual(len(items), 2)
        self.assertTrue(all(isinstance(gn, GroupNotification) for gn in items))
        by_id = {gn.instance.notification_id: gn for gn in items}
        self.assertEqual(set(by_id), {NTF_A, NTF_B})
        self.assertIsInstance(by_id[NTF_A].item, NotificationCompleted)
        self.assertEqual(by_id[NTF_A].item.reply,
                         NotificationChoiceReply(selected_index=0, selected_value="Yes"))
        self.assertIsNone(by_id[NTF_B].item.reply)
        self.assertEqual(by_id[NTF_A].recipient.name, "Alice")
        self.assertEqual(by_id[NTF_B].recipient.name, "Bob")

    async def test_quiet_member_never_ends_the_group_before_the_timeout(self):
        client, group = make_group()
        client._hub._dispatch(completed_event(NTF_A, 1))

        items = await collect(group.inputs(replay=True, timeout=0.15))

        # Only Alice answered; Bob's silence ends iteration via the GROUP-WIDE
        # timeout, not by dropping his membership.
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].instance.notification_id, NTF_A)

    async def test_empty_group_yields_nothing(self):
        empty = dict(GROUP_RESPONSE, instances=[])
        _client, group = make_group(empty)
        items = await collect(group.inputs(replay=True, timeout=0.15))
        self.assertEqual(items, [])


if __name__ == "__main__":
    unittest.main()
