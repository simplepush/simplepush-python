"""Unit tests for independent task groups (the default send mode).

Covers the two create-response shapes (`TaskGroup` by default, a single `Task`
with `shared=True`), the request flag, hub registration per instance, and the
group subtask append. No network: `_post` is stubbed on the client to serve
canned responses and record request bodies. Run with

    python3 -m unittest discover tests

from python-library/.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import Client, Subtask, Task, TaskGroup, TaskGroupRecipient  # noqa: E402


GROUP_RESPONSE = {
    "groupId": "grptsk_00000000-0000-7000-8000-000000000001",
    "createdAt": "2026-07-03T10:00:00Z",
    "groupWaitToken": "wt_group",
    "groupAppendToken": "at_group",
    "instances": [
        {"taskId": "tsk_00000000-0000-7000-8000-00000000000a", "waitToken": "wt_a",
         "appendToken": "at_a", "recipient": {"publicId": "usr_a", "name": "Alice"}},
        # A nameless recipient arrives WITHOUT a name key (zio-json omits None
        # on encode) — never as "name": null.
        {"taskId": "tsk_00000000-0000-7000-8000-00000000000b", "waitToken": "wt_b",
         "appendToken": "at_b", "recipient": {"publicId": "usr_b"}},
    ],
    "attachments": [],
}

SHARED_RESPONSE = {
    "taskId": "tsk_00000000-0000-7000-8000-00000000000c",
    "createdAt": "2026-07-03T10:00:00Z",
    "waitToken": "wt_s",
    "appendToken": "at_s",
    "attachments": [],
}

APPEND_GROUP_RESPONSE = {
    "groupId": GROUP_RESPONSE["groupId"],
    "createdAt": "2026-07-03T10:05:00Z",
    "subtasks": [
        {"taskId": GROUP_RESPONSE["instances"][0]["taskId"],
         "subtaskId": "sub_00000000-0000-7000-8000-000000000010"},
        {"taskId": GROUP_RESPONSE["instances"][1]["taskId"],
         "subtaskId": "sub_00000000-0000-7000-8000-000000000011"},
    ],
}


def make_client(responses, calls):
    """A personal client whose `_post` pops canned responses and records
    (path, body) — nothing touches the network."""
    client = Client("localhost", 8000, ssl=False, api_token="tok")
    queue = list(responses)

    def fake_post(path, body, headers=None, **kwargs):
        calls.append((path, body))
        return queue.pop(0)

    client._post = fake_post
    return client


class GroupSendTest(unittest.TestCase):

    def test_default_send_returns_task_group(self):
        calls = []
        client = make_client([GROUP_RESPONSE], calls)
        group = client.send_task(topic="alerts", content="hi")

        self.assertIsInstance(group, TaskGroup)
        self.assertEqual(group.group_id, GROUP_RESPONSE["groupId"])
        self.assertEqual(group.append_token, "at_group")
        self.assertEqual(group.wait_token, "wt_group")
        self.assertEqual(len(group), 2)
        self.assertEqual([t.task_id for t in group],
                         [i["taskId"] for i in GROUP_RESPONSE["instances"]])

        first = group.instances[0]
        self.assertIsInstance(first, Task)
        self.assertEqual(first.append_token, "at_a")
        self.assertEqual(first.recipient,
                         TaskGroupRecipient(public_id="usr_a", name="Alice"))
        self.assertIsNone(group.instances[1].recipient.name)

        # No `shared` key rides the request in default mode.
        path, body = calls[0]
        self.assertEqual(path, "/tasks/json")
        self.assertNotIn("shared", body)

        # Each instance is registered with the hub so its events buffer from now.
        for inst in GROUP_RESPONSE["instances"]:
            self.assertIn(inst["taskId"], client._hub._buffers)

    def test_sole_unwraps_a_single_instance_group(self):
        one = dict(GROUP_RESPONSE, instances=[GROUP_RESPONSE["instances"][0]])
        client = make_client([one], [])
        group = client.send_task(topic="alerts", content="hi")
        self.assertEqual(group.sole.task_id, GROUP_RESPONSE["instances"][0]["taskId"])

    def test_sole_raises_unless_exactly_one(self):
        client = make_client([GROUP_RESPONSE], [])
        group = client.send_task(topic="alerts", content="hi")
        with self.assertRaises(ValueError):
            group.sole

    def test_shared_sends_flag_and_returns_task(self):
        calls = []
        client = make_client([SHARED_RESPONSE], calls)
        task = client.send_task(topic="alerts", content="hi", shared=True)

        self.assertIsInstance(task, Task)
        self.assertEqual(task.task_id, SHARED_RESPONSE["taskId"])
        self.assertEqual(task.append_token, "at_s")
        self.assertIs(calls[0][1].get("shared"), True)


class GroupAppendTest(unittest.TestCase):

    def test_append_returns_one_subtask_per_member(self):
        calls = []
        client = make_client([GROUP_RESPONSE, APPEND_GROUP_RESPONSE], calls)
        group = client.send_task(topic="alerts", content="hi")
        subtasks = group.append(content="follow-up")

        self.assertEqual(len(subtasks), 2)
        self.assertIsInstance(subtasks[0], Subtask)
        self.assertEqual(subtasks[0].subtask_id,
                         APPEND_GROUP_RESPONSE["subtasks"][0]["subtaskId"])
        self.assertEqual(subtasks[0].parent_task_id,
                         GROUP_RESPONSE["instances"][0]["taskId"])

        path, body = calls[1]
        self.assertEqual(path, "/subtasks/json")
        self.assertEqual(body["appendToken"], "at_group")
        self.assertNotIn("instances", body)

    def test_append_threads_the_instance_subset(self):
        calls = []
        client = make_client([GROUP_RESPONSE, APPEND_GROUP_RESPONSE], calls)
        group = client.send_task(topic="alerts", content="hi")
        # Task handles and raw ids both name members.
        group.append(content="x", instances=[group.instances[0],
                                             group.instances[1].task_id])
        body = calls[1][1]
        self.assertEqual(body["instances"],
                         [i["taskId"] for i in GROUP_RESPONSE["instances"]])

    def test_append_with_files_uploads_once_for_the_batch(self):
        import tempfile

        calls = []
        with_attachment = dict(
            APPEND_GROUP_RESPONSE,
            attachments=[{"id": "att_00000000-0000-7000-8000-000000000020", "filename": "a.png"}],
        )
        client = make_client([GROUP_RESPONSE, with_attachment], calls)
        uploads = []
        client._upload_files = lambda headers, prepared, created: uploads.append((prepared, created))

        with tempfile.NamedTemporaryFile(suffix=".png") as f:
            f.write(b"\x89PNG fake bytes")
            f.flush()
            group = client.send_task(topic="alerts", content="hi")
            subtasks = group.append(content="x", files=[f.name])

        self.assertEqual(len(subtasks), 2)
        body = calls[1][1]
        # ONE file meta rides the append body; ONE upload pass for the batch.
        self.assertEqual(len(body["data"]["files"]), 1)
        self.assertEqual(len(uploads), 1)
        prepared, created = uploads[0]
        self.assertEqual(len(prepared), 1)
        self.assertEqual(created, with_attachment["attachments"])


if __name__ == "__main__":
    unittest.main()
