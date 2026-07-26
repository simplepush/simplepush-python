"""Unit tests for topicless "note to self" sends (send to your own devices).

A personal `Client` may omit topic/member/broadcast: the send goes straight to
the sender's own devices and comes back as a single `Task` / `Notification`. When
a default account `password` is configured the body is encrypted under the
account key (default password + the server password_salt); otherwise plaintext.
No network: `_post` is stubbed and the account salt is injected directly.

Run with `python3 -m unittest discover tests` from python-library/.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import Client, Notification, OrgClient, Task  # noqa: E402


TASK_RESPONSE = {
    "taskId": "tsk_00000000-0000-7000-8000-00000000000c",
    "createdAt": "2026-07-07T10:00:00Z",
    "waitToken": "wt_s",
    "appendToken": "at_s",
    "attachments": [],
}

NOTIFICATION_RESPONSE = {
    "notificationId": "ntf_00000000-0000-7000-8000-00000000000c",
    "createdAt": "2026-07-07T10:00:00Z",
    "waitToken": "wt_s",
}


def make_client(responses, calls, *, passwords=None):
    client = Client("localhost", 8000, ssl=False, api_token="tok", passwords=passwords)
    queue = list(responses)

    def fake_post(path, body, headers=None):
        calls.append((path, body, headers))
        return queue.pop(0)

    client._post = fake_post
    # Inject the account salt so the encryption path never touches the network.
    client._account_salt_fetched = True
    client._account_salt_value = "account-salt-value"
    return client


class SelfSendTest(unittest.TestCase):

    def test_task_no_target_is_note_to_self_plaintext(self):
        calls = []
        client = make_client([TASK_RESPONSE], calls)  # no default password
        task = client.send_task(content="hi")

        self.assertIsInstance(task, Task)
        self.assertEqual(task.task_id, TASK_RESPONSE["taskId"])
        path, body, headers = calls[0]
        self.assertEqual(path, "/tasks/json")
        # No addressing target rides the request.
        self.assertNotIn("topic", body)
        self.assertNotIn("member", body)
        self.assertFalse(body.get("broadcast"))
        # No default password => plaintext (no encryption marker, content in clear).
        self.assertNotIn("encryption", body)
        self.assertEqual(body["content"], "hi")

    def test_task_no_target_encrypts_under_account_key(self):
        calls = []
        client = make_client([TASK_RESPONSE], calls, passwords="my-account-pw")
        client.send_task(title="secret", content="hi")

        _, body, headers = calls[0]
        self.assertNotIn("topic", body)
        # Encrypted under the account key: personal marker + ciphertext body.
        self.assertEqual(body["encryption"]["type"], "personal")
        self.assertIn("passwordFingerprint", body["encryption"])
        self.assertNotEqual(body["content"], "hi")
        self.assertNotEqual(body["title"], "secret")

    def test_text_input_default_value_encrypts_under_account_key(self):
        # defaultValue must be encrypted like every other body field: the
        # backend materializes it as a TextSubmission upload, which the app
        # AEAD-decrypts — a plaintext value there fails the whole task.
        from simplepush import TextInput
        from simplepush.crypto import decrypt

        calls = []
        client = make_client([TASK_RESPONSE], calls, passwords="my-account-pw")
        client.send_task(
            title="t",
            inputs=[TextInput(description="Service visit", default_value="$120")],
        )

        _, body, _ = calls[0]
        inp = body["inputs"][0]
        self.assertNotEqual(inp["description"], "Service visit")
        self.assertNotEqual(inp["defaultValue"], "$120")
        # Round-trips under the account key, like every other encrypted field.
        dk = client._self_send_key()
        self.assertEqual(decrypt(inp["defaultValue"], dk.symmetric_key), "$120")
        self.assertEqual(decrypt(inp["description"], dk.symmetric_key), "Service visit")

    def test_notification_no_target_is_note_to_self(self):
        calls = []
        client = make_client([NOTIFICATION_RESPONSE], calls)
        note = client.send_notification(content="ping")

        self.assertIsInstance(note, Notification)
        path, body, headers = calls[0]
        self.assertEqual(path, "/notifications/json")
        self.assertNotIn("topic", body)
        self.assertNotIn("member", body)
        self.assertNotIn("encryption", body)
        # A personal notification create (even plaintext, no media) MUST carry
        # the API-Token — the backend rejects unauthenticated sends.
        self.assertEqual(headers, {"API-Token": "tok"})

    def test_notification_no_target_encrypts_under_account_key(self):
        calls = []
        client = make_client([NOTIFICATION_RESPONSE], calls, passwords="my-account-pw")
        client.send_notification(content="ping")

        _, body, headers = calls[0]
        self.assertEqual(body["encryption"]["type"], "personal")
        self.assertNotEqual(body["content"], "ping")

    def test_explicit_password_without_topic_is_rejected(self):
        calls = []
        client = make_client([TASK_RESPONSE], calls)
        with self.assertRaises(ValueError):
            client.send_task(content="hi", password="ad-hoc")

    def test_org_client_requires_a_target(self):
        client = OrgClient("localhost", 8000, ssl=False, api_key="key")
        with self.assertRaises(ValueError):
            client.send_task(content="hi")
        with self.assertRaises(ValueError):
            client.send_notification(content="hi")


if __name__ == "__main__":
    unittest.main()
