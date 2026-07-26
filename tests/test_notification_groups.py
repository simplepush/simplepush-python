"""Unit tests for independent notification groups + the notification Action input.

Mirrors ``test_groups.py`` (the task-groups precedent). Covers the two
create-response shapes (`NotificationGroup` by default, a single `Notification`
with `shared=True`), the request flag, per-instance hub registration + recipient
(with an absent name key), and the `NotificationActionInput` (payload shape,
validation, key+label both encrypted) plus `NotificationActionReply`
decoding. No network: `_post` is stubbed on the client to serve canned responses
and record request bodies. Run with

    python3 -m unittest discover tests

from python-library/.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import (  # noqa: E402
    Action, ActionStyle, Client, Notification, NotificationActionInput, NotificationActionReply,
    NotificationChoiceInput, NotificationChoiceReply, NotificationGroup,
    NotificationGroupRecipient, NotificationTextInput, NotificationTextReply,
)
from simplepush.client import _wrap_notification_reply  # noqa: E402
from simplepush.crypto import Decryptor, decrypt, encrypt  # noqa: E402


GROUP_RESPONSE = {
    "groupId": "grpntf_00000000-0000-7000-8000-000000000001",
    "createdAt": "2026-07-05T10:00:00Z",
    "groupWaitToken": "wt_group",
    "instances": [
        {"notificationId": "ntf_00000000-0000-7000-8000-00000000000a", "waitToken": "wt_a",
         "recipient": {"publicId": "usr_a", "name": "Alice"}},
        # A nameless recipient arrives WITHOUT a name key (zio-json omits None on
        # encode) — never as "name": null.
        {"notificationId": "ntf_00000000-0000-7000-8000-00000000000b", "waitToken": "wt_b",
         "recipient": {"publicId": "usr_b"}},
    ],
}

# Group send that resolved to zero recipients — a valid group with no instances.
EMPTY_GROUP_RESPONSE = {
    "groupId": "grpntf_00000000-0000-7000-8000-000000000002",
    "createdAt": "2026-07-05T10:00:00Z",
    "groupWaitToken": "wt_empty",
    "instances": [],
}

SHARED_RESPONSE = {
    "notificationId": "ntf_00000000-0000-7000-8000-00000000000c",
    "createdAt": "2026-07-05T10:00:00Z",
    "waitToken": "wt_s",
}


def make_client(responses, calls):
    """A personal client whose `_post` pops canned responses and records
    (path, body) — nothing touches the network."""
    client = Client("localhost", 8000, ssl=False, api_token="tok")
    queue = list(responses)

    def fake_post(path, body, headers=None):
        calls.append((path, body))
        return queue.pop(0)

    client._post = fake_post
    return client


class NotificationGroupSendTest(unittest.TestCase):

    def test_default_send_returns_notification_group(self):
        calls = []
        client = make_client([GROUP_RESPONSE], calls)
        group = client.send_notification(topic="alerts", content="hi")

        self.assertIsInstance(group, NotificationGroup)
        self.assertEqual(group.group_id, GROUP_RESPONSE["groupId"])
        self.assertEqual(group.wait_token, "wt_group")
        self.assertEqual(len(group), 2)
        self.assertEqual([n.notification_id for n in group],
                         [i["notificationId"] for i in GROUP_RESPONSE["instances"]])

        first = group.instances[0]
        self.assertIsInstance(first, Notification)
        self.assertEqual(first.wait_token, "wt_a")
        self.assertEqual(first.recipient,
                         NotificationGroupRecipient(public_id="usr_a", name="Alice"))
        # Absent name key normalizes to None (never "name": null on the wire).
        self.assertIsNone(group.instances[1].recipient.name)
        self.assertEqual(group.instances[1].recipient.public_id, "usr_b")

        # No `shared` key rides the request in default mode.
        path, body = calls[0]
        self.assertEqual(path, "/notifications/json")
        self.assertNotIn("shared", body)

        # Each instance is registered with the hub so its events buffer from now.
        for inst in GROUP_RESPONSE["instances"]:
            self.assertIn(inst["notificationId"], client._hub._buffers)

    def test_empty_group_is_valid_with_no_instances(self):
        client = make_client([EMPTY_GROUP_RESPONSE], [])
        group = client.send_notification(topic="alerts", content="hi")
        self.assertIsInstance(group, NotificationGroup)
        self.assertEqual(len(group), 0)

    def test_sole_unwraps_a_single_instance_group(self):
        one = dict(GROUP_RESPONSE, instances=[GROUP_RESPONSE["instances"][0]])
        client = make_client([one], [])
        group = client.send_notification(topic="alerts", content="hi")
        self.assertEqual(group.sole.notification_id,
                         GROUP_RESPONSE["instances"][0]["notificationId"])

    def test_sole_raises_unless_exactly_one(self):
        client = make_client([GROUP_RESPONSE], [])
        group = client.send_notification(topic="alerts", content="hi")
        with self.assertRaises(ValueError):
            group.sole

    def test_shared_sends_flag_and_returns_notification(self):
        calls = []
        client = make_client([SHARED_RESPONSE], calls)
        note = client.send_notification(topic="alerts", content="hi", shared=True)

        self.assertIsInstance(note, Notification)
        self.assertEqual(note.notification_id, SHARED_RESPONSE["notificationId"])
        self.assertEqual(note.wait_token, "wt_s")
        self.assertIs(calls[0][1].get("shared"), True)

    def test_group_send_carries_a_text_input(self):
        calls = []
        client = make_client([GROUP_RESPONSE], calls)
        client.send_notification(topic="alerts", input=NotificationTextInput())
        self.assertEqual(calls[0][1]["textInput"], {})


class NotificationActionInputTest(unittest.TestCase):

    def test_action_input_builds_action_payload(self):
        calls = []
        client = make_client([GROUP_RESPONSE], calls)
        client.send_notification(
            topic="alerts",
            title="Approve deploy?",
            input=NotificationActionInput(actions=[
                Action(key="approve", label="Approve"),
                Action(key="deny", label="Deny", style="destructive"),
            ]),
        )
        body = calls[0][1]
        self.assertNotIn("choiceInput", body)
        self.assertNotIn("textInput", body)
        self.assertEqual(body["actionInput"], {"actions": [
            {"key": "approve", "label": "Approve"},
            {"key": "deny", "label": "Deny", "style": "destructive"},
        ]})

    def test_action_input_rejects_empty_and_duplicate_keys(self):
        client = make_client([GROUP_RESPONSE, GROUP_RESPONSE], [])
        with self.assertRaises(ValueError):
            client.send_notification(topic="alerts", input=NotificationActionInput(actions=[]))
        with self.assertRaises(ValueError):
            client.send_notification(topic="alerts", input=NotificationActionInput(actions=[
                Action(key="dup", label="A"), Action(key="dup", label="B"),
            ]))

    def test_wrong_input_type_raises_typeerror(self):
        client = make_client([GROUP_RESPONSE], [])
        with self.assertRaises(TypeError):
            client.send_notification(topic="alerts", input="not-an-input")

    def test_action_input_encrypts_keys_and_labels(self):
        # Needs the crypto extra (pynacl). BOTH the key and the label are sealed
        # under the topic password, exactly like a task's actions input — the key
        # carries the same meaning as the label, so leaving it plaintext would
        # leak the intent. `style` stays plaintext (a fixed render enum).
        try:
            import nacl  # noqa: F401
        except ImportError:
            self.skipTest("pynacl not installed")
        calls = []
        client = make_client([GROUP_RESPONSE], calls)
        client.send_notification(
            topic="alerts", password="hunter2",
            input=NotificationActionInput(actions=[
                Action(key="approve", label="Approve", style=ActionStyle.PRIMARY),
            ]),
        )
        action = calls[0][1]["actionInput"]["actions"][0]
        self.assertNotEqual(action["key"], "approve")       # ciphertext
        self.assertNotEqual(action["label"], "Approve")     # ciphertext
        self.assertEqual(action["style"], "primary")        # plaintext render hint
        self.assertEqual(calls[0][1]["encryption"]["type"], "personal")
        # Round-trips: the recipient decrypts both under the same topic key.
        dec = Decryptor.from_password("hunter2", "alerts")
        self.assertEqual(decrypt(action["key"], dec._dk.symmetric_key), "approve")
        self.assertEqual(decrypt(action["label"], dec._dk.symmetric_key), "Approve")

    def test_action_input_plaintext_send_keeps_keys_and_labels_clear(self):
        # Without a password nothing is encrypted — the guard against a stray
        # encrypt() on the plaintext path.
        calls = []
        client = make_client([GROUP_RESPONSE], calls)
        client.send_notification(
            topic="alerts",
            input=NotificationActionInput(actions=[Action(key="approve", label="Approve")]),
        )
        action = calls[0][1]["actionInput"]["actions"][0]
        self.assertEqual(action["key"], "approve")
        self.assertEqual(action["label"], "Approve")
        self.assertNotIn("encryption", calls[0][1])


class NotificationActionReplyTest(unittest.TestCase):

    def test_actions_reply_decrypts_key(self):
        # The recipient encrypts the tapped key on the wire (server-blind), just
        # like a task action upload — it must be decrypted via the event marker.
        dec = Decryptor.from_password("hunter2", "alerts")
        marker = {"type": "personal", "passwordFingerprint": dec.fingerprint}
        ct = encrypt("approve", dec._dk.symmetric_key)
        reply = _wrap_notification_reply({"type": "actions", "selectedKey": ct}, marker, dec)
        self.assertEqual(reply, NotificationActionReply(selected_key="approve"))

    def test_actions_reply_passes_through_without_key(self):
        # No decryptor/marker: the raw ciphertext is passed through unchanged.
        reply = _wrap_notification_reply({"type": "actions", "selectedKey": "cipher=="}, None, None)
        self.assertEqual(reply, NotificationActionReply(selected_key="cipher=="))

    def test_text_and_choice_replies_still_decode(self):
        self.assertEqual(
            _wrap_notification_reply({"type": "text", "value": "hi"}, None, None),
            NotificationTextReply(value="hi"),
        )
        self.assertEqual(
            _wrap_notification_reply({"type": "choice", "selectedIndex": 1, "selectedValue": "mute"}, None, None),
            NotificationChoiceReply(selected_index=1, selected_value="mute"),
        )


if __name__ == "__main__":
    unittest.main()
