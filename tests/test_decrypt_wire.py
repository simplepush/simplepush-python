"""Unit tests for the field-schema wire decryptors: payloads are sealed the way
the send side seals them, and exactly those fields come back as plaintext.

Run with `python3 -m unittest discover tests` from simplepush-python/.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from simplepush import DerivedKey, Keyring, encrypt  # noqa: E402
    from simplepush.decrypt import (  # noqa: E402
        decrypt_event, decrypt_submission, decrypt_task_payload, decrypt_task_summary,
    )
    HAVE_CRYPTO = True
except Exception:  # crypto extra missing
    HAVE_CRYPTO = False

KEY = bytes([7]) * 32
OTHER_KEY = bytes([9]) * 32
FP = "test-fp"
MARKER = {"type": "personal", "keyFingerprint": FP}

# 64 hex chars of pure base64 alphabet: plaintext that must survive untouched.
CHECKSUM = "a" * 32 + "0123456789abcdef0123456789abcdef"
BASE64ISH_ANSWER = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0MjQyNDI0Mg=="


@unittest.skipUnless(HAVE_CRYPTO, "crypto extra required")
class DecryptWireTest(unittest.TestCase):
    def setUp(self):
        self.ring = Keyring()
        self.ring.add(DerivedKey(symmetric_key=KEY, fingerprint=FP))

    def e(self, s: str) -> str:
        return encrypt(s, KEY)

    def test_task_payload_opens_exactly_the_sealed_fields(self):
        payload = {
            "id": "tsk_x",
            "title": self.e("Pool pH check"),
            "content": self.e("Log the readings"),
            "status": "pending",
            "encryption": MARKER,
            "attachments": [{"type": "link", "url": self.e("https://example.com/manual")}],
            "inputs": [
                {"type": "text", "id": "inp_1", "required": True, "description": self.e("Pressure (bar)"), "defaultValue": self.e("7")},
                {"type": "choice", "id": "inp_2", "required": True, "options": [self.e("Yes"), self.e("No")], "multi": False},
                {"type": "actions", "id": "inp_3", "required": True, "actions": [{"key": self.e("ok"), "label": self.e("Done"), "style": "primary"}]},
                {"type": "slider", "id": "inp_4", "required": True, "encrypted": self.e(json.dumps({"min": 0, "max": 14, "step": 0.5, "unit": "pH"}))},
                {"type": "photo", "id": "inp_5", "required": False},
            ],
            "uploads": [
                {"type": "textUploaded", "id": "inp_1", "value": self.e("8.5")},
                {"type": "fileUploaded", "id": "inp_5", "filename": "report.pdf", "checksumSha256": CHECKSUM, "objectKey": CHECKSUM},
            ],
            "replies": [{
                "id": "rpl_1", "authorPublicUserId": "usr_a",
                "body": {"type": "text", "value": self.e("All good")},
                "encryption": MARKER, "createdAt": "2026-08-27T10:00:00Z",
            }],
            "declines": [{"by": "usr_b", "reason": "other", "note": self.e("On vacation"), "encryption": MARKER, "declinedAt": "2026-08-27T10:00:00Z"}],
        }
        out = decrypt_task_payload(payload, self.ring)
        p = out.value
        self.assertEqual(out.undecryptable, 0)
        self.assertEqual(p["title"], "Pool pH check")
        self.assertEqual(p["content"], "Log the readings")
        self.assertNotIn("encryption", p)
        self.assertEqual(p["attachments"][0]["url"], "https://example.com/manual")
        self.assertEqual(p["inputs"][0]["description"], "Pressure (bar)")
        self.assertEqual(p["inputs"][0]["defaultValue"], "7")
        self.assertEqual(p["inputs"][1]["options"], ["Yes", "No"])
        self.assertEqual(p["inputs"][2]["actions"][0], {"key": "ok", "label": "Done", "style": "primary"})
        self.assertEqual({k: p["inputs"][3][k] for k in ("min", "max", "step", "unit")}, {"min": 0, "max": 14, "step": 0.5, "unit": "pH"})
        self.assertNotIn("encrypted", p["inputs"][3])
        self.assertEqual(p["uploads"][0]["value"], "8.5")
        self.assertEqual(p["uploads"][1]["checksumSha256"], CHECKSUM)
        self.assertEqual(p["uploads"][1]["objectKey"], CHECKSUM)
        self.assertEqual(p["replies"][0]["body"]["value"], "All good")
        self.assertEqual(p["declines"][0]["note"], "On vacation")
        # The input is not mutated.
        self.assertNotEqual(payload["title"], "Pool pH check")

    def test_plaintext_payload_passes_through(self):
        payload = {"id": "tsk_y", "title": "Plain", "status": "pending", "inputs": [],
                   "uploads": [{"type": "textUploaded", "id": "inp_1", "value": BASE64ISH_ANSWER}]}
        out = decrypt_task_payload(payload, self.ring)
        self.assertEqual(out.undecryptable, 0)
        self.assertEqual(out.value["uploads"][0]["value"], BASE64ISH_ANSWER)

    def test_unheld_key_is_counted_not_mangled(self):
        foreign = encrypt("secret", OTHER_KEY)
        payload = {"id": "tsk_z", "title": foreign, "status": "pending", "encryption": {"type": "personal", "keyFingerprint": "unknown-fp"}}
        out = decrypt_task_payload(payload, self.ring)
        self.assertEqual(out.undecryptable, 1)
        self.assertEqual(out.value["title"], foreign)

    def test_upload_own_marker_wins(self):
        payload = {"id": "tsk_r", "title": self.e("t"), "status": "pending", "encryption": MARKER,
                   "uploads": [{"type": "textUploaded", "id": "inp_1", "value": self.e("rotated"), "encryption": MARKER}]}
        out = decrypt_task_payload(payload, self.ring)
        self.assertEqual(out.undecryptable, 0)
        self.assertEqual(out.value["uploads"][0]["value"], "rotated")
        self.assertNotIn("encryption", out.value["uploads"][0])

    def test_summary_title_only(self):
        out = decrypt_task_summary(
            {"taskId": "tsk_s", "title": self.e("Sealed title"), "tag": self.e("safety"), "topic": "alerts", "status": "pending", "recipients": [], "subtasks": {}, "inputs": ["text"], "encryption": MARKER},
            self.ring,
        )
        self.assertEqual(out.undecryptable, 0)
        self.assertEqual(out.value["title"], "Sealed title")
        self.assertEqual(out.value["tag"], "safety")
        self.assertEqual(out.value["topic"], "alerts")
        self.assertEqual(out.value["inputs"], ["text"])

    def test_submission_body_and_location(self):
        out = decrypt_submission(
            {"id": "sbm_1", "body": {"type": "text", "value": self.e("pump 3 leaking")},
             "location": {"encrypted": self.e(json.dumps({"latitude": 48.1, "longitude": 11.5}))},
             "createdAt": "2026-08-27T09:00:00Z"},
            self.ring, MARKER,
        )
        self.assertEqual(out.undecryptable, 0)
        self.assertEqual(out.value["body"]["value"], "pump 3 leaking")
        self.assertEqual(out.value["location"]["latitude"], 48.1)
        self.assertNotIn("encrypted", out.value["location"])

    def test_event_field_maps(self):
        answer = decrypt_event(
            {"version": 1, "type": "TaskInputCompleted", "encryption": MARKER,
             "data": {"type": "taskInputCompleted", "taskId": "tsk_1",
                      "inputUploaded": {"type": "choiceSelected", "id": "inp_1", "selectedIndex": 0, "selectedValue": self.e("Yes")}}},
            self.ring,
        )
        self.assertEqual(answer.undecryptable, 0)
        self.assertEqual(answer.value["data"]["inputUploaded"]["selectedValue"], "Yes")

        reply = decrypt_event(
            {"version": 2, "type": "ReplyAppended", "encryption": MARKER,
             "data": {"type": "replyAppended", "reply": {"id": "rpl_1", "body": {"type": "text", "value": self.e("On it")}}}},
            self.ring,
        )
        self.assertEqual(reply.value["data"]["reply"]["body"]["value"], "On it")

        ntf = decrypt_event(
            {"version": 3, "type": "NotificationCompleted", "encryption": MARKER,
             "data": {"type": "notificationCompleted", "notificationId": "ntf_1", "reply": {"type": "actions", "selectedKey": self.e("ack")}}},
            self.ring,
        )
        self.assertEqual(ntf.value["data"]["reply"]["selectedKey"], "ack")

        cancel = decrypt_event(
            {"version": 4, "type": "TaskCanceled", "encryption": MARKER,
             "data": {"type": "taskCanceled", "taskId": "tsk_1", "reason": "canceled", "note": self.e("Sent by mistake")}},
            self.ring,
        )
        self.assertEqual(cancel.value["data"]["note"], "Sent by mistake")
        self.assertEqual(cancel.value["data"]["reason"], "canceled")

    def test_unencrypted_event_passes_through(self):
        ev = {"version": 5, "type": "TaskCompleted",
              "data": {"type": "taskCompleted", "taskId": "tsk_1", "inputsUploaded": [{"type": "textUploaded", "id": "i", "value": BASE64ISH_ANSWER}]}}
        out = decrypt_event(ev, self.ring)
        self.assertEqual(out.undecryptable, 0)
        self.assertEqual(out.value["data"]["inputsUploaded"][0]["value"], BASE64ISH_ANSWER)


if __name__ == "__main__":
    unittest.main()
