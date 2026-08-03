"""Unit tests for observing submissions (the `Submission` view, body decryption
via the keyring, and downloadable photo/file). No network: a stub transport
stands in for the presign POST + S3 GET.

Run with `python3 -m unittest discover tests` from python-library/.
"""

import base64
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush.client import (  # noqa: E402
    DownloadError,
    Event,
    Submission,
    SubmissionFile,
    SubmissionAudio,
    TextBody,
    _FileBinder,
    _wrap_reply_location,
    _wrap_submission,
    _wrap_upload,
    LocationUpload,
)

try:
    from simplepush.crypto import Keyring, derive_key, encrypt
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def _checksum(blob: bytes) -> str:
    return base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")


class StubTransport:
    def __init__(self, blob: bytes, url: str = "https://s3.example/presigned"):
        self.blob = blob
        self.url = url
        self.presign_calls: list[tuple[str, str, str, str]] = []

    def presign(self, scope: str, scope_id: str, kind: str, file_id: str) -> dict:
        self.presign_calls.append((scope, scope_id, kind, file_id))
        return {"presignedGetUrl": self.url, "expiresAt": "2026-06-13T00:00:00Z"}

    def get(self, url: str) -> bytes:
        return self.blob


def _event(submission: dict) -> Event:
    return Event.from_raw({"eventType": "SubmissionCreated",
                           "data": {"type": "submissionCreated", "submission": submission}})


class WrapSubmissionTest(unittest.IsolatedAsyncioTestCase):
    def _binder(self, transport, decryptor=None):
        return _FileBinder(transport, "submissions", None, decryptor)

    def test_wraps_text_body_and_metadata(self):
        ev = _event({"id": "sbm-1", "body": {"type": "text", "value": "hello"}, "createdAt": "2026-06-13T00:00:00Z"})
        sub = _wrap_submission(ev, None, None)
        self.assertIsInstance(sub, Submission)
        self.assertEqual(sub.id, "sbm-1")
        self.assertEqual(sub.body, TextBody(text="hello"))
        self.assertIsNone(sub.photo)
        self.assertIsNone(sub.file)

    async def test_photo_and_file_are_downloadable_against_submission_path(self):
        blob = b"submission photo bytes"
        transport = StubTransport(blob)
        ev = _event({
            "id": "sbm-3",
            "photo": {"id": "sbf-1", "contentType": "image/jpeg", "checksumSha256": _checksum(blob), "size": len(blob)},
            "file": {"id": "sbf-2", "contentType": "application/pdf", "checksumSha256": _checksum(blob),
                     "size": len(blob), "filename": "doc.pdf"},
        })
        sub = _wrap_submission(ev, None, self._binder(transport))
        self.assertIsInstance(sub.photo, SubmissionFile)
        self.assertEqual(await sub.photo.read(), blob)
        self.assertEqual(await sub.file.read(), blob)
        # Scope is `submissions`, scope_id is the per-event submission id, kind `files`.
        self.assertEqual(transport.presign_calls, [
            ("submissions", "sbm-3", "files", "sbf-1"),
            ("submissions", "sbm-3", "files", "sbf-2"),
        ])

    async def test_audio_is_downloadable_with_duration_seconds(self):
        blob = b"submission audio bytes"
        transport = StubTransport(blob)
        ev = _event({
            "id": "sbm-8",
            "audio": {"id": "sba-1", "contentType": "audio/mpeg", "checksumSha256": _checksum(blob),
                      "size": len(blob), "durationSeconds": 5.25, "filename": "voice.mp3"},
        })
        sub = _wrap_submission(ev, None, self._binder(transport))
        self.assertIsInstance(sub.audio, SubmissionAudio)
        self.assertEqual(await sub.audio.read(), blob)
        self.assertEqual(sub.audio.duration_seconds, 5.25)
        self.assertEqual(sub.audio.filename, "voice.mp3")
        self.assertEqual(transport.presign_calls, [("submissions", "sbm-8", "files", "sba-1")])

    async def test_unbound_file_rejects_download(self):
        ev = _event({"id": "sbm-4", "photo": {"id": "sbf-9", "contentType": "image/png",
                                              "checksumSha256": None, "size": 1}})
        sub = _wrap_submission(ev, None, None)  # no binder → unbound
        with self.assertRaises(DownloadError):
            await sub.photo.read()

    def test_pattern_matching_on_body(self):
        ev = _event({"id": "sbm-5", "body": {"type": "text", "value": "x"}})
        sub = _wrap_submission(ev, None, None)
        match sub.body:
            case TextBody(text=t):
                self.assertEqual(t, "x")
            case _:
                self.fail("expected TextBody")


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class EncryptedSubmissionTest(unittest.IsolatedAsyncioTestCase):
    """Body text decrypts via the client keyring (submissions are unsolicited —
    no per-send key)."""

    def test_body_decrypts_with_keyring(self):
        password, topic = "secret", "alerts"
        dk = derive_key(password, topic)
        keyring = Keyring.build(passwords=[password], topics=[topic])
        ciphertext = encrypt("classified", dk.symmetric_key)
        marker = {"type": "personal", "keyFingerprint": dk.fingerprint}
        ev = _event({"id": "sbm-6", "body": {"type": "text", "value": ciphertext}, "encryption": marker})
        sub = _wrap_submission(ev, keyring, None)
        self.assertEqual(sub.body, TextBody(text="classified"))

    def test_body_without_key_passes_ciphertext_through(self):
        marker = {"type": "personal", "keyFingerprint": "unknown"}
        ev = _event({"id": "sbm-7", "body": {"type": "text", "value": "ciphertext-blob"}, "encryption": marker})
        keyring = Keyring.build(passwords=["other"], topics=["t"])
        sub = _wrap_submission(ev, keyring, None)
        self.assertEqual(sub.body, TextBody(text="ciphertext-blob"))


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class SubmissionsPasswordOverrideTest(unittest.TestCase):
    """`Client.submissions(password=...)` folds that account key for the call;
    `OrgClient` has no such parameter."""

    def test_per_call_password_folds_account_key(self):
        from simplepush import Client
        client = Client(api_token="tok")  # no constructor default password
        client._fetch_password_salt = lambda: "server-salt"
        client.submissions(password="given-pw")  # supply it at call time
        dk = derive_key("given-pw", "server-salt")
        marker = {"type": "personal", "keyFingerprint": dk.fingerprint}
        ct = encrypt("secret", dk.symmetric_key)
        self.assertEqual(client.keyring().try_decrypt_marker(ct, marker), "secret")

    def test_salt_is_fetched_once_across_calls(self):
        from simplepush import Client
        client = Client(api_token="tok", passwords="acct")
        calls = []
        client._fetch_password_salt = lambda: (calls.append(1), "salt")[1]
        client.submissions()
        client.submissions(password="another")
        self.assertEqual(len(calls), 1)  # salt cached after the first fetch

    def test_org_client_submissions_has_no_password_param(self):
        import inspect
        from simplepush import OrgClient
        self.assertNotIn("password", inspect.signature(OrgClient.submissions).parameters)


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class DefaultKeyFoldTest(unittest.TestCase):
    """submissions() folds the personal default key (password + server
    password_salt) into the keyring — submissions encrypt under it, not a topic
    key."""

    def test_default_key_is_folded_for_decryption(self):
        from simplepush import Client

        salt, password = "server-salt-xyz", "hunter2"
        client = Client(api_token="tok", passwords=password)  # bare string = default password
        client._fetch_password_salt = lambda: salt  # stub GET /v1/user

        client.submissions()  # triggers the fold

        dk = derive_key(password, salt)
        marker = {"type": "personal", "keyFingerprint": dk.fingerprint}
        ciphertext = encrypt("secret", dk.symmetric_key)
        # The keyring now resolves content encrypted under the default key.
        self.assertEqual(client.keyring().try_decrypt_marker(ciphertext, marker), "secret")

    def test_no_default_password_means_no_fetch(self):
        from simplepush import Client

        client = Client(api_token="tok")  # no password
        called = []
        client._fetch_password_salt = lambda: called.append(True) or "x"
        client.submissions()
        self.assertEqual(called, [])  # nothing fetched without a default password


class PasswordsArgTest(unittest.TestCase):
    """The personal-client `passwords` argument: pairs → topic keys (and the send
    default for that topic); at most one bare string → the account default
    password (decryption-only, never a send password)."""

    def test_parse_string_is_default(self):
        from simplepush.api import _parse_passwords
        self.assertEqual(_parse_passwords("pw"), ([], "pw"))

    def test_parse_mixed_list(self):
        from simplepush.api import _parse_passwords
        topic_pw, default_pw = _parse_passwords([("a", "alerts"), ("b", "deploys"), "acct"])
        self.assertEqual(topic_pw, [("a", "alerts"), ("b", "deploys")])
        self.assertEqual(default_pw, "acct")

    def test_parse_rejects_bad_entry(self):
        from simplepush.api import _parse_passwords
        with self.assertRaises(ValueError):
            _parse_passwords([("only-one",)])
        with self.assertRaises(ValueError):
            _parse_passwords([123])

    def test_parse_rejects_multiple_defaults(self):
        from simplepush.api import _parse_passwords
        with self.assertRaises(ValueError):
            _parse_passwords(["one", "two"])  # only one default password allowed

    def test_send_password_is_topic_pair_only_never_default(self):
        from simplepush import Client
        client = Client(api_token="tok", passwords=[("a", "alerts"), "acct"])
        self.assertEqual(client._send_password("alerts"), "a")     # topic pair
        self.assertIsNone(client._send_password("other"))          # NO default fallback
        self.assertIsNone(Client(api_token="tok")._send_password("x"))  # nothing configured


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class KeyringFromPairsTest(unittest.TestCase):
    def test_topic_pairs_become_topic_keys(self):
        from simplepush import Client
        client = Client(api_token="tok", passwords=[("topicpw", "alerts")])
        dk = derive_key("topicpw", "alerts")
        marker = {"type": "personal", "keyFingerprint": dk.fingerprint}
        ct = encrypt("hi", dk.symmetric_key)
        self.assertEqual(client.keyring().try_decrypt_marker(ct, marker), "hi")


def _org_client_has_no_password_args():
    import inspect
    from simplepush import OrgClient
    return "passwords" not in inspect.signature(OrgClient.__init__).parameters \
        and "topics" not in inspect.signature(OrgClient.__init__).parameters


class OrgClientNoPasswordsTest(unittest.TestCase):
    def test_org_client_rejects_passwords_and_topics(self):
        self.assertTrue(_org_client_has_no_password_args())


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class SubmissionLocationTest(unittest.IsolatedAsyncioTestCase):
    """Location field on submissions: an inline value (decrypted via the body's
    marker, like the text body), NOT a downloadable file. Unencrypted chains
    carry structured fields; encrypted chains carry only `encrypted` (the
    ciphertext of the coords JSON)."""

    def test_plaintext_location_from_structured_fields(self):
        from simplepush.client import Location
        ev = _event({
            "id": "sbm-loc-1",
            "location": {
                "latitude": 37.7749,
                "longitude": -122.4194,
                "accuracy": 5.0,
                "altitude": 10.0,
                "heading": 90.0,
                "speed": 2.5,
                "timestamp": 1234567890000,
            },
        })
        sub = _wrap_submission(ev, None, None)
        self.assertIsInstance(sub.location, Location)
        self.assertEqual(sub.location.latitude, 37.7749)
        self.assertEqual(sub.location.longitude, -122.4194)
        self.assertEqual(sub.location.accuracy, 5.0)
        self.assertEqual(sub.location.altitude, 10.0)
        self.assertEqual(sub.location.heading, 90.0)
        self.assertEqual(sub.location.speed, 2.5)
        self.assertEqual(sub.location.timestamp, 1234567890000)

    def test_encrypted_location_decrypts_json_coords(self):
        import json
        from simplepush.client import Location
        password, topic = "secret", "alerts"
        dk = derive_key(password, topic)
        keyring = Keyring.build(passwords=[password], topics=[topic])
        coords = {
            "latitude": 40.7128,
            "longitude": -74.0060,
            "accuracy": 10.0,
            "altitude": 20.0,
            "heading": 180.0,
            "speed": 1.5,
            "timestamp": 9876543210000,
        }
        ciphertext = encrypt(json.dumps(coords), dk.symmetric_key)
        marker = {"type": "personal", "keyFingerprint": dk.fingerprint}
        ev = _event({
            "id": "sbm-loc-2",
            "location": {"encrypted": ciphertext},
            "encryption": marker,
        })
        sub = _wrap_submission(ev, keyring, None)
        self.assertIsInstance(sub.location, Location)
        self.assertEqual(sub.location.latitude, 40.7128)
        self.assertEqual(sub.location.longitude, -74.0060)
        self.assertEqual(sub.location.accuracy, 10.0)
        self.assertEqual(sub.location.altitude, 20.0)
        self.assertEqual(sub.location.heading, 180.0)
        self.assertEqual(sub.location.speed, 1.5)
        self.assertEqual(sub.location.timestamp, 9876543210000)

    def test_encrypted_location_without_key_returns_none(self):
        import json
        coords = {"latitude": 0.0, "longitude": 0.0}
        dk = derive_key("secret", "alerts")
        ciphertext = encrypt(json.dumps(coords), dk.symmetric_key)
        # A marker whose fingerprint the keyring can't resolve → undecryptable.
        marker = {"type": "personal", "keyFingerprint": "wrong"}
        ev = _event({
            "id": "sbm-loc-3",
            "location": {"encrypted": ciphertext},
            "encryption": marker,
        })
        keyring = Keyring.build(passwords=["other"], topics=["t"])
        sub = _wrap_submission(ev, keyring, None)
        self.assertIsNone(sub.location)

    def test_location_with_partial_fields(self):
        from simplepush.client import Location
        ev = _event({
            "id": "sbm-loc-4",
            "location": {"latitude": 35.0, "longitude": -120.0},
        })
        sub = _wrap_submission(ev, None, None)
        self.assertIsInstance(sub.location, Location)
        self.assertEqual(sub.location.latitude, 35.0)
        self.assertEqual(sub.location.longitude, -120.0)
        self.assertIsNone(sub.location.accuracy)
        self.assertIsNone(sub.location.altitude)
        self.assertIsNone(sub.location.heading)
        self.assertIsNone(sub.location.speed)
        self.assertIsNone(sub.location.timestamp)

    def test_missing_location_is_none(self):
        ev = _event({"id": "sbm-loc-5"})
        sub = _wrap_submission(ev, None, None)
        self.assertIsNone(sub.location)


class WrapUploadLocationTest(unittest.TestCase):
    """A submitted `location` TASK INPUT answer (distinct from the reply/submission
    `location` field). The backend's LocationUploadedEvent (discriminator
    "locationUploaded") FLATTENS the coordinate fields directly onto the upload
    object — there is NO nested `location` key. Pins both wire facts: any other
    discriminator or shape would make received location answers silently
    vanish."""

    def test_plaintext_location_upload_decodes_flattened_coords(self):
        from simplepush.client import Location
        u = {"type": "locationUploaded", "id": "in-loc-1",
             "latitude": 48.8566, "longitude": 2.3522, "accuracy": 7.0}
        up = _wrap_upload(u, None, None, None)
        self.assertIsInstance(up, LocationUpload)
        self.assertEqual(up.id, "in-loc-1")
        self.assertIsInstance(up.location, Location)
        self.assertEqual(up.location.latitude, 48.8566)
        self.assertEqual(up.location.longitude, 2.3522)
        self.assertEqual(up.location.accuracy, 7.0)

    def test_invented_discriminator_is_not_decoded(self):
        # "locationSubmitted" is not a wire discriminator — unknown types drop.
        up = _wrap_upload({"type": "locationSubmitted", "id": "x", "latitude": 1.0}, None, None, None)
        self.assertNotIsInstance(up, LocationUpload)
        self.assertIsNone(up)


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class WrapUploadEncryptedLocationTest(unittest.TestCase):
    def test_encrypted_location_upload_decrypts_via_marker(self):
        import json
        from simplepush.client import Location
        password, topic = "secret", "alerts"
        dk = derive_key(password, topic)
        keyring = Keyring.build(passwords=[password], topics=[topic])
        coords = {"latitude": 40.7128, "longitude": -74.006, "accuracy": 12.0}
        ciphertext = encrypt(json.dumps(coords), dk.symmetric_key)
        marker = {"type": "personal", "keyFingerprint": dk.fingerprint}
        u = {"type": "locationUploaded", "id": "in-loc-2", "encrypted": ciphertext}
        up = _wrap_upload(u, marker, keyring, None)
        self.assertIsInstance(up, LocationUpload)
        self.assertEqual(up.location.latitude, 40.7128)
        self.assertEqual(up.location.longitude, -74.006)
        self.assertEqual(up.location.accuracy, 12.0)


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class OrgEncryptedLocationTest(unittest.TestCase):
    """ORG-mode location decode, exercising the real org key path: a 32-byte org
    master key folded into a `Keyring` at version V, content encrypted under it,
    and an `{"type": "org", "v": V}` marker resolved via the keyring's
    `_by_version` map. No stub decryptor — the real `Keyring`/`add_org` resolves
    the version. Covers BOTH decode sites that share `_wrap_reply_location`'s
    `try_decrypt_marker` + `json.loads`:

      (a) the NESTED reply/submission `location` field, and
      (b) the FLATTENED task-input answer (discriminator `locationUploaded`,
          coords flattened onto the upload dict).

    These MUST fail if the org marker were mishandled (e.g. resolved by
    fingerprint, ignored as a personal-only marker, or the version dropped)."""

    def _org_keyring(self, version):
        """A Keyring holding a fresh 32-byte org master key at `version`, plus a
        decoy personal key — so resolution must go through the org `v` branch,
        not fall through to a fingerprint match."""
        org_key = os.urandom(32)
        keyring = Keyring.build(passwords=["decoy-personal-pw"], topics=["decoy-topic"])
        keyring.add_org(version, org_key)
        return keyring, org_key

    def test_nested_reply_submission_location_decrypts_via_org_marker(self):
        import json
        from simplepush.client import Location
        version = 7
        keyring, org_key = self._org_keyring(version)
        coords = {
            "latitude": 51.5074,
            "longitude": -0.1278,
            "accuracy": 8.0,
            "altitude": 35.0,
            "heading": 270.0,
            "speed": 3.0,
            "timestamp": 1718000000000,
        }
        ciphertext = encrypt(json.dumps(coords), org_key)
        marker = {"type": "org", "v": version}
        loc = _wrap_reply_location({"encrypted": ciphertext}, marker, keyring)
        self.assertIsInstance(loc, Location)
        self.assertEqual(loc.latitude, 51.5074)
        self.assertEqual(loc.longitude, -0.1278)
        self.assertEqual(loc.accuracy, 8.0)
        self.assertEqual(loc.altitude, 35.0)
        self.assertEqual(loc.heading, 270.0)
        self.assertEqual(loc.speed, 3.0)
        self.assertEqual(loc.timestamp, 1718000000000)

    def test_flattened_location_upload_decrypts_via_org_marker(self):
        import json
        from simplepush.client import Location
        version = 4
        keyring, org_key = self._org_keyring(version)
        coords = {"latitude": 35.6895, "longitude": 139.6917, "accuracy": 6.0}
        ciphertext = encrypt(json.dumps(coords), org_key)
        marker = {"type": "org", "v": version}
        # FLATTENED: coords ciphertext sits directly on the upload dict as
        # `encrypted`, no nested `location` key.
        up = _wrap_upload(
            {"type": "locationUploaded", "id": "in-org-loc-1", "encrypted": ciphertext},
            marker, keyring, None,
        )
        self.assertIsInstance(up, LocationUpload)
        self.assertEqual(up.id, "in-org-loc-1")
        self.assertIsInstance(up.location, Location)
        self.assertEqual(up.location.latitude, 35.6895)
        self.assertEqual(up.location.longitude, 139.6917)
        self.assertEqual(up.location.accuracy, 6.0)

    def test_org_marker_wrong_version_does_not_decrypt(self):
        # Encrypted under the held key, but the marker claims a version the
        # keyring doesn't hold → must NOT resolve (no cross-version key reuse).
        import json
        version = 9
        keyring, org_key = self._org_keyring(version)
        ciphertext = encrypt(json.dumps({"latitude": 1.0, "longitude": 2.0}), org_key)
        marker = {"type": "org", "v": version + 1}  # unheld version
        self.assertIsNone(_wrap_reply_location({"encrypted": ciphertext}, marker, keyring))
        up = _wrap_upload(
            {"type": "locationUploaded", "id": "x", "encrypted": ciphertext},
            marker, keyring, None,
        )
        self.assertIsInstance(up, LocationUpload)
        self.assertIsNone(up.location)  # undecryptable → location degrades to None


if __name__ == "__main__":
    unittest.main()
