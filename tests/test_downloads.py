"""Unit tests for file downloads (the _DownloadableFile surface on
PhotoUpload/VoiceUpload/FileUpload/ReplyFile).

No network: a stub transport stands in for the presign POST + S3 GET. Run with

    python3 -m unittest discover tests

from python-library/.
"""

import asyncio
import base64
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush.client import (  # noqa: E402
    DownloadError,
    Event,
    FileUpload,
    PhotoUpload,
    ReplyFile,
    ReplyAudio,
    _FileBinder,
    _FileContext,
    _wrap_input,
    _wrap_reply,
)

try:
    from simplepush.crypto import OrgDecryptor, encrypt
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def _checksum(blob: bytes) -> str:
    return base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")


class StubTransport:
    """Records presign/get calls and serves canned bytes."""

    def __init__(self, blob: bytes, url: str = "https://s3.example/presigned"):
        self.blob = blob
        self.url = url
        self.presign_calls: list[tuple[str, str, str, str]] = []
        self.get_calls: list[str] = []

    def presign(self, scope: str, scope_id: str, kind: str, file_id: str) -> dict:
        self.presign_calls.append((scope, scope_id, kind, file_id))
        return {"presignedGetUrl": self.url, "expiresAt": "2026-06-12T00:00:00Z"}

    def get(self, url: str) -> bytes:
        self.get_calls.append(url)
        return self.blob


def _ctx(transport, scope="tasks", scope_id="task-1", marker=None, decryptor=None) -> _FileContext:
    return _FileContext(transport, scope, scope_id, marker, decryptor)


class PlainDownloadTest(unittest.IsolatedAsyncioTestCase):

    async def test_read_returns_bytes_and_verifies_checksum(self):
        blob = b"hello plaintext file"
        transport = StubTransport(blob)
        photo = PhotoUpload(id="in-1", content_type="image/jpeg",
                            checksum_sha256=_checksum(blob), size=len(blob),
                            _ctx=_ctx(transport))
        data = await photo.read()
        self.assertEqual(data, blob)
        self.assertEqual(transport.presign_calls, [("tasks", "task-1", "inputs", "in-1")])
        self.assertEqual(transport.get_calls, [transport.url])

    async def test_checksum_mismatch_raises(self):
        transport = StubTransport(b"tampered bytes")
        photo = PhotoUpload(id="in-1", content_type="image/jpeg",
                            checksum_sha256=_checksum(b"original bytes"), size=14,
                            _ctx=_ctx(transport))
        with self.assertRaises(DownloadError):
            await photo.read()

    async def test_download_url_presigns_lazily(self):
        transport = StubTransport(b"")
        f = FileUpload(id="in-2", content_type="application/pdf",
                       checksum_sha256=None, size=0, _ctx=_ctx(transport))
        url, expires = await f.download_url()
        self.assertEqual(url, transport.url)
        self.assertEqual(expires, "2026-06-12T00:00:00Z")
        self.assertEqual(transport.get_calls, [])  # nothing fetched

    async def test_unbound_object_raises(self):
        photo = PhotoUpload(id="in-1", content_type="image/jpeg",
                            checksum_sha256=None, size=0)
        with self.assertRaises(DownloadError):
            await photo.read()

    async def test_save_uses_filename_then_id_fallback(self):
        blob = b"file body"
        transport = StubTransport(blob)
        with tempfile.TemporaryDirectory() as tmp:
            named = ReplyFile(id="rf-1", content_type="application/pdf",
                              checksum_sha256=_checksum(blob), size=len(blob),
                              filename="report.pdf", _ctx=_ctx(transport))
            path = await named.save(tmp)
            self.assertEqual(os.path.basename(path), "report.pdf")
            with open(path, "rb") as f:
                self.assertEqual(f.read(), blob)

            unnamed = PhotoUpload(id="in-9", content_type="image/png",
                                  checksum_sha256=None, size=len(blob),
                                  _ctx=_ctx(transport))
            path2 = await unnamed.save(tmp)
            self.assertEqual(os.path.basename(path2), "in-9.png")

    async def test_reply_file_uses_replies_endpoint(self):
        blob = b"reply photo"
        transport = StubTransport(blob)
        rf = ReplyFile(id="rf-7", content_type="image/jpeg",
                       checksum_sha256=None, size=len(blob),
                       filename=None, _ctx=_ctx(transport))
        await rf.read()
        self.assertEqual(transport.presign_calls, [("tasks", "task-1", "replies", "rf-7")])


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class EncryptedDownloadTest(unittest.IsolatedAsyncioTestCase):
    """Encrypted chains: the S3 object is the raw nonce||ct||tag blob and the
    checksum covers the ciphertext (matching the uploading app)."""

    KEY = bytes(range(32))
    MARKER = {"type": "org", "v": 1}

    def _encrypted_blob(self, plaintext: bytes) -> bytes:
        # crypto.encrypt operates on str and returns base64(nonce||ct||tag);
        # the uploaded S3 object is those raw bytes.
        return base64.b64decode(encrypt(plaintext.decode("utf-8"), self.KEY))

    async def test_read_decrypts_with_marker_key(self):
        plaintext = b"secret file body"
        blob = self._encrypted_blob(plaintext)
        transport = StubTransport(blob)
        f = FileUpload(id="in-3", content_type="application/octet-stream",
                       checksum_sha256=_checksum(blob), size=len(blob),
                       _ctx=_ctx(transport, marker=self.MARKER,
                                 decryptor=OrgDecryptor({1: self.KEY})))
        self.assertEqual(await f.read(), plaintext)

    async def test_encrypted_without_key_raises(self):
        blob = self._encrypted_blob(b"secret")
        transport = StubTransport(blob)
        f = FileUpload(id="in-3", content_type="application/octet-stream",
                       checksum_sha256=_checksum(blob), size=len(blob),
                       _ctx=_ctx(transport, marker=self.MARKER, decryptor=None))
        with self.assertRaises(DownloadError):
            await f.read()

    async def test_encrypted_wrong_version_raises(self):
        blob = self._encrypted_blob(b"secret")
        transport = StubTransport(blob)
        f = FileUpload(id="in-3", content_type="application/octet-stream",
                       checksum_sha256=_checksum(blob), size=len(blob),
                       _ctx=_ctx(transport, marker=self.MARKER,
                                 decryptor=OrgDecryptor({2: bytes(32)})))
        with self.assertRaises(DownloadError):
            await f.read()


class WrapBindingTest(unittest.IsolatedAsyncioTestCase):
    """Event wrapping binds the stream's transport/task into the file objects."""

    def _binder(self, transport):
        return _FileBinder(transport, "tasks", "root-task", None)

    async def test_wrap_input_binds_file_uploads(self):
        transport = StubTransport(b"x")
        ev = Event.from_raw({
            "data": {
                "type": "taskInputCompleted",
                "taskId": "root-task",
                "inputUploaded": {
                    "type": "fileUploaded", "id": "in-5",
                    "contentType": "application/pdf",
                    "checksumSha256": _checksum(b"x"), "size": 1,
                    "filename": "doc.pdf",
                },
            },
        })
        item = _wrap_input(ev, None, self._binder(transport))
        upload = item.uploads[0]
        self.assertEqual(upload.filename, "doc.pdf")
        self.assertEqual(await upload.read(), b"x")
        self.assertEqual(transport.presign_calls, [("tasks", "root-task", "inputs", "in-5")])

    async def test_wrap_input_without_binder_yields_unbound_objects(self):
        ev = Event.from_raw({
            "data": {
                "type": "taskInputCompleted",
                "taskId": "root-task",
                "inputUploaded": {"type": "photoUploaded", "id": "in-6",
                                  "contentType": "image/jpeg",
                                  "checksumSha256": None, "size": 1},
            },
        })
        item = _wrap_input(ev, None, None)
        with self.assertRaises(DownloadError):
            await item.uploads[0].read()

    async def test_wrap_reply_binds_photo_file_and_audio(self):
        transport = StubTransport(b"y")
        ev = Event.from_raw({
            "data": {
                "type": "replyAppended",
                "taskId": "root-task",
                "reply": {
                    "id": "r-1",
                    "photo": {"id": "rf-1", "contentType": "image/jpeg",
                              "checksumSha256": _checksum(b"y"), "size": 1},
                    "file": {"id": "rf-2", "contentType": "application/zip",
                             "checksumSha256": _checksum(b"y"), "size": 1,
                             "filename": "a.zip"},
                    "audio": {"id": "ra-1", "contentType": "audio/mpeg",
                              "checksumSha256": _checksum(b"y"), "size": 1,
                              "durationSeconds": 3.5, "filename": "recording.mp3"},
                },
            },
        })
        reply = _wrap_reply(ev, None, self._binder(transport))
        self.assertEqual(await reply.photo.read(), b"y")
        self.assertEqual(await reply.file.read(), b"y")
        self.assertEqual(await reply.audio.read(), b"y")
        self.assertEqual(reply.audio.duration_seconds, 3.5)
        self.assertEqual(reply.audio.filename, "recording.mp3")
        self.assertEqual(transport.presign_calls,
                         [("tasks", "root-task", "replies", "rf-1"),
                          ("tasks", "root-task", "replies", "rf-2"),
                          ("tasks", "root-task", "replies", "ra-1")])

    async def test_reply_audio_has_duration_seconds(self):
        transport = StubTransport(b"y")
        ev = Event.from_raw({
            "data": {
                "type": "replyAppended",
                "taskId": "root-task",
                "reply": {
                    "id": "r-2",
                    "audio": {"id": "ra-2", "contentType": "audio/mpeg",
                              "checksumSha256": _checksum(b"y"), "size": 1,
                              "durationSeconds": 12.75},
                },
            },
        })
        reply = _wrap_reply(ev, None, self._binder(transport))
        self.assertIsInstance(reply.audio, ReplyAudio)
        self.assertEqual(reply.audio.duration_seconds, 12.75)
        self.assertEqual(await reply.audio.read(), b"y")
        self.assertEqual(transport.presign_calls,
                         [("tasks", "root-task", "replies", "ra-2")])

    def test_pattern_matching_still_works(self):
        photo = PhotoUpload(id="p", content_type="image/jpeg",
                            checksum_sha256=None, size=3)
        match photo:
            case PhotoUpload(id=pid, size=s):
                self.assertEqual((pid, s), ("p", 3))
            case _:
                self.fail("pattern match failed")


def _reply_event(reply: dict) -> Event:
    return Event.from_raw({"data": {"type": "replyAppended", "taskId": "root-task",
                                    "reply": reply}})


class ReplyLocationTest(unittest.IsolatedAsyncioTestCase):
    """A reply's `location` is inline data (decrypted via the body's marker, like
    the text body), NOT a downloadable file."""

    def test_plaintext_location_from_structured_fields(self):
        from simplepush.client import Location
        ev = _reply_event({
            "id": "r-loc-1",
            "location": {"latitude": 51.5074, "longitude": -0.1278,
                         "accuracy": 8.0, "timestamp": 1700000000000},
        })
        reply = _wrap_reply(ev, None, None)
        self.assertIsInstance(reply.location, Location)
        self.assertEqual(reply.location.latitude, 51.5074)
        self.assertEqual(reply.location.longitude, -0.1278)
        self.assertEqual(reply.location.accuracy, 8.0)
        self.assertEqual(reply.location.timestamp, 1700000000000)
        self.assertIsNone(reply.location.altitude)

    def test_missing_location_is_none(self):
        reply = _wrap_reply(_reply_event({"id": "r-loc-2"}), None, None)
        self.assertIsNone(reply.location)


@unittest.skipUnless(HAVE_CRYPTO, "pynacl not installed")
class EncryptedReplyLocationTest(unittest.IsolatedAsyncioTestCase):
    """An encrypted reply carries only `encrypted` — the ciphertext of the coords
    JSON under the body's marker — decrypted via the keyring then JSON-parsed."""

    def test_encrypted_location_decrypts_json_coords(self):
        import json
        from simplepush.crypto import Keyring, derive_key
        from simplepush.client import Location
        password, topic = "secret", "alerts"
        dk = derive_key(password, topic)
        keyring = Keyring.build(passwords=[password], topics=[topic])
        coords = {"latitude": 48.8566, "longitude": 2.3522, "speed": 0.0,
                  "timestamp": 1700000001000}
        ciphertext = encrypt(json.dumps(coords), dk.symmetric_key)
        marker = {"type": "personal", "keyFingerprint": dk.fingerprint}
        ev = _reply_event({"id": "r-loc-3", "encryption": marker,
                           "location": {"encrypted": ciphertext}})
        reply = _wrap_reply(ev, keyring, None)
        self.assertIsInstance(reply.location, Location)
        self.assertEqual(reply.location.latitude, 48.8566)
        self.assertEqual(reply.location.longitude, 2.3522)
        self.assertEqual(reply.location.speed, 0.0)
        self.assertEqual(reply.location.timestamp, 1700000001000)

    def test_encrypted_location_without_key_degrades_to_none(self):
        import json
        from simplepush.crypto import Keyring, derive_key
        dk = derive_key("secret", "alerts")
        ciphertext = encrypt(json.dumps({"latitude": 1.0, "longitude": 2.0}),
                             dk.symmetric_key)
        marker = {"type": "personal", "keyFingerprint": "wrong"}
        ev = _reply_event({"id": "r-loc-4", "encryption": marker,
                           "location": {"encrypted": ciphertext}})
        keyring = Keyring.build(passwords=["other"], topics=["t"])
        reply = _wrap_reply(ev, keyring, None)
        self.assertIsNone(reply.location)


if __name__ == "__main__":
    unittest.main()
