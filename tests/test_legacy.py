"""Unit tests for sending to the old app with a device key.

The expected payloads were produced by the 2.x library, so the encryption
here stays compatible with what the old app decrypts. No network:
`urlopen` is stubbed.

Run with `python3 -m unittest discover tests` from python-library/.
"""

import io
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import legacy  # noqa: E402

IV = bytes(range(16))
ATTACHMENTS = [
    "https://x.example/a.jpg",
    {"thumbnail": "https://x.example/t.jpg", "video": "https://x.example/v.mp4"},
]

# From simplepush 2.2.5 `_generate_payload` with the same IV.
ENCRYPTED_2X = {
    "key": "abc",
    "encrypted": "true",
    "iv": "000102030405060708090A0B0C0D0E0F",
    "title": "-XWzVap9S3650i8IEyN63w==",
    "event": "ev",
    "msg": "SSC1918PMgvtdRh_tkM1_g==",
    "attachments": [
        "zkkzaxitgylhn4Cx-obtCQxxLo32LDZ_rc-3cS1DyxE=",
        {
            "thumbnail": "zkkzaxitgylhn4Cx-obtCZ9814l0s3rYwy_WE1pBhOs=",
            "video": "zkkzaxitgylhn4Cx-obtCeI5YOhM5GF28apmlyR8Bhg=",
        },
    ],
}


def response(payload, code=200):
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__ = lambda self: self
    resp.__exit__ = lambda self, *a: False
    return resp


def http_error(code, payload):
    return urllib.error.HTTPError(
        "https://api-legacy.simplepu.sh/send", code, "err", {}, io.BytesIO(json.dumps(payload).encode())
    )


class PayloadTest(unittest.TestCase):
    def test_plain_payload_matches_2x(self):
        payload = legacy._payload("abc", "Hello", "Hi", None, None, ["https://x.example/a.jpg"], "ev")

        self.assertEqual(
            payload,
            {"key": "abc", "msg": "Hello", "title": "Hi", "event": "ev", "attachments": ["https://x.example/a.jpg"]},
        )

    def test_encrypted_payload_matches_2x(self):
        with mock.patch.object(legacy.os, "urandom", return_value=IV):
            payload = legacy._payload("abc", "Hello", "Hi", "secret", "1234", ATTACHMENTS, "ev")

        self.assertEqual(payload, ENCRYPTED_2X)

    def test_key_without_salt_matches_2x(self):
        self.assertEqual(legacy._encryption_key("secret", None).hex(), "ad1bb50dbef728b31b433b69e52c5e6b")


class SendTest(unittest.TestCase):
    def send(self, result, **kwargs):
        requests = []

        def fake_urlopen(req, *a, **kw):
            requests.append((req, kw.get("timeout")))
            if isinstance(result, Exception):
                raise result
            return response(result)

        with mock.patch("simplepush.legacy.urllib.request.urlopen", fake_urlopen):
            legacy.send(**{"key": "abc", "message": "Hello", **kwargs})
        return requests

    def test_posts_to_the_legacy_api_with_a_timeout(self):
        ((req, timeout),) = self.send({"status": "OK"}, title="Hi")

        self.assertEqual(req.full_url, "https://api-legacy.simplepu.sh/send")
        self.assertEqual(req.get_header("User-agent"), "simplepush-python")
        self.assertEqual(json.loads(req.data), {"key": "abc", "msg": "Hello", "title": "Hi"})
        self.assertEqual(timeout, legacy._TIMEOUT)

    def test_too_long_is_bad_request(self):
        with self.assertRaises(legacy.BadRequest):
            self.send({"status": "BadRequest", "message": "Title or message too long"})

    def test_other_failures_are_unknown_errors(self):
        for result in (
            {"status": "BadRequest", "message": "Invalid key"},
            http_error(500, {"status": "Error"}),
            http_error(429, {"status": "Error"}),
            urllib.error.URLError("refused"),
            TimeoutError("timed out"),
        ):
            with self.subTest(result=result), self.assertRaises(legacy.UnknownError):
                self.send(result)

    def test_invalid_arguments(self):
        for kwargs in (
            {"message": ""},
            {"password": "secret"},
            {"salt": "1234"},
            {"attachments": "https://x.example/a.jpg"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.send({"status": "OK"}, **kwargs)


if __name__ == "__main__":
    unittest.main()
