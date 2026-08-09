"""Unit tests for the create-path retry + idempotency-key behavior.

`_post(..., retry=True)` resends on 503 (honoring Retry-After), network-level
URLError, and 409 idempotency_in_flight — always with the SAME body, so the
idempotency key minted before the first attempt rides every retry and the
backend replays instead of re-creating. Other statuses surface immediately.
No network: `urllib.request.urlopen` is stubbed; sleeps are captured.

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

from simplepush import Client  # noqa: E402


TASK_RESPONSE = {
    "taskId": "tsk_00000000-0000-7000-8000-00000000000c",
    "createdAt": "2026-07-07T10:00:00Z",
    "waitToken": "wt_s",
    "appendToken": "at_s",
    "attachments": [],
}


def http_error(code, body=b"down", headers=None):
    return urllib.error.HTTPError(
        "http://test/", code, "err", headers or {}, io.BytesIO(body)
    )


def ok_response(payload):
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__ = lambda self: self
    resp.__exit__ = lambda self, *a: False
    return resp


class RetryTest(unittest.TestCase):
    def setUp(self):
        self.client = Client("localhost", 8000, ssl=False, api_token="t")
        self.sleeps = []
        self.sleep_patch = mock.patch("simplepush.api.time.sleep", self.sleeps.append)
        self.sleep_patch.start()
        self.addCleanup(self.sleep_patch.stop)

    def run_send(self, side_effects):
        bodies = []

        def fake_urlopen(req, *a, **kw):
            bodies.append(json.loads(req.data.decode("utf-8")))
            effect = side_effects.pop(0)
            if isinstance(effect, Exception):
                raise effect
            return effect

        with mock.patch("simplepush.api.urllib.request.urlopen", fake_urlopen):
            task = self.client.send_task(content="hello")
        return task, bodies

    def test_retries_503_with_same_idempotency_key(self):
        task, bodies = self.run_send([
            http_error(503, headers={"Retry-After": "0"}),
            http_error(503),
            ok_response(TASK_RESPONSE),
        ])
        self.assertEqual(task.task_id, TASK_RESPONSE["taskId"])
        self.assertEqual(len(bodies), 3)
        key = bodies[0]["idempotencyKey"]
        self.assertTrue(key)
        self.assertEqual([b["idempotencyKey"] for b in bodies], [key, key, key])

    def test_retries_network_error(self):
        task, bodies = self.run_send([
            urllib.error.URLError("connection refused"),
            ok_response(TASK_RESPONSE),
        ])
        self.assertEqual(task.task_id, TASK_RESPONSE["taskId"])
        self.assertEqual(len(bodies), 2)

    def test_retries_409_idempotency_in_flight_only(self):
        in_flight = json.dumps({"error": "idempotency_in_flight", "msg": "..."}).encode()
        task, bodies = self.run_send([
            http_error(409, body=in_flight),
            ok_response(TASK_RESPONSE),
        ])
        self.assertEqual(len(bodies), 2)

        from simplepush import ApiError
        canceled = json.dumps({"error": "task_canceled", "msg": "..."}).encode()
        with self.assertRaises(ApiError):
            self.run_send([http_error(409, body=canceled)])

    def test_gives_up_after_max_attempts(self):
        from simplepush import ApiError
        effects = [http_error(503) for _ in range(10)]
        with self.assertRaises(ApiError):
            self.run_send(effects)
        # 6 attempts total: the initial call + 5 retries.
        self.assertEqual(len(effects), 10 - 6)

    def test_non_create_posts_do_not_retry(self):
        calls = []

        def fake_urlopen(req, *a, **kw):
            calls.append(req)
            raise http_error(503)

        from simplepush import ApiError
        with mock.patch("simplepush.api.urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(ApiError):
                self.client._post("/anything", {})
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
