"""Unit tests for the HTTP timeouts.

Every request passes a timeout to `urlopen`, so a connection that stops
answering fails instead of blocking forever. A create that times out while
waiting for the response is retried like any network failure: the idempotency
key makes the resend safe. No network: `urlopen` is stubbed.

Run with `python3 -m unittest discover tests` from python-library/.
"""

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from simplepush import Client  # noqa: E402
from simplepush.client import _HTTP_TIMEOUT, _DownloadTransport  # noqa: E402


TASK_RESPONSE = {
    "taskId": "tsk_00000000-0000-7000-8000-00000000000c",
    "createdAt": "2026-07-07T10:00:00Z",
    "waitToken": "wt_s",
    "appendToken": "at_s",
    "attachments": [],
}


def ok_response(payload):
    resp = mock.MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__ = lambda self: self
    resp.__exit__ = lambda self, *a: False
    return resp


class TimeoutTest(unittest.TestCase):
    def setUp(self):
        self.client = Client("localhost", 8000, ssl=False, api_token="t")
        self.sleep_patch = mock.patch("simplepush.api.time.sleep")
        self.sleep_patch.start()
        self.addCleanup(self.sleep_patch.stop)

    def test_send_passes_the_timeout(self):
        timeouts = []

        def fake_urlopen(req, *a, **kw):
            timeouts.append(kw.get("timeout"))
            return ok_response(TASK_RESPONSE)

        with mock.patch("simplepush.api.urllib.request.urlopen", fake_urlopen):
            self.client.send_task(content="hello")

        self.assertEqual(timeouts, [_HTTP_TIMEOUT])

    def test_create_is_retried_after_a_read_timeout(self):
        responses = [TimeoutError("timed out"), ok_response(TASK_RESPONSE)]
        bodies = []

        def fake_urlopen(req, *a, **kw):
            bodies.append(req.data)
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with mock.patch("simplepush.api.urllib.request.urlopen", fake_urlopen):
            task = self.client.send_task(content="hello")

        self.assertEqual(task.task_id, TASK_RESPONSE["taskId"])
        self.assertEqual(len(bodies), 2)
        self.assertEqual(bodies[0], bodies[1])

    def test_downloads_pass_the_timeout(self):
        transport = _DownloadTransport("http://localhost:8000/v1", {"API-Token": "t"})
        timeouts = []

        def fake_urlopen(target, *a, **kw):
            timeouts.append(kw.get("timeout"))
            resp = mock.MagicMock()
            resp.read.return_value = b"{}"
            resp.__enter__ = lambda self: self
            resp.__exit__ = lambda self, *a: False
            return resp

        with mock.patch("simplepush.client.urllib.request.urlopen", fake_urlopen):
            transport.presign("tasks", "tsk_1", "inputs", "inp_1")
            transport.get("http://files.example/blob")

        self.assertEqual(timeouts, [_HTTP_TIMEOUT, _HTTP_TIMEOUT])


if __name__ == "__main__":
    unittest.main()
