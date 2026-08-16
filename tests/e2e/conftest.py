"""Live end-to-end fixtures.

This directory tests the SDK against a REAL backend (sender -> wire ->
observer). Every test here is skipped unless the environment points at a
disposable dev backend:

    SP_E2E_BASE_URL=http://localhost:8000 \
    SP_E2E_API_TOKEN=... \
    pytest tests/e2e

Optional:
    SP_E2E_TOPIC    - a personal topic the test account holds (topic tests skip without it)
    SP_E2E_JS_DIST  - path to simplepush-js dist/index.mjs for the cross-SDK
                      suite (defaults to the sibling checkout's build)

The suites bring their own throwaway client-side passwords; nothing needs to
be configured in the app. Every account has a server-issued password_salt from
creation, which is all the Personal-Password tests rely on. App-held passwords
(if any) neither help nor conflict — encryption markers carry key
fingerprints, so differently-keyed content coexists.
"""

import json
import os
import queue
import subprocess
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pytest

BASE = os.environ.get("SP_E2E_BASE_URL")
TOKEN = os.environ.get("SP_E2E_API_TOKEN")
TOPIC = os.environ.get("SP_E2E_TOPIC")
JS_DIST = os.environ.get(
    "SP_E2E_JS_DIST",
    str(Path(__file__).resolve().parents[3] / "simplepush-js" / "dist" / "index.mjs"),
)


def pytest_collection_modifyitems(config, items):
    if BASE and TOKEN:
        return
    skip = pytest.mark.skip(reason="e2e disabled: set SP_E2E_BASE_URL and SP_E2E_API_TOKEN")
    here = str(Path(__file__).resolve().parent)
    # This hook sees the WHOLE session's items, not just this directory's —
    # scope the skip to e2e tests or a plain `pytest tests/` run loses everything.
    for item in items:
        if str(item.fspath).startswith(here):
            item.add_marker(skip)


def secret() -> str:
    """Unique marker so wire greps can never match another test's traffic."""
    return f"e2e-{uuid.uuid4().hex[:10]}"


@pytest.fixture(scope="session")
def conn():
    u = urlparse(BASE)
    return {
        "host": u.hostname,
        "port": u.port or (443 if u.scheme == "https" else 80),
        "ssl": u.scheme == "https",
        "api_token": TOKEN,
    }


@pytest.fixture(scope="session")
def topic():
    if not TOPIC:
        pytest.skip("SP_E2E_TOPIC unset")
    return TOPIC


def _get_json(path: str) -> dict:
    req = urllib.request.Request(f"{BASE}{path}", headers={"API-Token": TOKEN})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())


@pytest.fixture(scope="session")
def sender_read():
    """The send-shape oracle: GET /v1/tasks/{id} returns the at-rest payload.
    (Task creation appends NO event — /ws/v1/events only carries recipient
    actions and lifecycle changes, so it is not a send oracle.)"""

    def read(task_id: str) -> dict:
        return _get_json(f"/v1/tasks/{task_id}")

    return read


@pytest.fixture(scope="session")
def password_salt():
    """The account's server-issued salt (exists for every account)."""
    return _get_json("/v1/user")["passwordSalt"]


class EventWatcher:
    """Runs a client's live `events()` feed on a background thread and lets the
    (synchronous) test wait for a matching event. Python `events()` is
    live-only, so the watcher MUST be started before the send it observes."""

    CONNECT_GRACE = 1.5  # seconds for the WS to actually attach before sends

    def __init__(self, client):
        self._client = client
        self._q: queue.Queue = queue.Queue()
        self._loop = None
        self._task = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        import asyncio

        async def main():
            self._loop = asyncio.get_running_loop()
            self._task = asyncio.current_task()
            self._ready.set()
            try:
                async for ev in self._client.events():
                    self._q.put(ev)
            except asyncio.CancelledError:
                pass

        asyncio.run(main())

    def start(self):
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("event watcher thread failed to start")
        time.sleep(self.CONNECT_GRACE)
        return self

    def wait(self, pred, timeout=25):
        deadline = time.monotonic() + timeout
        seen = []
        while time.monotonic() < deadline:
            try:
                ev = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if pred(ev):
                return ev
            seen.append(ev.event_type)
        raise AssertionError(f"no matching event within {timeout}s; saw types: {seen}")

    def stop(self):
        if self._loop and self._task:
            self._loop.call_soon_threadsafe(self._task.cancel)
        self._thread.join(5)


@pytest.fixture
def watch():
    watchers = []

    def _watch(client):
        w = EventWatcher(client).start()
        watchers.append(w)
        return w

    yield _watch
    for w in watchers:
        w.stop()


@pytest.fixture(scope="session")
def js_helper():
    """Runs one mode of _js_helper.mjs (the JS SDK end of the cross-SDK suite)
    and returns its JSON result line."""
    if not Path(JS_DIST).exists():
        pytest.skip(f"JS SDK build not found at {JS_DIST} (set SP_E2E_JS_DIST)")

    def run(*args):
        env = {
            **os.environ,
            "SP_E2E_JS_DIST": JS_DIST,
            "SP_E2E_BASE_URL": BASE,
            "SP_E2E_API_TOKEN": TOKEN,
        }
        proc = subprocess.run(
            ["node", str(Path(__file__).parent / "_js_helper.mjs"), *args],
            capture_output=True,
            text=True,
            timeout=90,
            env=env,
        )
        assert proc.returncode == 0, f"js helper failed: {proc.stderr[-800:]}"
        return json.loads(proc.stdout.strip().splitlines()[-1])

    return run
