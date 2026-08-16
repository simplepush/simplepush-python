"""Same-SDK encryption round-trips against a live backend.

Sends are asserted via the sender-side read (`GET /v1/tasks/{id}`, the at-rest
payload) — task creation appends no event, so the events stream is NOT a send
oracle. The events stream is used only where events exist (cancel)."""

import json
import uuid

import pytest

pytest.importorskip("nacl", reason="crypto extra required: pip install 'simplepush[crypto]'")

from simplepush import Client, try_decrypt_event_data  # noqa: E402
from simplepush.crypto import decrypt  # noqa: E402  (bare `simplepush.decrypt` is shadowed by the submodule)


def secret() -> str:
    return f"e2e-{uuid.uuid4().hex[:10]}"


def _refs_task(ev, task_id: str) -> bool:
    if ev.task_id == task_id:
        return True
    return isinstance(ev.data, dict) and ev.data.get("taskId") == task_id


def test_encrypted_self_send_is_ciphertext_at_rest(conn, sender_read):
    s = secret()
    sender = Client(**conn, passwords="e2e-pw")
    task = sender.send_task(content=f"note {s}")

    read = sender_read(task.task_id)
    assert s not in json.dumps(read), "plaintext stored at rest"
    marker = read.get("encryption")
    assert marker and marker.get("type") == "personal", f"no personal marker: {marker}"

    key = sender.keyring().key_for_marker(marker)
    assert key is not None, "sender keyring lacks the key for its own send marker"
    assert s in decrypt(read["content"], key)


def test_append_to_encrypted_parent_is_accepted(conn):
    """Server-side acceptance of a handle append on an encrypted topicless
    parent. Python has no injectable transport, so the assertion that the
    append BODY was ciphertext lives in the JS suite (capturing fetch); this
    guards the request path end-to-end."""
    sender = Client(**conn, passwords="e2e-pw")
    task = sender.send_task(content="append parent")
    sub = task.append(content=f"child {secret()}")
    assert sub.subtask_id.startswith("sub_"), sub.subtask_id
    assert sub.parent_task_id == task.task_id


def test_topic_key_send_decrypts_for_fresh_client(conn, topic, sender_read):
    s = secret()
    sender = Client(**conn, passwords=[("e2e-topic-pw", topic)])
    sent = sender.send_task(topic=topic, content=f"t {s}")
    instances = list(sent) if hasattr(sent, "__iter__") else [sent]

    read = sender_read(instances[0].task_id)
    assert s not in json.dumps(read)

    # A FRESH client configured with the same (password, topic) pair — not the
    # sender's in-memory key cache — must be able to derive the key.
    fresh = Client(**conn, passwords=[("e2e-topic-pw", topic)])
    key = fresh.keyring().key_for_marker(read["encryption"])
    assert key is not None
    assert s in decrypt(read["content"], key)


def test_encrypted_cancel_note_on_the_events_stream(conn, watch):
    """Cancel IS an event — this also proves the events oracle itself."""
    s = secret()
    sender = Client(**conn, passwords="e2e-pw")
    keyless = Client(**conn)

    w = watch(keyless)
    task = sender.send_task(content="cancel target")
    task.cancel(note=f"why {s}")

    ev = w.wait(lambda e: _refs_task(e, task.task_id))
    assert s not in json.dumps(ev.raw), "cancel note leaked plaintext"
    dec = try_decrypt_event_data(ev, sender.keyring())
    assert dec is not None and s in json.dumps(dec)
