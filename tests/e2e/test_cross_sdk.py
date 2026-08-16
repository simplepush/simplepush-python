"""Cross-SDK wire-contract tests: one SDK sends, the OTHER decrypts.

Same-SDK round-trips cannot catch symmetric bugs (both sides wrong in the same
way looks like a pass); these pairings can. All tests use the account-default
key (bare password + server password_salt) so no topic setup is needed. The JS
end runs via _js_helper.mjs against the built dist (SP_E2E_JS_DIST)."""

import json
import uuid

import pytest

pytest.importorskip("nacl", reason="crypto extra required: pip install 'simplepush[crypto]'")

from simplepush import Client, derive_key, looks_like_ciphertext  # noqa: E402
from simplepush.crypto import decrypt  # noqa: E402  (bare `simplepush.decrypt` is shadowed by the submodule)


def secret() -> str:
    return f"e2e-{uuid.uuid4().hex[:10]}"


PW = "e2e-x-pw"


def test_js_encrypted_send_decrypts_in_python(sender_read, password_salt, js_helper):
    s1, s2 = secret(), secret()
    out = js_helper("send-encrypted-chain", PW, s1, s2)
    assert out.get("subtaskId"), f"js helper minted no subtask: {out}"

    read = sender_read(out["taskId"])
    assert s1 not in json.dumps(read), "JS send stored plaintext"

    dk = derive_key(PW, password_salt)
    marker = read.get("encryption") or {}
    assert marker.get("keyFingerprint") == dk.fingerprint, (
        f"fingerprint mismatch: python derives {dk.fingerprint}, JS wrote {marker}"
    )
    assert s1 in decrypt(read["content"], dk.symmetric_key), "python key cannot read a JS send"


def test_python_encrypted_send_decrypts_in_js(conn, js_helper):
    s = secret()
    sender = Client(**conn, passwords=PW)
    task = sender.send_task(content=f"x {s}")

    out = js_helper("read-decrypt", PW, task.task_id, s)
    assert out["found"], "JS could not read the python send"
    assert out["ciphertext"], "python send stored plaintext"
    assert out["decrypted"], "JS keyring cannot read a python send"


def test_wire_shape_parity_for_encrypted_tagged_sends(conn, sender_read, js_helper):
    """Send the same logical task from both SDKs; the at-rest payloads must
    have the same shape AND classify identically as ciphertext/plaintext per
    field. Catches one-sided encryption or naming drift mechanically."""
    s = secret()

    py_sender = Client(**conn, passwords=PW)
    py_task = py_sender.send_task(
        content=f"c {s}", title="parity", tag="parity-tag"
    )
    out = js_helper("send-parity", PW, s)

    shape_py = _shape(sender_read(py_task.task_id))
    shape_js = _shape(sender_read(out["taskId"]))
    assert shape_py == shape_js, f"\npython: {shape_py}\njs:     {shape_js}"


PARITY_FIELDS = ("title", "content", "tag", "contentFormat", "autoCommit", "inputs")


def _shape(read: dict):
    def classify(v):
        if isinstance(v, str):
            return "enc" if looks_like_ciphertext(v) else "plain"
        if isinstance(v, dict):
            return {k: classify(x) for k, x in sorted(v.items()) if x is not None}
        if isinstance(v, list):
            return [classify(x) for x in v]
        return v

    return {k: classify(read.get(k)) for k in PARITY_FIELDS}
