"""Attachment upload lifecycle against a live backend: presign -> PUT ->
complete, asserted via the sender-read (`status: "uploaded"` + stored-blob
metadata). Python has no injectable transport, so the stored-bytes capture
(the PUT body itself) lives in the JS suite; here the checksum/size asserts
pin the declared metadata to the local file's bytes."""

import base64
import hashlib
import json
import uuid

import pytest

from simplepush import Client


def secret() -> str:
    return f"e2e-{uuid.uuid4().hex[:10]}"


def _b64sha256(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def test_plaintext_attachment_uploads_and_completes(conn, sender_read, tmp_path):
    data = f"attachment payload {secret()}".encode()
    path = tmp_path / "e2e-att.txt"
    path.write_bytes(data)

    sender = Client(**conn)
    task = sender.send_task(content="att plaintext", files=[str(path)])

    read = sender_read(task.task_id)
    atts = read.get("attachments") or []
    assert len(atts) == 1, f"expected one attachment: {json.dumps(atts)}"
    att = atts[0]
    assert att["status"] == "uploaded", att
    assert att["id"].startswith("att_"), att
    assert att["filename"] == "e2e-att.txt"
    assert att["contentType"] == "text/plain"
    assert att["size"] == len(data)
    assert att["checksumSha256"] == _b64sha256(data)


def test_encrypted_attachment_metadata_describes_the_ciphertext(conn, sender_read, tmp_path):
    pytest.importorskip("nacl", reason="crypto extra required: pip install 'simplepush[crypto]'")
    data = f"sealed payload {secret()}".encode()
    path = tmp_path / "e2e-att-enc.bin"
    path.write_bytes(data)

    sender = Client(**conn, passwords="e2e-pw")
    task = sender.send_task(content="att encrypted", files=[str(path)])

    read = sender_read(task.task_id)
    assert (read.get("encryption") or {}).get("type") == "personal"
    att = (read.get("attachments") or [])[0]
    assert att["status"] == "uploaded", att
    # The declared metadata describes the CIPHERTEXT blob, not the plaintext.
    assert att["size"] > len(data)
    assert att["checksumSha256"] != _b64sha256(data)
