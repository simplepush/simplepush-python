"""Schema-driven decryption of the wire JSON the read surface returns: task
payloads, chains, summaries, submissions, raw events.

The encrypted fields are exactly the ones the send side seals (`api.py`) and
the watch views decrypt (`client.py`); this module mirrors that map field by
field.

Marker rules:
  - a payload/summary/entry marker covers its sender-authored fields;
  - an answer record's own ``encryption`` wins over the envelope's (answers
    sealed after an org key rotation carry newer keys than the task);
  - replies, decline notes and cancel notes carry strictly their own marker
    (authored after the send; absent marker = plaintext note);
  - a location's coords ride as one ``encrypted`` JSON blob, expanded in
    place, exactly like a slider input's sealed scale.

Every known-encrypted field under a marker either decrypts or increments
``undecryptable``; nothing else is ever attempted. A new encrypted wire field
must be added here (and to the watch views).

    ring = client.keyring()
    page = decrypt_task_payload(read, ring)   # page.value, page.undecryptable
"""

import copy
import json
from typing import Any, NamedTuple

from .crypto import decrypt


class DecryptedWire(NamedTuple):
    value: Any
    undecryptable: int


class _State:
    __slots__ = ("undecryptable",)

    def __init__(self) -> None:
        self.undecryptable = 0


def _marker_of(v: Any) -> dict | None:
    return v if isinstance(v, dict) and isinstance(v.get("type"), str) else None


def _dec_field(o: dict, field: str, marker: dict | None, keyring, st: _State) -> None:
    """Decrypt ``o[field]`` in place when it is a string and a marker applies.
    No marker = plaintext field, left alone; a marker with no matching key or a
    failed authentication counts as undecryptable and leaves the ciphertext."""
    v = o.get(field)
    if not isinstance(v, str) or marker is None:
        return
    key = keyring.key_for_marker(marker)
    if key is None:
        st.undecryptable += 1
        return
    try:
        o[field] = decrypt(v, key)
    except Exception:
        st.undecryptable += 1


def _dec_list(o: dict, field: str, marker: dict | None, keyring, st: _State) -> None:
    items = o.get(field)
    if not isinstance(items, list):
        return
    for i, v in enumerate(items):
        wrap = {"v": v}
        _dec_field(wrap, "v", marker, keyring, st)
        items[i] = wrap["v"]


def _dec_blob(o: dict, marker: dict | None, keyring, st: _State) -> None:
    """Decrypt-and-JSON-expand an ``{"encrypted": ...}`` blob (slider scale,
    location coords) onto the record itself, dropping the blob on success."""
    v = o.get("encrypted")
    if not isinstance(v, str) or marker is None:
        return
    key = keyring.key_for_marker(marker)
    if key is None:
        st.undecryptable += 1
        return
    try:
        plain = json.loads(decrypt(v, key))
    except Exception:
        st.undecryptable += 1
        return
    if isinstance(plain, dict):
        del o["encrypted"]
        o.update(plain)
    else:
        st.undecryptable += 1


def _dec_input(inp: Any, marker: dict | None, keyring, st: _State) -> None:
    if not isinstance(inp, dict):
        return
    _dec_field(inp, "description", marker, keyring, st)
    kind = inp.get("type")
    if kind == "text":
        _dec_field(inp, "defaultValue", marker, keyring, st)
    elif kind == "choice":
        _dec_list(inp, "options", marker, keyring, st)
    elif kind == "actions":
        for a in inp.get("actions") or []:
            if isinstance(a, dict):
                _dec_field(a, "key", marker, keyring, st)
                _dec_field(a, "label", marker, keyring, st)
    elif kind == "slider":
        _dec_blob(inp, marker, keyring, st)


def _dec_upload(u: Any, envelope: dict | None, keyring, st: _State) -> None:
    """An answer record (``textUploaded``, ``choiceSelected``, ...), as it appears
    both in event data and in a payload's ``uploads``. Own marker wins over the
    envelope's. File-kind records carry only plaintext metadata."""
    if not isinstance(u, dict):
        return
    marker = _marker_of(u.get("encryption")) or envelope
    u.pop("encryption", None)
    kind = u.get("type")
    if kind in ("textUploaded", "sliderUploaded"):
        _dec_field(u, "value", marker, keyring, st)
    elif kind == "choiceSelected":
        _dec_field(u, "selectedValue", marker, keyring, st)
    elif kind == "multiChoiceSelected":
        _dec_list(u, "selectedValues", marker, keyring, st)
    elif kind == "actionSelected":
        _dec_field(u, "selectedKey", marker, keyring, st)
    elif kind == "locationUploaded":
        # The coords are flattened onto the record itself, no nested key.
        _dec_blob(u, marker, keyring, st)


def _dec_message_body(container: dict, marker: dict | None, keyring, st: _State) -> None:
    """A reply/submission body plus inline location, under the given marker."""
    body = container.get("body")
    if isinstance(body, dict) and body.get("type") == "text":
        _dec_field(body, "value", marker, keyring, st)
    loc = container.get("location")
    if isinstance(loc, dict):
        _dec_blob(loc, marker, keyring, st)


def _dec_reply_record(r: Any, keyring, st: _State) -> None:
    """A reply off a payload's ``replies``: its own marker only."""
    if not isinstance(r, dict):
        return
    marker = _marker_of(r.pop("encryption", None))
    _dec_message_body(r, marker, keyring, st)


def _dec_note_record(r: Any, keyring, st: _State) -> None:
    """A decline record / the cancellation block: the note's own marker only."""
    if not isinstance(r, dict):
        return
    marker = _marker_of(r.pop("encryption", None))
    _dec_field(r, "note", marker, keyring, st)


def _dec_payload_in_place(p: dict, keyring, st: _State) -> None:
    marker = _marker_of(p.pop("encryption", None))
    for f in ("tag", "title", "content"):
        _dec_field(p, f, marker, keyring, st)
    for a in p.get("attachments") or []:
        if isinstance(a, dict) and a.get("type") == "link":
            _dec_field(a, "url", marker, keyring, st)
    for i in p.get("inputs") or []:
        _dec_input(i, marker, keyring, st)
    for u in p.get("uploads") or []:
        _dec_upload(u, marker, keyring, st)
    for r in p.get("replies") or []:
        _dec_reply_record(r, keyring, st)
    for d in p.get("declines") or []:
        _dec_note_record(d, keyring, st)
    _dec_note_record(p.get("cancellation"), keyring, st)


def decrypt_task_payload(value: Any, keyring) -> DecryptedWire:
    """A task or subtask payload (the shapes chain reads return)."""
    st = _State()
    out = copy.deepcopy(value)
    if isinstance(out, dict):
        _dec_payload_in_place(out, keyring, st)
    return DecryptedWire(out, st.undecryptable)


def decrypt_task_summary(value: Any, keyring) -> DecryptedWire:
    """A task index / group roster row: ``title`` and ``tag`` are its sealed fields."""
    st = _State()
    out = copy.deepcopy(value)
    if isinstance(out, dict):
        marker = _marker_of(out.pop("encryption", None))
        _dec_field(out, "title", marker, keyring, st)
        _dec_field(out, "tag", marker, keyring, st)
    return DecryptedWire(out, st.undecryptable)


def decrypt_submission(value: Any, keyring, marker: dict | None) -> DecryptedWire:
    """A submission (body + inline location) under its feed entry's marker;
    the submission carries no marker of its own."""
    st = _State()
    out = copy.deepcopy(value)
    if isinstance(out, dict):
        _dec_message_body(out, marker, keyring, st)
    return DecryptedWire(out, st.undecryptable)


def decrypt_event(raw: Any, keyring) -> DecryptedWire:
    """One wire event's ``data``, decrypted in place on a copy of the raw event
    dict by event-data type. Unrecognized types pass through untouched."""
    st = _State()
    out = copy.deepcopy(raw)
    data = out.get("data") if isinstance(out, dict) else None
    if not isinstance(data, dict):
        return DecryptedWire(out, 0)
    marker = _marker_of(out.get("encryption"))
    kind = data.get("type")
    if kind in ("taskInputUploaded", "taskInputCompleted", "subtaskInputUploaded", "subtaskInputCompleted"):
        _dec_upload(data.get("inputUploaded"), marker, keyring, st)
    elif kind in ("taskCompleted", "subtaskCompleted"):
        for u in data.get("inputsUploaded") or []:
            _dec_upload(u, marker, keyring, st)
    elif kind == "replyAppended":
        reply = data.get("reply")
        if isinstance(reply, dict):
            _dec_message_body(reply, marker, keyring, st)
    elif kind == "submissionCreated":
        submission = data.get("submission")
        if isinstance(submission, dict):
            _dec_message_body(submission, marker, keyring, st)
    elif kind == "notificationCompleted":
        reply = data.get("reply")
        if isinstance(reply, dict):
            rt = reply.get("type")
            if rt == "text":
                _dec_field(reply, "value", marker, keyring, st)
            elif rt == "choice":
                _dec_field(reply, "selectedValue", marker, keyring, st)
            elif rt == "actions":
                _dec_field(reply, "selectedKey", marker, keyring, st)
    elif kind in (
        "taskCanceled", "subtaskCanceled",
        "taskDeclinedByRecipient", "subtaskDeclinedByRecipient",
        "taskDeclined", "subtaskDeclined",
    ):
        # The envelope marker on these is the note's own; reason/supersededBy
        # stay plaintext.
        _dec_field(data, "note", marker, keyring, st)
    return DecryptedWire(out, st.undecryptable)


def try_decrypt_event_data(event, keyring) -> dict | None:
    """A decrypted copy of ``event.data``, or None when the event isn't
    encrypted or no held key matches its marker. A field that fails to decrypt
    (e.g. sealed under a newer org key) is left as ciphertext."""
    marker = _marker_of(event.raw.get("encryption"))
    if marker is None or keyring.key_for_marker(marker) is None:
        return None
    return decrypt_event(event.raw, keyring).value.get("data")
