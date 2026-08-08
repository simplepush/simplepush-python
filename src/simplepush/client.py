"""
Event streaming for the SimplePush Business Backend.

A single WebSocket connection (``/ws/v1/events``, authenticated with the
``API-Token`` header) is multiplexed across every task you send: the hub reads
the stream once and fans each event out to the task handles that care about it,
matched by ``taskId``.

The ergonomic surface is the ``TaskGroup`` returned by ``Client.send_task`` —
one independent ``Task`` instance per recipient, each yielding its own events
forever:

    group = client.send_task(topic="mykey", inputs=[ChoiceInput(options=["yes", "no"])])
    task = group.sole                     # single-recipient topic; iterate for many

    async for inp in task.inputs():       # input submissions for this task
        print(inp.type, inp.uploads)

    async for reply in task.replies(timeout=300):   # replies appended to this task
        match reply.body:
            case TextBody(text=t):
                print(t)

Notifications are a lighter sibling sent with ``Client.send_notification``: they
collect inputs (choice/text only) but have no replies and no subtasks, so the
``Notification`` handle exposes only ``inputs()``.

Both task streams stop on their own when the task is deleted (``taskDeleted``),
and ``timeout`` (seconds of silence) ends iteration early.

For ad-hoc inspection of the whole stream, ``Client.events()`` exposes the
raw feed (on an ``OrgClient`` it is the org-scoped stream).
"""

import asyncio
import base64
import collections
import hashlib
import json
import mimetypes
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal, Protocol, overload
from urllib.parse import quote

import websockets
import websockets.exceptions

if TYPE_CHECKING:
    # Type-only: api.py imports from this module at runtime, so a real import
    # here would be circular. The enum-or-Literal unions below give static
    # checkers the closed vocabulary while runtime keeps accepting plain str.
    from .api import CancelReason, ContentFormat, ReplyMode


class StreamError(Exception):
    """Raised into a stream consumer when the event connection fails in a way
    that won't recover on retry — e.g. the server rejected the WebSocket
    handshake with a 4xx (bad/expired token, forbidden, unknown endpoint).
    Transient failures (network blips, pod restarts, server 5xx, rate limits)
    are reconnected transparently and never surface here."""

    def __init__(self, message: str, *, status_code: int | None = None, cause: BaseException | None = None):
        super().__init__(message)
        self.status_code = status_code
        if cause is not None:
            self.__cause__ = cause


class DownloadError(Exception):
    """A file download failed: the presign request was rejected, the fetched
    bytes failed checksum verification, the file is encrypted and no matching
    key is held, or the object isn't bound to a client stream. `status_code`
    is set when an HTTP layer rejected the request."""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class _HubError:
    """Sentinel queued to a consumer so its `async for` raises the fatal stream
    error instead of blocking forever on a connection that won't come back."""

    __slots__ = ("error",)

    def __init__(self, error: Exception):
        self.error = error


# 4xx codes worth retrying despite being client errors: request timeout, too
# early, and rate-limited. Every other 4xx is treated as permanent.
_RETRYABLE_4XX = {408, 425, 429}


def _handshake_status(exc: BaseException) -> int | None:
    """HTTP status from a rejected WebSocket handshake, across websockets
    versions: `InvalidStatus.response.status_code` (>=12) or
    `InvalidStatusCode.status_code` (older)."""
    resp = getattr(exc, "response", None)
    code = getattr(resp, "status_code", None)
    if code is None:
        code = getattr(exc, "status_code", None)
    return code if isinstance(code, int) else None


def _is_permanent_ws_error(exc: BaseException) -> bool:
    """True for failures that won't fix themselves on reconnect: a 4xx handshake
    (auth/client error) or a malformed URL. Network drops, 5xx, and rate limits
    are transient."""
    code = _handshake_status(exc)
    if code is not None:
        return 400 <= code < 500 and code not in _RETRYABLE_4XX
    return isinstance(exc, getattr(websockets.exceptions, "InvalidURI", ()))


def _as_stream_error(exc: BaseException) -> StreamError:
    code = _handshake_status(exc)
    if code is not None:
        return StreamError(f"event stream rejected by server (HTTP {code})", status_code=code, cause=exc)
    return StreamError(f"event stream failed: {exc}", cause=exc)


# --- Wire event-type discriminators (the `data.type` field) ---

_TASK_DELETED = "taskDeleted"
_INPUT_TYPES = frozenset({
    "taskInputUploaded",
    "taskInputCompleted",
    "taskCompleted",
    "taskDeclinedByRecipient",
})
_REPLY_TYPES = frozenset({"replyAppended", "taskDeclinedByRecipient"})
# Terminal for the inputs() stream: taskCompleted carries the full committed
# input set, after which no further inputs arrive. It's yielded, then iteration
# ends. (Not terminal for replies(), which can continue under a sticky composer.)
_INPUT_TERMINAL = frozenset({"taskCompleted"})

# Sender-side cancel events. `taskCanceled` is entity-wide terminal like
# `taskDeleted` (a canceled root closes the whole chain — the backend emits NO
# per-subtask events for it); `subtaskCanceled` is scoped to one subtask and
# leaves the rest of the chain live.
_TASK_CANCELED = "taskCanceled"
_SUBTASK_CANCELED = "subtaskCanceled"

# Recipient-side decline events. `taskDeclined` (every recipient has declined,
# status flipped) is entity-wide terminal like `taskCanceled`;
# `taskDeclinedByRecipient` is a per-recipient SIGNAL, not a terminal — in
# shared mode the task stays live for the other recipients, so it's yielded
# mid-stream and a collector can count declines down. Independent-mode
# instances have a single recipient, so the terminal `taskDeclined` follows it
# in the same transaction.
_TASK_DECLINED = "taskDeclined"
_TASK_DECLINED_BY_RECIPIENT = "taskDeclinedByRecipient"
# Subtask mirrors, SCOPED like subtaskCanceled: one recipient refused THIS
# follow-up (signal) / every recipient has (scoped terminal); the rest of the
# chain stays live.
_SUBTASK_DECLINED = "subtaskDeclined"
_SUBTASK_DECLINED_BY_RECIPIENT = "subtaskDeclinedByRecipient"

# Subtask equivalents (events carry subtaskId + parentTaskId).
_SUBTASK_INPUT_TYPES = frozenset({
    "subtaskInputUploaded",
    "subtaskInputCompleted",
    "subtaskCompleted",
    _SUBTASK_CANCELED,
    _SUBTASK_DECLINED_BY_RECIPIENT,
    _SUBTASK_DECLINED,
})
_SUBTASK_INPUT_TERMINAL = frozenset({"subtaskCompleted", _SUBTASK_CANCELED, _SUBTASK_DECLINED})

# A notification emits exactly one event (`notificationCompleted`, carrying the
# recipient's single answer); there is no input-upload lifecycle and no deletion
# event, so its stream yields one item and ends.
_NOTIFICATION_TYPES = frozenset({"notificationCompleted"})
_NOTIFICATION_TERMINAL = frozenset({"notificationCompleted"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _open_ws(url: str, headers: dict[str, str] | None = None):
    """Open a WebSocket, tolerating the websockets 12 -> 13 header-kwarg rename."""
    if not headers:
        return await websockets.connect(url)
    try:
        return await websockets.connect(url, additional_headers=headers)
    except TypeError:
        return await websockets.connect(url, extra_headers=headers)


@dataclass(frozen=True, slots=True)
class Event:
    """A parsed event from the WebSocket stream."""
    stream_id: str | None = None
    entity_id: str | None = None
    event_type: str | None = None
    version: int | None = None
    created_at: str | None = None
    task_id: str | None = None      # the chain's root task id (always present for chain events)
    subtask_id: str | None = None   # set on subtask-scoped events
    notification_id: str | None = None  # set on notification-scoped events
    data_type: str | None = None
    download_url: str | None = None
    key_fingerprint: str | None = None
    # Attribution for receive-side actions ({publicId, name?, devicePublicId?,
    # deviceName?}); None on send-side / collective events. `entity_id` carries
    # the same identity as a bare UUID (internal partition key) — prefer this.
    actor: dict | None = None
    data: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict) -> "Event":
        raw_data = raw.get("data")
        data = raw_data if isinstance(raw_data, dict) else {}
        input_uploaded = data.get("inputUploaded") or {}
        download_url = input_uploaded.get("downloadUrl")
        return cls(
            stream_id=raw.get("streamId"),
            entity_id=raw.get("entityId"),
            event_type=raw.get("eventType"),
            version=raw.get("version"),
            created_at=raw.get("createdAt"),
            # Subtask events carry parentTaskId (not taskId); fold it into task_id
            # so task_id is uniformly the chain root and subtask_id is the scope.
            task_id=data.get("taskId") or data.get("parentTaskId"),
            subtask_id=data.get("subtaskId"),
            notification_id=data.get("notificationId"),
            data_type=data.get("type"),
            download_url=download_url,
            key_fingerprint=_marker_fingerprint(raw.get("encryption")),
            actor=raw.get("actor"),
            data=data,
            raw=raw,
        )

    @property
    def routing_id(self) -> str | None:
        """The hub demux key for this event: the chain's root task id for
        task/subtask events, or the notification id for notification events."""
        return self.task_id or self.notification_id


# --- File downloads ---

class _DownloadTransport:
    """Sync HTTP glue for file downloads: the presign POST against the backend's
    task-scoped download-url endpoints (with the client's credential header) and
    the S3 GET of the presigned URL. Kept tiny and duck-typed so tests can stub
    it."""

    def __init__(self, base: str, headers: dict[str, str]):
        self._base = base
        self._headers = dict(headers)

    def presign(self, scope: str, scope_id: str, kind: str, file_id: str) -> dict:
        # `/{scope}/{scope_id}/{kind}/{file_id}/download-url` — covers task files
        # (scope=tasks, kind=inputs|replies) and submission files (scope=
        # submissions, kind=files).
        url = f"{self._base}/{scope}/{quote(str(scope_id))}/{kind}/{quote(str(file_id))}/download-url"
        req = urllib.request.Request(url, data=b"", headers=self._headers, method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            raise DownloadError(f"download-url request failed: HTTP {e.code}: {detail}",
                                status_code=e.code) from e
        return json.loads(body) if body else {}

    def get(self, url: str) -> bytes:
        try:
            with urllib.request.urlopen(url) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            raise DownloadError(f"file fetch failed: HTTP {e.code}", status_code=e.code) from e


class _MarkerKeys(Protocol):
    """What a file context needs from a decryptor (Keyring / OrgDecryptor /
    Decryptor from the optional crypto extra, which this module can't import
    at runtime): resolve an encryption marker to a raw key."""

    def key_for_marker(self, marker) -> "bytes | None": ...


@dataclass(frozen=True, slots=True)
class _FileContext:
    """Everything a bound file handle needs to download itself: the client's
    transport, the download scope + its id (`tasks`/<taskId> for task & subtask
    files — subtask files resolve through the parent server-side; `submissions`/
    <submissionId> for submission files), the event's encryption marker, and the
    stream's decryptor for key resolution."""
    transport: "_DownloadTransport"
    scope: str
    scope_id: str
    marker: object
    decryptor: "_MarkerKeys | None"


class _FileBinder:
    """Per-stream factory for `_FileContext`s — one bind per wrapped event,
    since the encryption marker is per event. `scope_id` is fixed for streams
    scoped to one entity (a task's replies share the task id); it's None for the
    submissions feed, where each event carries its own id, passed to `bind`."""

    __slots__ = ("_transport", "_scope", "_scope_id", "_decryptor")

    def __init__(self, transport, scope, scope_id, decryptor):
        self._transport = transport
        self._scope = scope
        self._scope_id = scope_id
        self._decryptor = decryptor

    def bind(self, marker, scope_id=None) -> _FileContext:
        return _FileContext(self._transport, self._scope, scope_id or self._scope_id, marker, self._decryptor)


class _DownloadableFile:
    """Behavior mixin for file-ish objects (photo/voice/file uploads and reply
    files): lazy downloads against the backend's task-scoped download-url
    endpoints. Objects yielded by a client's streams are bound to that client;
    `read()` verifies the upload checksum and transparently decrypts encrypted
    tasks' files with the key the client already holds. Nothing is fetched
    until a method is called (presigned URLs live ~5 minutes, so they are
    minted per call, never ahead of time)."""

    __slots__ = ()

    if TYPE_CHECKING:
        # Supplied by the concrete dataclasses this is mixed into.
        id: str | None
        content_type: str | None
        checksum_sha256: str | None
        _ctx: "_FileContext | None"

    # Path segment of the download endpoint: "inputs" for input uploads,
    # "replies" for reply files (overridden on ReplyFile).
    _endpoint_kind = "inputs"

    def _context(self) -> "_FileContext":
        ctx = self._ctx
        if ctx is None:
            raise DownloadError(
                "this file is not bound to a client stream; downloads are only "
                "available on objects yielded by a task's inputs()/replies()"
            )
        return ctx

    async def download_url(self) -> "tuple[str | None, str | None]":
        """Presign and return `(url, expires_at)` for this file's S3 object.

        Escape hatch for handing the fetch to your own HTTP stack. The URL is
        short-lived (~5 minutes), so presign right before fetching. For an
        encrypted task the URL serves the raw AEAD ciphertext blob — prefer
        `read()` / `save()`, which verify the checksum and decrypt."""
        ctx = self._context()
        assert self.id is not None  # a stream-yielded file always carries its id
        resp = await asyncio.to_thread(ctx.transport.presign, ctx.scope, ctx.scope_id, self._endpoint_kind, self.id)
        return resp.get("presignedGetUrl"), resp.get("expiresAt")

    async def read(self) -> bytes:
        """Download and return the file's bytes.

        Verifies the upload's SHA-256 checksum and, when the task is encrypted,
        decrypts with the key the client already holds. The whole blob is one
        AEAD message, so the file is buffered in memory (uploads are capped at
        100 MB). Raises DownloadError on checksum mismatch or when the file is
        encrypted and no matching key is available."""
        ctx = self._context()
        return await asyncio.to_thread(self._read_sync, ctx)

    async def save(self, path: "str | None" = None) -> str:
        """Download to disk and return the written path.

        `path` may be a file path, an existing directory (the file's own name —
        `filename`, falling back to its id plus a content-type extension — is
        used inside it), or omitted for the current directory."""
        ctx = self._context()
        target = self._resolve_path(path)

        def _fetch_and_write() -> str:
            data = self._read_sync(ctx)
            with open(target, "wb") as f:
                f.write(data)
            return target

        return await asyncio.to_thread(_fetch_and_write)

    def _read_sync(self, ctx: "_FileContext") -> bytes:
        assert self.id is not None  # a stream-yielded file always carries its id
        resp = ctx.transport.presign(ctx.scope, ctx.scope_id, self._endpoint_kind, self.id)
        url = resp.get("presignedGetUrl")
        if not url:
            raise DownloadError("backend returned no presigned URL")
        blob = ctx.transport.get(url)
        if self.checksum_sha256:
            digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
            if digest != self.checksum_sha256:
                raise DownloadError(f"checksum mismatch: expected {self.checksum_sha256}, got {digest}")
        if ctx.marker is None:
            return blob
        # Encrypted chain: the S3 object is the raw `nonce || ct || tag` blob the
        # uploading device produced; resolve the key by the event's marker.
        key = ctx.decryptor.key_for_marker(ctx.marker) if ctx.decryptor is not None else None
        if key is None:
            raise DownloadError("file is encrypted but the client holds no matching key")
        from .crypto import decrypt_bytes  # optional extra (pynacl)
        try:
            return decrypt_bytes(blob, key)
        except ValueError as e:
            raise DownloadError(f"failed to decrypt file: {e}") from e

    def _resolve_path(self, path: "str | None") -> str:
        default_name = getattr(self, "filename", None) or \
            f"{self.id}{mimetypes.guess_extension(self.content_type or '') or ''}"
        if path is None:
            return default_name
        if os.path.isdir(path):
            return os.path.join(path, default_name)
        return path


# --- Typed views over task events ---

# A reply body is text (or none). `text` is decrypted when a matching password
# was supplied; otherwise it holds the raw (possibly ciphertext) value.

@dataclass(frozen=True, slots=True)
class TextBody:
    text: str | None

ReplyBody = TextBody


@dataclass(frozen=True, slots=True)
class ReplyFile(_DownloadableFile):
    """A photo or file attached to a reply. Bound to the originating client:
    `await f.read()` returns the verified (and, on encrypted chains, decrypted)
    bytes, `await f.save(path)` writes them to disk, and `await
    f.download_url()` presigns the raw S3 object."""
    id: str | None
    content_type: str | None
    checksum_sha256: str | None
    size: int | None
    filename: str | None
    _ctx: "_FileContext | None" = field(default=None, repr=False, compare=False)

    _endpoint_kind = "replies"


@dataclass(frozen=True, slots=True)
class ReplyAudio(_DownloadableFile):
    """An audio clip attached to a reply. Bound to the originating client:
    `await a.read()` returns the verified (and, on encrypted chains, decrypted)
    bytes, `await a.save(path)` writes them to disk, and `await
    a.download_url()` presigns the raw S3 object. Carries `duration_seconds`
    (the voice-recording length in seconds)."""
    id: str | None
    content_type: str | None
    checksum_sha256: str | None
    size: int | None
    duration_seconds: float | None = None
    filename: str | None = None
    _ctx: "_FileContext | None" = field(default=None, repr=False, compare=False)

    _endpoint_kind = "replies"


@dataclass(frozen=True, slots=True)
class Location:
    """GPS location coordinates from a reply or submission. An inline value
    (not a downloadable file): on an encrypted chain the wire carries only an
    `encrypted` ciphertext of the coords JSON, decrypted via the same marker as
    the text body. Fields are optional; `timestamp` is milliseconds since
    epoch."""
    latitude: float | None = None
    longitude: float | None = None
    accuracy: float | None = None
    altitude: float | None = None
    heading: float | None = None
    speed: float | None = None
    timestamp: int | None = None


@dataclass(frozen=True, slots=True)
class Reply:
    """A reply appended to a task (`replyAppended`). A reply is a product: it may
    carry a text `body`, a `photo`, a `file`, an `audio` clip, and a `location`
    at the same time — each independently optional. `location` is an inline value
    (decrypted via the body's marker), not a downloadable handle. The author is
    identified by the event's `entity_id` (`raw.entity_id`) — the replier's
    public user or member id — not by fields on the reply itself."""
    id: str | None
    body: TextBody | None
    photo: ReplyFile | None
    file: ReplyFile | None
    audio: ReplyAudio | None
    location: Location | None
    subtask_id: str | None
    created_at: str | None
    raw: Event


@dataclass(frozen=True, slots=True)
class SubmissionFile(_DownloadableFile):
    """A photo or file attached to a submission. Same download surface as
    `ReplyFile` (`read()` / `save()` / `download_url()`), addressed against the
    submission download-url endpoint."""
    id: str | None
    content_type: str | None
    checksum_sha256: str | None
    size: int | None
    filename: str | None
    _ctx: "_FileContext | None" = field(default=None, repr=False, compare=False)

    _endpoint_kind = "files"


@dataclass(frozen=True, slots=True)
class SubmissionAudio(_DownloadableFile):
    """An audio clip attached to a submission. Same download surface as
    `ReplyAudio` (`read()` / `save()` / `download_url()`), addressed against the
    submission download-url endpoint. Carries `duration_seconds`."""
    id: str | None
    content_type: str | None
    checksum_sha256: str | None
    size: int | None
    duration_seconds: float | None = None
    filename: str | None = None
    _ctx: "_FileContext | None" = field(default=None, repr=False, compare=False)

    _endpoint_kind = "files"


@dataclass(frozen=True, slots=True)
class Submission:
    """A submission (`submissionCreated`) — self-authored user content with no
    associated task: a task reply minus the task and author fields. Carries an
    optional text `body` plus an optional `photo`, `file`, `audio` clip, and
    `location`, each independently present. Body text decrypts via the client's
    keyring (configured passwords/topics/org keys); `photo`/`file`/`audio` are
    downloadable, and `location` is an inline value decrypted via the body's
    marker."""
    id: str | None
    body: TextBody | None
    photo: SubmissionFile | None
    file: SubmissionFile | None
    audio: SubmissionAudio | None
    location: Location | None
    created_at: str | None
    raw: Event


# Typed submitted-input values (a tagged union). Each is a dataclass, so they
# support structural pattern matching:
#
#     match upload:
#         case TextUpload(value=v): ...
#         case ChoiceUpload(value=v, index=i): ...
#         case PhotoUpload() as p: ...

@dataclass(frozen=True, slots=True)
class TextUpload:
    id: str | None
    value: str | None          # decrypted when a matching password was supplied

@dataclass(frozen=True, slots=True)
class ChoiceUpload:
    id: str | None
    index: int | None
    value: str | None          # decrypted when a matching password was supplied

@dataclass(frozen=True, slots=True)
class MultiChoiceUpload:
    id: str | None
    indices: list[int]         # chosen 0-based option positions (plaintext)
    values: list[str]          # parallel labels, each decrypted when a matching password was supplied

@dataclass(frozen=True, slots=True)
class ActionUpload:
    id: str | None
    key: str | None            # the tapped action's key, decrypted when a matching key was supplied

@dataclass(frozen=True, slots=True)
class SliderUpload:
    id: str | None
    value: float | None        # the chosen number, decrypted when a matching key was supplied

# The binary uploads (photo/voice/file) are downloadable: they carry
# `read()` / `save()` / `download_url()` via _DownloadableFile when yielded by
# a client's stream (see ReplyFile for the method docs).

@dataclass(frozen=True, slots=True)
class PhotoUpload(_DownloadableFile):
    id: str | None
    content_type: str | None
    checksum_sha256: str | None
    size: int | None
    filename: str | None = None
    _ctx: "_FileContext | None" = field(default=None, repr=False, compare=False)

@dataclass(frozen=True, slots=True)
class VoiceUpload(_DownloadableFile):
    id: str | None
    content_type: str | None
    checksum_sha256: str | None
    size: int | None
    duration_seconds: float | None = None
    filename: str | None = None
    _ctx: "_FileContext | None" = field(default=None, repr=False, compare=False)

@dataclass(frozen=True, slots=True)
class FileUpload(_DownloadableFile):
    id: str | None
    content_type: str | None
    checksum_sha256: str | None
    size: int | None
    filename: str | None = None
    _ctx: "_FileContext | None" = field(default=None, repr=False, compare=False)

# A submitted `location` input. Unlike photo/voice/file uploads this is inline
# data (decrypted via the marker, like the body), not a downloadable file: it
# carries the decoded `Location` directly.
@dataclass(frozen=True, slots=True)
class LocationUpload:
    id: str | None
    location: Location | None  # decoded inline (decrypted when a matching key was supplied)

Upload = TextUpload | ChoiceUpload | MultiChoiceUpload | ActionUpload | SliderUpload | PhotoUpload | VoiceUpload | FileUpload | LocationUpload


@dataclass(frozen=True, slots=True)
class InputEvent:
    """An intermediate input event for a task (`taskInputUploaded`,
    `taskInputCompleted`). `uploads` is the typed list of submitted inputs.
    Completion is delivered separately as the terminal `TaskCompleted`."""
    type: str                      # the `data.type` discriminator
    uploads: list[Upload]
    raw: Event


@dataclass(frozen=True, slots=True)
class TaskDeleted:
    """Terminal marker yielded as the final item of a task's `inputs()` /
    `replies()` stream when the task is deleted (collective `taskDeleted`).
    Iteration ends immediately after it. A stream that ends without yielding
    this stopped for another reason (timeout, or the connection closing)."""
    task_id: str | None
    created_at: str | None
    raw: Event


def _deleted_marker(ev: Event, decryptor=None) -> TaskDeleted:
    # routing_id is the deleted entity's id (a task chain root). Notifications
    # have no deletion event, so this only ever fires for task chains.
    # `decryptor` is unused — present so every entity-terminal marker factory
    # shares one signature (the canceled marker decrypts its note).
    return TaskDeleted(task_id=ev.routing_id, created_at=ev.created_at, raw=ev)


@dataclass(frozen=True, slots=True)
class TaskCanceled:
    """Terminal marker yielded as the final item of a task's `inputs()` /
    `replies()` stream (and every subtask stream of the chain — a canceled
    root closes the whole chain) when the SENDER cancels the task. `reason`
    is `canceled`, `answered`, or `superseded`; `note` is decrypted where the
    task's key is held; `superseded_by` names the replacement task when the
    reason is `superseded`. Iteration ends immediately after it."""
    task_id: str | None
    reason: str | None
    note: str | None
    superseded_by: str | None
    created_at: str | None
    raw: Event


def _canceled_marker(ev: Event, decryptor=None) -> TaskCanceled:
    return TaskCanceled(
        task_id=ev.routing_id,
        reason=ev.data.get("reason"),
        # The envelope marker on a canceled event IS the note's own marker
        # (not the task's) — the backend sets it that way because the note is
        # this event's only encrypted field and may use a different key than
        # the send (org rotation; encrypted note on a plaintext task).
        note=_maybe_decrypt(ev.data.get("note"), ev.raw.get("encryption"), decryptor),
        superseded_by=ev.data.get("supersededBy"),
        created_at=ev.created_at,
        raw=ev,
    )


@dataclass(frozen=True, slots=True)
class SubtaskCanceled:
    """Terminal marker for ONE subtask's `inputs()` / `replies()` stream when
    the sender withdraws that follow-up. Scoped: the rest of the chain stays
    live. `superseded_by` names the replacement subtask (same chain) when the
    reason is `superseded`."""
    subtask_id: str | None
    parent_task_id: str | None
    reason: str | None
    note: str | None
    superseded_by: str | None
    created_at: str | None
    raw: Event


def _subtask_canceled_marker(ev: Event, decryptor=None) -> SubtaskCanceled:
    return SubtaskCanceled(
        subtask_id=ev.subtask_id,
        parent_task_id=ev.task_id,
        reason=ev.data.get("reason"),
        # Envelope marker = the note's own marker; see _canceled_marker.
        note=_maybe_decrypt(ev.data.get("note"), ev.raw.get("encryption"), decryptor),
        superseded_by=ev.data.get("supersededBy"),
        created_at=ev.created_at,
        raw=ev,
    )


@dataclass(frozen=True, slots=True)
class TaskDeclinedByRecipient:
    """One recipient declined ("no answer is coming from me") — yielded
    MID-STREAM in a task's `inputs()` / `replies()` stream, NOT a terminal:
    in shared mode the task stays live for the other recipients, so a
    collector can count declines down. When the last recipient declines, the
    terminal `TaskDeclined` follows (same transaction backend-side). `reason`
    is `declined` or `failed` ("tried and couldn't"); `note` is the
    recipient's free-text context, decrypted where its key is held; `actor`
    is the decliner's identity snapshot (publicId / name / device) as sent by
    the backend."""
    task_id: str | None
    reason: str | None
    note: str | None
    actor: dict | None
    created_at: str | None
    raw: Event


def _declined_by_recipient_marker(ev: Event, decryptor=None) -> TaskDeclinedByRecipient:
    return TaskDeclinedByRecipient(
        task_id=ev.routing_id,
        reason=ev.data.get("reason"),
        # Envelope marker = the note's own marker; see _canceled_marker.
        note=_maybe_decrypt(ev.data.get("note"), ev.raw.get("encryption"), decryptor),
        actor=ev.actor,
        created_at=ev.created_at,
        raw=ev,
    )


@dataclass(frozen=True, slots=True)
class TaskDeclined:
    """Terminal marker yielded as the final item of a task's `inputs()` /
    `replies()` stream (and every subtask stream of the chain) when EVERY
    recipient has declined — the recipient-side mirror of `TaskCanceled`.
    Collective: per-recipient reasons/notes arrived on the preceding
    `TaskDeclinedByRecipient` items. Iteration ends immediately after it."""
    task_id: str | None
    created_at: str | None
    raw: Event


def _declined_marker(ev: Event, decryptor=None) -> TaskDeclined:
    return TaskDeclined(task_id=ev.routing_id, created_at=ev.created_at, raw=ev)


@dataclass(frozen=True, slots=True)
class SubtaskDeclinedByRecipient:
    """One recipient refused THIS follow-up — the subtask-scoped twin of
    `TaskDeclinedByRecipient`: a mid-stream signal, not a terminal (in shared
    mode the subtask stays live for the others; the chain always stays live)."""
    subtask_id: str | None
    parent_task_id: str | None
    reason: str | None
    note: str | None
    actor: dict | None
    created_at: str | None
    raw: Event


def _subtask_declined_by_recipient_marker(ev: Event, decryptor=None) -> SubtaskDeclinedByRecipient:
    return SubtaskDeclinedByRecipient(
        subtask_id=ev.subtask_id,
        parent_task_id=ev.task_id,
        reason=ev.data.get("reason"),
        # Envelope marker = the note's own marker; see _canceled_marker.
        note=_maybe_decrypt(ev.data.get("note"), ev.raw.get("encryption"), decryptor),
        actor=ev.actor,
        created_at=ev.created_at,
        raw=ev,
    )


@dataclass(frozen=True, slots=True)
class SubtaskDeclined:
    """Scoped terminal for ONE subtask's `inputs()` / `replies()` stream when
    every recipient declined that follow-up — the decline-side twin of
    `SubtaskCanceled`. The rest of the chain stays live."""
    subtask_id: str | None
    parent_task_id: str | None
    created_at: str | None
    raw: Event


def _subtask_declined_marker(ev: Event, decryptor=None) -> SubtaskDeclined:
    return SubtaskDeclined(subtask_id=ev.subtask_id, parent_task_id=ev.task_id,
                           created_at=ev.created_at, raw=ev)


# Entity-wide terminal events: they ignore subtask scope, so one of these ends
# the root's streams AND every subtask stream of the chain. Maps data.type to
# the marker factory yielded as the stream's final item.
_ENTITY_TERMINALS = {
    _TASK_DELETED: _deleted_marker,
    _TASK_CANCELED: _canceled_marker,
    _TASK_DECLINED: _declined_marker,
}


@dataclass(frozen=True, slots=True)
class TaskCompleted:
    """Terminal marker yielded as the final item of a task's `inputs()` stream
    once all required inputs are committed. `uploads` is the full committed input
    set (typed, decrypted where possible). Iteration ends immediately after it."""
    task_id: str | None
    uploads: list[Upload]
    raw: Event


@dataclass(frozen=True, slots=True)
class SubtaskCompleted:
    """Terminal marker yielded as the final item of a subtask's `inputs()` stream
    once its inputs are committed. `uploads` is the full committed set."""
    subtask_id: str | None
    parent_task_id: str | None
    uploads: list[Upload]
    raw: Event


# The recipient's answer to a notification's input (mirrors the backend domain
# `NotificationReply`: a sum of text XOR choice). Distinct from the task `Upload`
# types — a notification reply carries no id. `value` / `selected_value` are
# decrypted when a matching password was supplied; otherwise the raw value.

@dataclass(frozen=True, slots=True)
class NotificationTextReply:
    value: str | None

@dataclass(frozen=True, slots=True)
class NotificationChoiceReply:
    selected_index: int | None
    selected_value: str | None

@dataclass(frozen=True, slots=True)
class NotificationActionReply:
    # The tapped action's `key`, decrypted where the marker's password was
    # supplied. Both the key and the labels are encrypted on the wire
    # (server-blind); otherwise the raw ciphertext is passed through.
    selected_key: str | None

NotificationReply = NotificationTextReply | NotificationChoiceReply | NotificationActionReply


@dataclass(frozen=True, slots=True)
class NotificationCompleted:
    """The single event a notification emits: the recipient answered it. `reply`
    is the typed answer — a `NotificationTextReply` or `NotificationChoiceReply` —
    decrypted where possible, or `None` if the notification carried no input.
    Yielded as the sole, terminal item of `Notification.inputs()`."""
    notification_id: str | None
    reply: NotificationReply | None
    raw: Event


def _marker_fingerprint(marker) -> str | None:
    """The personal fingerprint from an `Encryption` wire marker:
    ``{"type": "personal", "keyFingerprint": ...}`` -> the fingerprint;
    ``{"type": "org", "v": ...}`` or ``None`` -> ``None``. This SDK is
    topic/personal-mode, so org ciphertext (decrypted via a device master_key,
    which the SDK doesn't hold) is passed through unchanged."""
    if isinstance(marker, dict) and marker.get("type") == "personal":
        return marker.get("keyFingerprint")
    return None


@overload
def _maybe_decrypt(value: str, marker, decryptor) -> str: ...
@overload
def _maybe_decrypt(value: None, marker, decryptor) -> None: ...
def _maybe_decrypt(value, marker, decryptor):
    if value is None or decryptor is None or marker is None:
        return value
    try:
        plain = decryptor.try_decrypt_marker(value, marker)
    except ValueError:
        return value
    return plain if plain is not None else value


def _wrap_upload(u: dict, marker, decryptor, files) -> Upload | None:
    t = u.get("type")
    if t == "textUploaded":
        return TextUpload(id=u.get("id"),
                          value=_maybe_decrypt(u.get("value"), marker, decryptor))
    if t == "choiceSelected":
        return ChoiceUpload(id=u.get("id"), index=u.get("selectedIndex"),
                            value=_maybe_decrypt(u.get("selectedValue"), marker, decryptor))
    if t == "multiChoiceSelected":
        return MultiChoiceUpload(
            id=u.get("id"),
            indices=u.get("selectedIndices") or [],
            values=[_maybe_decrypt(v, marker, decryptor) for v in (u.get("selectedValues") or [])],
        )
    if t == "actionSelected":
        return ActionUpload(id=u.get("id"),
                            key=_maybe_decrypt(u.get("selectedKey"), marker, decryptor))
    if t == "sliderUploaded":
        raw = _maybe_decrypt(u.get("value"), marker, decryptor)
        try:
            value = float(raw) if raw is not None else None
        except (TypeError, ValueError):
            value = None
        return SliderUpload(id=u.get("id"), value=value)
    if t == "locationUploaded":
        # Inline data (like text/choice), decoded via the marker — NOT a file.
        # The backend's LocationUploadedEvent FLATTENS the coordinate fields
        # (latitude/.../encrypted) directly onto the upload object — there is no
        # nested `location` key (unlike the reply/submission `location` field) —
        # so the whole upload dict is the location payload.
        return LocationUpload(id=u.get("id"),
                              location=_wrap_reply_location(u, marker, decryptor))
    ctx = files.bind(marker) if files is not None else None
    if t == "photoUploaded":
        return PhotoUpload(id=u.get("id"), content_type=u.get("contentType"),
                           checksum_sha256=u.get("checksumSha256"), size=u.get("size"),
                           filename=u.get("filename"), _ctx=ctx)
    if t == "voiceRecorded":
        return VoiceUpload(id=u.get("id"), content_type=u.get("contentType"),
                           checksum_sha256=u.get("checksumSha256"), size=u.get("size"),
                           duration_seconds=u.get("durationSeconds"),
                           filename=u.get("filename"), _ctx=ctx)
    if t == "fileUploaded":
        return FileUpload(id=u.get("id"), content_type=u.get("contentType"),
                          checksum_sha256=u.get("checksumSha256"), size=u.get("size"),
                          filename=u.get("filename"), _ctx=ctx)
    return None  # unrecognised upload type — dropped from the list


def _wrap_reply_body(body: dict | None, marker, decryptor) -> ReplyBody | None:
    if not body:
        return None
    t = body.get("type")
    if t == "text":
        return TextBody(text=_maybe_decrypt(body.get("value"), marker, decryptor))
    return None  # unrecognised body type


def _wrap_reply_file(f: dict | None, ctx) -> ReplyFile | None:
    if not f:
        return None
    return ReplyFile(
        id=f.get("id"),
        content_type=f.get("contentType"),
        checksum_sha256=f.get("checksumSha256"),
        size=f.get("size"),
        filename=f.get("filename"),
        _ctx=ctx,
    )


def _wrap_reply_audio(a: dict | None, ctx) -> ReplyAudio | None:
    if not a:
        return None
    return ReplyAudio(
        id=a.get("id"),
        content_type=a.get("contentType"),
        checksum_sha256=a.get("checksumSha256"),
        size=a.get("size"),
        duration_seconds=a.get("durationSeconds"),
        filename=a.get("filename"),
        _ctx=ctx,
    )


def _wrap_reply_location(loc: dict | None, marker, decryptor) -> Location | None:
    """Build a `Location` from a reply/submission `location` dict. Mirrors the
    body: an encrypted chain carries only `encrypted` (the ciphertext of the
    coords JSON under the same marker), which is decrypted then `json.loads`-d;
    an unencrypted chain carries the structured fields directly. Degrades to
    `None` on a decrypt failure or invalid JSON (like an undecryptable body)."""
    if not loc:
        return None
    if "encrypted" in loc:
        encrypted_value = loc.get("encrypted")
        if encrypted_value and marker is not None and decryptor is not None:
            try:
                plain = decryptor.try_decrypt_marker(encrypted_value, marker)
            except ValueError:
                return None
            if plain is not None:
                try:
                    coords = json.loads(plain)
                except (ValueError, TypeError):
                    return None
                if isinstance(coords, dict):
                    return Location(
                        latitude=coords.get("latitude"),
                        longitude=coords.get("longitude"),
                        accuracy=coords.get("accuracy"),
                        altitude=coords.get("altitude"),
                        heading=coords.get("heading"),
                        speed=coords.get("speed"),
                        timestamp=coords.get("timestamp"),
                    )
        return None  # encrypted but undecryptable / unparseable — degrade gracefully
    # Unencrypted: use the structured fields directly.
    return Location(
        latitude=loc.get("latitude"),
        longitude=loc.get("longitude"),
        accuracy=loc.get("accuracy"),
        altitude=loc.get("altitude"),
        heading=loc.get("heading"),
        speed=loc.get("speed"),
        timestamp=loc.get("timestamp"),
    )


def _wrap_reply(ev: Event, decryptor, files) -> "Reply | SubtaskCanceled | TaskDeclinedByRecipient":
    # A subtask reply stream also wants its own cancel (scoped terminal).
    if ev.data_type == _SUBTASK_CANCELED:
        return _subtask_canceled_marker(ev, decryptor)
    # Per-recipient declines are mid-stream signals, not terminals.
    if ev.data_type == _TASK_DECLINED_BY_RECIPIENT:
        return _declined_by_recipient_marker(ev, decryptor)
    if ev.data_type == _SUBTASK_DECLINED_BY_RECIPIENT:
        return _subtask_declined_by_recipient_marker(ev, decryptor)
    if ev.data_type == _SUBTASK_DECLINED:
        return _subtask_declined_marker(ev, decryptor)
    reply = ev.data.get("reply") or {}
    marker = ev.raw.get("encryption")
    ctx = files.bind(marker) if files is not None else None
    return Reply(
        id=reply.get("id"),
        body=_wrap_reply_body(reply.get("body"), marker, decryptor),
        photo=_wrap_reply_file(reply.get("photo"), ctx),
        file=_wrap_reply_file(reply.get("file"), ctx),
        audio=_wrap_reply_audio(reply.get("audio"), ctx),
        location=_wrap_reply_location(reply.get("location"), marker, decryptor),
        subtask_id=ev.data.get("subtaskId"),
        created_at=reply.get("createdAt"),
        raw=ev,
    )


def _wrap_submission_file(f: dict | None, ctx) -> SubmissionFile | None:
    if not f:
        return None
    return SubmissionFile(
        id=f.get("id"),
        content_type=f.get("contentType"),
        checksum_sha256=f.get("checksumSha256"),
        size=f.get("size"),
        filename=f.get("filename"),
        _ctx=ctx,
    )


def _wrap_submission_audio(a: dict | None, ctx) -> SubmissionAudio | None:
    if not a:
        return None
    return SubmissionAudio(
        id=a.get("id"),
        content_type=a.get("contentType"),
        checksum_sha256=a.get("checksumSha256"),
        size=a.get("size"),
        duration_seconds=a.get("durationSeconds"),
        filename=a.get("filename"),
        _ctx=ctx,
    )


def _wrap_submission(ev: Event, decryptor, files) -> Submission:
    submission = ev.data.get("submission") or {}
    marker = ev.raw.get("encryption")
    # Each submission carries its own id; bind the file context to it (the
    # binder's scope is `submissions`, scope_id is per-event).
    ctx = files.bind(marker, scope_id=submission.get("id")) if files is not None else None
    return Submission(
        id=submission.get("id"),
        body=_wrap_reply_body(submission.get("body"), marker, decryptor),
        photo=_wrap_submission_file(submission.get("photo"), ctx),
        file=_wrap_submission_file(submission.get("file"), ctx),
        audio=_wrap_submission_audio(submission.get("audio"), ctx),
        location=_wrap_reply_location(submission.get("location"), marker, decryptor),
        created_at=submission.get("createdAt"),
        raw=ev,
    )


def _wrap_uploads(raw_uploads, marker, decryptor, files) -> list[Upload]:
    return [w for u in raw_uploads
            if (w := _wrap_upload(u, marker, decryptor, files)) is not None]


def _wrap_input(ev: Event, decryptor, files) -> "InputEvent | TaskCompleted | SubtaskCompleted | SubtaskCanceled | TaskDeclinedByRecipient":
    """Wrap a task OR subtask input event. The completion events become the
    dedicated terminal markers; the rest become `InputEvent`."""
    data = ev.data
    marker = ev.raw.get("encryption")
    if ev.data_type == "taskCompleted":
        return TaskCompleted(task_id=ev.task_id,
                             uploads=_wrap_uploads(data.get("inputsUploaded") or [], marker, decryptor, files),
                             raw=ev)
    if ev.data_type == "subtaskCompleted":
        return SubtaskCompleted(subtask_id=ev.subtask_id, parent_task_id=ev.task_id,
                                uploads=_wrap_uploads(data.get("inputsUploaded") or [], marker, decryptor, files),
                                raw=ev)
    if ev.data_type == _SUBTASK_CANCELED:
        return _subtask_canceled_marker(ev, decryptor)
    # Per-recipient declines are mid-stream signals, not terminals.
    if ev.data_type == _TASK_DECLINED_BY_RECIPIENT:
        return _declined_by_recipient_marker(ev, decryptor)
    if ev.data_type == _SUBTASK_DECLINED_BY_RECIPIENT:
        return _subtask_declined_by_recipient_marker(ev, decryptor)
    if ev.data_type == _SUBTASK_DECLINED:
        return _subtask_declined_marker(ev, decryptor)
    raw_uploads = [data["inputUploaded"]] if data.get("inputUploaded") else []
    return InputEvent(type=ev.data_type or "", uploads=_wrap_uploads(raw_uploads, marker, decryptor, files), raw=ev)


def _wrap_notification_reply(reply: dict | None, marker, decryptor) -> "NotificationReply | None":
    """The recipient's answer on a `notificationCompleted` event: a text reply
    (`{type:"text", value}`), a choice reply (`{type:"choice", selectedIndex,
    selectedValue}`), or an action reply (`{type:"actions", selectedKey}`)."""
    if not reply:
        return None
    t = reply.get("type")
    if t == "text":
        return NotificationTextReply(value=_maybe_decrypt(reply.get("value"), marker, decryptor))
    if t == "choice":
        return NotificationChoiceReply(
            selected_index=reply.get("selectedIndex"),
            selected_value=_maybe_decrypt(reply.get("selectedValue"), marker, decryptor),
        )
    if t == "actions":
        # The tapped action's key is encrypted on the wire (server-blind), like
        # the labels — decrypt it via the event marker (same as the task path).
        return NotificationActionReply(
            selected_key=_maybe_decrypt(reply.get("selectedKey"), marker, decryptor))
    return None  # unrecognised reply type


def _wrap_notification(ev: Event, decryptor, files) -> "NotificationCompleted":
    """Wrap the sole notification event (`notificationCompleted`). `files` is
    unused (notifications carry no downloadable uploads) — present so all wrap
    functions share one signature."""
    return NotificationCompleted(
        notification_id=ev.notification_id,
        reply=_wrap_notification_reply(ev.data.get("reply"), ev.raw.get("encryption"), decryptor),
        raw=ev,
    )


# --- Demux hub: one connection, many task subscribers ---

class _TaskBuffer:
    """Per-task replay buffer plus the live consumer queues attached to it.

    Events are buffered from the moment `send` registers the task, so a consumer
    that attaches a little later (the common send-then-await case) still sees
    everything. Each buffered/queued item is `(seq, Event)`; `seq` lets a fresh
    consumer replay the snapshot and then skip duplicates that also arrived live
    during the replay."""
    __slots__ = ("deque", "queues")

    def __init__(self):
        self.deque: collections.deque = collections.deque(maxlen=2000)
        self.queues: set[asyncio.Queue] = set()


class _Hub:
    def __init__(self, host: str, port: int, ssl: bool, *,
                 connect_path: str, auth_headers: dict | None = None):
        self._host = host
        self._port = port
        self._protocol = "wss" if ssl else "ws"
        self._connect_path = connect_path
        self._auth_headers = auth_headers or {}
        self._buffers: dict[str, _TaskBuffer] = {}
        self._raw_queues: set[asyncio.Queue] = set()
        self._since: str | None = None
        # Resume version paired with `_since`: the last-seen event's version. The
        # `since` window is inclusive (created_at >= since), so on reconnect we
        # also send `after_version` to drop the boundary event we already saw.
        # None until the first event arrives (initial connect filters by `since`
        # only — there's no version to resume past yet).
        self._after_version: int | None = None
        self._seq = 0
        self._runner: asyncio.Task | None = None
        self._consumers = 0                       # live iterators; runner stops at 0
        self._failed: Exception | None = None     # set on an unrecoverable stream error

    @property
    def protocol(self) -> str:
        return self._protocol

    def base_url(self) -> str:
        return f"{self._protocol}://{self._host}:{self._port}"

    # -- registration (sync, safe to call from send) --
    # An "entity" is whatever a handle subscribes under: a task chain's root id
    # (Task / Subtask) or a notification id. Events route to the matching buffer
    # by Event.routing_id, so tasks and notifications share this demux.

    def register_entity(self, entity_id: str, created_at: str | None):
        self._buffers.setdefault(entity_id, _TaskBuffer())
        if created_at and (self._since is None or created_at < self._since):
            self._since = created_at
            # The version watermark was recorded against a later cursor; rewinding
            # `since` to replay an older backlog invalidates it (else `version >
            # after_version` would drop the very backlog we're rewinding for).
            self._after_version = None

    def attach_entity(self, entity_id: str) -> tuple[asyncio.Queue, list]:
        buf = self._buffers.setdefault(entity_id, _TaskBuffer())
        q: asyncio.Queue = asyncio.Queue()
        buf.queues.add(q)
        self._consumers += 1
        if self._failed is not None:  # already-failed hub: surface immediately
            q.put_nowait(_HubError(self._failed))
        return q, list(buf.deque)

    def detach_entity(self, entity_id: str, q: asyncio.Queue):
        buf = self._buffers.get(entity_id)
        if buf is not None and q in buf.queues:
            buf.queues.discard(q)
            self._release()

    def attach_raw(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._raw_queues.add(q)
        self._consumers += 1
        if self._failed is not None:
            q.put_nowait(_HubError(self._failed))
        return q

    def detach_raw(self, q: asyncio.Queue):
        if q in self._raw_queues:
            self._raw_queues.discard(q)
            self._release()

    def _release(self):
        """Drop one consumer; stop the background connection when none remain."""
        self._consumers -= 1
        if self._consumers <= 0:
            self._consumers = 0
            self._stop_runner_nowait()

    def _stop_runner_nowait(self):
        # Sync, fire-and-forget: safe to call from a consumer's `finally` (which
        # may run during cancellation). The cancelled runner closes its socket on
        # its own; `ensure_running` will start a fresh one if a consumer returns.
        if self._runner is not None:
            self._runner.cancel()
            self._runner = None

    async def ensure_running(self):
        # Don't restart after an unrecoverable failure — it would just hit the
        # same error again. A fresh client (e.g. new token) gets a fresh hub.
        if self._failed is not None:
            return
        if self._runner is None or self._runner.done():
            self._runner = asyncio.create_task(self._run())

    def _fail(self, err: Exception):
        """Mark the hub permanently failed and push the error to every consumer
        so their `async for` raises instead of hanging."""
        self._failed = err
        sentinel = _HubError(err)
        for q in list(self._raw_queues):
            q.put_nowait(sentinel)
        for buf in self._buffers.values():
            for q in list(buf.queues):
                q.put_nowait(sentinel)

    async def aclose(self):
        if self._runner is not None:
            self._runner.cancel()
            try:
                await self._runner
            except asyncio.CancelledError:
                pass
            self._runner = None

    def _dispatch(self, ev: Event):
        self._seq += 1
        for q in list(self._raw_queues):
            q.put_nowait(ev)
        # Route by the event's demux key (Event.routing_id): the chain's root
        # task id for task/subtask events, or the notification id. Parent Task and
        # its Subtasks subscribe under the root id and filter by subtaskId.
        rid = ev.routing_id
        if rid is not None:
            buf = self._buffers.get(rid)
            if buf is not None:
                item = (self._seq, ev)
                buf.deque.append(item)
                for q in list(buf.queues):
                    q.put_nowait(item)

    async def _run(self):
        url = f"{self.base_url()}{self._connect_path}"
        headers = self._auth_headers
        since = self._since or _now_iso()
        after_version = self._after_version
        backoff = 1.0
        while True:
            try:
                full = f"{url}?since={quote(since, safe='')}"
                if after_version is not None:
                    full += f"&after_version={after_version}"
                ws = await _open_ws(full, headers)
                try:
                    backoff = 1.0
                    async for message in ws:
                        ev = Event.from_raw(json.loads(message))
                        if ev.created_at:
                            # Resume cursor: created_at + its version move together
                            # so the next reconnect skips exactly this event.
                            since = ev.created_at
                            self._since = since                 # persist across runner restarts
                            if ev.version is not None:
                                after_version = ev.version
                                self._after_version = after_version
                        self._dispatch(ev)
                finally:
                    await ws.close()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if _is_permanent_ws_error(exc):
                    # Auth/4xx/bad-URL: won't recover on retry. Surface it to
                    # consumers (their `async for` raises) rather than looping
                    # silently forever.
                    self._fail(_as_stream_error(exc))
                    return
                # Transient (network drop, pod restart, 5xx, rate limit):
                # reconnect with backoff, resuming from the last-seen cursor.
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30.0)


# --- Task / Subtask handles ---

@dataclass
class TaskGroupRecipient:
    """The recipient behind one task instance in a group: their shareable
    public id (`usr_...`) plus a display name — the org member name for org
    sends, the personal name for topic sends (may be None)."""
    public_id: str | None
    name: str | None


class Task:
    """Handle for a task you sent. Its `inputs()` and `replies()` are async
    iterators scoped to this task; `append()` adds a subtask to its chain.

    An independent-mode send (the default) returns a `TaskGroup` instead; each
    of its member instances is a `Task` carrying the `recipient` it belongs to."""

    def __init__(self, task_id: str, created_at: str | None, wait_token: str | None,
                 hub: _Hub, *, append_token: str | None = None, client=None, send_key=None,
                 decryptor=None, recipient: "TaskGroupRecipient | None" = None):
        self.task_id = task_id
        self.created_at = created_at
        self.wait_token = wait_token
        self.append_token = append_token
        self.recipient = recipient
        self._hub = hub
        self._client = client
        self._send_key = send_key  # the topic key, reused to encrypt subtasks
        # Org tasks pass a ready OrgDecryptor (versioned master keys); personal
        # topic tasks build a fingerprint-gated Decryptor from the topic key,
        # which also decrypts recipients' replies/inputs (shared-password).
        self._decryptor = decryptor
        if self._decryptor is None and send_key is not None:
            from .crypto import Decryptor  # optional extra
            self._decryptor = Decryptor(send_key)

    def _file_binder(self) -> "_FileBinder | None":
        """Binder attaching download behavior to this task's file-ish uploads.
        None when the task wasn't created by a client (no transport to bind)."""
        if self._client is None:
            return None
        return _FileBinder(self._client._file_transport(), "tasks", self.task_id, self._decryptor)

    def inputs(self, *, timeout: float | None = None, replay: bool = False):
        """Yield `InputEvent` objects for this task. Iteration ends after a
        terminal marker: `TaskCompleted` (all inputs committed; carries the
        full set), `TaskDeleted` (task deleted), or `TaskCanceled` (sender
        withdrew it). Each is yielded as the final item. Also stops (without a
        marker) after `timeout` seconds with no event.

        With `replay=True` the buffered backlog since the task was sent is
        replayed first (so nothing in the send-to-iterate gap is missed); the
        default delivers only events from the point of subscription onward.

        Photo/voice/file uploads on the yielded events are downloadable:
        `await upload.read()` / `await upload.save(path)`.

        Yields: InputEvent | TaskCompleted | TaskDeleted | TaskCanceled | TaskDeclinedByRecipient | TaskDeclined
        """
        return _TaskStream(self._hub, self.task_id, None, self._decryptor,
                           _INPUT_TYPES, _wrap_input, timeout, _INPUT_TERMINAL, replay=replay,
                           files=self._file_binder())

    def replies(self, *, timeout: float | None = None, replay: bool = False):
        """Yield `Reply` objects anchored to this task (not its subtasks). Ends
        with a `TaskDeleted` / `TaskCanceled` marker if the task is deleted or
        canceled, or after `timeout`. `replay=True` replays the buffered
        backlog first.

        A reply's `photo` / `file` are downloadable: `await reply.photo.read()`
        / `await reply.photo.save(path)`.

        Yields: Reply | TaskDeleted | TaskCanceled | TaskDeclinedByRecipient | TaskDeclined
        """
        return _TaskStream(self._hub, self.task_id, None, self._decryptor,
                           _REPLY_TYPES, _wrap_reply, timeout, frozenset(), replay=replay,
                           files=self._file_binder())

    def append(self, *, title: str | None = None, content: str | None = None,
               inputs=None, links: list[str] | None = None,
               files: "list[str | os.PathLike] | None" = None,
               auto_commit: bool = True, critical: bool = False,
               reply: "ReplyMode | Literal['one-shot', 'sticky', 'one-time-per-user'] | None" = None,
               content_format: "ContentFormat | Literal['plain', 'markdown'] | None" = None) -> "Subtask":
        """Append a subtask to this task's chain and return a `Subtask` handle.
        The subtask inherits the parent's recipients (no targeting) and, when the
        parent was sent with a password, its encryption.

        `files` are local file paths uploaded after the subtask is
        created (and encrypted under the chain's key when the parent was). A
        personal append with attachments authenticates with the user API-Token."""
        if self._client is None:
            raise RuntimeError("this Task was not created by a client; cannot append")
        return self._client._append_subtask(
            self, title=title, content=content, inputs=inputs,
            links=links, files=files,
            auto_commit=auto_commit, critical=critical, reply=reply,
            content_format=content_format,
        )

    def cancel(self, *, reason: "CancelReason | Literal['canceled', 'answered', 'superseded']" = "canceled",
               note: str | None = None,
               superseded_by: "str | Task | None" = None) -> None:
        """Cancel this pending task (sender-side withdrawal). Recipients see the
        card flip to canceled; a collector's `inputs()`/`replies()` stream ends
        with a `TaskCanceled` marker. `reason` is a `CancelReason` (or its
        string value `canceled`, `answered`, `superseded`); `superseded_by`
        (a task id or `Task`, requires reason
        `superseded`) names the replacement. `note` is encrypted under the
        chain's key when the send was encrypted. Idempotent on re-cancel;
        raises `ApiError` (`task_already_completed`) if the task was answered
        first."""
        if self._client is None:
            raise RuntimeError("this Task was not created by a client; cannot cancel")
        sid = superseded_by.task_id if isinstance(superseded_by, Task) else superseded_by
        self._client._cancel_task(self, reason=reason, note=note, superseded_by=sid)


@dataclass
class GroupReply:
    """A reply collected over a whole task group (`TaskGroup.replies()`): the
    `item` — a `Reply`, or a `TaskDeleted` / `TaskCanceled` marker when that
    member's task was deleted or canceled — together with the member `instance`
    it arrived on. `recipient` is a shortcut to `instance.recipient`: who
    replied."""
    instance: "Task"
    item: "Reply | TaskDeleted | TaskCanceled | TaskDeclinedByRecipient | TaskDeclined"

    @property
    def recipient(self) -> "TaskGroupRecipient | None":
        return self.instance.recipient


@dataclass
class GroupInput:
    """An input event collected over a whole task group (`TaskGroup.inputs()`):
    the `item` — an `InputEvent`, a terminal `TaskCompleted` (that member's full
    committed input set), or a `TaskDeleted` / `TaskCanceled` marker — together
    with the member `instance` it arrived on. `recipient` is a shortcut to
    `instance.recipient`: whose input it is."""
    instance: "Task"
    item: "InputEvent | TaskCompleted | TaskDeleted | TaskCanceled | TaskDeclinedByRecipient | TaskDeclined"

    @property
    def recipient(self) -> "TaskGroupRecipient | None":
        return self.instance.recipient


@dataclass(frozen=True, slots=True)
class GroupCancelResult:
    """How a group cancel landed: `canceled` instances were still pending and
    got the cancel; `skipped` were already terminal (completed or canceled)
    and were left untouched. canceled + skipped = instance count."""
    canceled: int
    skipped: int


class TaskGroup:
    """Handle for an independent-mode send (the default): every recipient got
    their own task instance under one group, so one recipient's answers never
    touch another's task. Iterate it (or read `instances`) for the per-recipient
    `Task` handles — each streams and appends like any single task. `append()`
    adds a subtask to every member's chain atomically (or a subset via
    `instances=`); `sole` unwraps the single instance of a one-recipient group.
    """

    def __init__(self, group_id: str, created_at: str | None, wait_token: str | None,
                 hub: _Hub, *, append_token: str | None = None,
                 instances: "list[Task] | None" = None, client=None, send_key=None,
                 decryptor=None):
        self.group_id = group_id
        self.created_at = created_at
        self.wait_token = wait_token
        self.append_token = append_token
        self.instances: list[Task] = list(instances or [])
        self._hub = hub
        self._client = client
        self._send_key = send_key  # the topic key, reused to encrypt group appends
        self._decryptor = decryptor
        if self._decryptor is None and send_key is not None:
            from .crypto import Decryptor  # optional extra
            self._decryptor = Decryptor(send_key)

    def __iter__(self):
        return iter(self.instances)

    def __len__(self) -> int:
        return len(self.instances)

    @property
    def sole(self) -> "Task":
        """The single instance of a one-recipient group. Raises ValueError when
        the group holds zero or several instances."""
        if len(self.instances) != 1:
            raise ValueError(
                f"group {self.group_id} has {len(self.instances)} instances, not exactly 1"
            )
        return self.instances[0]

    def inputs(self, *, timeout: float | None = None, replay: bool = False):
        """Collect input events across EVERY member instance of this group,
        demuxed off the one shared WS stream (no extra connection — each
        member's `taskId` is already a routing key on the hub). Yields a
        `GroupInput` per event: an `InputEvent`, a terminal `TaskCompleted`
        (that member's full committed input set), or a `TaskDeleted`, plus the
        member `instance` it arrived on, so you know whose input it is.

        `timeout` is GROUP-WIDE: iteration stops after that many seconds with no
        event from any member (a single quiet member never ends the group).
        `replay=True` replays each member's buffered backlog first. Iteration
        otherwise ends when every member's stream has ended — each on its own
        `TaskCompleted` or `TaskDeleted`.

        Upload files on the yielded events are downloadable:
        `await event.item.uploads[0].read()`.

        Yields: GroupInput
        """
        return _GroupStream(
            self.instances,
            lambda inst: inst.inputs(replay=replay),
            lambda inst, item: GroupInput(instance=inst, item=item),
            timeout=timeout,
        )

    def replies(self, *, timeout: float | None = None, replay: bool = False):
        """Collect replies across EVERY member instance of this group, demuxed
        off the one shared WS stream (no extra connection — each member's
        `taskId` is already a routing key on the hub). Yields a `GroupReply` per
        reply: the `Reply` (or a `TaskDeleted` marker) plus the member
        `instance` it arrived on, so you know which recipient replied.

        `timeout` is GROUP-WIDE: iteration stops after that many seconds with no
        reply from any member (a single quiet member never ends the group).
        `replay=True` replays each member's buffered backlog first. Iteration
        otherwise ends when every member's stream has ended (each on its own
        `TaskDeleted`).

        A reply's `photo` / `file` are downloadable: `await reply.item.photo.read()`.

        Yields: GroupReply
        """
        return _GroupStream(
            self.instances,
            lambda inst: inst.replies(replay=replay),
            lambda inst, item: GroupReply(instance=inst, item=item),
            timeout=timeout,
        )

    def append(self, *, title: str | None = None, content: str | None = None,
               inputs=None, links: "list[str] | None" = None,
               files: "list[str | os.PathLike] | None" = None,
               instances: "list[str | Task] | None" = None,
               auto_commit: bool = True, critical: bool = False,
               reply: "ReplyMode | Literal['one-shot', 'sticky', 'one-time-per-user'] | None" = None,
               content_format: "ContentFormat | Literal['plain', 'markdown'] | None" = None) -> "list[Subtask]":
        """Append a subtask to every member instance's chain atomically — or
        only to the instances named in `instances` (task ids or `Task` handles
        from this group). Returns one `Subtask` handle per appended member.
        Encryption inherits the group send's.

        `files` are local paths uploaded ONCE for the whole batch — every
        sibling subtask references the same attachment (encrypted under the
        group's key when the send was encrypted)."""
        if self._client is None:
            raise RuntimeError("this TaskGroup was not created by a client; cannot append")
        ids = None
        if instances is not None:
            ids = [t.task_id if isinstance(t, Task) else t for t in instances]
        return self._client._append_subtasks_to_group(
            self, instances=ids, title=title, content=content, inputs=inputs,
            links=links, files=files, auto_commit=auto_commit, critical=critical,
            reply=reply, content_format=content_format,
        )

    def cancel(self, *, reason: "CancelReason | Literal['canceled', 'answered', 'superseded']" = "canceled",
               note: str | None = None,
               superseded_by: "str | TaskGroup | None" = None) -> "GroupCancelResult":
        """Cancel every still-pending member instance (cancel-the-rest:
        `reason=CancelReason.ANSWERED` after one member's answer). Completed/canceled
        members are skipped, never failed — the returned `GroupCancelResult`
        reports both counts. `superseded_by` (a group id or `TaskGroup`,
        requires reason `superseded`) names the replacement GROUP; the server
        points each canceled instance at its own recipient's replacement
        instance."""
        if self._client is None:
            raise RuntimeError("this TaskGroup was not created by a client; cannot cancel")
        sid = superseded_by.group_id if isinstance(superseded_by, TaskGroup) else superseded_by
        return self._client._cancel_task_group(self, reason=reason, note=note, superseded_by=sid)


class Subtask:
    """Handle for a subtask appended to a task. `inputs()` / `replies()` are
    scoped to this subtask within the parent's chain. One level deep — a subtask
    cannot itself be appended to."""

    def __init__(self, subtask_id: str, parent_task_id: str, created_at: str | None,
                 hub: _Hub, *, decryptor=None, client=None, send_key=None):
        self.subtask_id = subtask_id
        self.parent_task_id = parent_task_id
        self.created_at = created_at
        self._hub = hub
        self._decryptor = decryptor
        self._client = client
        self._send_key = send_key  # the chain's key — encrypts a cancel note

    def _file_binder(self) -> "_FileBinder | None":
        # The download endpoints are task-scoped and resolve subtask files
        # through the parent server-side, so the binder carries the parent's id.
        if self._client is None:
            return None
        return _FileBinder(self._client._file_transport(), "tasks", self.parent_task_id, self._decryptor)

    def inputs(self, *, timeout: float | None = None, replay: bool = False):
        """Yield `InputEvent` objects for this subtask. Ends with a
        `SubtaskCompleted` marker (inputs committed), `SubtaskCanceled` (this
        follow-up withdrawn), or `TaskDeleted` / `TaskCanceled` (chain deleted
        or its root canceled), or after `timeout`. `replay=True` replays the
        backlog first.

        Photo/voice/file uploads on the yielded events are downloadable:
        `await upload.read()` / `await upload.save(path)`.

        Yields: InputEvent | SubtaskCompleted | SubtaskCanceled | TaskDeleted | TaskCanceled | TaskDeclined | SubtaskDeclinedByRecipient | SubtaskDeclined
        """
        return _TaskStream(self._hub, self.parent_task_id, self.subtask_id, self._decryptor,
                           _SUBTASK_INPUT_TYPES, _wrap_input, timeout, _SUBTASK_INPUT_TERMINAL,
                           replay=replay, files=self._file_binder())

    def replies(self, *, timeout: float | None = None, replay: bool = False):
        """Yield `Reply` objects anchored to this subtask. Ends with a
        `TaskDeleted` / `TaskCanceled` marker if the chain is deleted or its
        root canceled, a `SubtaskCanceled` marker if THIS subtask is canceled,
        or after `timeout`. `replay=True` replays the backlog first.

        A reply's `photo` / `file` are downloadable: `await reply.photo.read()`
        / `await reply.photo.save(path)`.

        Yields: Reply | TaskDeleted | TaskCanceled | SubtaskCanceled | TaskDeclined | SubtaskDeclinedByRecipient | SubtaskDeclined
        """
        return _TaskStream(self._hub, self.parent_task_id, self.subtask_id, self._decryptor,
                           _REPLY_TYPES | {_SUBTASK_CANCELED, _SUBTASK_DECLINED_BY_RECIPIENT, _SUBTASK_DECLINED},
                           _wrap_reply, timeout,
                           frozenset({_SUBTASK_CANCELED, _SUBTASK_DECLINED}), replay=replay,
                           files=self._file_binder())

    def cancel(self, *, reason: "CancelReason | Literal['canceled', 'answered', 'superseded']" = "canceled",
               note: str | None = None,
               superseded_by: "str | Subtask | None" = None) -> None:
        """Cancel this pending follow-up while the chain stays live. `reason`
        is a `CancelReason` (or its string value); the replacement named by
        `superseded_by` (a subtask id or `Subtask`, requires reason
        `superseded`) must belong to the SAME chain."""
        if self._client is None:
            raise RuntimeError("this Subtask was not created by a client; cannot cancel")
        sid = superseded_by.subtask_id if isinstance(superseded_by, Subtask) else superseded_by
        self._client._cancel_subtask(self, reason=reason, note=note, superseded_by=sid)


# Who an independent-mode notification instance was delivered to — the
# notification analogue of `TaskGroupRecipient`, mirroring the TS SDK's
# distinct name. Same shape, and deliberately the same class (not a subclass):
# TS's aliases are structurally interchangeable, so equality and isinstance
# must keep working across both names here too.
NotificationGroupRecipient = TaskGroupRecipient


class Notification:
    """Handle for a notification you sent. A notification is a lighter sibling of
    a task: it carries a single input (choice/text/actions only) and emits one
    event when the recipient answers, so `inputs()` is the only stream it exposes.

    An independent-mode send (the default) returns a `NotificationGroup` instead;
    each of its member instances is a `Notification` carrying the `recipient` it
    belongs to."""

    def __init__(self, notification_id: str, created_at: str | None, wait_token: str | None,
                 hub: _Hub, *, client=None, send_key=None, decryptor=None,
                 recipient: "NotificationGroupRecipient | None" = None):
        self.notification_id = notification_id
        self.created_at = created_at
        self.wait_token = wait_token
        self.recipient = recipient
        self._hub = hub
        self._client = client
        self._send_key = send_key
        # Same decryptor story as Task: org notifications pass a ready
        # OrgDecryptor; personal topic notifications build a fingerprint-gated
        # Decryptor from the topic key (which also decrypts the recipient's reply).
        self._decryptor = decryptor
        if self._decryptor is None and send_key is not None:
            from .crypto import Decryptor  # optional extra
            self._decryptor = Decryptor(send_key)

    def inputs(self, *, timeout: float | None = None, replay: bool = False):
        """Yield this notification's events. A notification emits exactly one —
        `NotificationCompleted`, carrying the recipient's answer (`reply`) — so
        the stream yields that single item and ends. It also stops (yielding
        nothing) after `timeout` seconds of silence; `replay=True` replays the
        buffered backlog first.

        Yields: NotificationCompleted
        """
        return _TaskStream(self._hub, self.notification_id, None, self._decryptor,
                           _NOTIFICATION_TYPES, _wrap_notification, timeout,
                           _NOTIFICATION_TERMINAL, replay=replay, entity_terminals={})


@dataclass
class GroupNotification:
    """An answer collected over a whole notification group
    (`NotificationGroup.inputs()`): the `item` — a `NotificationCompleted`
    carrying the recipient's reply — together with the member `instance` it
    arrived on. `recipient` is a shortcut to `instance.recipient`: who
    answered."""
    instance: "Notification"
    item: "NotificationCompleted"

    @property
    def recipient(self) -> "NotificationGroupRecipient | None":
        return self.instance.recipient


class NotificationGroup:
    """Handle for an independent-mode notification send (the default): every
    recipient got their own notification instance under one group, so each
    answers their own. Iterate it (or read `instances`) for the per-recipient
    `Notification` handles — each streams its single completion event like any
    notification; `sole` unwraps the single instance of a one-recipient group;
    `inputs()` collects the answers across every member.

    Unlike a `TaskGroup` there is no `append` — notifications have no subtasks.
    """

    def __init__(self, group_id: str, created_at: str | None, wait_token: str | None,
                 hub: _Hub, *, instances: "list[Notification] | None" = None,
                 client=None, send_key=None, decryptor=None):
        self.group_id = group_id
        self.created_at = created_at
        self.wait_token = wait_token
        self.instances: list[Notification] = list(instances or [])
        self._hub = hub
        self._client = client
        self._send_key = send_key
        self._decryptor = decryptor
        if self._decryptor is None and send_key is not None:
            from .crypto import Decryptor  # optional extra
            self._decryptor = Decryptor(send_key)

    def __iter__(self):
        return iter(self.instances)

    def __len__(self) -> int:
        return len(self.instances)

    @property
    def sole(self) -> "Notification":
        """The single instance of a one-recipient group. Raises ValueError when
        the group holds zero or several instances."""
        if len(self.instances) != 1:
            raise ValueError(
                f"group {self.group_id} has {len(self.instances)} instances, not exactly 1"
            )
        return self.instances[0]

    def inputs(self, *, timeout: float | None = None, replay: bool = False):
        """Collect the answers across EVERY member instance of this group,
        demuxed off the one shared WS stream (no extra connection — each
        member's `notificationId` is already a routing key on the hub). Yields
        a `GroupNotification` per answer: the terminal `NotificationCompleted`
        (with the recipient's reply, if any) plus the member `instance` it
        arrived on, so you know who answered.

        Each member's stream ends on its single `NotificationCompleted`, so
        iteration ends once every recipient has answered. `timeout` is
        GROUP-WIDE: iteration also stops after that many seconds with no answer
        from any member (a single quiet member never ends the group).
        `replay=True` replays each member's buffered backlog first.

        Yields: GroupNotification
        """
        return _GroupStream(
            self.instances,
            lambda inst: inst.inputs(replay=replay),
            lambda inst, item: GroupNotification(instance=inst, item=item),
            timeout=timeout,
        )


class _TaskStream:
    """Async iterator over a chain's shared buffer (keyed by root task id),
    filtered to either the root task (`subtask_id is None`) or one subtask."""

    def __init__(self, hub, root_id, subtask_id, decryptor,
                 want_types, wrap, timeout, terminal_types=frozenset(), replay=False,
                 entity_terminals=None, files=None):
        self._hub = hub
        self._root_id = root_id
        self._subtask_id = subtask_id
        self._decryptor = decryptor
        self._want = want_types
        self._wrap = wrap
        self._timeout = timeout
        self._terminal = terminal_types
        self._replay = replay
        # data.type -> marker factory for entity-wide terminals (deleted,
        # canceled). None = the default table; pass {} for streams with no
        # entity-wide terminal (notifications).
        self._entity_terminals = _ENTITY_TERMINALS if entity_terminals is None else entity_terminals
        self._files = files  # _FileBinder | None — binds file handles to the client

    def __aiter__(self):
        return self._iter()

    def _in_scope(self, ev) -> bool:
        if self._subtask_id is None:
            return ev.subtask_id is None
        return ev.subtask_id == self._subtask_id

    def _match(self, ev):
        """Return (item_to_yield_or_None, stop)."""
        # Entity-wide terminals (taskDeleted, taskCanceled) ignore subtask
        # scope: a deleted or canceled root ends the chain's every stream.
        factory = self._entity_terminals.get(ev.data_type)
        if factory is not None:
            return factory(ev, self._decryptor), True
        if not self._in_scope(ev):
            return None, False
        if ev.data_type in self._want:
            return self._wrap(ev, self._decryptor, self._files), ev.data_type in self._terminal
        return None, False

    async def _iter(self):
        hub = self._hub
        await hub.ensure_running()
        q, snapshot = hub.attach_entity(self._root_id)
        last_seq = 0
        try:
            if self._replay:
                # Replay the buffered backlog (events since the task was sent),
                # then continue live, skipping anything the snapshot already covered.
                last_seq = snapshot[-1][0] if snapshot else 0
                for _seq, ev in snapshot:
                    item, stop = self._match(ev)
                    if item is not None:
                        yield item
                    if stop:
                        return
            while True:
                if self._timeout is not None:
                    try:
                        msg = await asyncio.wait_for(q.get(), self._timeout)
                    except asyncio.TimeoutError:
                        return
                else:
                    msg = await q.get()
                if isinstance(msg, _HubError):
                    raise msg.error
                seq, ev = msg
                if seq <= last_seq:
                    continue  # already replayed from the snapshot
                item, stop = self._match(ev)
                if item is not None:
                    yield item
                if stop:
                    return
        finally:
            hub.detach_entity(self._root_id, q)


class _GroupStream:
    """Merge of every member instance's per-task stream — `replies()` or
    `inputs()` — demuxed off the one shared hub connection. Each member runs its
    own `_TaskStream` (built by `substream`); items are tagged with their
    originating instance (via `wrap`) and interleaved as they arrive. The
    `timeout` here is GROUP-WIDE silence — enforced by this merge loop, not by
    the per-member streams (which run without a timeout so one quiet member
    never ends the whole group)."""

    # Sentinels marking a worker's control messages (vs. a real tagged item).
    _DONE = object()
    _ERR = object()

    def __init__(self, instances, substream, wrap, *, timeout=None):
        self._instances = list(instances)
        self._substream = substream  # inst -> async iterator of per-task items
        self._wrap = wrap            # (inst, item) -> GroupReply | GroupInput
        self._timeout = timeout

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        if not self._instances:
            return
        queue: asyncio.Queue = asyncio.Queue()

        async def pump(inst):
            try:
                async for item in self._substream(inst):
                    await queue.put((inst, item))
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # surface a hub failure to the caller
                await queue.put((self._ERR, exc))
            finally:
                await queue.put((self._DONE, inst))

        workers = [asyncio.ensure_future(pump(inst)) for inst in self._instances]
        remaining = len(workers)
        try:
            while remaining > 0:
                if self._timeout is not None:
                    try:
                        tag, payload = await asyncio.wait_for(queue.get(), self._timeout)
                    except asyncio.TimeoutError:
                        return
                else:
                    tag, payload = await queue.get()
                if tag is self._DONE:
                    remaining -= 1
                elif tag is self._ERR:
                    raise payload
                else:
                    yield self._wrap(tag, payload)
        finally:
            for w in workers:
                w.cancel()
            # Let each member stream's `finally` (hub.detach_entity) run.
            await asyncio.gather(*workers, return_exceptions=True)


# --- Raw event stream (manual inspection) ---

class RawEvents:
    """The full event feed for the client's shared stream — the personal stream
    (api_token) or the org-wide stream (api_key)."""

    def __init__(self, hub: _Hub):
        self._hub = hub

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        await self._hub.ensure_running()
        q = self._hub.attach_raw()
        try:
            while True:
                msg = await q.get()
                if isinstance(msg, _HubError):
                    raise msg.error
                yield msg
        finally:
            self._hub.detach_raw(q)


class Submissions:
    """Typed stream of `Submission`s for the client's shared feed. Submissions
    are unsolicited (no send, no per-entity demux), so this filters the whole
    feed for `submissionCreated` events and wraps each — body text decrypted via
    the client keyring, `photo`/`file` bound as downloadable. Stops after
    `timeout` seconds of silence (None = forever)."""

    def __init__(self, hub: _Hub, decryptor, files, timeout: float | None = None):
        self._hub = hub
        self._decryptor = decryptor
        self._files = files
        self._timeout = timeout

    def __aiter__(self):
        return self._iter()

    async def _iter(self):
        await self._hub.ensure_running()
        q = self._hub.attach_raw()
        try:
            while True:
                if self._timeout is not None:
                    try:
                        msg = await asyncio.wait_for(q.get(), self._timeout)
                    except asyncio.TimeoutError:
                        return
                else:
                    msg = await q.get()
                if isinstance(msg, _HubError):
                    raise msg.error
                if msg.data_type == "submissionCreated":
                    yield _wrap_submission(msg, self._decryptor, self._files)
        finally:
            self._hub.detach_raw(q)
