"""
Client for the SimplePush Business Backend.

Sending is HTTP; receiving rides a single multiplexed WebSocket. The connection
defaults to the production endpoint over TLS; pass host/port/ssl to override
(e.g. `Client("localhost", 8080, ssl=False, ...)` for local development).

Two parallel aggregates are sent the same way, differing in surface. Both
default to independent per-recipient instances under a group and take a
keyword-only target: exactly one of `topic=`, `member=`, or `broadcast=`.
`send_task` returns a `TaskGroup` — every recipient gets their own independent
task instance (a `Task`: multiple inputs, replies, subtasks); pass `shared=True`
for one shared `Task`. `send_notification` returns a `NotificationGroup`
of lighter `Notification`s (a single choice/text/actions input, no replies, no
subtasks); pass `shared=True` for one shared `Notification`.

    client = Client(api_token="USER_API_TOKEN")

    group = client.send_task(topic="deploys", title="Deploy?",
                             inputs=[ChoiceInput(options=["yes", "no"])],
                             password="secret")
    async for reply in group.sole.replies():   # or iterate the group's instances
        print(reply.body)        # TextBody / None

    notes = client.send_notification(topic="deploys", title="Build failed",
                                     input=NotificationChoiceInput(options=["ack", "mute"]))
    async for ev in notes.sole.inputs():        # or iterate the group's instances
        print(ev.reply)          # NotificationTextReply / NotificationChoiceReply / NotificationActionReply

Org access uses OrgClient (authenticated by the org Api-Key), which adds the
`member=` / `broadcast=` targets:

    org = OrgClient(api_key="ORG_API_KEY")
    task = org.send_task(broadcast=True, title="All-hands?",
                         inputs=[ChoiceInput(options=["in", "out"])])

`client.events()` exposes the raw event feed for manual inspection.
"""

import base64
import datetime
import hashlib
import json
import mimetypes
import os
import time
import urllib.request
import urllib.error
import uuid
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Literal

from .client import (
    Event, GroupCancelResult, InputEvent, Notification, NotificationGroup,
    NotificationGroupRecipient, RawEvents, Reply, Subtask, Submissions, Task,
    TaskGroup, TaskGroupRecipient,
    _HTTP_TIMEOUT, _DownloadTransport, _FileBinder, _Hub,
)


# --- Wire serialization helpers ---

def _priority_wire(priority, critical, critical_volume) -> dict:
    """The `priority` / `criticalVolume` fields of a create request. `priority`
    is 1 (minimal) to 5 (critical), absent = 3; the deprecated `critical` flag
    means 5 when no priority is given. `critical_volume` (0 < v <= 1) is the
    iOS critical alert volume and is only valid with level 5."""
    level = priority if priority is not None else (5 if critical else None)
    if level is not None and (not isinstance(level, int) or isinstance(level, bool) or not 1 <= level <= 5):
        raise ValueError("priority must be an integer between 1 and 5")
    if critical_volume is not None:
        if level != 5:
            raise ValueError("critical_volume applies to priority 5 only")
        if not 0 < critical_volume <= 1:
            raise ValueError("critical_volume must be greater than 0 and at most 1")
    out: dict = {}
    if level is not None:
        out["priority"] = level
    if critical_volume is not None:
        out["criticalVolume"] = critical_volume
    return out


def _expires_at_wire(value) -> str:
    """Serialize a task deadline to wire ISO-8601. A naive datetime is
    rejected rather than guessed at — the server compares against UTC."""
    if isinstance(value, str):
        return value
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            raise ValueError("expires_at datetime must be timezone-aware")
        return value.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    raise TypeError("expires_at must be a datetime or an ISO-8601 string")


# --- Input types ---

@dataclass
class TextInput:
    description: str | None = None
    default_value: str | None = None
    required: bool = True

    def to_dict(self) -> dict:
        d: dict = {"type": "text", "required": self.required}
        if self.description is not None:
            d["description"] = self.description
        if self.default_value is not None:
            d["defaultValue"] = self.default_value
        return d


@dataclass
class ChoiceInput:
    options: list[str] = field(default_factory=list)
    description: str | None = None
    required: bool = True
    # Multi-select mode: the recipient may pick more than one option.
    # `min_selections`/`max_selections` are only meaningful when `multi` is True.
    multi: bool = False
    min_selections: int | None = None
    max_selections: int | None = None

    def to_dict(self) -> dict:
        d: dict = {"type": "choice", "options": self.options, "required": self.required}
        if self.description is not None:
            d["description"] = self.description
        if self.multi:
            d["multi"] = True
        if self.min_selections is not None:
            d["minSelections"] = self.min_selections
        if self.max_selections is not None:
            d["maxSelections"] = self.max_selections
        return d


class ActionStyle(str, Enum):
    """Render hint for an ``Action`` button (its `style` field). Plaintext
    (never encrypted) and purely visual — it doesn't change behavior. Members
    are `str`, so they serialize directly and compare equal to their wire value
    (e.g. ``ActionStyle.PRIMARY == "primary"``).
    """
    DEFAULT = "default"          # plain look (same as omitting style)
    PRIMARY = "primary"          # emphasized: the suggested/main choice
    DESTRUCTIVE = "destructive"  # danger affordance (rendered red)


@dataclass
class Action:
    """A single button in an ``ActionsInput`` (task) or ``NotificationActionInput``
    (notification). ``key`` is a stable, sender-chosen id (e.g. "approve"/"deny"),
    unique within the set, reported back as the recipient's answer. ``label`` is
    the button text. ``style`` is an optional render hint — an `ActionStyle` (or
    its wire string), always plaintext.

    On an encrypted send BOTH the key and the label are sealed, for tasks and
    notifications alike: the key usually carries the same meaning as the label
    ("approve"), so encrypting only the label would hide the wording and leak
    the intent. The recipient's device decrypts both before rendering, and
    encrypts the tapped key again before posting the answer — so the server sees
    only ciphertext in either direction and cannot correlate the two."""
    key: str
    label: str
    style: ActionStyle | Literal["default", "primary", "destructive"] | None = None

    def to_dict(self) -> dict:
        d: dict = {"key": self.key, "label": self.label}
        if self.style is not None:
            d["style"] = self.style.value if isinstance(self.style, ActionStyle) else self.style
        return d


@dataclass
class ActionsInput:
    actions: list[Action] = field(default_factory=list)
    description: str | None = None
    required: bool = True

    def to_dict(self) -> dict:
        d: dict = {
            "type": "actions",
            "actions": [a.to_dict() for a in self.actions],
            "required": self.required,
        }
        if self.description is not None:
            d["description"] = self.description
        return d


@dataclass
class SliderInput:
    """A numeric slider on a [min, max] scale (e.g. a pool's pH on 0..14). The
    scale config (min/max/step/unit/default_value) is sent in the clear; the
    recipient's chosen value comes back E2E-encrypted. `step` None = continuous;
    `unit` is a short display label like "pH"; `default_value` is the initial
    thumb position."""
    min: float
    max: float
    step: float | None = None
    unit: str | None = None
    default_value: float | None = None
    description: str | None = None
    required: bool = True

    def to_dict(self) -> dict:
        d: dict = {"type": "slider", "min": self.min, "max": self.max, "required": self.required}
        if self.step is not None:
            d["step"] = self.step
        if self.unit is not None:
            d["unit"] = self.unit
        if self.default_value is not None:
            d["defaultValue"] = self.default_value
        if self.description is not None:
            d["description"] = self.description
        return d


@dataclass
class PhotoInput:
    description: str | None = None
    required: bool = True

    def to_dict(self) -> dict:
        d: dict = {"type": "photo", "required": self.required}
        if self.description is not None:
            d["description"] = self.description
        return d


@dataclass
class VoiceRecordingInput:
    description: str | None = None
    required: bool = True

    def to_dict(self) -> dict:
        # Wire discriminator is "voiceRecording" (matches the backend
        # InputRequestData / domain Input @jsonHint).
        d: dict = {"type": "voiceRecording", "required": self.required}
        if self.description is not None:
            d["description"] = self.description
        return d


@dataclass
class LocationInput:
    description: str | None = None
    required: bool = True

    def to_dict(self) -> dict:
        # Wire discriminator is "location" — asks the recipient for their GPS
        # position (mirrors the "voiceRecording" input type).
        d: dict = {"type": "location", "required": self.required}
        if self.description is not None:
            d["description"] = self.description
        return d


@dataclass
class FileUploadInput:
    description: str | None = None
    required: bool = True

    def to_dict(self) -> dict:
        d: dict = {"type": "file", "required": self.required}
        if self.description is not None:
            d["description"] = self.description
        return d


InputType = TextInput | ChoiceInput | ActionsInput | SliderInput | PhotoInput | VoiceRecordingInput | LocationInput | FileUploadInput


def _validate_actions(actions) -> None:
    """Enforce the action-set invariants the backend can't check once the keys and
    labels are encrypted (E2EE): at least one action, a non-empty key + label per
    action, and unique keys within the set so the recipient's answer maps to
    exactly one action. Shared by the task `ActionsInput` and the notification
    `NotificationActionInput`. Always runs on the PLAINTEXT actions, before the
    send path encrypts them — uniqueness is meaningless across ciphertexts, since
    each encryption uses a fresh nonce."""
    if not actions:
        raise ValueError("an actions input needs at least one action")
    valid_styles = {s.value for s in ActionStyle}
    seen: set[str] = set()
    for a in actions:
        if not a.key:
            raise ValueError("each action needs a non-empty key")
        if not a.label:
            raise ValueError("each action needs a non-empty label")
        if a.key in seen:
            raise ValueError(f"duplicate action key: {a.key}")
        seen.add(a.key)
        # The backend rejects unknown styles at JSON decode (an opaque 400);
        # catch a typo'd plain string here instead. ActionStyle members compare
        # equal to their wire strings, so one check covers both.
        if a.style is not None and a.style not in valid_styles:
            raise ValueError(f"unknown action style: {a.style!r} (expected one of {sorted(valid_styles)})")


def _validate_action_inputs(inputs) -> None:
    """Validate every `ActionsInput` among a task's inputs (see `_validate_actions`)."""
    for inp in inputs or []:
        if isinstance(inp, ActionsInput):
            _validate_actions(inp.actions)


# --- Notification input types ---
#
# A notification carries at most one input, and only text or choice render as
# actionable controls on the push surface (photo/voice/file need an in-app flow,
# so those live on tasks). These are deliberately distinct from the task input
# types above — mirroring the backend domain `NotificationInput`, a notification
# input has no description (the choice options are the button labels; the text
# field has no placeholder) and, with only one possible, nothing to mark required.

@dataclass
class NotificationTextInput:
    """A free-text reply field on a notification. Carries no fields — its mere
    presence solicits a text reply (wire: `textInput: {}`)."""

    def to_request(self) -> dict:
        return {}


@dataclass
class NotificationChoiceInput:
    """Choice buttons on a notification; each option string is a button label
    (1-30 options). Wire: `choiceInput: {"options": [...]}`."""
    options: list[str] = field(default_factory=list)

    def to_request(self) -> dict:
        return {"options": list(self.options)}


@dataclass
class NotificationActionInput:
    """Action buttons on a notification — each `Action` (reusing the task Action
    shape `{key, label, style?}`) renders one button. Wire: `actionInput:
    {"actions": [...]}`. Encryption matches the task `ActionsInput` exactly: on an
    encrypted notification both the `key` and the `label` are sealed (the apps
    decrypt them in the notification-service extension / FCM handler before
    building their native action buttons), and the reported answer
    (`selected_key`) comes back encrypted too. `style` is an optional render hint
    — an `ActionStyle` (or its wire string), always plaintext."""
    actions: list[Action] = field(default_factory=list)

    def to_request(self) -> dict:
        return {"actions": [a.to_dict() for a in self.actions]}


NotificationInput = NotificationTextInput | NotificationChoiceInput | NotificationActionInput


class ApiError(Exception):
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        # The backend error envelope is {"error": "<code>", "msg": "..."};
        # surface the machine-readable code (e.g. "task_canceled",
        # "task_already_completed") so callers can branch without parsing.
        self.code: str | None = None
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
                self.code = parsed["error"]
        except ValueError:
            pass
        super().__init__(f"HTTP {status}: {body}")


class ReplyMode(str, Enum):
    """Reply-composer mode for a task (the `reply=` argument to send methods).
    Setting any mode shows recipients a composer; omitting `reply` means no
    composer. Members are `str`, so they serialize directly and compare equal to
    their wire value (e.g. ``ReplyMode.STICKY == "sticky"``).
    """
    ONE_SHOT = "one-shot"                  # first reply wins; the slot closes for everyone
    STICKY = "sticky"                      # composer stays open indefinitely
    ONE_TIME_PER_USER = "one-time-per-user"  # one reply per user


class CancelReason(str, Enum):
    """Why a sender cancels (the `reason=` argument to the `.cancel()`
    methods), rendered on the recipient's card. Members are `str`, so they
    serialize directly and compare equal to their wire value (e.g.
    ``CancelReason.ANSWERED == "answered"``).
    """
    CANCELED = "canceled"      # plain withdrawal (the default when omitted)
    ANSWERED = "answered"      # another recipient's answer made the rest moot
    SUPERSEDED = "superseded"  # a replacement exists; superseded_by names it


class ContentFormat(str, Enum):
    """How recipients render a task or subtask `content` body (the
    `content_format=` argument to `send_task` / `append`). Governs `content`
    only; titles are always plain. Notifications have no format marker: a
    push always shows its body as plain text. The marker is sent as plaintext (never
    encrypted). Members are `str`, so they serialize directly and compare
    equal to their wire value (e.g. ``ContentFormat.MARKDOWN == "markdown"``).
    """
    PLAIN = "plain"        # render content verbatim (the default when omitted)
    MARKDOWN = "markdown"  # render content as Markdown


def _parse_passwords(passwords) -> "tuple[list[tuple[str, str]], str | None]":
    """Normalize the personal-client `passwords` argument into
    (topic_passwords, default_password). Accepts a single default-password
    string, or a list whose entries are `(password, topic)` pairs (a topic key)
    and/or at most one bare default-password string (the account default key —
    decrypts your submissions)."""
    if passwords is None:
        return [], None
    if isinstance(passwords, str):
        return [], passwords
    topic_passwords: list = []
    default_password: str | None = None
    for item in passwords:
        if isinstance(item, str):
            if default_password is not None:
                raise ValueError("only one default password (a bare string) is allowed in `passwords`")
            default_password = item
        elif isinstance(item, (tuple, list)) and len(item) == 2 and all(isinstance(x, str) for x in item):
            pw, topic = item
            topic_passwords.append((pw, topic))
        else:
            raise ValueError(
                "each `passwords` entry must be a (password, topic) pair or a "
                f"default-password string, got {item!r}"
            )
    return topic_passwords, default_password


class _BaseClient:
    """Shared transport for the SimplePush clients: topic sending, the
    multiplexed event hub, and the raw feed. Not used directly — construct a
    `Client` (personal) or an `OrgClient` (organization).
    """

    def __init__(self, host: str, port: int, ssl: bool, *,
                 api_token: str | None, api_key: str | None,
                 connect_path: str, auth_headers: dict,
                 org_master_keys: "dict[int, bytes | str] | None" = None,
                 topic_passwords: "list[tuple[str, str]] | None" = None,
                 default_password: "str | None" = None):
        self._scheme = "https" if ssl else "http"
        self._base = f"{self._scheme}://{host}:{port}/v1"
        self._api_token = api_token
        self._api_key = api_key
        # Personal-mode decrypt/send material (empty for OrgClient, which uses
        # org master keys). `topic_passwords` are (password, topic) pairs → one
        # topic key each, and the send default for that topic. `default_password`
        # is the user's single account password → the account default key (salt =
        # server password_salt), which decrypts submissions; it never encrypts a
        # send.
        self._topic_passwords = list(topic_passwords or [])
        self._default_password = default_password
        self._org_master_keys = org_master_keys
        self._extra_keys: list = []           # per-send derived keys, folded in
        self._keyring = None
        # Org-mode encryption: versioned master keys. None for personal clients.
        # New content encrypts under the highest version; received content
        # decrypts under whichever version its `{type: "org", v}` marker names.
        self._org_decryptor = None
        if org_master_keys:
            from .crypto import OrgDecryptor  # optional extra (pynacl)
            self._org_decryptor = OrgDecryptor(org_master_keys)
        self._hub = _Hub(host, port, ssl, connect_path=connect_path, auth_headers=auth_headers)
        self._file_transport_obj: _DownloadTransport | None = None
        # Account-key folding (submissions): the server password_salt is fetched
        # once and cached; each account password is derived against it at most once.
        self._account_salt_fetched = False
        self._account_salt_value: str | None = None
        self._folded_account_passwords: set = set()

    def _file_transport(self) -> _DownloadTransport:
        """Lazy HTTP transport for file downloads, carrying this client's
        credential header (API-Token / Api-Key). Task/Subtask handles bind it
        into the file objects their streams yield."""
        if self._file_transport_obj is None:
            if self._api_token:
                headers = {"API-Token": self._api_token}
            else:
                assert self._api_key is not None  # a client always holds one credential
                headers = {"Api-Key": self._api_key}
            self._file_transport_obj = _DownloadTransport(self._base, headers)
        return self._file_transport_obj

    def events(self) -> RawEvents:
        """The raw event feed for this client's shared stream (manual inspection).
        Pair with `keyring()` + `try_decrypt_event_data` to decrypt it."""
        return RawEvents(self._hub)

    def submissions(self, *, timeout: float | None = None) -> Submissions:
        """Observe `Submission`s arriving on this client's stream — self-authored
        user content (text body + optional photo/file) with no associated task; a
        task reply without the task. Available on both `Client`
        and `OrgClient`. Body text decrypts via this client's keyring; `photo`/
        `file` are downloadable (`read()` / `save()`). Delivers submissions
        from now on: one created before the first read is skipped, by this
        machine's clock. Stops after `timeout` seconds of silence."""
        return self._build_submissions(timeout, self._default_password)

    def _build_submissions(self, timeout, default_password) -> Submissions:
        # Keyring is the decryptor for these unsolicited events (no per-send key).
        # Build it if the crypto extra is present; without it, encrypted bodies
        # pass through as ciphertext and plaintext submissions still work.
        try:
            decryptor = self.keyring()
        except ImportError:
            decryptor = None
        # Submissions are encrypted under the personal default key (the account
        # password + the server password_salt), NOT a topic key — so fold that key
        # in (the configured topic passwords and org keys don't cover it).
        self._fold_account_key(decryptor, default_password)
        files = _FileBinder(self._file_transport(), "submissions", None, decryptor)
        return Submissions(self._hub, decryptor, files, timeout)

    def _fold_account_key(self, keyring, password) -> None:
        """Derive the account default key (`password` + the server password_salt,
        fetched once via GET /v1/user) and add it to `keyring`. Each password is
        folded at most once. No-op without a token + password, or for an org
        client (no token)."""
        if keyring is None or not self._api_token or not password or password in self._folded_account_passwords:
            return
        if not self._account_salt_fetched:
            self._account_salt_value = self._fetch_password_salt()
            self._account_salt_fetched = True
        if self._account_salt_value:
            from .crypto import derive_key  # optional extra
            keyring.add(derive_key(password, self._account_salt_value))
        self._folded_account_passwords.add(password)

    def _self_send_key(self):
        """The symmetric key for a topicless note-to-self, derived from the
        account default password + the server `password_salt` (fetched once via
        GET /v1/user) — the SAME key that decrypts your submissions, so a
        note-to-self round-trips to your own devices/clients. Returns a
        `DerivedKey`, or None when no default password is configured (or no token)
        → the note-to-self is sent in plaintext."""
        if not self._default_password or not self._api_token:
            return None
        if not self._account_salt_fetched:
            self._account_salt_value = self._fetch_password_salt()
            self._account_salt_fetched = True
        if not self._account_salt_value:
            return None
        from .crypto import derive_key  # optional extra
        return derive_key(self._default_password, self._account_salt_value)

    def _send_password(self, topic: str | None) -> str | None:
        """The password to encrypt a topic send with when none is passed per-send:
        the password paired with `topic`, or None. The account default password is
        decryption-only — it never encrypts a send (it's your personal account
        secret, not a shared topic password)."""
        if topic is not None:
            for pw, t in self._topic_passwords:
                if t == topic:
                    return pw
        return None

    def _fetch_password_salt(self) -> str | None:
        """`GET /v1/user` (API-Token auth) → the account's password_salt."""
        assert self._api_token is not None  # only reachable on API-Token clients
        req = urllib.request.Request(
            f"{self._base}/user",
            headers={"API-Token": self._api_token, "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                info = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode("utf-8")) from e
        return info.get("passwordSalt")

    def keyring(self):
        """The decryption keyring for this client (built lazily): a topic key per
        configured `(password, topic)` pair plus any org master keys, grown with
        every send's derived key. The account default key(s) join on demand (see
        `_fold_account_key`, used by `submissions()`). Use it to decrypt the raw
        `events()` feed via `try_decrypt_event_data`."""
        if self._keyring is None:
            from .crypto import Keyring, derive_key  # optional extra
            ring = Keyring.build(org_master_keys=self._org_master_keys)
            for pw, topic in self._topic_passwords:
                ring.add(derive_key(pw, topic))
            for dk in self._extra_keys:
                ring.add(dk)
            self._keyring = ring
        return self._keyring

    def _remember_key(self, dk) -> None:
        """Fold a send's derived key into the keyring so the raw `events()` feed
        can decrypt that send's replies (handle streams use the key directly)."""
        self._extra_keys.append(dk)
        if self._keyring is not None:
            self._keyring.add(dk)

    async def aclose(self):
        """Close the shared event connection."""
        await self._hub.aclose()

    def send_task(
        self,
        *,
        topic: str | None = None,
        member: str | None = None,
        broadcast: bool = False,
        title: str | None = None,
        content: str | None = None,
        inputs: list[InputType] | None = None,
        links: list[str] | None = None,
        files: "list[str | os.PathLike] | None" = None,
        auto_commit: bool = False,
        password: str | None = None,
        tag: str | None = None,
        critical: bool = False,
        priority: int | None = None,
        critical_volume: float | None = None,
        reply: ReplyMode | Literal["one-shot", "sticky", "one-time-per-user"] | None = None,
        content_format: ContentFormat | Literal["plain", "markdown"] | None = None,
        shared: bool = False,
        expires_at: "datetime.datetime | str | None" = None,
    ) -> "Task | TaskGroup":
        """Send a task and return a handle to its event streams.

        By default every recipient gets their OWN independent task instance
        under a group (one recipient's answers never touch another's task), and
        this returns a `TaskGroup` — iterate it for the per-recipient `Task`
        handles, or use `.sole` when the target has exactly one recipient. Pass
        `shared=True` for shared mode: ONE task all recipients see and
        answer together, returned as a plain `Task`.

        Targeting: pass `topic=` (any client) or `member=` / `broadcast=`
        (OrgClient only — they require the Api-Key). Pass NO target on a personal
        `Client` for a "note to self": the task goes straight to your own devices
        (a single `Task`). A note-to-self is encrypted under the client's default
        `password` (the account key) when one is configured, else sent plaintext.

        Args:
            topic: The topic to send to (also the encryption salt). Mutually
                   exclusive with member/broadcast. Omit (personal Client) for a
                   note-to-self to your own devices.
            member: Send to a single org member by name (OrgClient only).
            broadcast: Send to every member of the org (OrgClient only).
            title: Optional task title.
            content: Optional task content/body.
            inputs: Optional list of input requests (TextInput, ChoiceInput, etc.).
            links: Optional list of http(s) URLs to attach.
            files: Optional list of local file paths to upload and
                   attach. Encrypted with the send's key (when the send is
                   encrypted) before upload — the server only stores ciphertext.
                   Each file is read fully into memory, so this is unsuited to
                   very large files. Uploaded after the task is created; an
                   upload that fails is marked failed without failing the send.
            auto_commit: Default False: the task renders as a form with one
                Submit for all inputs. True commits each input as it is filled.
            password: Optional password to encrypt body fields with. Requires a
                      topic (used as the salt for key derivation). Falls back to
                      the client's default `password` when omitted. Not accepted
                      on a note-to-self (raises ValueError) — that always uses the
                      account key; pass no password.
            reply: Show a reply composer on the task. A `ReplyMode` (or its wire
                   string). Omit for no composer.
            content_format: Set to `ContentFormat.MARKDOWN` (or its wire string
                   "markdown") to have recipients render `content` as Markdown.
                   Plaintext marker (never encrypted); omit for plain.
            shared: Shared mode — one task all recipients share, returned
                   as a `Task`. Default False (independent instances, `TaskGroup`).
            expires_at: Optional deadline (a `datetime` — naive values are
                   rejected — or an ISO-8601 string; must lie in the future).
                   Plaintext metadata. Past it, an unanswered task expires:
                   the terminal `TaskExpired` ends its streams and further
                   answers are rejected with `task_expired`.

        Returns:
            A `TaskGroup` of per-recipient `Task` instances (default), or a
            single shared `Task` with `shared=True`. Either handle's `inputs()`
            / `replies()` stream the task's events.

        Raises:
            ApiError: If the server returns a non-2xx status.
            ValueError: If neither content nor inputs are provided, or if not
                        exactly one target is set.
        """
        return self._create_task(
            topic=topic, member=member, broadcast=broadcast,
            title=title, content=content, inputs=inputs,
            links=links, files=files,
            auto_commit=auto_commit,
            password=password if password is not None else self._send_password(topic),
            tag=tag, critical=critical, priority=priority, critical_volume=critical_volume, reply=reply,
            content_format=content_format, shared=shared,
            expires_at=expires_at,
        )

    def send_notification(
        self,
        *,
        topic: str | None = None,
        member: str | None = None,
        broadcast: bool = False,
        title: str | None = None,
        content: str | None = None,
        input: NotificationInput | None = None,
        image: "str | os.PathLike | None" = None,
        audio: "str | os.PathLike | None" = None,
        link: str | None = None,
        password: str | None = None,
        tag: str | None = None,
        critical: bool = False,
        priority: int | None = None,
        critical_volume: float | None = None,
        shared: bool = False,
    ) -> "Notification | NotificationGroup":
        """Send a notification and return a handle to its event stream.

        By default every recipient gets their OWN independent notification
        instance under a group (one recipient's answer never touches another's),
        and this returns a `NotificationGroup` — iterate it for the per-recipient
        `Notification` handles, or use `.sole` when the target has exactly one
        recipient. Pass `shared=True` for shared mode: ONE notification
        all recipients see and answer together, returned as a plain
        `Notification`.

        A notification is a lighter sibling of a task: it carries at most one
        input (a single NotificationTextInput, NotificationChoiceInput, or
        NotificationActionInput — never photo/voice/file) and has no reply
        composer and no subtasks. Targeting works exactly like `send_task` —
        `topic=` / `member=` / `broadcast=` (the latter two OrgClient only), or
        NO target on a personal `Client` for a "note to self" to your own devices
        (encrypted under the account key when a default `password` is configured).

        Args:
            topic: The topic to send to (also the encryption salt). Mutually
                   exclusive with member/broadcast. Omit (personal Client) for a
                   note-to-self to your own devices.
            member: Send to a single org member by name (OrgClient only).
            broadcast: Send to every member of the org (OrgClient only).
            title: Optional notification title.
            content: Optional notification body. Either content or an input must
                     be provided.
            input: Optional single NotificationTextInput,
                   NotificationChoiceInput, or NotificationActionInput (the
                   notification-specific input types, distinct from the task
                   TextInput/ChoiceInput/ActionsInput).
            image: Optional single image to show in the push, as either an
                   http(s) URL (sent as a link) or a local file path (uploaded,
                   encrypted when the notification is). Renders on iOS + Android.
            audio: Optional single audio clip (URL or local path), like `image`.
                   Plays inline on iOS; Android has no inline audio. Mutually
                   exclusive with `image` (a notification shows at most one media).
            link: Optional URL shown as an "Open link" button on the push. Any
                  scheme: an https URL opens the browser, an app's deep link
                  (`unifi-protect://...`) opens that app. Mutually exclusive
                  with `input` (the input's buttons take the action slots).
            password: Optional password to encrypt body fields with. Requires a
                      topic (used as the salt for key derivation). Falls back to
                      the client's default `password` when omitted. Not accepted
                      on a note-to-self (raises ValueError) — that always uses the
                      account key; pass no password.

            shared: Shared mode — one notification all recipients share,
                   returned as a `Notification`. Default False (independent
                   instances, `NotificationGroup`).

        Returns:
            A `NotificationGroup` of per-recipient `Notification` instances
            (default), or a single shared `Notification` with `shared=True`.
            Either handle's `inputs()` streams the completion event(s).

        Raises:
            ApiError: If the server returns a non-2xx status.
            ValueError: If neither content nor an input is provided, or if not
                        exactly one target is set.
            TypeError: If `input` is not a NotificationTextInput,
                        NotificationChoiceInput, or NotificationActionInput.
        """
        return self._create_notification(
            topic=topic, member=member, broadcast=broadcast,
            title=title, content=content, input=input,
            image=image, audio=audio, link=link,
            password=password if password is not None else self._send_password(topic),
            tag=tag, critical=critical, priority=priority, critical_volume=critical_volume, shared=shared,
        )

    def _create_task(self, *, topic=None, member=None, broadcast=False,
                     title=None, content=None, inputs=None, links=None,
                     files=None,
                     auto_commit=False, password=None, tag=None, critical=False, priority=None, critical_volume=None,
                     reply=None, content_format=None, shared=False,
                     expires_at=None) -> "Task | TaskGroup":
        if not content and not inputs:
            raise ValueError("Either content or inputs must be provided")
        target_count = sum((topic is not None, member is not None, bool(broadcast)))
        if target_count > 1:
            raise ValueError("topic, member, and broadcast are mutually exclusive")
        if (member is not None or broadcast) and not self._api_key:
            raise RuntimeError("member/broadcast targeting requires OrgClient(api_key=...)")
        # Zero targets = a personal "note to self" (send to your own devices),
        # valid only for a personal Client. An OrgClient send needs a target.
        if target_count == 0 and self._api_key:
            raise ValueError("an org send requires one of topic, member, or broadcast")

        _validate_action_inputs(inputs)
        input_dicts = [inp.to_dict() for inp in (inputs or [])]
        remote = list(links or [])

        # Personal encryption key: a topic send derives it from (password, topic);
        # a note-to-self (no target) derives it from the account default password +
        # the server password_salt — the same key that decrypts your submissions.
        personal_dk = None
        if password is not None:
            if topic is None:
                raise ValueError(
                    "password= requires a topic to use as its salt; a note-to-self "
                    "is encrypted with the client's default password instead"
                )
            from .crypto import derive_key
            personal_dk = derive_key(password, topic)  # salt = topic value
        elif topic is None and member is None and not broadcast:
            personal_dk = self._self_send_key()  # note-to-self; None -> plaintext

        encryption_dict = None
        send_key = None
        file_key = None  # symmetric key for encrypting local attachment bytes; None = plaintext send
        if personal_dk is not None:
            from .crypto import encrypt
            dk = personal_dk
            send_key = dk  # reused to encrypt subtasks appended to this task
            file_key = dk.symmetric_key  # local attachment bytes share the send key
            self._remember_key(dk)  # fold into the keyring for events()-feed decryption
            if title is not None:
                title = encrypt(title, dk.symmetric_key)
            if content is not None:
                content = encrypt(content, dk.symmetric_key)
            if tag is not None:
                tag = encrypt(tag, dk.symmetric_key)
            for inp in input_dicts:
                if inp.get("description") is not None:
                    inp["description"] = encrypt(inp["description"], dk.symmetric_key)
                if inp.get("type") == "text" and inp.get("defaultValue") is not None:
                    inp["defaultValue"] = encrypt(inp["defaultValue"], dk.symmetric_key)
                if inp.get("type") == "choice" and "options" in inp:
                    inp["options"] = [encrypt(opt, dk.symmetric_key) for opt in inp["options"]]
                if inp.get("type") == "actions" and "actions" in inp:
                    for a in inp["actions"]:
                        a["key"] = encrypt(a["key"], dk.symmetric_key)
                        a["label"] = encrypt(a["label"], dk.symmetric_key)
                if inp.get("type") == "slider":
                    meta = {k: inp.pop(k) for k in ("min", "max", "step", "unit", "defaultValue") if k in inp}
                    inp["encrypted"] = encrypt(json.dumps(meta), dk.symmetric_key)
            remote = [encrypt(url, dk.symmetric_key) for url in remote]
            encryption_dict = {"type": "personal", "keyFingerprint": dk.fingerprint}
        elif self._org_decryptor is not None:
            # Org-mode: encrypt the body under the org's current master key.
            from .crypto import encrypt
            version = self._org_decryptor.current_version
            key = self._org_decryptor.key_for_version(version)
            assert key is not None  # the decryptor always holds its current version's key
            file_key = key  # local attachment bytes share the org master key
            if title is not None:
                title = encrypt(title, key)
            if content is not None:
                content = encrypt(content, key)
            if tag is not None:
                tag = encrypt(tag, key)
            for inp in input_dicts:
                if inp.get("description") is not None:
                    inp["description"] = encrypt(inp["description"], key)
                if inp.get("type") == "text" and inp.get("defaultValue") is not None:
                    inp["defaultValue"] = encrypt(inp["defaultValue"], key)
                if inp.get("type") == "choice" and "options" in inp:
                    inp["options"] = [encrypt(opt, key) for opt in inp["options"]]
                if inp.get("type") == "actions" and "actions" in inp:
                    for a in inp["actions"]:
                        a["key"] = encrypt(a["key"], key)
                        a["label"] = encrypt(a["label"], key)
                if inp.get("type") == "slider":
                    meta = {k: inp.pop(k) for k in ("min", "max", "step", "unit", "defaultValue") if k in inp}
                    inp["encrypted"] = encrypt(json.dumps(meta), key)
            remote = [encrypt(url, key) for url in remote]
            encryption_dict = {"type": "org", "v": version}

        # Read + (optionally) encrypt each local attachment up front so the
        # createTaskJson body carries the metadata the server needs to mint the
        # rows. `prepared` keeps each blob alongside its metadata for the upload
        # pass after the task exists. Checksum/size describe the uploaded blob
        # (ciphertext when encrypted), matching what the receiver verifies.
        from .crypto import encrypt_bytes
        prepared: list[tuple[dict, bytes]] = []
        for path in (files or []):
            raw = Path(path).read_bytes()
            filename = os.path.basename(os.fspath(path))
            content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            blob = encrypt_bytes(raw, file_key) if file_key is not None else raw
            checksum = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
            prepared.append((
                {"filename": filename, "contentType": content_type, "size": len(blob), "checksumSha256": checksum},
                blob,
            ))

        body: dict = {
            "autoCommit": auto_commit,
            "broadcast": broadcast,
            "inputs": input_dicts,
            "links": remote,
            "files": [meta for (meta, _) in prepared],
        }
        if topic is not None:
            body["topic"] = topic
        if member is not None:
            body["member"] = member
        if tag is not None:
            body["tag"] = tag
        if title is not None:
            body["title"] = title
        if content is not None:
            body["content"] = content
        body.update(_priority_wire(priority, critical, critical_volume))
        if reply is not None:
            body["reply"] = reply.value if isinstance(reply, ReplyMode) else reply
        if content_format is not None:
            body["contentFormat"] = content_format.value if isinstance(content_format, ContentFormat) else content_format
        if encryption_dict is not None:
            body["encryption"] = encryption_dict
        if shared:
            body["shared"] = True
        if expires_at is not None:
            body["expiresAt"] = _expires_at_wire(expires_at)

        # Org sends authenticate with the Api-Key; personal sends require the
        # API-Token (the server uses it to own the task's attachments).
        headers = {"Api-Key": self._api_key} if self._api_key else {"API-Token": self._api_token}
        body.setdefault("idempotencyKey", self._mint_idempotency_key())
        resp = self._post("/tasks/json", body, headers, retry=True) or {}

        # Independent mode (the default) answers with the group shape: one task
        # instance per recipient plus group-level tokens. The sender's local
        # attachments are group-shared (one file row for all instances), so the
        # upload pass runs once against the group response's attachments.
        if "groupId" in resp:
            created_at = resp.get("createdAt")
            instance_tasks: list[Task] = []
            for inst in resp.get("instances") or []:
                task_id = inst.get("taskId")
                assert task_id is not None  # every group instance carries its task id
                self._hub.register_entity(task_id, created_at)
                rec = inst.get("recipient") or {}
                instance_tasks.append(Task(
                    task_id,
                    created_at,
                    inst.get("waitToken"),
                    self._hub,
                    append_token=inst.get("appendToken"),
                    client=self,
                    send_key=send_key,
                    decryptor=self._org_decryptor,
                    recipient=TaskGroupRecipient(public_id=rec.get("publicId"), name=rec.get("name")),
                ))
            if prepared:
                self._upload_files(headers, prepared, resp.get("attachments") or [])
            return TaskGroup(
                resp["groupId"],
                created_at,
                resp.get("groupWaitToken"),
                self._hub,
                append_token=resp.get("groupAppendToken"),
                instances=instance_tasks,
                client=self,
                send_key=send_key,
                decryptor=self._org_decryptor,
            )

        task_id = resp.get("taskId")
        assert task_id is not None
        created_at = resp.get("createdAt")
        # Register before returning so the hub buffers this task's events from
        # now, even if the caller awaits the streams a moment later.
        self._hub.register_entity(task_id, created_at)
        # Upload the local attachment bytes now that the task (and its rows) exist.
        if prepared:
            self._upload_files(headers, prepared, resp.get("attachments") or [])
        return Task(
            task_id,
            created_at,
            resp.get("waitToken"),
            self._hub,
            append_token=resp.get("appendToken"),
            client=self,
            send_key=send_key,
            decryptor=self._org_decryptor,
        )

    def _create_notification(self, *, topic=None, member=None, broadcast=False,
                             title=None, content=None, input=None, image=None, audio=None,
                             link=None, password=None, tag=None, critical=False, priority=None, critical_volume=None,
                             shared=False) -> "Notification | NotificationGroup":
        if not content and input is None:
            raise ValueError("Either content or an input must be provided")
        target_count = sum((topic is not None, member is not None, bool(broadcast)))
        if target_count > 1:
            raise ValueError("topic, member, and broadcast are mutually exclusive")
        if (member is not None or broadcast) and not self._api_key:
            raise RuntimeError("member/broadcast targeting requires OrgClient(api_key=...)")
        # Zero targets = a personal "note to self"; valid only for a personal Client.
        if target_count == 0 and self._api_key:
            raise ValueError("an org send requires one of topic, member, or broadcast")
        if input is not None and not isinstance(
            input, (NotificationTextInput, NotificationChoiceInput, NotificationActionInput)
        ):
            raise TypeError(
                "a notification input must be a NotificationTextInput, "
                "NotificationChoiceInput, or NotificationActionInput, got "
                f"{type(input).__name__}"
            )
        if isinstance(input, NotificationActionInput):
            _validate_actions(input.actions)
        if image is not None and audio is not None:
            raise ValueError("a notification can carry at most one media attachment (image or audio, not both)")
        if link is not None and input is not None:
            raise ValueError("a notification carries either an input or a link, not both: the input's buttons take the action slots, so the link would never be shown")

        # A notification carries at most one input, sent as `textInput {}` XOR
        # `choiceInput {options}` XOR `actionInput {actions}`. For actions, both
        # the keys and the labels are encrypted below (validation above already
        # ran on the plaintext actions).
        choice_options = input.options if isinstance(input, NotificationChoiceInput) else None
        action_defs = [a.to_dict() for a in input.actions] if isinstance(input, NotificationActionInput) else None

        # Personal key: a topic send derives it from (password, topic); a
        # note-to-self (no target) from the account default password + password_salt.
        personal_dk = None
        if password is not None:
            if topic is None:
                raise ValueError(
                    "password= requires a topic to use as its salt; a note-to-self "
                    "is encrypted with the client's default password instead"
                )
            from .crypto import derive_key
            personal_dk = derive_key(password, topic)  # salt = topic value
        elif topic is None and member is None and not broadcast:
            personal_dk = self._self_send_key()  # note-to-self; None -> plaintext

        encryption_dict = None
        send_key = None
        enc_key = None  # symmetric key for encrypting media (URL string / file bytes); None = plaintext
        if personal_dk is not None:
            from .crypto import encrypt
            dk = personal_dk
            send_key = dk
            enc_key = dk.symmetric_key
            self._remember_key(dk)  # fold into the keyring for events()-feed decryption
            if title is not None:
                title = encrypt(title, dk.symmetric_key)
            if content is not None:
                content = encrypt(content, dk.symmetric_key)
            if tag is not None:
                tag = encrypt(tag, dk.symmetric_key)
            if choice_options is not None:
                choice_options = [encrypt(opt, dk.symmetric_key) for opt in choice_options]
            if link is not None:
                link = encrypt(link, dk.symmetric_key)
            if action_defs is not None:
                # Key AND label, exactly like a task's ActionsInput: the key
                # usually carries the same meaning as the label ("approve"), so
                # sealing only the label would hide the wording and leak the
                # intent. The apps decrypt both before building their native
                # action buttons.
                for a in action_defs:
                    a["key"] = encrypt(a["key"], dk.symmetric_key)
                    a["label"] = encrypt(a["label"], dk.symmetric_key)
            encryption_dict = {"type": "personal", "keyFingerprint": dk.fingerprint}
        elif self._org_decryptor is not None:
            from .crypto import encrypt
            version = self._org_decryptor.current_version
            key = self._org_decryptor.key_for_version(version)
            assert key is not None  # the decryptor always holds its current version's key
            enc_key = key
            if title is not None:
                title = encrypt(title, key)
            if content is not None:
                content = encrypt(content, key)
            if tag is not None:
                tag = encrypt(tag, key)
            if choice_options is not None:
                choice_options = [encrypt(opt, key) for opt in choice_options]
            if link is not None:
                link = encrypt(link, key)
            if action_defs is not None:
                for a in action_defs:   # key AND label, as above
                    a["key"] = encrypt(a["key"], key)
                    a["label"] = encrypt(a["label"], key)
            encryption_dict = {"type": "org", "v": version}

        # Single optional media (image or audio), as a link (URL) or file (path).
        # `prepared_media` holds (metadata, blob) for the file case to upload after
        # the notification is created (mirrors the task file-attachment lifecycle).
        media_dict, prepared_media = self._build_notification_media(image, audio, enc_key)

        payload: dict = {
            "broadcast": broadcast,
        }
        if media_dict is not None:
            payload["media"] = media_dict
        if link is not None:
            payload["link"] = link
        if topic is not None:
            payload["topic"] = topic
        if member is not None:
            payload["member"] = member
        if tag is not None:
            payload["tag"] = tag
        if title is not None:
            payload["title"] = title
        if content is not None:
            payload["content"] = content
        if isinstance(input, NotificationTextInput):
            payload["textInput"] = {}
        elif choice_options is not None:
            payload["choiceInput"] = {"options": choice_options}
        elif action_defs is not None:
            payload["actionInput"] = {"actions": action_defs}
        payload.update(_priority_wire(priority, critical, critical_volume))
        if encryption_dict is not None:
            payload["encryption"] = encryption_dict
        if shared:
            payload["shared"] = True

        # Every notification send carries its sender credential: the Api-Key
        # for an org client, the API-Token for a personal one. The backend
        # rejects a personal notification create without an API-Token (it
        # identifies the sender, and owns + quotas any media file). Mirrors the
        # task/subtask create headers.
        headers = {"Api-Key": self._api_key} if self._api_key else {"API-Token": self._api_token}
        payload.setdefault("idempotencyKey", self._mint_idempotency_key())
        resp = self._post("/notifications/json", payload, headers, retry=True) or {}

        # Independent mode (the default) answers with the group shape: one
        # notification instance per recipient plus group-level tokens. The single
        # media is group-shared (one file row for all instances), so the upload
        # pass runs once against the group response's mediaAttachment.
        if "groupId" in resp:
            created_at = resp.get("createdAt")
            instance_notifications: list[Notification] = []
            for inst in resp.get("instances") or []:
                nid = inst.get("notificationId")
                assert nid is not None  # every group instance carries its notification id
                self._hub.register_entity(nid, created_at)
                rec = inst.get("recipient") or {}
                instance_notifications.append(Notification(
                    nid,
                    created_at,
                    inst.get("waitToken"),
                    self._hub,
                    client=self,
                    send_key=send_key,
                    decryptor=self._org_decryptor,
                    recipient=NotificationGroupRecipient(public_id=rec.get("publicId"), name=rec.get("name")),
                ))
            created = resp.get("mediaAttachment")
            if prepared_media is not None and created is not None:
                self._upload_files(headers, [prepared_media], [created])
            return NotificationGroup(
                resp["groupId"],
                created_at,
                resp.get("groupWaitToken"),
                self._hub,
                instances=instance_notifications,
                client=self,
                send_key=send_key,
                decryptor=self._org_decryptor,
            )

        notification_id = resp.get("notificationId")
        assert notification_id is not None
        created_at = resp.get("createdAt")
        self._hub.register_entity(notification_id, created_at)
        # Upload the media file's bytes now that the notification (+ its file row) exists.
        created = resp.get("mediaAttachment")
        if prepared_media is not None and created is not None:
            self._upload_files(headers, [prepared_media], [created])
        return Notification(
            notification_id,
            created_at,
            resp.get("waitToken"),
            self._hub,
            client=self,
            send_key=send_key,
            decryptor=self._org_decryptor,
        )

    # Supported notification media content types — mirror the backend allow-list
    # (the iOS UNNotificationAttachment UTIs). image/* renders on iOS + Android;
    # audio/* plays inline on iOS only.
    _NOTIFICATION_IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif"}
    _NOTIFICATION_AUDIO_TYPES = {
        "audio/aiff", "audio/x-aiff", "audio/wav", "audio/x-wav", "audio/vnd.wave",
        "audio/mpeg", "audio/mp3", "audio/mp4", "audio/aac", "audio/x-m4a",
    }
    # Extension → MIME, used before mimetypes (whose audio answers vary by OS).
    _NOTIFICATION_EXT_TYPES = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
        ".aiff": "audio/aiff", ".aif": "audio/aiff", ".wav": "audio/wav",
        ".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac",
    }

    def _build_notification_media(self, image, audio, enc_key):
        """Build the single optional notification media (image XOR audio) as a
        link (http(s) URL) or a file (local path). Returns
        (media_dict_or_None, prepared_or_None) — `prepared` is (metadata, blob)
        for the file case, uploaded after the notification is created. Derives the
        content type from the extension and validates it against the backend's
        supported set + the requested kind."""
        if image is not None:
            value, kind, supported = image, "image", self._NOTIFICATION_IMAGE_TYPES
        elif audio is not None:
            value, kind, supported = audio, "audio", self._NOTIFICATION_AUDIO_TYPES
        else:
            return None, None

        src = value if isinstance(value, str) else os.fspath(value)
        is_url = src.startswith(("http://", "https://"))
        name = src if is_url else os.path.basename(src)
        ext = os.path.splitext(name.split("?", 1)[0])[1].lower()
        content_type = self._NOTIFICATION_EXT_TYPES.get(ext) or mimetypes.guess_type(name)[0]
        if content_type not in supported:
            raise ValueError(
                f"{kind} media must be a supported {kind} type ({sorted(supported)}); "
                f"could not derive one from {value!r} (got {content_type!r})"
            )

        if is_url:
            from .crypto import encrypt
            url = encrypt(src, enc_key) if enc_key is not None else src
            return {"type": "link", "url": url, "contentType": content_type}, None

        from .crypto import encrypt_bytes
        raw = Path(src).read_bytes()
        blob = encrypt_bytes(raw, enc_key) if enc_key is not None else raw
        checksum = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
        meta = {
            "filename": os.path.basename(src),
            "contentType": content_type,
            "size": len(blob),
            "checksumSha256": checksum,
        }
        return {"type": "file", **meta}, (meta, blob)

    def _build_subtask_data(self, send_key, *, title=None, content=None, inputs=None,
                            links=None, files=None,
                            auto_commit=False, critical=False, priority=None, critical_volume=None,
                            reply=None, content_format=None) -> "tuple[dict, list]":
        """Build the (encrypted) `data` dict of a subtask append plus the
        prepared local attachments awaiting upload — shared by the single-task
        and group append paths. `send_key` is the parent chain's topic key
        (personal encryption); without one, the org master key applies when
        configured, else the subtask goes in plaintext."""
        if not content and not inputs:
            raise ValueError("Either content or inputs must be provided")

        _validate_action_inputs(inputs)
        input_dicts = [inp.to_dict() for inp in (inputs or [])]
        remote = list(links or [])

        encryption_dict = None
        file_key = None  # symmetric key for encrypting local attachment bytes; None = plaintext send
        if send_key is not None:
            from .crypto import encrypt
            file_key = send_key.symmetric_key  # local attachment bytes share the chain key
            if title is not None:
                title = encrypt(title, send_key.symmetric_key)
            if content is not None:
                content = encrypt(content, send_key.symmetric_key)
            for inp in input_dicts:
                if inp.get("description") is not None:
                    inp["description"] = encrypt(inp["description"], send_key.symmetric_key)
                if inp.get("type") == "text" and inp.get("defaultValue") is not None:
                    inp["defaultValue"] = encrypt(inp["defaultValue"], send_key.symmetric_key)
                if inp.get("type") == "choice" and "options" in inp:
                    inp["options"] = [encrypt(opt, send_key.symmetric_key) for opt in inp["options"]]
                if inp.get("type") == "actions" and "actions" in inp:
                    for a in inp["actions"]:
                        a["key"] = encrypt(a["key"], send_key.symmetric_key)
                        a["label"] = encrypt(a["label"], send_key.symmetric_key)
                if inp.get("type") == "slider":
                    meta = {k: inp.pop(k) for k in ("min", "max", "step", "unit", "defaultValue") if k in inp}
                    inp["encrypted"] = encrypt(json.dumps(meta), send_key.symmetric_key)
            remote = [encrypt(url, send_key.symmetric_key) for url in remote]
            encryption_dict = {"type": "personal", "keyFingerprint": send_key.fingerprint}
        elif self._org_decryptor is not None:
            from .crypto import encrypt
            version = self._org_decryptor.current_version
            key = self._org_decryptor.key_for_version(version)
            assert key is not None  # the decryptor always holds its current version's key
            file_key = key  # local attachment bytes share the org master key
            if title is not None:
                title = encrypt(title, key)
            if content is not None:
                content = encrypt(content, key)
            for inp in input_dicts:
                if inp.get("description") is not None:
                    inp["description"] = encrypt(inp["description"], key)
                if inp.get("type") == "text" and inp.get("defaultValue") is not None:
                    inp["defaultValue"] = encrypt(inp["defaultValue"], key)
                if inp.get("type") == "choice" and "options" in inp:
                    inp["options"] = [encrypt(opt, key) for opt in inp["options"]]
                if inp.get("type") == "actions" and "actions" in inp:
                    for a in inp["actions"]:
                        a["key"] = encrypt(a["key"], key)
                        a["label"] = encrypt(a["label"], key)
                if inp.get("type") == "slider":
                    meta = {k: inp.pop(k) for k in ("min", "max", "step", "unit", "defaultValue") if k in inp}
                    inp["encrypted"] = encrypt(json.dumps(meta), key)
            remote = [encrypt(url, key) for url in remote]
            encryption_dict = {"type": "org", "v": version}

        # Read + (optionally) encrypt each local attachment up front, same as
        # _create_task: the metadata rides the append body so the server mints
        # the subtask's `file` rows, and `prepared` keeps the blobs for the
        # presign + upload pass once the subtask exists.
        from .crypto import encrypt_bytes
        prepared: list[tuple[dict, bytes]] = []
        for path in (files or []):
            raw = Path(path).read_bytes()
            filename = os.path.basename(os.fspath(path))
            content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            blob = encrypt_bytes(raw, file_key) if file_key is not None else raw
            checksum = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
            prepared.append((
                {"filename": filename, "contentType": content_type, "size": len(blob), "checksumSha256": checksum},
                blob,
            ))

        data: dict = {
            "autoCommit": auto_commit,
            "inputs": input_dicts,
            "links": remote,
            "files": [meta for (meta, _) in prepared],
        }
        if title is not None:
            data["title"] = title
        if content is not None:
            data["content"] = content
        data.update(_priority_wire(priority, critical, critical_volume))
        if reply is not None:
            data["reply"] = reply.value if isinstance(reply, ReplyMode) else reply
        if content_format is not None:
            data["contentFormat"] = content_format.value if isinstance(content_format, ContentFormat) else content_format
        if encryption_dict is not None:
            data["encryption"] = encryption_dict
        return data, prepared

    def _append_subtask(self, task, *, title=None, content=None, inputs=None,
                        links=None, files=None,
                        auto_commit=False, critical=False, priority=None, critical_volume=None,
                        reply=None, content_format=None) -> Subtask:
        if not task.append_token:
            raise RuntimeError("this task has no append token; cannot append a subtask")
        # Inherit the parent's key (subtask encryption must match the chain's).
        data, prepared = self._build_subtask_data(
            task._send_key, title=title, content=content, inputs=inputs,
            links=links, files=files, auto_commit=auto_commit, critical=critical, priority=priority, critical_volume=critical_volume,
            reply=reply, content_format=content_format,
        )

        body = {"appendToken": task.append_token, "data": data}
        # Org appends authenticate with the Api-Key; personal appends carrying
        # local attachments require the API-Token so the server can own the
        # subtask's attachments (harmless to send it when there are none).
        headers = {"Api-Key": self._api_key} if self._api_key else {"API-Token": self._api_token}
        data.setdefault("idempotencyKey", self._mint_idempotency_key())
        resp = self._post("/subtasks/json", body, headers, retry=True) or {}
        subtask_id = resp.get("subtaskId")
        assert subtask_id is not None
        created_at = resp.get("createdAt")
        if prepared:
            self._upload_files(headers, prepared, resp.get("attachments") or [])
        # Subtask events route to the chain's root buffer; ensure it exists.
        self._hub.register_entity(task.task_id, created_at)
        return Subtask(
            subtask_id,
            task.task_id,
            created_at,
            self._hub,
            decryptor=task._decryptor,
            client=self,
            send_key=task._send_key,
        )

    def _append_subtasks_to_group(self, group, *, instances=None, title=None,
                                  content=None, inputs=None, links=None, files=None,
                                  auto_commit=False, critical=False, priority=None, critical_volume=None,
                                  reply=None, content_format=None) -> "list[Subtask]":
        """Append one subtask per member instance to a task group's chains,
        atomically, via the group append token. `instances` (task ids) restricts
        the append to those members; None appends to every member. Returns one
        `Subtask` handle per appended member. `files` are minted ONCE for the
        batch (the response's `attachments`) and uploaded a single time — every
        sibling subtask references the same attachment ids."""
        if not group.append_token:
            raise RuntimeError("this task group has no append token; cannot append a subtask")
        data, prepared = self._build_subtask_data(
            group._send_key, title=title, content=content, inputs=inputs,
            links=links, files=files, auto_commit=auto_commit, critical=critical, priority=priority, critical_volume=critical_volume,
            reply=reply, content_format=content_format,
        )

        body: dict = {"appendToken": group.append_token, "data": data}
        if instances is not None:
            body["instances"] = list(instances)
        headers = {"Api-Key": self._api_key} if self._api_key else {"API-Token": self._api_token}
        data.setdefault("idempotencyKey", self._mint_idempotency_key())
        resp = self._post("/subtasks/json", body, headers, retry=True) or {}
        # ONE upload pass for the whole batch (an empty group mints nothing —
        # the server returns no attachments and zip() drives zero uploads).
        if prepared:
            self._upload_files(headers, prepared, resp.get("attachments") or [])
        created_at = resp.get("createdAt")
        subtasks: list[Subtask] = []
        for ref in resp.get("subtasks") or []:
            parent_task_id = ref.get("taskId")
            assert parent_task_id is not None
            # Subtask events route to each member chain's root buffer.
            self._hub.register_entity(parent_task_id, created_at)
            subtasks.append(Subtask(
                ref.get("subtaskId"),
                parent_task_id,
                created_at,
                self._hub,
                decryptor=group._decryptor,
                client=self,
                send_key=group._send_key,
            ))
        return subtasks

    def _cancel_body(self, send_key, *, reason: "str | CancelReason", note: str | None,
                     superseded_by: str | None) -> dict:
        """Shared body builder for the three cancel endpoints. Validates the
        reason/pointer coupling client-side (mirrors the server's rule) and
        encrypts the note under the chain's key — personal topic key or the
        org master key — exactly like task/subtask content."""
        reason = reason.value if isinstance(reason, CancelReason) else reason
        if reason not in ("canceled", "answered", "superseded"):
            raise ValueError(f"reason must be 'canceled', 'answered', or 'superseded', not {reason!r}")
        if superseded_by is not None and reason != "superseded":
            raise ValueError("superseded_by requires reason='superseded'")
        body: dict = {"reason": reason}
        if note is not None:
            # The note carries its OWN marker (not the task's): a cancel is
            # authored after the send, so an org note may use a newer
            # master_key version than the task's marker names.
            if send_key is not None:
                from .crypto import encrypt
                note = encrypt(note, send_key.symmetric_key)
                body["encryption"] = {"type": "personal", "keyFingerprint": send_key.fingerprint}
            elif self._org_decryptor is not None:
                from .crypto import encrypt
                version = self._org_decryptor.current_version
                key = self._org_decryptor.key_for_version(version)
                assert key is not None  # the decryptor always holds its current version's key
                note = encrypt(note, key)
                body["encryption"] = {"type": "org", "v": version}
            body["note"] = note
        if superseded_by is not None:
            body["supersededBy"] = superseded_by
        return body

    def _cancel_task(self, task, *, reason: str, note: str | None, superseded_by: str | None) -> None:
        body = self._cancel_body(task._send_key, reason=reason, note=note, superseded_by=superseded_by)
        headers = {"Api-Key": self._api_key} if self._api_key else {"API-Token": self._api_token}
        self._post(f"/tasks/{task.task_id}/cancel", body, headers)

    def _cancel_subtask(self, subtask, *, reason: str, note: str | None, superseded_by: str | None) -> None:
        body = self._cancel_body(subtask._send_key, reason=reason, note=note, superseded_by=superseded_by)
        headers = {"Api-Key": self._api_key} if self._api_key else {"API-Token": self._api_token}
        self._post(f"/subtasks/{subtask.subtask_id}/cancel", body, headers)

    def _cancel_task_group(self, group, *, reason: str, note: str | None,
                           superseded_by: str | None) -> GroupCancelResult:
        body = self._cancel_body(group._send_key, reason=reason, note=note, superseded_by=superseded_by)
        headers = {"Api-Key": self._api_key} if self._api_key else {"API-Token": self._api_token}
        resp = self._post(f"/task-groups/{group.group_id}/cancel", body, headers) or {}
        return GroupCancelResult(canceled=resp.get("canceled", 0), skipped=resp.get("skipped", 0))

    # Retry budget for the create endpoints: 1+2+4+8+16 = ~31s of backoff
    # across 6 attempts, comfortably outlasting a managed-Postgres failover.
    # Only creates opt in (retry=True) — they carry an idempotency key, so a
    # resend is replayed by the backend, never applied twice.
    _RETRY_MAX_ATTEMPTS = 6
    _RETRY_BASE_DELAY = 1.0
    _RETRY_MAX_DELAY = 16.0

    @staticmethod
    def _mint_idempotency_key() -> str:
        return str(uuid.uuid4())

    @classmethod
    def _retry_delay(cls, attempt: int, retry_after: str | None) -> float:
        if retry_after is not None:
            try:
                return min(max(float(retry_after), 0.0), cls._RETRY_MAX_DELAY)
            except ValueError:
                pass
        return min(cls._RETRY_BASE_DELAY * 2 ** (attempt - 1), cls._RETRY_MAX_DELAY)

    @staticmethod
    def _is_idempotency_in_flight(payload: str) -> bool:
        try:
            return json.loads(payload).get("error") == "idempotency_in_flight"
        except (ValueError, AttributeError):
            return False

    def _post(self, path: str, body: dict, headers: dict | None = None, *,
              retry: bool = False) -> dict | None:
        url = f"{self._base}{path}"
        data = json.dumps(body).encode("utf-8")
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        attempt = 0
        while True:
            attempt += 1
            req = urllib.request.Request(url, data=data, headers=req_headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                    resp_body = resp.read().decode("utf-8")
                    if resp_body:
                        return json.loads(resp_body)
                    return None
            except urllib.error.HTTPError as e:
                payload = e.read().decode("utf-8")
                retryable = e.code == 503 or (e.code == 409 and self._is_idempotency_in_flight(payload))
                if not (retry and retryable) or attempt >= self._RETRY_MAX_ATTEMPTS:
                    raise ApiError(e.code, payload) from e
                time.sleep(self._retry_delay(attempt, e.headers.get("Retry-After")))
            except (urllib.error.URLError, TimeoutError) as e:
                # Network-level failure (connection refused/reset, DNS, or no
                # response within the timeout).
                if not retry or attempt >= self._RETRY_MAX_ATTEMPTS:
                    raise
                time.sleep(self._retry_delay(attempt, None))

    def _post_empty(self, path: str, headers: dict | None = None) -> dict | None:
        """POST with no request body — for the attachment lifecycle endpoints
        (presign / complete / failed), which take their inputs from the path +
        headers. Returns the parsed JSON response, or None when empty."""
        url = f"{self._base}{path}"
        req = urllib.request.Request(url, data=b"", headers=dict(headers or {}), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                resp_body = resp.read().decode("utf-8")
                return json.loads(resp_body) if resp_body else None
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode("utf-8")) from e

    def _put_bytes(self, url: str, data: bytes) -> None:
        """Raw PUT of a file blob to a presigned S3 URL. Content-Type isn't part
        of the presigned signature, so we set octet-stream explicitly (the real
        type travels in the FileAttachment metadata)."""
        req = urllib.request.Request(url, data=data, method="PUT")
        req.add_header("Content-Type", "application/octet-stream")
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode("utf-8")) from e

    def _upload_files(self, headers, prepared, created) -> None:
        """Drive each local attachment's upload after the task/subtask exists:
        presign → PUT the blob → complete. The lifecycle endpoints are keyed
        purely by attachmentId (ownership is enforced from the caller's
        credential), so the same flow serves tasks and subtasks. `created` is the
        server's ordered [{id, filename}], aligned with `prepared`. An attachment
        whose upload fails is marked failed (best-effort) and skipped — the
        parent and its other attachments still stand."""
        for (meta, blob), att in zip(prepared, created):
            attachment_id = att.get("id")
            if attachment_id is None:
                continue
            base = f"/attachments/{attachment_id}"
            try:
                presign = self._post_empty(f"{base}/upload-url", headers) or {}
                self._put_bytes(presign["presignedPutUrl"], blob)
                self._post_empty(f"{base}/complete", headers)
            except Exception:
                try:
                    self._post_empty(f"{base}/failed", headers)
                except Exception:
                    pass


class Client(_BaseClient):
    """Personal client for the SimplePush Business Backend, authenticated by a
    user API-Token. Sends to topics and receives task events over the multiplexed
    `/ws/v1/events` stream.

    For organization access (member/broadcast sends, org-wide events, and future
    org management) use `OrgClient`.

    Args:
        host: Server hostname. Defaults to the production endpoint.
        port: Server port. Defaults to 443.
        ssl: Use https/wss instead of http/ws. Defaults to True; set False only
             for plaintext local development.
        api_token: User API-Token (required).
        passwords: Your personal-mode passwords. Either a single default-password
            string, or a list whose entries are:
              - `(password, topic)` pairs — the password for that topic; derives
                its topic key (decrypts that topic's content, and is the send
                default for it), and
              - at most one bare default-password string — your account password;
                derives the account default key, which decrypts your submissions.
                It is decryption-only — it never encrypts a send.
            Examples: `"account-pw"` (just the default), or
            `[("alerts-pw", "alerts"), "account-pw"]`. A per-send `password=`
            always overrides for that send.
    """

    def __init__(self, host: str = "api.simplepu.sh", port: int = 443, ssl: bool = True,
                 *, api_token: str, passwords: "str | list[tuple[str, str] | str] | None" = None):
        topic_passwords, default_password = _parse_passwords(passwords)
        super().__init__(
            host, port, ssl, api_token=api_token, api_key=None,
            connect_path="/ws/v1/events",
            auth_headers={"API-Token": api_token},
            topic_passwords=topic_passwords,
            default_password=default_password,
        )

    def submissions(self, *, timeout: float | None = None, password: str | None = None) -> Submissions:
        """Observe `Submission`s on this user's stream. `password` overrides the
        account default password used to decrypt them for this call (otherwise the
        client's configured default password is used); supply it when you didn't
        set one at construction. See `_BaseClient.submissions` for the rest."""
        return self._build_submissions(timeout, password if password is not None else self._default_password)


class OrgClient(_BaseClient):
    """Organization client, authenticated by the org Api-Key.

    Sends org tasks (topic / member / broadcast) with the Api-Key header and
    receives org-wide events over `/ws/v1/events/organization` (the org is
    derived from the key). Future org-management surfaces (members, invites,
    topics, key rotation) will live here.

    Args:
        host: Server hostname. Defaults to the production endpoint.
        port: Server port. Defaults to 443.
        ssl: Use https/wss instead of http/ws. Defaults to True; set False only
             for plaintext local development.
        api_key: Org Api-Key (required).
    """

    def __init__(self, host: str = "api.simplepu.sh", port: int = 443, ssl: bool = True,
                 *, api_key: str,
                 master_keys: "dict[int, bytes | str] | None" = None,
                 master_key: "bytes | str | None" = None,
                 master_key_version: int | None = None):
        # Org encryption keys (optional). Either a full version -> key map, or a
        # single current `master_key` + `master_key_version`. Keys are 32-byte
        # XChaCha20-Poly1305 keys as raw bytes or base64, obtained out-of-band
        # from the org's encryption vault. Without them, org sends/receives stay
        # in plaintext (and org ciphertext is passed through undecrypted).
        if master_keys is not None and master_key is not None:
            raise ValueError("pass either master_keys or master_key, not both")
        if master_key is not None:
            if master_key_version is None:
                raise ValueError("master_key requires master_key_version")
            master_keys = {master_key_version: master_key}
        super().__init__(
            host, port, ssl, api_token=None, api_key=api_key,
            connect_path="/ws/v1/events/organization",
            auth_headers={"Api-Key": api_key},
            org_master_keys=master_keys,
        )

    # Member / broadcast targeting is reached through the inherited
    # `send_task` / `send_notification` via the `member=` / `broadcast=` kwargs.
