# simplepush

Python client for [Simplepush](https://simplepu.sh).

Send tasks, stream events over WebSocket, and decrypt end-to-end-encrypted
payloads from Python.

## Install

```bash
pip install simplepush            # HTTP + WebSocket only
pip install 'simplepush[crypto]'  # adds end-to-end encryption support
```

Requires Python 3.10+.

## Sending a task

```python
from simplepush import Client, TextInput, ChoiceInput

client = Client(api_token="USER_API_TOKEN")

group = client.send_task(
    topic="mytopic",
    title="Approve deploy?",
    inputs=[
        ChoiceInput(description="Deploy v1.2.3?", options=["yes", "no"], required=True),
        TextInput(description="Note (optional)"),
    ],
)
task = group.sole  # single-recipient topic; iterate the group for many
```

> **Ids are type-prefixed strings.** `task_id`, `subtask_id`, input/reply/file
> ids and the like come back type-tagged — `tsk_…`, `sub_…`, `inp_…`, `rpl_…`
> (a reply), `rfl_…` (a reply's file) — not bare UUIDs.

By default every recipient gets their **own independent task instance** (one
recipient's answers never touch another's task), returned as a `TaskGroup` of
per-recipient `Task` handles:

```python
group = client.send_task(topic="mytopic", content="check in")
for task in group:      # or group.instances
    print(task.task_id, task.recipient.public_id, task.recipient.name)

subs = group.append(content="follow-up")                      # a subtask on every member's chain
group.append(content="just you", instances=[group.instances[0]])  # or a subset

task = client.send_task(topic="mytopic", content="hi", shared=True)  # shared mode: ONE task everyone answers together
```

Both send methods take exactly one keyword-only target: `topic=` on any client,
or `member=` / `broadcast=` on an `OrgClient`. Omit the target on a personal
`Client` to send to your own devices (a self-send, returned as a single `Task` /
`Notification`; encrypted under the account personal password when one is
configured).

Other send options: `auto_commit=False` has the recipient submit the whole
form at once (by default each filled input arrives as an intermediate
`InputEvent`, then the terminal `TaskCompleted` carries the full committed
set); `reply=ReplyMode.STICKY` (or `"one-shot"` / `"one-time-per-user"`) shows
recipients an in-thread reply composer (collect via `replies()`);
`content_format=ContentFormat.MARKDOWN` renders a task's `content` as
Markdown (notifications are always plain); `priority=` sets how loudly the
push interrupts, 1 (minimal) to 5 (critical; sounds even on a muted phone),
default 3, with `critical_volume=` (0 to 1) for level 5 on iOS.

A task can have **subtasks** appended to its chain. A subtask inherits the
parent's recipients and encryption (no target, no password); its `inputs()` /
`replies()` are scoped to it, and stream off the same shared connection:

```python
sub = task.append(title="One more thing", inputs=[TextInput()])
async for ev in sub.inputs():
    if isinstance(ev, SubtaskCompleted):
        print(ev.uploads)
```

## Inputs

Task inputs: `TextInput`, `ChoiceInput` (set `multi=True`, with optional
`min_selections`/`max_selections`), `ActionsInput` (styled buttons; the tapped
action's stable `key` comes back), `SliderInput` (`min`/`max`/`step`/`unit`),
`PhotoInput`, `VoiceRecordingInput`, `FileUploadInput`, `LocationInput`.

```python
from simplepush import (
    Client, Action, ActionStyle, ActionsInput, SliderInput, ChoiceInput, PhotoInput,
    TaskCompleted, ActionUpload, SliderUpload, MultiChoiceUpload, PhotoUpload,
)

client = Client(api_token="USER_API_TOKEN")

incident = client.send_task(
    topic="ops",
    title="Incident 4711",
    inputs=[
        ActionsInput(actions=[
            Action(key="ack", label="Acknowledge", style=ActionStyle.PRIMARY),
            Action(key="escalate", label="Escalate", style=ActionStyle.DESTRUCTIVE),
        ]),
        SliderInput(min=0, max=10, step=1, unit="sev"),
        ChoiceInput(options=["db", "api", "infra"], multi=True, required=False),
        PhotoInput(required=False),
    ],
)
async for ev in incident.inputs():
    if not isinstance(ev.item, TaskCompleted):
        continue
    for u in ev.item.uploads:
        match u:
            case ActionUpload(key=key):
                print(ev.recipient.name, "pressed", key)
            case SliderUpload(value=value):
                print("severity", value)
            case MultiChoiceUpload(values=values):
                print("areas", values)
            case PhotoUpload() as photo:
                await photo.save("./incident-4711")
```

Streams accept `timeout=` (seconds of silence before iteration stops; on a
group stream the timeout is group-wide) and `replay=True` (replay the buffered
backlog since the send before going live).

**File downloads.** The binary upload objects (photo/voice/file uploads, a
reply's `photo`/`file`/`audio`, and submission files) are download handles
bound to the client that yielded them: `await x.read()` returns the bytes
(checksum-verified, decrypted on encrypted chains), `await x.save(path)`
writes to disk (a directory uses the file's own name), and
`await x.download_url()` returns the raw short-lived presigned URL plus its
expiry. Failures raise `DownloadError`.

## Sending a notification

A notification is a lighter sibling of a task: it carries a single input
(choice/text/actions only) and has no replies or subtasks.

Like `send_task`, the default is **independent** — every recipient gets their
own notification instance, returned as a `NotificationGroup`:

```python
from simplepush import Client, NotificationChoiceInput, NotificationActionInput, Action, ActionStyle

client = Client(api_token="USER_API_TOKEN")

group = client.send_notification(
    topic="mytopic",
    title="Build failed",
    content="main @ a1b2c3 failed 3 tests",
    input=NotificationChoiceInput(options=["ack", "mute"]),
)
note = group.sole   # single-recipient topic; iterate the group for many

async for ev in note.inputs():
    print(ev.reply)   # NotificationTextReply / NotificationChoiceReply / NotificationActionReply

# Action buttons (approve/deny), like a task's ActionsInput — on an encrypted
# send both the `key` and the `label` are sealed, and so is the reported answer:
group = client.send_notification(
    topic="mytopic",
    title="Deploy v1.2.3?",
    input=NotificationActionInput(actions=[
        Action(key="approve", label="Approve"),
        Action(key="deny", label="Deny", style=ActionStyle.DESTRUCTIVE),
    ]),
)

# Shared mode: ONE notification all recipients see and answer together (the
# first answer completes it for everyone), returned as a plain `Notification`:
note = client.send_notification(topic="mytopic", content="heads up", shared=True)
```

A notification can also carry ONE media item — `image=` (renders on iOS +
Android) or `audio=` (plays inline on iOS only) — as either an http(s) URL or
a local file path (uploaded, encrypted when the notification is).

## Attachments

`files=` uploads local files alongside a task/subtask (encrypted when the send
is; each file is read fully into memory). A notification takes its single
media item the same way, or as a URL:

```python
client.send_task(
    topic="reports",
    title="Q3 numbers",
    content="Full report attached.",
    files=["q3.pdf"],
)
client.send_notification(topic="alerts", title="Door cam", image="https://cam.example/last.jpg")
```

## Submissions

A **submission** is self-authored user content — a text body plus an optional
photo, file, audio clip, and location — pushed into a user's own stream with
no associated task; a task reply without the task. Submissions are *created*
by the app; the library *observes* them on the client's feed (both `Client`
and `OrgClient`):

```python
async for sub in client.submissions(timeout=300):
    # sub: Submission — body / photo / file / audio / location
    if sub.photo:
        await sub.photo.save("./inbox")
```

`photo`/`file`/`audio` are download handles (`read()` / `save()` /
`download_url()`); `audio` carries `duration_seconds`. `location` is inline
decoded data (latitude, longitude, accuracy, altitude, heading, speed,
timestamp). `timeout=` stops iteration after that many seconds of silence.

Encrypted submissions are decrypted with your **personal password**
(not a topic password). Pass it in `passwords=` (a bare string), or per call:

```python
client = Client(api_token="USER_API_TOKEN", passwords="your-personal-password")
# or: client.submissions(password="your-personal-password")
```

## Streaming events

```python
import asyncio
from simplepush import Client

async def main():
    client = Client(api_token="USER_API_TOKEN")
    async for event in client.events():
        print(event.event_type, event.data)

asyncio.run(main())
```

Every stream on a client shares one WebSocket. Call `await client.aclose()` when
you are done collecting; sends on their own never open it.

## End-to-end encryption

Pass `password=` to encrypt a send's body fields. The returned handle decrypts
the recipient's replies/inputs under the same password.

```python
from simplepush import Client, ReplyMode

# Per-send password (`reply=` so there is a composer to collect from):
client = Client(api_token="USER_API_TOKEN")
group = client.send_task(topic="mytopic", title="Secret", content="🤫",
                         password="hunter2", reply=ReplyMode.STICKY)

# Or configure a topic's password on the client; sends to it omit `password=`,
# and a per-send password still overrides. The pair's topic must match the
# topic you send to — otherwise nothing matches and the send goes plaintext:
client = Client(api_token="USER_API_TOKEN", passwords=[("hunter2", "mytopic")])
client.send_task(topic="mytopic", content="🤫")              # encrypted with "hunter2"
client.send_task(topic="mytopic", content="!", password="x") # overridden for this send

async for reply in group.sole.replies():
    print(reply.body)   # decrypted
```

To decrypt the raw `events()` feed across many passwords, build a keyring from
the client's configured `(password, topic)` pairs (it also grows with every
send) and apply it per event:

```python
from simplepush import try_decrypt_event_data

client = Client(api_token="USER_API_TOKEN", passwords=[("hunter2", "mytopic"), ("other", "alerts")])
ring = client.keyring()
async for event in client.events():
    data = try_decrypt_event_data(event, ring)   # decrypted dict, or None if no key matches
```

## Organizations

`OrgClient` authenticates with the org `api_key` and addresses sends with
exactly one target: `topic=`, `member=` (by member name), or `broadcast=True`.
Encryption is automatic: pass the org's master key(s) (from your org's
encryption vault; the library can't derive them) and every send is encrypted
under the current key — there are no per-send passwords. Without keys, sends
go out in the clear and org ciphertext is passed through undecrypted.

```python
from simplepush import OrgClient, ChoiceInput

org = OrgClient(
    api_key="ORG_API_KEY",
    master_key=MASTER_KEY,   # 32 bytes (raw or base64)
    master_key_version=3,    # or several: master_keys={3: key3, 2: key2}
)

group = org.send_task(
    broadcast=True,
    title="All hands?",
    inputs=[ChoiceInput(options=["yes", "no"])],
)
async for ev in group.inputs():
    print(ev.recipient.name, ev.item)   # recipient = the org member
```

Everything else works as on a personal `Client`: independent-mode groups (the
member name rides on each instance's `recipient`), subtasks, streams,
submissions, downloads.

## Old app

The old Simplepush app receives messages through the legacy API, addressed by
its device key. `simplepush.legacy` sends to it:

```python
from simplepush import legacy

legacy.send(key="HuxgBB", title="Garage", message="The door is open.")
```

With `password` and `salt`, title, message and attachments are encrypted for
the old app. That needs the `legacy` extra:

```bash
pip install "simplepush[legacy]"
```

Failures raise `legacy.BadRequest` (title or message too long) or
`legacy.UnknownError`.

## License

MIT
