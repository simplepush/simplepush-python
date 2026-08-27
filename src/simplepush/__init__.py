from .api import (
    Client, OrgClient, ApiError, CancelReason, ReplyMode, ContentFormat, ActionStyle,
    NotificationInput, NotificationTextInput, NotificationChoiceInput, NotificationActionInput,
    TextInput, ChoiceInput, Action, ActionsInput, SliderInput, PhotoInput, VoiceRecordingInput, LocationInput, FileUploadInput,
)
from .client import (
    Event, Task, TaskGroup, TaskGroupRecipient, GroupReply, GroupInput, Subtask, Notification, NotificationGroup, NotificationGroupRecipient, GroupNotification, Reply, InputEvent,
    TaskCompleted, SubtaskCompleted, NotificationCompleted, TaskDeleted, RawEvents,
    TaskCanceled, SubtaskCanceled, GroupCancelResult,
    TaskDeclined, TaskDeclinedByRecipient, SubtaskDeclined, SubtaskDeclinedByRecipient,
    TaskExpired,
    NotificationReply, NotificationTextReply, NotificationChoiceReply, NotificationActionReply,
    TextBody, ReplyFile, ReplyAudio, Location,
    TextUpload, ChoiceUpload, MultiChoiceUpload, ActionUpload, SliderUpload, PhotoUpload, VoiceUpload, FileUpload, LocationUpload,
    Submission, SubmissionFile, SubmissionAudio, Submissions,
    StreamError, DownloadError,
)

__all__ = [
    "Client", "OrgClient", "ApiError", "StreamError", "DownloadError", "CancelReason", "ReplyMode", "ContentFormat", "ActionStyle",
    "Event", "Task", "TaskGroup", "TaskGroupRecipient", "GroupReply", "GroupInput", "Subtask", "Notification", "NotificationGroup", "NotificationGroupRecipient", "GroupNotification", "Reply", "InputEvent",
    "TaskCompleted", "SubtaskCompleted", "NotificationCompleted", "TaskDeleted", "RawEvents",
    "TaskCanceled", "SubtaskCanceled", "GroupCancelResult",
    "TaskDeclined", "TaskDeclinedByRecipient", "SubtaskDeclined", "SubtaskDeclinedByRecipient",
    "TaskExpired",
    "NotificationReply", "NotificationTextReply", "NotificationChoiceReply", "NotificationActionReply",
    "TextBody", "ReplyFile", "ReplyAudio", "Location",
    "TextUpload", "ChoiceUpload", "MultiChoiceUpload", "ActionUpload", "SliderUpload", "PhotoUpload", "VoiceUpload", "FileUpload", "LocationUpload",
    "Submission", "SubmissionFile", "SubmissionAudio", "Submissions",
    "NotificationInput", "NotificationTextInput", "NotificationChoiceInput", "NotificationActionInput",
    "TextInput", "ChoiceInput", "Action", "ActionsInput", "SliderInput", "PhotoInput",
    "VoiceRecordingInput", "LocationInput", "FileUploadInput",
]

from ._extras import CRYPTO_HINT, MissingCryptoExtra

# The end-to-end encryption API rides on the optional `crypto` extra (pynacl).
_CRYPTO_NAMES = (
    "Decryptor", "OrgDecryptor", "Keyring", "DerivedKey",
    "derive_key", "encrypt", "decrypt", "key_fingerprint",
    "try_decrypt_event_data", "DecryptedWire",
    "decrypt_task_payload", "decrypt_task_summary", "decrypt_submission", "decrypt_event",
)

try:
    from .crypto import (
        Decryptor, OrgDecryptor, Keyring, DerivedKey,
        derive_key, encrypt, decrypt, key_fingerprint,
    )
    from .decrypt import (
        try_decrypt_event_data, DecryptedWire,
        decrypt_task_payload, decrypt_task_summary, decrypt_submission, decrypt_event,
    )
    # Literal list (not `list(_CRYPTO_NAMES)`) so static checkers can follow
    # the export list; keep it in sync with _CRYPTO_NAMES above.
    __all__ += [
        "Decryptor", "OrgDecryptor", "Keyring", "DerivedKey",
        "derive_key", "encrypt", "decrypt", "key_fingerprint",
        "try_decrypt_event_data", "DecryptedWire",
        "decrypt_task_payload", "decrypt_task_summary", "decrypt_submission", "decrypt_event",
    ]
except MissingCryptoExtra:
    # pynacl is absent: keep the crypto names out of the namespace (and out of
    # `__all__`, so `import *` stays clean), but make reaching for one say why
    # rather than raising a bare AttributeError. Note this catches only
    # MissingCryptoExtra — a genuine ImportError from inside crypto.py or
    # decrypt.py propagates instead of being silently swallowed into a
    # confusing "module has no attribute" further downstream.
    def __getattr__(name: str):
        if name in _CRYPTO_NAMES:
            raise MissingCryptoExtra(f"simplepush.{name} {CRYPTO_HINT}")
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
