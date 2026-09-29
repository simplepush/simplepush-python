"""Send to the old Simplepush app with a device key.

The old app receives messages through the legacy API, addressed by the device
key it shows. The new app does not: it uses `Client`. Encryption uses the old
app's scheme (AES-CBC with a key from password and salt) and needs the
`legacy` extra (`pip install simplepush[legacy]`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import urllib.error
import urllib.request

LEGACY_URL = "https://api-legacy.simplepu.sh"

# Seconds a request may take before it fails.
_TIMEOUT = 5

# Salt of the old app's first encryption version, used when none is given.
_DEFAULT_SALT = "1789F0B8C4A051E5"


class BadRequest(Exception):
    """Raised when the title or message is too long."""


class UnknownError(Exception):
    """Raised when the message could not be sent."""


def send(
    key: str,
    message: str,
    title: str | None = None,
    password: str | None = None,
    salt: str | None = None,
    attachments: list[str | dict[str, str]] | None = None,
    event: str | None = None,
) -> None:
    """Send a message to the old app's device `key`.

    With `password` and `salt`, title, message and attachments are encrypted
    for the old app. An attachment is a URL, or a dict with a `video` URL and
    its `thumbnail` URL. `event` names the old app's event and is not
    encrypted.
    """
    if not key or not message:
        raise ValueError("Key and message argument must be set")
    if password and not salt:
        raise ValueError("Salt is missing")
    if salt and not password:
        raise ValueError("Password is missing")
    if attachments is not None and not isinstance(attachments, list):
        raise ValueError("Attachments malformed")

    payload = _payload(key, message, title, password, salt, attachments, event)
    request = urllib.request.Request(
        f"{LEGACY_URL}/send",
        data=json.dumps(payload).encode("utf-8"),
        # Cloudflare refuses urllib's default agent where the legacy API runs behind it.
        headers={"Content-Type": "application/json", "User-Agent": "simplepush-python"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            body = response.read()
    except urllib.error.HTTPError as err:
        body = err.read()
    except OSError as err:
        raise UnknownError(f"Failed to reach the legacy API: {err}") from err

    try:
        result = json.loads(body)
    except ValueError as err:
        raise UnknownError("The legacy API sent an invalid response") from err
    if result.get("status") == "BadRequest" and result.get("message") == "Title or message too long":
        raise BadRequest
    if result.get("status") != "OK":
        raise UnknownError(result.get("message") or result.get("status"))


def _payload(
    key: str,
    message: str,
    title: str | None,
    password: str | None,
    salt: str | None,
    attachments: list[str | dict[str, str]] | None,
    event: str | None,
) -> dict:
    """The legacy API's request body, encrypted when a password is given."""
    payload: dict = {"key": key}
    if not password:
        payload["msg"] = message
        if title:
            payload["title"] = title
        if event:
            payload["event"] = event
        if attachments:
            payload["attachments"] = attachments
        return payload

    encryption_key = _encryption_key(password, salt)
    iv = os.urandom(16)
    payload.update({"encrypted": "true", "iv": iv.hex().upper()})
    if title:
        payload["title"] = _encrypt(encryption_key, iv, title)
    if event:
        payload["event"] = event
    payload["msg"] = _encrypt(encryption_key, iv, message)
    if attachments:
        encrypted: list[str | dict[str, str]] = []
        for attachment in attachments:
            if isinstance(attachment, dict) and "thumbnail" in attachment and "video" in attachment:
                encrypted.append(
                    {
                        "thumbnail": _encrypt(encryption_key, iv, attachment["thumbnail"]),
                        "video": _encrypt(encryption_key, iv, attachment["video"]),
                    }
                )
            elif isinstance(attachment, str):
                encrypted.append(_encrypt(encryption_key, iv, attachment))
        payload["attachments"] = encrypted
    return payload


def _encryption_key(password: str, salt: str | None) -> bytes:
    """The old app's AES key: the first 16 bytes of SHA-1 of password and salt."""
    salted = password + (salt or _DEFAULT_SALT)
    return bytes.fromhex(hashlib.sha1(salted.encode("utf-8")).hexdigest()[:32])


def _encrypt(encryption_key: bytes, iv: bytes, data: str) -> str:
    """AES-CBC with PKCS#7 padding, URL-safe base64 like the old app expects."""
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as err:
        raise ImportError(
            "Encrypted messages to the old app need the legacy extra: "
            "pip install simplepush[legacy]"
        ) from err

    padder = padding.PKCS7(128).padder()  # AES blocks are 128 bits
    padded = padder.update(data.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    return base64.urlsafe_b64encode(encryptor.update(padded) + encryptor.finalize()).decode("ascii")
