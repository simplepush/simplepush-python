"""Best-effort decryption of an event's ``data`` payload via a `Keyring`.

Mirrors the TS SDK's ``tryDecryptEventData``: for an encrypted event, resolve the
key from its marker and recursively decrypt every base64 string in ``data`` that
looks like spush ciphertext. Cheap heuristic — spush ciphertext is base64 of
>=28 bytes, so the encoded form is >=40 base64 chars. Use it to decrypt the raw
``Client.events()`` feed across many candidate passwords:

    ring = client.keyring()
    async for event in client.events():
        data = try_decrypt_event_data(event, ring)   # decrypted dict, or None
"""

import copy
import re

from .crypto import decrypt

_CIPHERTEXT_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def looks_like_ciphertext(s: str) -> bool:
    return 40 <= len(s) <= 8192 and bool(_CIPHERTEXT_RE.match(s))


def try_decrypt_event_data(event, keyring) -> dict | None:
    """Return a decrypted copy of ``event.data``, or None when the event isn't
    encrypted or no held key matches its marker. Ciphertext that fails to decrypt
    is left in place."""
    marker = event.raw.get("encryption")
    if not marker:
        return None
    key = keyring.key_for_marker(marker)
    if key is None:
        return None
    # event.data is always a dict, so inline its branch of _decrypt_in_place
    # (which would just run this same comprehension) to keep the return a dict.
    data = copy.deepcopy(event.data)
    return {k: _decrypt_in_place(v, key) for k, v in data.items()}


def _decrypt_in_place(value, key: bytes):
    if isinstance(value, str):
        if looks_like_ciphertext(value):
            try:
                return decrypt(value, key)
            except Exception:
                return value  # leave ciphertext in place
        return value
    if isinstance(value, list):
        return [_decrypt_in_place(v, key) for v in value]
    if isinstance(value, dict):
        return {k: _decrypt_in_place(v, key) for k, v in value.items()}
    return value
