"""
End-to-end encryption for SimplePush (personal / topic-based).

Mirrors `ts-library/src/crypto.ts`, the CLI, and the app, using libsodium
(PyNaCl) so the wire format is interoperable:

    derive:  sha256(salt)[:16] --Argon2id(password)--> master(64B)   (t=3, m=64 MiB)
                                       |
                                       +-- HKDF-SHA256 expand, info="symmetric-key" --> key(32B)

    cipher:  XChaCha20-Poly1305 (IETF), 24-byte nonce
    wire:    base64( nonce(24) || ciphertext || Poly1305 tag(16) )
    fingerprint: base64( sha256(symmetric_key)[:8] )

`salt` is the topic value (the user-typed topic name), so external senders can
derive the key from public info alone (topic name + password) without a backend
lookup. Topic encryption is shared-password: everyone who knows the topic name
and password derives the same key and can read each other's content. See E2EE.md.

Requires the crypto extra: pip install 'simplepush[crypto]'
"""

import base64
import hashlib
import hmac
from dataclasses import dataclass

from ._extras import MissingCryptoExtra

# pynacl is the `crypto` extra, absent from a base install. Fail here with the
# install hint rather than letting a bare "No module named 'nacl'" escape from
# whichever call site touched encryption first.
try:
    import nacl.bindings as _sodium
except ImportError as exc:  # pragma: no cover - depends on install extras
    raise MissingCryptoExtra() from exc

# Argon2id parameters (must match ts-library / CLI / app).
_ARGON2_MEMORY_BYTES = 64 * 1024 * 1024   # 64 MiB
_ARGON2_ITERATIONS = 3
_ARGON2_OUTPUT_LEN = 64                    # 64-byte master secret
_HKDF_INFO = b"symmetric-key"
_SYMMETRIC_KEY_LEN = 32
_NONCE_BYTES = _sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES   # 24
_TAG_BYTES = _sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES        # 16
_FINGERPRINT_BYTES = 8


def key_fingerprint(symmetric_key: bytes) -> str:
    """base64(sha256(symmetric_key)[:8]) — identifies a derived key on the wire."""
    return base64.b64encode(
        hashlib.sha256(symmetric_key).digest()[:_FINGERPRINT_BYTES]
    ).decode("ascii")


@dataclass(frozen=True)
class DerivedKey:
    """A symmetric key derived from (password, salt), with its fingerprint."""
    symmetric_key: bytes  # 32-byte XChaCha20-Poly1305 key
    fingerprint: str      # base64(sha256(symmetric_key)[:8])


def _hkdf_sha256_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # RFC 5869 expand, single block (length <= 32): T(1) = HMAC-SHA256(PRK, info || 0x01).
    if not 1 <= length <= 32:
        raise ValueError("length must be 1..32")
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def derive_key(password: str, salt: str) -> DerivedKey:
    """Derive the topic/personal symmetric key. `salt` is the topic value.

    Steps (identical to the reference clients):
      1. sha256(salt)[:16]  as the Argon2id salt
      2. Argon2id(password) -> 64-byte master  (t=3, m=64 MiB, p=1, v1.3)
      3. HKDF-SHA256 expand(master, "symmetric-key") -> 32-byte key
    """
    salt32 = hashlib.sha256(salt.encode("utf-8")).digest()
    master = _sodium.crypto_pwhash_alg(
        _ARGON2_OUTPUT_LEN,
        password.encode("utf-8"),
        salt32[: _sodium.crypto_pwhash_SALTBYTES],   # 16 bytes
        _ARGON2_ITERATIONS,
        _ARGON2_MEMORY_BYTES,
        _sodium.crypto_pwhash_ALG_ARGON2ID13,
    )
    symmetric_key = _hkdf_sha256_expand(master, _HKDF_INFO, _SYMMETRIC_KEY_LEN)
    return DerivedKey(symmetric_key=symmetric_key, fingerprint=key_fingerprint(symmetric_key))


def encrypt(plaintext: str, key: bytes) -> str:
    """Encrypt with XChaCha20-Poly1305. Wire: base64(24-byte nonce || ciphertext || tag)."""
    nonce = _sodium.randombytes(_NONCE_BYTES)
    ct = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext.encode("utf-8"), None, nonce, key
    )
    return base64.b64encode(nonce + ct).decode("ascii")


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt raw bytes to a `nonce(24) || ciphertext || tag(16)` blob (no base64).

    This is the on-S3 format for encrypted file uploads — the inverse of
    `decrypt_bytes`. Local attachments are encrypted with this before upload, so
    the server (and CDN) only ever see ciphertext; the receiver downloads the
    blob and runs `decrypt_bytes` with the same per-topic / org key."""
    nonce = _sodium.randombytes(_NONCE_BYTES)
    ct = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)
    return nonce + ct


def decrypt(ciphertext_b64: str, key: bytes) -> str:
    """Decrypt base64(24-byte nonce || ciphertext || tag). Raises ValueError on failure."""
    return decrypt_bytes(base64.b64decode(ciphertext_b64), key).decode("utf-8")


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    """Decrypt a raw `nonce(24) || ciphertext || tag(16)` blob (no base64).

    This is the format file uploads are stored in on S3: the uploading device
    AEAD-encrypts the whole file and uploads the binary blob as-is, so a
    downloaded encrypted file decrypts with exactly this. Raises ValueError on
    failure."""
    if len(blob) < _NONCE_BYTES + _TAG_BYTES:
        raise ValueError("Ciphertext too short")
    nonce, body = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        return _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(body, None, nonce, key)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e


class Decryptor:
    """Fingerprint-gated decryptor wrapping a single derived key.

    Build it from the topic key you already derived for sending (the same key
    decrypts topic replies/inputs, since topic encryption is shared-password):

        dec = Decryptor(derive_key("secret", "alerts"))
        # or:
        dec = Decryptor.from_password("secret", "alerts")
        plaintext = dec.try_decrypt(ciphertext_b64, fingerprint)
    """

    def __init__(self, key: DerivedKey):
        self._dk = key

    @classmethod
    def from_password(cls, password: str, salt: str) -> "Decryptor":
        return cls(derive_key(password, salt))

    def try_decrypt(self, ciphertext_b64: str, fingerprint: str | None) -> str | None:
        """Decrypt if the fingerprint matches; else None. Raises ValueError if the
        fingerprint matches but decryption fails."""
        if fingerprint is None or fingerprint != self._dk.fingerprint:
            return None
        return decrypt(ciphertext_b64, self._dk.symmetric_key)

    def try_decrypt_marker(self, ciphertext_b64: str, marker) -> str | None:
        """Decrypt a personal-mode marker ``{type: "personal", keyFingerprint}``
        when its fingerprint matches this key; else None. Ignores org markers."""
        if not isinstance(marker, dict) or marker.get("type") != "personal":
            return None
        return self.try_decrypt(ciphertext_b64, marker.get("keyFingerprint"))

    def key_for_marker(self, marker) -> bytes | None:
        """The raw symmetric key when a personal marker's fingerprint matches this
        key; else None. (Same shape as `Keyring.key_for_marker` — used for binary
        payloads like file downloads, where the marker-gated string helpers don't
        apply.)"""
        if not isinstance(marker, dict) or marker.get("type") != "personal":
            return None
        if marker.get("keyFingerprint") != self._dk.fingerprint:
            return None
        return self._dk.symmetric_key

    @property
    def fingerprint(self) -> str:
        return self._dk.fingerprint

    def has_fingerprint(self, fingerprint: str | None) -> bool:
        return fingerprint is not None and fingerprint == self._dk.fingerprint


def _coerce_key(key: bytes | str) -> bytes:
    """Accept a 32-byte symmetric key as raw bytes or base64, return raw bytes."""
    raw = bytes(key) if isinstance(key, (bytes, bytearray)) else base64.b64decode(key)
    if len(raw) != _SYMMETRIC_KEY_LEN:
        raise ValueError(f"master key must be {_SYMMETRIC_KEY_LEN} bytes, got {len(raw)}")
    return raw


class OrgDecryptor:
    """Decrypts org-mode content using the org's versioned ``master_key`` set.

    Org content carries a ``{type: "org", v}`` marker; this looks ``v`` up in the
    supplied key set. The keys are obtained out-of-band from the org's encryption
    vault (the SDK cannot derive them) and passed in as version -> 32-byte key
    (raw bytes or base64):

        dec = OrgDecryptor({3: master_key_v3_b64})
    """

    def __init__(self, master_keys: dict[int, bytes | str]):
        if not master_keys:
            raise ValueError("master_keys must not be empty")
        self._keys: dict[int, bytes] = {int(v): _coerce_key(k) for v, k in master_keys.items()}

    def try_decrypt_marker(self, ciphertext_b64: str, marker) -> str | None:
        """Decrypt an org marker ``{type: "org", v}`` with the key for version ``v``;
        None if not an org marker or the version isn't held."""
        key = self.key_for_marker(marker)
        if key is None:
            return None
        return decrypt(ciphertext_b64, key)

    def key_for_marker(self, marker) -> bytes | None:
        """The raw master key an org marker ``{type: "org", v}`` resolves to, or
        None. (Same shape as `Keyring.key_for_marker`.)"""
        if not isinstance(marker, dict) or marker.get("type") != "org":
            return None
        return self._keys.get(marker.get("v"))

    @property
    def current_version(self) -> int:
        """The highest-numbered version held — used to encrypt new content."""
        return max(self._keys)

    def key_for_version(self, version: int) -> bytes | None:
        return self._keys.get(version)


class Keyring:
    """A fingerprint-indexed set of candidate keys, for decrypting a feed of
    events whose markers could be under any of several passwords/topics (or org
    versions) — e.g. the raw ``Client.events()`` stream. Unlike `Decryptor` (one
    key) it resolves the key per event by its marker:

        ring = Keyring.build(passwords=["secret"], topics=["alerts", "deploys"])
        plaintext = ring.try_decrypt_marker(ciphertext_b64, marker)

    Personal markers (``{type: "personal", keyFingerprint}``) resolve by
    fingerprint over ``passwords × topics``; org markers (``{type: "org", v}``)
    by version. It implements ``try_decrypt_marker`` so it is a drop-in wherever a
    decryptor is expected. Keys can be folded in after construction with `add`
    (cheap — no derivation), letting a client grow the ring as sends happen."""

    def __init__(self):
        self._by_fingerprint: dict[str, bytes] = {}
        self._by_version: dict[int, bytes] = {}

    @classmethod
    def build(cls, *, passwords=(), topics=(), password_salt: str | None = None,
              org_master_keys: "dict[int, bytes | str] | None" = None) -> "Keyring":
        ring = cls()
        for version, key in (org_master_keys or {}).items():
            ring._by_version[int(version)] = _coerce_key(key)
        for password in passwords:
            salts = list(topics)
            if password_salt:
                salts.append(password_salt)
            for salt in salts:
                ring.add(derive_key(password, salt))
        return ring

    def add(self, key: DerivedKey) -> None:
        """Fold in an already-derived key (e.g. a per-send key), matched by its
        fingerprint. No Argon2 — the key is already derived."""
        self._by_fingerprint[key.fingerprint] = key.symmetric_key

    def add_org(self, version: int, key: "bytes | str") -> None:
        self._by_version[int(version)] = _coerce_key(key)

    def key_for_marker(self, marker) -> bytes | None:
        """The raw symmetric key for an encryption marker, or None. Personal
        markers match a derived key by fingerprint; org markers a key by version."""
        if not isinstance(marker, dict):
            return None
        if marker.get("type") == "personal":
            return self._by_fingerprint.get(marker.get("keyFingerprint"))
        if marker.get("type") == "org":
            return self._by_version.get(marker.get("v"))
        return None

    def try_decrypt_marker(self, ciphertext_b64: str, marker) -> str | None:
        """Decrypt ``ciphertext_b64`` with the key the marker resolves to; None if
        no key matches. (Same shape as `Decryptor`/`OrgDecryptor`, so a `Keyring`
        can be passed wherever a decryptor is.)"""
        key = self.key_for_marker(marker)
        if key is None:
            return None
        return decrypt(ciphertext_b64, key)

    @property
    def size(self) -> int:
        return len(self._by_fingerprint)

    @property
    def org_key_count(self) -> int:
        return len(self._by_version)
