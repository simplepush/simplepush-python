"""Optional-dependency plumbing for the `crypto` extra.

End-to-end encryption needs libsodium via `pynacl`, which the base install
deliberately leaves out (see the dependency comment in pyproject.toml) so
plaintext/HTTP-only callers take on no C extension. This module holds the marker
error for "the crypto extra is missing", so `crypto.py` (raising at import) and
`__init__.py` (raising on attribute access) report the same actionable thing.

It must never import nacl itself — that is the whole point.
"""

CRYPTO_HINT = "requires the optional crypto extra: pip install 'simplepush[crypto]'"


class MissingCryptoExtra(ImportError):
    """Raised when the crypto API is reached without `pynacl` installed.

    Subclasses `ImportError` so the internal `except ImportError` degradation
    paths keep working (`submissions()` passes ciphertext through rather than
    failing), and so `from simplepush import derive_key` surfaces the hint
    verbatim instead of Python's generic "cannot import name". The trade-off is
    that `hasattr(simplepush, "derive_key")` raises rather than returning False;
    feature-detect with `try: ... except ImportError:` instead.
    """

    def __init__(self, message: str = f"end-to-end encryption {CRYPTO_HINT}"):
        super().__init__(message)
