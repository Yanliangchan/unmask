"""Application-level encryption for sensitive fields.

Values are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before they reach
Postgres, so a database dump alone never exposes emails, phone numbers or
breach data. Because ciphertext is non-deterministic, lookups use a separate
HMAC "blind index" (``digest``) computed with its own key.

Keys are read from the environment of the *application* service only; they
must never be configured on the database service.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import unicodedata
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.config import get_settings

_PREFIX = "enc:v1:"


class CryptoNotConfigured(RuntimeError):
    pass


class _Cipher:
    def __init__(self) -> None:
        self._fernet: MultiFernet | None = None
        self._index_key: bytes | None = None

    def configure(self, data_keys: str, index_key: str) -> None:
        keys = [k.strip() for k in data_keys.split(",") if k.strip()]
        if not keys or not index_key:
            raise CryptoNotConfigured("UNMASK_DATA_KEYS and UNMASK_INDEX_KEY are required")
        self._fernet = MultiFernet([Fernet(k.encode()) for k in keys])
        self._index_key = index_key.encode()

    def _ensure(self) -> None:
        if self._fernet is None:
            s = get_settings()
            self.configure(s.data_keys, s.index_key)

    def encrypt(self, plaintext: str) -> str:
        self._ensure()
        assert self._fernet is not None
        return _PREFIX + self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        self._ensure()
        assert self._fernet is not None
        if not token.startswith(_PREFIX):
            raise InvalidToken("value is not an unmask ciphertext")
        return self._fernet.decrypt(token[len(_PREFIX) :].encode()).decode()

    def rotate(self, token: str) -> str:
        """Re-encrypt a value under the current primary key."""
        self._ensure()
        assert self._fernet is not None
        return _PREFIX + self._fernet.rotate(token[len(_PREFIX) :].encode()).decode()

    def digest(self, kind: str, value: str) -> str:
        self._ensure()
        assert self._index_key is not None
        msg = f"{kind}\x00{normalize(value)}".encode()
        return hmac.new(self._index_key, msg, hashlib.sha256).hexdigest()


cipher = _Cipher()


def normalize(value: str) -> str:
    """Canonical form used for blind indexing and duplicate detection."""
    return unicodedata.normalize("NFKC", value).strip().casefold()


def encrypt(value: str) -> str:
    return cipher.encrypt(value)


def decrypt(value: str) -> str:
    return cipher.decrypt(value)


def digest(kind: str, value: str) -> str:
    return cipher.digest(kind, value)


def encrypt_json(data: Any) -> dict:
    return {"_enc": cipher.encrypt(json.dumps(data, separators=(",", ":"), default=str))}


def decrypt_json(stored: Any) -> Any:
    if isinstance(stored, dict) and set(stored) == {"_enc"}:
        return json.loads(cipher.decrypt(stored["_enc"]))
    return stored


def generate_key() -> str:
    return Fernet.generate_key().decode()
