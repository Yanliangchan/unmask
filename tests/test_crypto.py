import pytest
from cryptography.fernet import Fernet, InvalidToken

from app import crypto


def test_roundtrip_and_ciphertext_is_opaque():
    token = crypto.encrypt("someone@example.com")
    assert token.startswith("enc:v1:")
    assert "someone" not in token
    assert crypto.decrypt(token) == "someone@example.com"


def test_encryption_is_non_deterministic_but_digest_is_stable():
    assert crypto.encrypt("x") != crypto.encrypt("x")
    assert crypto.digest("email", "A@Example.com ") == crypto.digest("email", "a@example.com")
    assert crypto.digest("email", "a@example.com") != crypto.digest("username", "a@example.com")


def test_json_roundtrip():
    data = {"breach": ["LinkedIn 2012"], "hash": "abc"}
    stored = crypto.encrypt_json(data)
    assert set(stored) == {"_enc"}
    assert "LinkedIn" not in stored["_enc"]
    assert crypto.decrypt_json(stored) == data


def test_key_rotation_keeps_old_ciphertext_readable():
    old_key, new_key = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    c = crypto._Cipher()
    c.configure(old_key, "idx")
    token = c.encrypt("secret")
    c.configure(f"{new_key},{old_key}", "idx")
    assert c.decrypt(token) == "secret"
    rotated = c.rotate(token)
    c.configure(new_key, "idx")
    assert c.decrypt(rotated) == "secret"
    with pytest.raises(InvalidToken):
        c.decrypt(token)


def test_unconfigured_cipher_refuses():
    c = crypto._Cipher()
    with pytest.raises(crypto.CryptoNotConfigured):
        c.configure("", "")
