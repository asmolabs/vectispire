import pytest

from zanshin.services.encryption_service import (
    ENCRYPTION_KEY_ENV_VAR,
    LEGACY_DEFAULT_KEY,
    EncryptionService,
    MissingEncryptionKeyError,
)

# `encryption_service` (an instance with an explicit test key) comes from
# tests/conftest.py.


def test_encrypt_then_decrypt_round_trip(encryption_service):
    plaintext = "-----BEGIN RSA PRIVATE KEY-----\nfake-key-content\n-----END-----"

    encrypted = encryption_service.encrypt(plaintext)

    assert encrypted != plaintext
    assert encryption_service.decrypt(encrypted) == plaintext


def test_encrypt_empty_string_is_passthrough(encryption_service):
    assert encryption_service.encrypt("") == ""
    assert encryption_service.decrypt("") == ""


def test_encrypt_output_is_not_deterministic(encryption_service):
    """A random IV is prepended each time, so encrypting the same plaintext
    twice must not produce the same ciphertext (otherwise the IV isn't
    actually random and the scheme is weaker than intended)."""
    a = encryption_service.encrypt("same-secret")
    b = encryption_service.encrypt("same-secret")
    assert a != b
    assert encryption_service.decrypt(a) == "same-secret"
    assert encryption_service.decrypt(b) == "same-secret"


def test_decrypt_tampered_ciphertext_raises(encryption_service):
    encrypted = encryption_service.encrypt("top-secret")
    tampered = encrypted[:-4] + ("AAAA" if not encrypted.endswith("AAAA") else "BBBB")
    with pytest.raises(RuntimeError):
        encryption_service.decrypt(tampered)


def test_decrypt_with_a_different_key_raises(encryption_service):
    """Not just "no crash": a wrong key must not yield plaintext. Guards the
    multi-key decryption path — trying several candidate keys must not turn
    into accepting anything."""
    encrypted = encryption_service.encrypt("top-secret")

    other = EncryptionService(key="a-completely-different-32byte-ke")

    with pytest.raises(RuntimeError):
        other.decrypt(encrypted)


def test_encrypt_refuses_to_run_without_a_configured_key(monkeypatch):
    """Fail closed: with no ENCRYPTION_KEY, the service must not silently fall
    back to the well-known default key published in this repository — that
    would leave stored SSH private keys readable by anyone holding a copy of
    the database file."""
    monkeypatch.delenv(ENCRYPTION_KEY_ENV_VAR, raising=False)

    svc = EncryptionService()

    assert svc.is_configured() is False
    with pytest.raises(MissingEncryptionKeyError):
        svc.encrypt("a new secret")


def test_key_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "env-provided-key-of-32-bytes!!!!")

    svc = EncryptionService()

    assert svc.is_configured() is True
    assert svc.decrypt(svc.encrypt("secret")) == "secret"


def test_data_encrypted_with_the_legacy_default_key_still_decrypts(monkeypatch):
    """Enabling a real key on an existing deployment must not strand rows that
    were encrypted with the old default — decryption falls back to it."""
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, LEGACY_DEFAULT_KEY)
    legacy_ciphertext = EncryptionService().encrypt("historical secret")

    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "brand-new-rotated-key-32-bytes!!")
    rotated = EncryptionService()

    assert rotated.decrypt(legacy_ciphertext) == "historical secret"
    # ...and new values are written under the new key, not the legacy one.
    fresh = rotated.encrypt("new secret")
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, LEGACY_DEFAULT_KEY)
    with pytest.raises(RuntimeError):
        EncryptionService().decrypt(fresh)
