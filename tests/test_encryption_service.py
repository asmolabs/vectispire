"""Tests for encryption at rest.

The case that shapes this file is the first one: the application used to carry, in its
own source, the key that unlocked its own database. A previous change stopped
*encrypting* with it and left it usable for decryption "so existing rows aren't
stranded" — which meant a copy of the database file plus a copy of this public
repository was still enough to read every stored SSH private key. That is closed here,
and `test_the_published_default_key_no_longer_decrypts_anything` is the test that would
fail if it ever came back.

The rest covers what replaces the compatibility argument: an explicit list of previous
keys, so rotation is possible at all, and a reported state so a secret that has not
been rotated is visible instead of merely logged.
"""
import pytest

from zanshin.services.encryption_service import (
    ENCRYPTION_KEY_ENV_VAR,
    PREVIOUS_KEYS_ENV_VAR,
    EncryptionService,
    MissingEncryptionKeyError,
    SecretState,
    UndecryptableSecretError,
)

# `encryption_service` (an instance with an explicit test key) comes from
# tests/conftest.py.

# The key an earlier implementation used when none was configured. Written here rather
# than imported, because the point of this file is that the application no longer knows
# it.
PUBLISHED_DEFAULT_KEY = "my-secret-encryption-key-32bytes"


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
    """Fail closed: with no ENCRYPTION_KEY, the service must not write a secret it
    cannot protect."""
    monkeypatch.delenv(ENCRYPTION_KEY_ENV_VAR, raising=False)

    svc = EncryptionService()

    assert svc.is_configured() is False
    with pytest.raises(MissingEncryptionKeyError):
        svc.encrypt("a new secret")


def test_key_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "env-provided-key-of-32-bytes!!!!")
    monkeypatch.delenv(PREVIOUS_KEYS_ENV_VAR, raising=False)

    svc = EncryptionService()

    assert svc.is_configured() is True
    assert svc.decrypt(svc.encrypt("secret")) == "secret"


# --- The published default key -------------------------------------------------

def test_the_published_default_key_no_longer_decrypts_anything(monkeypatch):
    """The whole point of this change.

    A database file plus a clone of this repository used to be enough to read every
    stored SSH private key, because the fallback key was a constant in the source. If
    this test starts failing, that is back.
    """
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, PUBLISHED_DEFAULT_KEY)
    historical = EncryptionService(previous_keys=[]).encrypt("historical secret")

    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "brand-new-rotated-key-32-bytes!!")
    monkeypatch.delenv(PREVIOUS_KEYS_ENV_VAR, raising=False)

    with pytest.raises(UndecryptableSecretError):
        EncryptionService().decrypt(historical)


def test_the_module_holds_no_key_material():
    """Not just unused: absent. A constant left behind "for reference" is one import
    away from being a fallback again, and it is still a published key in the meantime."""
    from zanshin.services import encryption_service

    literals = [value for value in vars(encryption_service).values() if isinstance(value, str)]

    assert PUBLISHED_DEFAULT_KEY not in literals
    assert not hasattr(encryption_service, "LEGACY_DEFAULT_KEY")


# --- Rotation ------------------------------------------------------------------

def test_a_previous_key_reads_values_it_encrypted(monkeypatch):
    """What replaces the built-in fallback: the operator supplies the old key, so
    reading a legacy secret is a deliberate act rather than the default."""
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "the-old-key-of-exactly-32-bytes!!")
    old_ciphertext = EncryptionService(previous_keys=[]).encrypt("historical secret")

    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "brand-new-rotated-key-32-bytes!!")
    monkeypatch.setenv(PREVIOUS_KEYS_ENV_VAR, "the-old-key-of-exactly-32-bytes!!")
    rotated = EncryptionService()

    assert rotated.decrypt(old_ciphertext) == "historical secret"


def test_new_values_are_written_under_the_current_key_only(monkeypatch):
    """A previous key must not come back as an encryption key: rotation has to
    converge, and it only converges if writes stop using the old one."""
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "brand-new-rotated-key-32-bytes!!")
    monkeypatch.setenv(PREVIOUS_KEYS_ENV_VAR, "the-old-key-of-exactly-32-bytes!!")
    fresh = EncryptionService().encrypt("new secret")

    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "the-old-key-of-exactly-32-bytes!!")
    monkeypatch.delenv(PREVIOUS_KEYS_ENV_VAR, raising=False)
    with pytest.raises(UndecryptableSecretError):
        EncryptionService().decrypt(fresh)


def test_several_previous_keys_are_tried_in_order(monkeypatch):
    """A rotation can be interrupted, so a deployment can carry more than two
    generations of secrets at once."""
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-one-key-of-32-bytes!!")
    oldest = EncryptionService(previous_keys=[]).encrypt("from the first era")

    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-three-key-of-32-byte!")
    monkeypatch.setenv(
        PREVIOUS_KEYS_ENV_VAR,
        "generation-two-key-of-32-bytes!! , generation-one-key-of-32-bytes!!",
    )

    assert EncryptionService().decrypt(oldest) == "from the first era"


def test_the_refusal_says_how_to_read_a_legacy_value(monkeypatch):
    """An operator upgrading gets "Error decrypting value" from the old code, which is
    accurate and useless. The message has to name the way out."""
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-one-key-of-32-bytes!!")
    old = EncryptionService(previous_keys=[]).encrypt("secret")

    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-two-key-of-32-bytes!!")
    monkeypatch.delenv(PREVIOUS_KEYS_ENV_VAR, raising=False)

    with pytest.raises(UndecryptableSecretError) as refusal:
        EncryptionService().decrypt(old)

    assert PREVIOUS_KEYS_ENV_VAR in str(refusal.value)


# --- Reported state ------------------------------------------------------------

def test_state_reports_a_value_under_the_current_key(encryption_service):
    assert encryption_service.state_of(encryption_service.encrypt("s")) is SecretState.CURRENT


def test_state_reports_a_value_that_has_not_been_rotated(monkeypatch):
    """The state the SSH keys page shows as "à faire tourner": readable, but only
    because the old key is still listed."""
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-one-key-of-32-bytes!!")
    old = EncryptionService(previous_keys=[]).encrypt("secret")

    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-two-key-of-32-bytes!!")
    monkeypatch.setenv(PREVIOUS_KEYS_ENV_VAR, "generation-one-key-of-32-bytes!!")

    assert EncryptionService().state_of(old) is SecretState.PREVIOUS_KEY


def test_state_reports_an_unreadable_value_rather_than_raising(monkeypatch):
    """Called per row while rendering a page: one unreadable secret must not take the
    page down with it."""
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-one-key-of-32-bytes!!")
    old = EncryptionService(previous_keys=[]).encrypt("secret")

    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-two-key-of-32-bytes!!")
    monkeypatch.delenv(PREVIOUS_KEYS_ENV_VAR, raising=False)

    assert EncryptionService().state_of(old) is SecretState.UNREADABLE
    assert EncryptionService().state_of("not even base64 ###") is SecretState.UNREADABLE


def test_nothing_is_current_when_no_key_is_configured(monkeypatch):
    """With only previous keys set, every value is legacy — reporting them as current
    would hide precisely the deployment that most needs telling."""
    monkeypatch.setenv(ENCRYPTION_KEY_ENV_VAR, "generation-one-key-of-32-bytes!!")
    old = EncryptionService(previous_keys=[]).encrypt("secret")

    monkeypatch.delenv(ENCRYPTION_KEY_ENV_VAR, raising=False)
    monkeypatch.setenv(PREVIOUS_KEYS_ENV_VAR, "generation-one-key-of-32-bytes!!")

    assert EncryptionService().state_of(old) is SecretState.PREVIOUS_KEY
