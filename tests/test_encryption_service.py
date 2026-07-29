from zanshin.services.encryption_service import EncryptionService


def test_encrypt_then_decrypt_round_trip():
    svc = EncryptionService()
    plaintext = "-----BEGIN RSA PRIVATE KEY-----\nfake-key-content\n-----END-----"

    encrypted = svc.encrypt(plaintext)

    assert encrypted != plaintext
    assert svc.decrypt(encrypted) == plaintext


def test_encrypt_empty_string_is_passthrough():
    svc = EncryptionService()
    assert svc.encrypt("") == ""
    assert svc.decrypt("") == ""


def test_encrypt_output_is_not_deterministic():
    """A random IV is prepended each time, so encrypting the same plaintext
    twice must not produce the same ciphertext (otherwise the IV isn't
    actually random and the scheme is weaker than intended)."""
    svc = EncryptionService()
    a = svc.encrypt("same-secret")
    b = svc.encrypt("same-secret")
    assert a != b
    assert svc.decrypt(a) == "same-secret"
    assert svc.decrypt(b) == "same-secret"


def test_decrypt_tampered_ciphertext_raises():
    svc = EncryptionService()
    encrypted = svc.encrypt("top-secret")
    tampered = encrypted[:-4] + ("AAAA" if not encrypted.endswith("AAAA") else "BBBB")
    try:
        svc.decrypt(tampered)
        assert False, "expected a RuntimeError for tampered ciphertext"
    except RuntimeError:
        pass
