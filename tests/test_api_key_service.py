from zanshin.services.api_key_service import ApiKeyService, KEY_PREFIX


def test_create_key_returns_raw_secret_once_and_stores_only_a_hash(api_key_repository):
    svc = ApiKeyService(api_key_repository)

    saved, raw_secret = svc.create_key("CI/CD Jenkins")

    assert saved.name == "CI/CD Jenkins"
    assert raw_secret.startswith(f"{KEY_PREFIX}_")
    # The stored row must never contain the raw secret in cleartext.
    assert saved.key_hash != raw_secret
    assert raw_secret not in saved.key_hash
    # Non-secret prefix kept for UI display, itself never the full secret.
    assert saved.prefix is not None
    assert saved.prefix != raw_secret


def test_verify_key_accepts_correct_secret(api_key_repository):
    svc = ApiKeyService(api_key_repository)
    _, raw_secret = svc.create_key("Test key")

    verified = svc.verify_key(raw_secret)

    assert verified is not None
    assert verified.name == "Test key"


def test_verify_key_rejects_wrong_secret(api_key_repository):
    svc = ApiKeyService(api_key_repository)
    svc.create_key("Test key")

    assert svc.verify_key(f"{KEY_PREFIX}_totally-wrong-secret") is None


def test_verify_key_rejects_empty_string(api_key_repository):
    svc = ApiKeyService(api_key_repository)
    assert svc.verify_key("") is None
    assert svc.verify_key(None) is None


def test_verify_key_with_no_keys_at_all(api_key_repository):
    svc = ApiKeyService(api_key_repository)
    assert svc.verify_key("zsk_anything") is None
