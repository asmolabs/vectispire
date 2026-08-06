import bcrypt
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


# --- Verification cost and usage tracking (wave 3) ---

def test_verification_looks_the_key_up_by_prefix(api_key_repository, monkeypatch):
    """Verification used to bcrypt-compare against *every* stored key — one
    deliberately-slow hash per key on every API call. The `prefix` column existed
    precisely to avoid that."""
    svc = ApiKeyService(api_key_repository)
    _, raw_a = svc.create_key("a")
    for name in "bcdef":
        svc.create_key(name)

    calls = {"count": 0}
    real_checkpw = bcrypt.checkpw

    def counting_checkpw(*args, **kwargs):
        calls["count"] += 1
        return real_checkpw(*args, **kwargs)

    monkeypatch.setattr("zanshin.services.api_key_service.bcrypt.checkpw", counting_checkpw)

    assert svc.verify_key(raw_a) is not None
    # One comparison, not six.
    assert calls["count"] == 1


def test_verification_can_record_the_use(api_key_repository):
    svc = ApiKeyService(api_key_repository)
    saved, raw = svc.create_key("ci")
    assert saved.last_used_at is None

    svc.verify_key(raw, record_use=True)

    assert api_key_repository.find_by_id(saved.id).last_used_at is not None


def test_verification_does_not_record_use_by_default(api_key_repository):
    svc = ApiKeyService(api_key_repository)
    saved, raw = svc.create_key("ci")

    svc.verify_key(raw)

    assert api_key_repository.find_by_id(saved.id).last_used_at is None


def test_a_key_shorter_than_a_prefix_is_rejected_without_a_query(api_key_repository):
    svc = ApiKeyService(api_key_repository)
    assert svc.verify_key("zsk_") is None
    assert svc.verify_key("x") is None


def test_looks_like_a_key_screens_obvious_junk():
    assert ApiKeyService.looks_like_a_key("zsk_abcdef") is True
    assert ApiKeyService.looks_like_a_key("ghp_abcdef") is False
    assert ApiKeyService.looks_like_a_key("no-underscore") is False
    assert ApiKeyService.looks_like_a_key("") is False
