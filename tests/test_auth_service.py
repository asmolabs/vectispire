from zanshin.services.auth_service import AuthService


def test_hash_password_is_not_plaintext_and_verifies(auth_service):
    hashed = auth_service.hash_password("password123")
    assert hashed != "password123"
    assert auth_service.verify_password("password123", hashed) is True
    assert auth_service.verify_password("wrong-password", hashed) is False


def test_verify_password_handles_empty_hash_gracefully(auth_service):
    assert auth_service.verify_password("anything", "") is False
    assert auth_service.verify_password("anything", None) is False


def test_verify_password_handles_garbage_hash_without_raising(auth_service):
    # Not a real bcrypt hash at all — must return False, not raise.
    assert auth_service.verify_password("anything", "not-a-real-hash") is False


def test_authenticate_user_success(auth_service, make_user):
    hashed = auth_service.hash_password("password123")
    make_user(username="alice", password_hash=hashed, is_active=True)

    user = auth_service.authenticate_user("alice", "password123")

    assert user is not None
    assert user.username == "alice"


def test_authenticate_user_wrong_password(auth_service, make_user):
    hashed = auth_service.hash_password("password123")
    make_user(username="alice", password_hash=hashed, is_active=True)

    assert auth_service.authenticate_user("alice", "wrong-password") is None


def test_authenticate_user_unknown_username(auth_service, make_user):
    assert auth_service.authenticate_user("ghost", "whatever") is None


def test_authenticate_inactive_user_is_rejected(auth_service, make_user):
    hashed = auth_service.hash_password("password123")
    make_user(username="disabled", password_hash=hashed, is_active=False)

    assert auth_service.authenticate_user("disabled", "password123") is None
