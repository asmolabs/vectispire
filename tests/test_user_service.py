import pytest

from zanshin.services.user_service import UserService


@pytest.fixture()
def user_service(user_repository, auth_service):
    return UserService(user_repository, auth_service)


def test_create_user_hashes_password_and_allows_login(user_service, auth_service):
    user = user_service.create_user("admin", "password123", display_name="Admin", role="SUPERUSER")

    assert user.password != "password123"
    assert auth_service.authenticate_user("admin", "password123") is not None
    assert auth_service.authenticate_user("admin", "wrong") is None


def test_create_user_rejects_duplicate_username(user_service):
    user_service.create_user("admin", "password123")
    with pytest.raises(ValueError):
        user_service.create_user("admin", "password123")


def test_create_user_rejects_short_password(user_service):
    with pytest.raises(ValueError):
        user_service.create_user("bob", "short")


def test_create_user_rejects_invalid_role(user_service):
    with pytest.raises(ValueError):
        user_service.create_user("carol", "password123", role="HACKER")


def test_create_user_rejects_duplicate_email(user_service):
    user_service.create_user("bob", "password123", email="bob@example.com")
    with pytest.raises(ValueError):
        user_service.create_user("bob2", "password123", email="bob@example.com")


def test_cannot_demote_the_last_active_superuser(user_service):
    admin = user_service.create_user("admin", "password123", role="SUPERUSER")
    with pytest.raises(ValueError):
        user_service.update_user(admin.id, "Admin", "", "USER", True)


def test_cannot_deactivate_the_last_active_superuser(user_service):
    admin = user_service.create_user("admin", "password123", role="SUPERUSER")
    with pytest.raises(ValueError):
        user_service.update_user(admin.id, "Admin", "", "SUPERUSER", False)


def test_cannot_delete_the_last_active_superuser(user_service):
    admin = user_service.create_user("admin", "password123", role="SUPERUSER")
    with pytest.raises(ValueError):
        user_service.delete_user(admin.id, requesting_username="someone_else")


def test_can_demote_superuser_once_another_active_superuser_exists(user_service):
    admin = user_service.create_user("admin", "password123", role="SUPERUSER")
    bob = user_service.create_user("bob", "password123", role="USER")

    user_service.update_user(bob.id, "Bob", "", "SUPERUSER", True)
    demoted = user_service.update_user(admin.id, "Admin", "", "USER", True)

    assert demoted.role == "USER"


def test_cannot_delete_own_account(user_service):
    bob = user_service.create_user("bob", "password123", role="USER")
    with pytest.raises(ValueError):
        user_service.delete_user(bob.id, requesting_username="bob")


def test_reset_password_changes_credentials(user_service, auth_service):
    bob = user_service.create_user("bob", "password123", role="USER")

    user_service.reset_password(bob.id, "brand-new-password")

    assert auth_service.authenticate_user("bob", "brand-new-password") is not None
    assert auth_service.authenticate_user("bob", "password123") is None


def test_reset_password_rejects_short_password(user_service):
    bob = user_service.create_user("bob", "password123", role="USER")
    with pytest.raises(ValueError):
        user_service.reset_password(bob.id, "short")


def test_delete_non_superuser_succeeds(user_service):
    admin = user_service.create_user("admin", "password123", role="SUPERUSER")
    bob = user_service.create_user("bob", "password123", role="USER")

    user_service.delete_user(bob.id, requesting_username="admin")

    assert user_service.find_by_id(bob.id) is None
