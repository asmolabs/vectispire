"""Tests for the first-run administrator bootstrap.

Like `ScanProcessor.process_scan`, `ensure_bootstrap_superuser` opens its own
session from the module-level `SessionLocal`, so these tests monkeypatch that
name to point at an isolated in-memory database.
"""
import pytest

import zanshin.bootstrap as bootstrap_module
from zanshin.bootstrap import (
    BOOTSTRAP_PASSWORD_ENV_VAR,
    BOOTSTRAP_USERNAME_ENV_VAR,
    ensure_bootstrap_superuser,
)
from zanshin.models.setting import Setting
from zanshin.models.user import User


@pytest.fixture(autouse=True)
def patch_bootstrap_session(monkeypatch, isolated_session_local):
    monkeypatch.setattr(bootstrap_module, "SessionLocal", isolated_session_local)


@pytest.fixture(autouse=True)
def clear_bootstrap_env(monkeypatch):
    monkeypatch.delenv(BOOTSTRAP_USERNAME_ENV_VAR, raising=False)
    monkeypatch.delenv(BOOTSTRAP_PASSWORD_ENV_VAR, raising=False)


@pytest.fixture()
def isolated_session(isolated_session_local):
    session = isolated_session_local()
    yield session
    session.close()


def _users(session):
    return session.query(User).all()


def test_creates_the_initial_superuser_from_the_environment(monkeypatch, isolated_session):
    monkeypatch.setenv(BOOTSTRAP_USERNAME_ENV_VAR, "admin")
    monkeypatch.setenv(BOOTSTRAP_PASSWORD_ENV_VAR, "a-long-enough-password")

    ensure_bootstrap_superuser()

    users = _users(isolated_session)
    assert len(users) == 1
    assert users[0].username == "admin"
    assert users[0].role == "SUPERUSER"
    assert users[0].is_active is True
    # Hashed via AuthService, never stored in cleartext.
    assert users[0].password != "a-long-enough-password"


def test_does_nothing_when_a_user_already_exists(monkeypatch, isolated_session):
    """Runs on every startup, so it must never resurrect an account that was
    deliberately deleted, nor add a second administrator."""
    isolated_session.add(User(username="alice", password="hashed", role="USER"))
    isolated_session.commit()

    monkeypatch.setenv(BOOTSTRAP_USERNAME_ENV_VAR, "admin")
    monkeypatch.setenv(BOOTSTRAP_PASSWORD_ENV_VAR, "a-long-enough-password")

    ensure_bootstrap_superuser()

    assert [u.username for u in _users(isolated_session)] == ["alice"]


def test_does_nothing_without_credentials(isolated_session, caplog):
    ensure_bootstrap_superuser()

    assert _users(isolated_session) == []
    assert BOOTSTRAP_USERNAME_ENV_VAR in caplog.text


def test_reports_a_rejected_password_without_raising(monkeypatch, isolated_session, caplog):
    """UserService enforces a minimum length; a too-short bootstrap password is
    the operator's input, so it must be reported as such — and must not prevent
    the application from starting."""
    monkeypatch.setenv(BOOTSTRAP_USERNAME_ENV_VAR, "admin")
    monkeypatch.setenv(BOOTSTRAP_PASSWORD_ENV_VAR, "short")

    ensure_bootstrap_superuser()

    assert _users(isolated_session) == []
    assert "8 caractères" in caplog.text


def test_an_unrelated_broken_setting_does_not_block_the_bootstrap(monkeypatch, isolated_session):
    """The reason this doesn't build an `IoCContainer`: the container also
    builds the scanner engine, which raises on an unknown `scan_backend`."""
    isolated_session.add(Setting(key="scan_backend", value="does-not-exist"))
    isolated_session.commit()

    monkeypatch.setenv(BOOTSTRAP_USERNAME_ENV_VAR, "admin")
    monkeypatch.setenv(BOOTSTRAP_PASSWORD_ENV_VAR, "a-long-enough-password")

    ensure_bootstrap_superuser()

    assert [u.username for u in _users(isolated_session)] == ["admin"]
