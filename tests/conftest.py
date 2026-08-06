"""Shared pytest fixtures.

Every test in this suite runs against an **in-memory** SQLite database
(`sqlite:///:memory:`), created fresh per test and thrown away afterward.
Nothing here ever opens `zanshin/database.sqlite` — the real file used by
the running app is never touched by the test suite.
"""
import uuid
from datetime import datetime

from zanshin.clock import utcnow

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from zanshin.database import Base
import zanshin.models  # noqa: F401 — registers every model on Base.metadata

from zanshin.models.user import User
from zanshin.models.scan import Scan
from zanshin.models.repository import ZanshinRepository
from zanshin.models.container import Container
from zanshin.repositories.user_repository import UserRepository
from zanshin.repositories.setting_repository import SettingRepository
from zanshin.repositories.finding_repository import FindingRepository
from zanshin.repositories.audit_log_repository import AuditLogRepository
from zanshin.repositories.api_key_repository import ApiKeyRepository
from zanshin.repositories.ssh_key_repository import SSHKeyRepository
from zanshin.repositories.repository_repository import RepositoryRepository
from zanshin.repositories.container_repository import ContainerRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.services.auth_service import AuthService
from zanshin.services.encryption_service import EncryptionService
from zanshin.services.settings_service import SettingsService

# Explicit test key. `EncryptionService` no longer falls back to the legacy
# default when `ENCRYPTION_KEY` is unset — it refuses to encrypt — so the suite
# supplies its own instead of depending on the developer's environment.
TEST_ENCRYPTION_KEY = "unit-test-encryption-key-32byte!"


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        # StaticPool keeps a *single* connection for the whole engine. Without
        # it, SQLAlchemy's default pool for an in-memory SQLite database opens
        # one connection per thread — and each new connection gets its own empty
        # database, so anything running off the test thread (FastAPI's
        # TestClient dispatches sync endpoints to a worker thread) finds no
        # tables at all.
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestSessionLocal = sessionmaker(bind=engine)
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def isolated_session_local():
    """A standalone session factory bound to its own in-memory engine.

    Used by tests that need to monkeypatch a module-level `SessionLocal`
    symbol (e.g. `ScanProcessor.process_scan`, `container.get_container`),
    rather than depending on the shared `db_session` fixture directly.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # see `db_session` for why
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine)
    yield factory
    engine.dispose()


@pytest.fixture()
def user_repository(db_session):
    return UserRepository(db_session)


@pytest.fixture()
def setting_repository(db_session):
    return SettingRepository(db_session)


@pytest.fixture()
def finding_repository(db_session):
    return FindingRepository(db_session)


@pytest.fixture()
def audit_log_repository(db_session):
    return AuditLogRepository(db_session)


@pytest.fixture()
def api_key_repository(db_session):
    return ApiKeyRepository(db_session)


@pytest.fixture()
def ssh_key_repository(db_session):
    return SSHKeyRepository(db_session)


@pytest.fixture()
def repository_repository(db_session):
    return RepositoryRepository(db_session)


@pytest.fixture()
def container_repository(db_session):
    return ContainerRepository(db_session)


@pytest.fixture()
def scan_repository(db_session):
    return ScanRepository(db_session)


@pytest.fixture()
def auth_service(user_repository):
    return AuthService(user_repository)


@pytest.fixture()
def encryption_service():
    return EncryptionService(key=TEST_ENCRYPTION_KEY)


@pytest.fixture()
def settings_service(setting_repository):
    return SettingsService(setting_repository)


@pytest.fixture()
def make_user(db_session):
    """Factory fixture: create+persist a User with sane defaults."""

    def _make(username="alice", role="USER", is_active=True, password_hash="hashed"):
        user = User(
            username=username,
            password=password_hash,
            display_name=username.capitalize(),
            role=role,
            is_active=is_active,
            created_at=utcnow(),
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    return _make


@pytest.fixture()
def make_repository(db_session):
    def _make(url="git@example.com:org/repo.git", branch="main", sub_path=""):
        repo = ZanshinRepository(url=url, branch=branch, sub_path=sub_path)
        db_session.add(repo)
        db_session.commit()
        db_session.refresh(repo)
        return repo

    return _make


@pytest.fixture()
def make_container(db_session):
    def _make(image_name="nginx", tag="latest", registry=None):
        c = Container(image_name=image_name, tag=tag, registry=registry)
        db_session.add(c)
        db_session.commit()
        db_session.refresh(c)
        return c

    return _make


@pytest.fixture()
def make_scan(db_session):
    def _make(repo_id=None, container_id=None, status="pending", branch="main"):
        scan = Scan(
            repo_id=repo_id,
            container_id=container_id,
            branch=branch,
            status=status,
            findings_count=0,
            created_at=utcnow(),
        )
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)
        return scan

    return _make


# --- Reflex UI harness ---------------------------------------------------------
#
# The UI layer was excluded from coverage with the note that `rx.State` classes
# "need Reflex's test harness, not plain pytest". `reflex.testing.AppHarness`
# spins up a real server and browser (it imports uvicorn), which is far too heavy
# for asserting what a loader puts in a state var.
#
# There is a lighter way. A State can be instantiated outside the server, and its
# handlers can be called as plain functions:
#
#   root = rx.State(_reflex_internal_init=True)     # the root state
#   state = root._get_state_from_cache(MyState)     # the substate, wired up
#   MyState.event_handlers["load"].fn(state)        # the function, not the EventHandler
#
# Three details make it work. The substate must come from the root (setting an
# inherited var like `logged_in` on a detached substate raises, because Reflex
# forwards it to `parent_state`); handlers must be reached through
# `event_handlers[...].fn` (attribute access yields an `EventHandler`, which
# builds an EventSpec instead of running anything); and the substate is taken
# from the in-process cache rather than `await root.get_state(...)`, which routes
# through the state manager and therefore requires a live `EventContext`.

class UIHarness:
    """Drives page states against an isolated database."""

    def __init__(self, session_factory):
        import reflex as rx

        self.session_factory = session_factory
        self._root = rx.State(_reflex_internal_init=True)

    def state(self, state_cls, *, logged_in=True, username="alice", role="SUPERUSER", **vars):
        """A page state, authenticated by default — the interesting assertions are
        rarely "the guard fired" (that's tests/test_ui_auth.py's job)."""
        state = self._root._get_state_from_cache(state_cls)
        state.logged_in = logged_in
        state.username = username
        state.user_role = role
        for name, value in vars.items():
            setattr(state, name, value)
        return state

    def run(self, state, handler_name, *args):
        """Call a handler and return the events it emitted."""
        handler = type(state).event_handlers[handler_name].fn
        result = handler(state, *args)
        return self._drain(result)

    def _drain(self, result):
        import inspect

        if result is None:
            return []
        if inspect.isasyncgen(result):
            return self._run(self._collect_async(result))
        if inspect.iscoroutine(result):
            return self._drain(self._run(result))
        if inspect.isgenerator(result):
            # Nested handler calls yield EventSpecs; keep them as-is, the point of
            # these tests is the state, not the event plumbing.
            return list(result)
        return [result] if not isinstance(result, list) else result

    @staticmethod
    async def _collect_async(async_gen):
        return [event async for event in async_gen]

    @staticmethod
    def _run(coro):
        import asyncio

        return asyncio.run(coro)


@pytest.fixture()
def ui(monkeypatch, isolated_session_local):
    """UI harness whose `get_container()` hits an isolated in-memory database."""
    import zanshin.container

    monkeypatch.setattr(zanshin.container, "SessionLocal", isolated_session_local)
    return UIHarness(isolated_session_local)


@pytest.fixture()
def ui_session(isolated_session_local):
    """A session on the same database the harness serves, to arrange fixtures."""
    session = isolated_session_local()
    yield session
    session.close()
