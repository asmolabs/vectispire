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
