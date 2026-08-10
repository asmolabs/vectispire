"""The text-to-timestamp conversion, against real database servers.

Migration `0013` rewrites every timestamp in the schema, and what it does cannot be
checked on SQLite alone: `ALTER COLUMN`, index handling and batch mode behave
differently per backend, and the migration failed first on exactly the *indexed*
timestamp columns.

The sub-second assertion below outlived the backend that motivated it. MySQL truncated
`DATETIME` to whole seconds unless a fractional precision was declared — silently — and
because the audit trail hashes `timestamp.isoformat()`, every entry re-read after a
write reported itself as tampered with. MySQL is gone (see `zanshin/database.py`), but
the invariant it exposed is a property of the audit chain, not of MySQL, so the check
stays: any backend that rounds a timestamp breaks integrity verification, and it does
not look like a timestamp bug when it happens.

The "before" state is built with the migration's own downgrade rather than an old
checkout: it puts the schema back to text columns, which is precisely what a database
created before this revision looks like.

Run with `pytest -m backends`.
"""
import uuid
from datetime import datetime

import pytest

pytestmark = pytest.mark.backends

testcontainers = pytest.importorskip(
    "testcontainers.core.container", reason="testcontainers is not installed"
)


def _docker_available() -> bool:
    import shutil
    import subprocess

    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except Exception:
        return False


if not _docker_available():
    pytest.skip("Docker is not available", allow_module_level=True)


BACKENDS = [
    pytest.param("postgres", id="postgresql-16"),
]

# The shapes the pre-Alembic implementation wrote, and what each must become.
LEGACY_VALUES = [
    ("https://example.com/iso.git", "2026-08-06T13:34:45.491348", datetime(2026, 8, 6, 13, 34, 45, 491348)),
    ("https://example.com/space.git", "2026-08-06 13:34:45", datetime(2026, 8, 6, 13, 34, 45)),
    ("https://example.com/zulu.git", "2026-08-06T13:34:45Z", datetime(2026, 8, 6, 13, 34, 45)),
    # An offset is converted to UTC, not merely stripped: keeping the wall-clock time
    # would move the event by two hours.
    ("https://example.com/offset.git", "2026-08-06T13:34:45+02:00", datetime(2026, 8, 6, 11, 34, 45)),
]


@pytest.fixture(autouse=True)
def _encryption_key(monkeypatch):
    from tests.conftest import TEST_ENCRYPTION_KEY

    monkeypatch.setenv("ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)


@pytest.fixture(scope="module", params=BACKENDS)
def backend_url(request):
    from testcontainers.community.postgres import PostgresContainer

    container = PostgresContainer("postgres:16-alpine", driver="psycopg")

    with container as running:
        yield running.get_connection_url()


@pytest.fixture()
def text_schema(backend_url):
    """A database at revision 0012: timestamps as text, as they were before this work.

    Built by upgrading to head and stepping back one revision, so the "before" state is
    produced by the code under test rather than by a stale copy of it.
    """
    from alembic import command

    from tests.backend_support import configured_database

    with configured_database(backend_url) as database:
        from zanshin.schema import _alembic_config, upgrade_to_head

        upgrade_to_head()
        command.downgrade(_alembic_config(), "0012")
        yield database
        # Left at head for whatever runs next, whatever this test did.
        command.upgrade(_alembic_config(), "head")


def _column_type(database, table: str, column: str) -> str:
    import sqlalchemy as sa

    with database.engine.connect() as connection:
        for found in sa.inspect(connection).get_columns(table):
            if found["name"] == column:
                return str(found["type"]).lower()
    raise AssertionError(f"{table}.{column} not found")


def _upgrade(database):
    from alembic import command

    from zanshin.schema import _alembic_config

    command.upgrade(_alembic_config(), "head")


# --- The conversion --------------------------------------------------------------

def test_text_timestamps_become_real_timestamps(text_schema):
    import sqlalchemy as sa

    from zanshin.models.repository import ZanshinRepository

    assert "char" in _column_type(text_schema, "repository", "last_scheduled_scan_at")

    session = text_schema.SessionLocal()
    try:
        for url, stored, _ in LEGACY_VALUES:
            session.execute(
                sa.text(
                    "insert into repository (url, branch, last_scheduled_scan_at) "
                    "values (:url, 'main', :value)"
                ),
                {"url": url, "value": stored},
            )
        session.commit()
    finally:
        session.close()

    _upgrade(text_schema)

    assert "char" not in _column_type(text_schema, "repository", "last_scheduled_scan_at")

    session = text_schema.SessionLocal()
    try:
        rows = {
            repo.url: repo.last_scheduled_scan_at
            for repo in session.query(ZanshinRepository).all()
        }
    finally:
        session.close()

    for url, _, expected in LEGACY_VALUES:
        assert rows[url] == expected, f"{url} converted to {rows[url]}, expected {expected}"


def test_microseconds_survive_the_round_trip(text_schema):
    """A stored timestamp must come back with its fraction intact.

    The audit chain hashes `timestamp.isoformat()`, so a backend that rounds turns every
    existing entry into a forgery report. PostgreSQL keeps microseconds on its own — this
    passes today without any help — which is exactly why the assertion is worth keeping:
    it is the tripwire for the next backend, not a fix for this one."""
    from zanshin.clock import utcnow
    from zanshin.models.repository import ZanshinRepository

    _upgrade(text_schema)
    stamp = utcnow().replace(microsecond=491348)

    session = text_schema.SessionLocal()
    try:
        session.add(ZanshinRepository(
            url=f"https://example.com/{uuid.uuid4().hex[:8]}.git",
            branch="main",
            last_scheduled_scan_at=stamp,
        ))
        session.commit()
        session.expire_all()
        stored = session.query(ZanshinRepository).order_by(
            ZanshinRepository.id.desc()
        ).first().last_scheduled_scan_at
    finally:
        session.close()

    assert stored.microsecond == 491348


def test_the_audit_chain_still_verifies_after_the_conversion(text_schema):
    """The concrete consequence of losing microseconds: every entry recomputes to a
    different hash, so an intact trail reports itself as tampered with."""
    from zanshin.repositories.audit_log_repository import AuditLogRepository
    from zanshin.services.audit_log_service import AuditLogService

    session = text_schema.SessionLocal()
    try:
        service = AuditLogService(AuditLogRepository(session))
        for index in range(3):
            service.record("LOGIN_SUCCESS", str(index), f"connexion {index}", user_id="alice")
        session.commit()
        assert service.verify_chain() is None, "the chain was already broken before"
    finally:
        session.close()

    _upgrade(text_schema)

    session = text_schema.SessionLocal()
    try:
        assert AuditLogService(AuditLogRepository(session)).verify_chain() is None
    finally:
        session.close()


def test_indexed_timestamp_columns_keep_their_index(text_schema):
    """The migration failed first on exactly these: batch mode recreates the table, and
    an index still pointing at the column being replaced makes the rename collide."""
    import sqlalchemy as sa

    _upgrade(text_schema)

    with text_schema.engine.connect() as connection:
        indexes = {i["name"] for i in sa.inspect(connection).get_indexes("scan")}

    assert "ix_scan_lease_expires_at" in indexes


def test_a_second_run_is_a_no_op(text_schema):
    """A migration re-run — or a database created after this revision — finds real
    timestamps and leaves them alone rather than converting a converted column."""
    _upgrade(text_schema)
    before = _column_type(text_schema, "scan", "created_at")

    _upgrade(text_schema)

    assert _column_type(text_schema, "scan", "created_at") == before


def test_the_schema_matches_the_models_afterwards(text_schema):
    """`alembic check`, in effect: a conversion that produced a different type than the
    models declare would drift silently until the next autogenerate."""
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext

    import zanshin.models  # noqa: F401

    _upgrade(text_schema)

    with text_schema.engine.connect() as connection:
        context = MigrationContext.configure(connection)
        differences = compare_metadata(context, text_schema.Base.metadata)

    timestamp_differences = [
        difference for difference in differences
        if "modify_type" in str(difference) or "timestamp" in str(difference).lower()
    ]
    assert timestamp_differences == [], f"schema drift after conversion: {timestamp_differences}"
