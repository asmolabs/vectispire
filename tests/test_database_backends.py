"""Cross-backend tests against real database servers.

Every portability defect found in this schema so far was invisible both to SQLite
and to reading the code: a column type rendered as `BINARY` in DDL (which SQLite
accepts because everything is a blob, and PostgreSQL rejects outright), and `FROM
user` in raw SQL (a reserved word in PostgreSQL, where it silently resolves to the
`current_user` function instead of the table). Neither could be caught by a mock, a
dialect-string check, or a careful reading — only by running the migrations against
the server.

So these tests start actual PostgreSQL and MySQL containers, apply all six
migrations, and then push one row through every custom column type and every service
that owns one. They are slow (an image pull on the first run) and they skip
themselves when Docker is unavailable, which is what keeps them from turning a
laptop without Docker into a red suite.

Run them alone with `pytest -m backends`.
"""
import os
import uuid

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


# Pinned by minor version, not `latest`: a suite that quietly changes what it tests
# between two runs cannot be used to decide whether a backend is supported.
BACKENDS = [
    pytest.param("postgres", id="postgresql-16"),
    pytest.param("mysql", id="mysql-8.4"),
]


@pytest.fixture(autouse=True)
def _encryption_key(monkeypatch):
    """The services encrypt for real here, so the key has to be in the environment —
    `EncryptionService` refuses to encrypt without one, by design."""
    from tests.conftest import TEST_ENCRYPTION_KEY

    monkeypatch.setenv("ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)


@pytest.fixture(scope="module", params=BACKENDS)
def backend_url(request):
    """A running server, and the URL to reach it.

    Module-scoped: starting a database server per test would dominate the runtime
    and prove nothing extra, since each test below writes its own rows.
    """
    if request.param == "postgres":
        from testcontainers.community.postgres import PostgresContainer

        container = PostgresContainer("postgres:16-alpine", driver="psycopg")
    else:
        from testcontainers.community.mysql import MySqlContainer

        container = MySqlContainer("mysql:8.4", dialect="pymysql")

    with container as running:
        yield running.get_connection_url()


@pytest.fixture(scope="module")
def migrated(backend_url):
    """The application's own schema management, run against that server.

    Deliberately `zanshin.schema.upgrade_to_head` and not a hand-rolled
    `create_all`: what is being tested is the path a real deployment takes, and
    `create_all` would skip the migrations entirely — where two of the three defects
    found so far actually lived.
    """
    from tests.backend_support import configured_database

    with configured_database(backend_url) as database:
        from zanshin.schema import upgrade_to_head

        upgrade_to_head()
        yield database


@pytest.fixture()
def session(migrated):
    """A session on an empty database.

    The server is module-scoped (starting one per test would dominate the runtime),
    so the *rows* have to be cleared instead — otherwise what one test commits is
    visible to the next, which silently invalidates any assertion about ordering or
    counts.
    """
    db = migrated.SessionLocal()
    _clear_all_rows(db, migrated)
    try:
        yield db
    finally:
        db.rollback()
        db.close()


def _clear_all_rows(db, migrated) -> None:
    """Delete every row, children first.

    `sorted_tables` is dependency-ordered, so reversing it deletes children before
    parents — which matters on the backends that actually enforce foreign keys.
    `alembic_version` is not in the metadata, so the schema's revision survives.
    """
    for table in reversed(migrated.Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.commit()


@pytest.fixture()
def container_for(session):
    """An IoC container on that session, so the services are the real ones."""
    from zanshin.container import IoCContainer

    return IoCContainer(session)


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# --- Schema ---

def test_every_migration_applies(migrated):
    """The whole point: 0001 through 0006 on a real server, not on SQLite."""
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    from zanshin.schema import _alembic_config

    head = ScriptDirectory.from_config(_alembic_config()).get_current_head()
    with migrated.engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_revision() == head


def test_the_schema_matches_the_models(migrated):
    """`alembic check` as the models see it. A migration that applies but produces
    a different schema than the code expects fails later, at a query."""
    from alembic import command
    from alembic.util.exc import AutogenerateDiffsDetected

    from zanshin.schema import _alembic_config

    try:
        command.check(_alembic_config())
    except AutogenerateDiffsDetected as e:
        pytest.fail(f"Schema drift on this backend: {e}")


def test_every_table_the_models_declare_exists(migrated):
    from sqlalchemy import inspect

    import zanshin.models  # noqa: F401 — registers every model

    expected = set(migrated.Base.metadata.tables)
    actual = set(inspect(migrated.engine).get_table_names())

    assert expected - actual == set()


# --- Custom column types ---

def test_a_uuid_primary_key_round_trips(container_for, session):
    """`GUID` used to render as `BINARY`, which PostgreSQL has no such type for.
    Here it is a native `uuid` there and 16 bytes elsewhere, and the value that comes
    back has to be a `uuid.UUID` either way — the services compare it to one."""
    key = container_for.ssh_key_service.create_key(
        name=_unique("deploy"), private_key="-----BEGIN KEY-----\nx\n-----END KEY-----"
    )
    session.commit()
    session.expire_all()

    reloaded = container_for.ssh_key_repository.find_by_id(key.id)

    assert isinstance(reloaded.id, uuid.UUID)
    assert reloaded.id == key.id


def test_an_encrypted_value_survives_the_round_trip(container_for, session):
    """The ciphertext is bound to the row id, so this exercises the UUID *and* the
    associated data at once: a driver that hands the id back in another shape would
    break decryption, not just equality."""
    secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END-----"
    key = container_for.ssh_key_service.create_key(name=_unique("deploy"), private_key=secret)
    session.commit()

    assert container_for.ssh_key_service.get_decrypted_key(key.id) == secret


def test_a_timestamp_round_trips_as_a_datetime(container_for, session):
    """`SafeDateTime` stores ISO-8601 strings on every backend. What matters is that
    a `datetime` goes in and a `datetime` comes out — a string leaking through would
    break every comparison in the issue lifecycle."""
    from datetime import datetime

    from zanshin.clock import utcnow

    key, _ = container_for.api_key_service.create_key(_unique("ci"), expires_in_days=30)
    session.commit()
    session.expire_all()

    reloaded = container_for.api_key_service.api_key_repository.find_all()[0]
    assert isinstance(reloaded.expires_at, datetime)
    assert reloaded.expires_at > utcnow()


def test_a_json_column_round_trips(migrated, session):
    """`Scan.sbom` holds a whole SBOM. On MySQL that is a native JSON column, on
    PostgreSQL a `json`, and on SQLite text — and `none_as_null` behaviour is what
    retention depends on."""
    from zanshin.models.container import Container
    from zanshin.models.scan import Scan

    image = Container(image_name=_unique("nginx"), tag="latest")
    session.add(image)
    session.commit()

    sbom = {"artifacts": [{"name": "libfoo", "version": "1.0", "purl": "pkg:deb/libfoo@1.0"}]}
    scan = Scan(status="completed", branch="main", findings_count=0, container_id=image.id, sbom=sbom)
    session.add(scan)
    session.commit()
    session.expire_all()

    reloaded = session.get(Scan, scan.id)
    assert reloaded.sbom == sbom

    # Retention sets it to NULL, and a JSON `null` would not be the same thing.
    reloaded.sbom = None
    session.commit()
    session.expire_all()
    assert session.get(Scan, scan.id).sbom is None


# --- The features that own a column ---

def test_a_user_is_created_and_authenticated(container_for, session):
    username = _unique("alice")
    user = container_for.user_service.create_user(
        username, "mot-de-passe-solide", "Alice", f"{username}@example.com", "ADMIN"
    )
    session.commit()

    assert container_for.auth_service.authenticate_user(username, "mot-de-passe-solide")
    assert container_for.auth_service.authenticate_user(username, "mauvais") is None
    assert user.must_change_password is False


def test_the_unique_username_constraint_is_real(container_for, session):
    """Declared `unique=True` in the model and added by migration 0003. On the
    previous schema it was enforced by application code only."""
    username = _unique("bob")
    container_for.user_service.create_user(username, "mot-de-passe-solide")
    session.commit()

    with pytest.raises(ValueError, match="existe déjà"):
        container_for.user_service.create_user(username, "autre-mot-de-passe")


def test_an_api_key_with_scopes_and_a_target_is_stored_and_verified(container_for, session):
    key, raw = container_for.api_key_service.create_key(
        _unique("ci"), scopes=["read"], target_kind="repository", target_id=7, expires_in_days=30
    )
    session.commit()
    session.expire_all()

    verified = container_for.api_key_service.verify_key(raw)
    assert verified is not None
    assert verified.scope_list == ["read"]
    assert verified.covers("repository", 7) is True
    assert verified.covers("repository", 8) is False
    assert verified.is_expired is False


def test_the_audit_chain_verifies(container_for, session):
    """The chain hashes a timestamp, so a backend that changes its precision on the
    way back out would break every entry's own verification."""
    container_for.audit_log_service.record(
        "LOGIN_SUCCESS", "1", "connexion", user_id="alice",
        ip_address="203.0.113.7", user_agent="curl/8",
    )
    container_for.audit_log_service.record("SETTING_UPDATED", "scan_backend", "docker")
    session.commit()

    assert container_for.audit_log_service.verify_chain() is None
    latest = container_for.audit_log_service.audit_log_repository.find_latest()
    assert latest.previous_hash is not None


def test_a_tampered_audit_entry_is_detected(container_for, session):
    container_for.audit_log_service.record("LOGIN_FAILURE", "alice", "échec suspect")
    container_for.audit_log_service.record("SETTING_UPDATED", "x", "sans rapport")
    session.commit()

    first = container_for.audit_log_service.audit_log_repository.find_all_oldest_first()[0]
    first.description = "rien à signaler"
    session.commit()

    assert container_for.audit_log_service.verify_chain() is not None


def test_the_issue_lifecycle_runs(container_for, session):
    """One scan's findings folded into issues, then the same finding again: the
    cross-scan identity depends on a unique constraint on `fingerprint`."""
    from zanshin.models.finding import Finding
    from zanshin.models.repository import ZanshinRepository
    from zanshin.models.scan import Scan

    repo = ZanshinRepository(name=_unique("app"), url=f"git@example.com:{_unique('a')}.git", branch="main")
    session.add(repo)
    session.commit()

    identifier = _unique("CVE-2024")

    def _scan_with_finding():
        scan = Scan(status="completed", branch="main", findings_count=1, repo_id=repo.id)
        session.add(scan)
        session.commit()
        finding = Finding(
            scan_id=scan.id, type="vulnerability", severity="high", identifier=identifier,
            package_name="libfoo", package_version="1.0.0", purl="pkg:deb/libfoo@1.0.0",
            source="grype", is_direct_dependency=True, line=None,
        )
        session.add(finding)
        session.commit()
        return container_for.issue_service.sync_from_scan(
            session, scan, [finding], {"vulnerability"}
        )

    first = _scan_with_finding()
    assert first.new == 1

    second = _scan_with_finding()
    assert second.new == 0 and second.still_open == 1


def test_a_triage_review_date_expires(container_for, session):
    from datetime import timedelta

    from zanshin.clock import utcnow
    from zanshin.models.issue import TRIAGE_NOT_AFFECTED, TRIAGE_UNDER_REVIEW, Issue

    issue = Issue(
        fingerprint=_unique("fp"), type="vulnerability", identifier="CVE-2024-1",
        severity="high", state="open", is_kev=False,
    )
    session.add(issue)
    session.commit()

    container_for.issue_service.triage(
        session, issue.id, TRIAGE_NOT_AFFECTED, actor="alice",
        justification="component_not_present", comment="Pas livré", expires_in_days=90,
    )
    assert issue.triage_expires_at is not None

    issue.triage_expires_at = utcnow() - timedelta(days=1)
    session.commit()

    expired = container_for.issue_service.expire_stale_triages(session)

    assert issue.id in [i.id for i in expired]
    assert issue.triage_status == TRIAGE_UNDER_REVIEW
    assert issue.triage_comment == "Pas livré"


def test_the_direct_dependency_filter_is_a_real_query(container_for, session):
    """It filters on `is_direct_dependency IS TRUE`, and boolean handling is exactly
    the sort of thing that differs between backends — MySQL has no boolean type."""
    from zanshin.models.issue import Issue

    for suffix, direct in (("d", True), ("t", False), ("u", None)):
        session.add(Issue(
            fingerprint=_unique(f"fp-{suffix}"), type="vulnerability",
            identifier=f"CVE-{suffix}", severity="high", state="open",
            is_kev=False, is_direct_dependency=direct,
        ))
    session.commit()

    direct_only = container_for.issue_repository.find_filtered(only_direct=True, limit=100)

    assert {i.identifier for i in direct_only} == {"CVE-d"}


def test_the_severity_ordering_works(container_for, session):
    """The listing orders by a CASE expression over severity, plus a KEV flag and a
    nullable float with `nullslast()` — three things worth checking per dialect."""
    from zanshin.models.issue import Issue

    for severity, kev, epss in (("low", False, 0.9), ("critical", False, 0.1), ("medium", True, None)):
        session.add(Issue(
            fingerprint=_unique("fp"), type="vulnerability", identifier=f"CVE-{severity}",
            severity=severity, state="open", is_kev=kev, epss_score=epss,
        ))
    session.commit()

    rows = container_for.issue_repository.find_filtered(limit=100)

    # KEV first regardless of severity, then severity rank.
    assert rows[0].identifier == "CVE-medium"
    assert [r.identifier for r in rows[1:3]] == ["CVE-critical", "CVE-low"]


def test_the_exports_build_from_real_rows(container_for, session):
    from zanshin.models.issue import Issue
    from zanshin.services.exports import (
        build_issues_csv,
        build_openvex_document,
        build_sarif_document,
    )

    session.add(Issue(
        fingerprint=_unique("fp"), type="vulnerability", identifier="CVE-2024-9999",
        severity="critical", state="open", is_kev=True, is_direct_dependency=True,
        package_name="libfoo", package_version="1.0.0", purl="pkg:deb/libfoo@1.0.0",
    ))
    session.commit()

    issues = container_for.issue_repository.find_filtered(limit=100)

    sarif = build_sarif_document(issues, target_name="app")
    assert sarif["runs"][0]["results"], "SARIF should not be empty"
    assert all(r["locations"] for r in sarif["runs"][0]["results"])

    vex = build_openvex_document(
        issues, author="Zanshin", product_id="app", document_id="urn:x", timestamp="2026-08-06T12:00:00"
    )
    assert vex["statements"]

    assert "CVE-2024-9999" in build_issues_csv(issues)


def test_the_dashboard_aggregates_run(container_for, session):
    """Grouped counts and a severity histogram — one query each, and the kind of
    thing a dialect difference breaks silently by returning zero."""
    from zanshin.models.issue import Issue

    session.add(Issue(
        fingerprint=_unique("fp"), type="vulnerability", identifier="CVE-1",
        severity="critical", state="open", is_kev=False,
    ))
    session.commit()

    counts = container_for.issue_repository.count_by_state_and_triage()
    by_severity = container_for.issue_repository.count_open_by_severity()

    assert counts["total"] >= 1
    assert counts["actionable"] >= 1
    assert by_severity.get("critical", 0) >= 1


# --- Delete rules (migration 0013) ---
#
# This is where "the database enforces this" is actually proved. On SQLite the rules are
# only honoured because a pragma asks for it; PostgreSQL and MySQL enforce them always,
# and they are the reason the rules had to exist at all — before 0013, deleting a scan
# on a server database failed outright, because `issue.first_seen_scan_id` referenced it
# with no rule and no ORM relationship to clear it.

def _target_with_history(session, suffix: str):
    from zanshin.models.ai_review_result import AiReviewResult
    from zanshin.models.finding import Finding
    from zanshin.models.issue import Issue
    from zanshin.models.repository import ZanshinRepository
    from zanshin.models.scan import Scan

    repo = ZanshinRepository(
        name=_unique("app"), url=f"git@example.com:{_unique(suffix)}.git", branch="main"
    )
    session.add(repo)
    session.commit()

    scan = Scan(repo_id=repo.id, branch="main", status="completed", findings_count=1)
    session.add(scan)
    session.commit()

    issue = Issue(
        repo_id=repo.id, fingerprint=_unique("fp"), type="vulnerability",
        identifier="CVE-2024-0001", severity="high", state="open", is_kev=False,
        first_seen_scan_id=scan.id, last_seen_scan_id=scan.id,
    )
    session.add(issue)
    session.commit()

    finding = Finding(
        scan_id=scan.id, type="vulnerability", severity="high",
        identifier="CVE-2024-0001", source="grype", issue_id=issue.id,
    )
    review = AiReviewResult(
        scan_id=scan.id, model="test", prompt="p", response="r", status="completed"
    )
    session.add_all([finding, review])
    session.commit()
    return repo, scan, issue, finding, review


def test_the_server_enforces_foreign_keys(session):
    """The premise. A driver that let an invalid reference through would make every
    rule below meaningless."""
    from sqlalchemy.exc import IntegrityError

    from zanshin.models.finding import Finding

    session.add(Finding(scan_id=999_999, type="vulnerability", severity="high", source="grype"))

    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()


def test_deleting_a_scan_no_longer_fails(session):
    """The bug 0013 fixes, in its original form: on PostgreSQL this raised, because two
    issue columns referenced the scan with no delete rule and no ORM relationship
    through which SQLAlchemy could have cleared them."""
    from zanshin.models.issue import Issue

    _repo, scan, issue, _finding, _review = _target_with_history(session, "del-scan")
    issue_id = issue.id

    session.delete(scan)
    session.commit()
    session.expunge_all()

    reloaded = session.get(Issue, issue_id)
    assert reloaded is not None
    assert reloaded.first_seen_scan_id is None
    assert reloaded.last_seen_scan_id is None


def test_deleting_a_target_cascades_on_the_server(session):
    from zanshin.models.finding import Finding
    from zanshin.models.issue import Issue
    from zanshin.models.scan import Scan

    repo, scan, issue, finding, _review = _target_with_history(session, "del-target")
    scan_id, issue_id, finding_id = scan.id, issue.id, finding.id

    session.delete(repo)
    session.commit()
    session.expunge_all()

    assert session.get(Scan, scan_id) is None
    assert session.get(Issue, issue_id) is None
    assert session.get(Finding, finding_id) is None


def test_deleting_an_issue_detaches_its_findings_on_the_server(session):
    """SET NULL and not CASCADE: the observation genuinely happened, only its
    attachment to an issue goes away."""
    from zanshin.models.finding import Finding

    _repo, _scan, issue, finding, _review = _target_with_history(session, "del-issue")
    finding_id = finding.id

    session.delete(issue)
    session.commit()
    session.expunge_all()

    reloaded = session.get(Finding, finding_id)
    assert reloaded is not None
    assert reloaded.issue_id is None


def test_every_foreign_key_carries_a_delete_rule(migrated):
    """No column left behind. Read from the server's own catalogue rather than from the
    models, so this checks what was actually applied."""
    from sqlalchemy import inspect

    expected = {
        ("scan", "repo_id"): "CASCADE",
        ("scan", "container_id"): "CASCADE",
        ("issue", "repo_id"): "CASCADE",
        ("issue", "container_id"): "CASCADE",
        ("issue", "first_seen_scan_id"): "SET NULL",
        ("issue", "last_seen_scan_id"): "SET NULL",
        ("finding", "scan_id"): "CASCADE",
        ("finding", "issue_id"): "SET NULL",
        ("ai_review_result", "scan_id"): "CASCADE",
        ("repository", "ssh_key_id"): "SET NULL",
    }

    inspector = inspect(migrated.engine)
    actual = {}
    for table in {name for name, _ in expected}:
        for fk in inspector.get_foreign_keys(table):
            for column in fk.get("constrained_columns") or []:
                rule = (fk.get("options") or {}).get("ondelete")
                actual[(table, column)] = (rule or "").upper() or None

    missing = {key: rule for key, rule in expected.items() if actual.get(key) != rule}
    assert not missing, f"delete rule missing or wrong: {missing}"
