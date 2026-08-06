"""Concurrency of the scan claim, against real database servers.

This file exists because the guarantee it tests **cannot** be tested on SQLite:
`FOR UPDATE SKIP LOCKED` does not exist there, and SQLAlchemy's SQLite dialect
silently drops `FOR UPDATE` rather than refusing it. A claim that looks
transactional, passes on a developer's machine, and hands the same scan to two
processes in production is exactly the class of defect ADR-002 §7 warns about — every
portability bug found in this schema so far was invisible both to SQLite and to
reading the code.

So the claimants here are *real*: separate sessions on separate connections, running
in threads, hitting PostgreSQL 16 and MySQL 8.4. The assertion that matters is not
"it didn't crash" but "each scan was handed out exactly once".

Run with `pytest -m backends`.
"""
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

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
    pytest.param("mysql", id="mysql-8.4"),
]


@pytest.fixture(scope="module", params=BACKENDS)
def backend_url(request):
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
    from tests.backend_support import configured_database

    with configured_database(backend_url) as database:
        from zanshin.schema import upgrade_to_head

        upgrade_to_head()
        yield database


@pytest.fixture()
def empty(migrated):
    """An empty database, and the factory to open sessions on it.

    Rows are cleared rather than the server restarted (module-scoped for runtime), and
    every claimant below opens its *own* session — a shared one would serialise
    everything through a single connection and quietly test nothing.
    """
    session = migrated.SessionLocal()
    for table in reversed(migrated.Base.metadata.sorted_tables):
        session.execute(table.delete())
    session.commit()
    session.close()
    return migrated


def _queue_scans(migrated, count: int) -> list:
    """`count` queued scans, in a known creation order."""
    from datetime import timedelta

    from zanshin.clock import utcnow
    from zanshin.models.repository import ZanshinRepository
    from zanshin.models.scan import Scan
    from zanshin.services.scan_queue import STATUS_QUEUED

    session = migrated.SessionLocal()
    try:
        repo = ZanshinRepository(
            url=f"https://example.com/org/{uuid.uuid4().hex[:8]}.git", branch="main"
        )
        session.add(repo)
        session.commit()

        base = utcnow()
        ids = []
        for index in range(count):
            scan = Scan(
                repo_id=repo.id, branch="main", status=STATUS_QUEUED, findings_count=0,
                created_at=base + timedelta(seconds=index),
            )
            session.add(scan)
            session.commit()
            ids.append(scan.id)
        return ids
    finally:
        session.close()


def _claim_in_thread(migrated, worker: str, limit: int, start: threading.Event) -> list:
    """One claimant, on its own session and connection."""
    from zanshin.services.scan_queue import claim_next

    session = migrated.SessionLocal()
    try:
        # Released together, so the claims genuinely overlap instead of happening in
        # whatever order the threads were created.
        start.wait(timeout=10)
        return [scan.id for scan in claim_next(session, limit=limit, worker=worker)]
    finally:
        session.close()


# --- The guarantee --------------------------------------------------------------

def test_the_backend_supports_skip_locked(empty):
    """If this fails, everything below is testing the fallback by accident."""
    from zanshin.services.scan_queue import supports_skip_locked

    session = empty.SessionLocal()
    try:
        assert supports_skip_locked(session) is True
    finally:
        session.close()


def test_concurrent_claimants_never_receive_the_same_scan(empty):
    """The property ADR-002 D1 is about, and the reason this file needs a server.

    Ten claimants, one scan each, twenty scans available: every scan handed out at most
    once, and no claimant handed a scan another one also got.
    """
    scan_ids = _queue_scans(empty, count=20)
    start = threading.Event()

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [
            pool.submit(_claim_in_thread, empty, f"worker-{index}", 1, start)
            for index in range(10)
        ]
        start.set()
        results = [future.result(timeout=60) for future in futures]

    claimed = [scan_id for result in results for scan_id in result]
    assert len(claimed) == len(set(claimed)), (
        f"a scan was claimed twice: {sorted(claimed)}"
    )
    assert len(claimed) == 10  # each claimant asked for one and there were plenty
    assert set(claimed) <= set(scan_ids)


def test_every_scan_is_claimed_exactly_once_when_claimants_outnumber_work(empty):
    """The harder direction: more claimants than scans, so most of them must come back
    empty rather than sharing."""
    scan_ids = _queue_scans(empty, count=4)
    start = threading.Event()

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = [
            pool.submit(_claim_in_thread, empty, f"worker-{index}", 2, start)
            for index in range(12)
        ]
        start.set()
        results = [future.result(timeout=60) for future in futures]

    claimed = [scan_id for result in results for scan_id in result]
    assert sorted(claimed) == sorted(scan_ids), (
        "every queued scan must be claimed once and only once"
    )


def test_a_claim_records_one_owner_per_scan(empty):
    """Not just "claimed once" but "owned by one": the lease and `claimed_by` are what
    startup recovery and `still_owned` read, so a row with the wrong owner is as bad as
    a row claimed twice."""
    from zanshin.models.scan import Scan
    from zanshin.services.scan_queue import STATUS_RUNNING

    _queue_scans(empty, count=6)
    start = threading.Event()

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [
            pool.submit(_claim_in_thread, empty, f"worker-{index}", 1, start)
            for index in range(6)
        ]
        start.set()
        claimed = [scan_id for future in futures for scan_id in future.result(timeout=60)]

    session = empty.SessionLocal()
    try:
        rows = session.query(Scan).filter(Scan.id.in_(claimed)).all()
        assert len(rows) == 6
        for row in rows:
            assert row.status == STATUS_RUNNING
            assert row.claimed_by is not None
            assert row.lease_expires_at is not None
            assert row.attempts == 1
        # Six distinct workers claimed six scans; none of them shares an owner.
        assert len({row.claimed_by for row in rows}) == 6
    finally:
        session.close()


def test_claimants_do_not_block_each_other_on_the_oldest_row(empty):
    """`SKIP LOCKED`, not just `FOR UPDATE`: without the skip, every claimant would
    queue behind the first one on the oldest row, and a fleet would drain the queue one
    scan at a time no matter how many agents it had.

    Measured as throughput rather than timing: if the claims serialised, the four
    claimants asking for two scans each could not all come back full.
    """
    _queue_scans(empty, count=8)
    start = threading.Event()

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [
            pool.submit(_claim_in_thread, empty, f"worker-{index}", 2, start)
            for index in range(4)
        ]
        start.set()
        results = [future.result(timeout=30) for future in futures]

    assert sum(len(result) for result in results) == 8
    assert all(len(result) == 2 for result in results), (
        f"claims did not proceed in parallel: {results}"
    )


def test_the_claim_is_still_ordered_oldest_first(empty):
    """Parallel claiming must not turn the queue into a free-for-all: a caller shown
    "3 ahead of you" has to be served third."""
    scan_ids = _queue_scans(empty, count=5)
    session = empty.SessionLocal()
    try:
        from zanshin.services.scan_queue import claim_next

        claimed = [scan.id for scan in claim_next(session, limit=3, worker="solo")]
        assert claimed == scan_ids[:3]
    finally:
        session.close()


def test_a_claimed_scan_is_not_offered_again(empty):
    scan_ids = _queue_scans(empty, count=2)
    first_session = empty.SessionLocal()
    second_session = empty.SessionLocal()
    try:
        from zanshin.services.scan_queue import claim_next

        first = [scan.id for scan in claim_next(first_session, limit=5, worker="a")]
        second = [scan.id for scan in claim_next(second_session, limit=5, worker="b")]

        assert sorted(first) == sorted(scan_ids)
        assert second == []
    finally:
        first_session.close()
        second_session.close()
