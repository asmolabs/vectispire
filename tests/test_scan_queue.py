"""Tests for the scan queue.

Three properties are what was asked for and what has to hold: scans run **in the order
they were requested**, no more than **the configured number** run at once, and a
request **survives** the process that accepted it. The third is the one the old design
could not do at all — the queue was a `ThreadPoolExecutor`, so a restart lost everything
waiting in it while leaving the rows behind as `pending` forever.
"""
import pytest

from zanshin.models.scan import Scan
from zanshin.services import scan_queue
from zanshin.services.scan_queue import (
    STATUS_QUEUED,
    STATUS_RUNNING,
    claim_next,
    count_queued,
    count_running,
    dispatch,
    max_concurrent,
    position_of,
)


@pytest.fixture()
def queue(db_session, settings_service, monkeypatch):
    """A dispatcher pointed at this session, recording what it submits.

    `executor.submit` is replaced by a plain call: the point of these tests is the
    claim and the ordering, and a real thread pool would make them race.
    """
    submitted = []

    class ImmediateExecutor:
        @staticmethod
        def submit(fn, *args, **kwargs):
            submitted.append(args)

    class FakeContainer:
        def __init__(self, db):
            self.settings_service = settings_service
            self.scan_processor = None

    monkeypatch.setattr(scan_queue, "executor", ImmediateExecutor)

    class NonClosing:
        def __init__(self, session):
            self._session = session

        def __getattr__(self, name):
            return getattr(self._session, name)

        def close(self):
            return None

    def run():
        return dispatch(
            session_factory=lambda: NonClosing(db_session), container_factory=FakeContainer
        )

    return run, submitted


def _queued(db, make_repository, count=1):
    """`count` queued scans, in a known creation order."""
    from datetime import timedelta

    from zanshin.clock import utcnow

    base = utcnow()
    scans = []
    for index in range(count):
        repo = make_repository(url=f"git@example.com:org/r{index}.git")
        scan = Scan(
            repo_id=repo.id,
            branch="main",
            status=STATUS_QUEUED,
            findings_count=0,
            created_at=base + timedelta(seconds=index),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scans.append(scan)
    return scans


# --- Configuration ---

def test_the_limit_defaults_to_the_old_environment_variable(settings_service):
    """An existing deployment behaves exactly as before until somebody changes it."""
    assert max_concurrent(settings_service) == scan_queue.DEFAULT_MAX_CONCURRENT


def test_the_limit_is_read_from_the_setting(settings_service, setting_repository):
    from zanshin.models.setting import Setting

    setting_repository.save(Setting(key="scan_max_concurrent", value="3"))

    assert max_concurrent(settings_service) == 3


def test_a_nonsense_limit_falls_back_to_the_default(settings_service, setting_repository):
    from zanshin.models.setting import Setting

    setting_repository.save(Setting(key="scan_max_concurrent", value="beaucoup"))

    assert max_concurrent(settings_service) == scan_queue.DEFAULT_MAX_CONCURRENT


def test_the_limit_is_at_least_one_and_never_exceeds_the_pool(settings_service):
    """A limit above the pool size would be a lie: the pool would cap it silently."""
    settings_service.update_setting("scan_max_concurrent", "0")
    assert max_concurrent(settings_service) == 1

    settings_service.update_setting("scan_max_concurrent", "9999")
    assert max_concurrent(settings_service) == scan_queue.POOL_THREADS


# --- Ordering ---

def test_scans_are_claimed_in_the_order_they_were_requested(db_session, make_repository):
    scans = _queued(db_session, make_repository, count=3)

    claimed = claim_next(db_session, limit=3)

    assert [s.id for s in claimed] == [s.id for s in scans]


def test_ties_are_broken_by_id_so_the_order_is_total(db_session, make_repository):
    """Two scans queued in the same instant must still have a defined order, or the
    position shown to a caller would not be the position it is served in."""
    from zanshin.clock import utcnow

    moment = utcnow()
    repo = make_repository()
    first = Scan(repo_id=repo.id, branch="main", status=STATUS_QUEUED, findings_count=0, created_at=moment)
    second = Scan(repo_id=repo.id, branch="main", status=STATUS_QUEUED, findings_count=0, created_at=moment)
    db_session.add_all([first, second])
    db_session.commit()

    claimed = claim_next(db_session, limit=2)

    assert [s.id for s in claimed] == sorted([first.id, second.id])


def test_a_claim_marks_the_scan_running(db_session, make_repository):
    _queued(db_session, make_repository)

    claimed = claim_next(db_session, limit=1)

    assert claimed[0].status == STATUS_RUNNING
    assert count_queued(db_session) == 0
    assert count_running(db_session) == 1


def test_a_scan_is_never_claimed_twice(db_session, make_repository):
    """The conditional update is what decides the winner: without it, two dispatchers
    reading the same row would both submit it and the target would be scanned twice at
    once — the thing the in-flight guard exists to prevent."""
    _queued(db_session, make_repository)

    first = claim_next(db_session, limit=5)
    second = claim_next(db_session, limit=5)

    assert len(first) == 1
    assert second == []


def test_claiming_nothing_is_not_an_error(db_session):
    assert claim_next(db_session, limit=5) == []
    assert claim_next(db_session, limit=0) == []


# --- The limit ---

def test_dispatch_starts_no_more_than_the_limit(db_session, make_repository, queue, setting_repository):
    from zanshin.models.setting import Setting

    run, submitted = queue
    setting_repository.save(Setting(key="scan_max_concurrent", value="2"))
    _queued(db_session, make_repository, count=5)

    started = run()

    assert started == 2
    assert len(submitted) == 2
    assert count_queued(db_session) == 3


def test_dispatch_accounts_for_what_is_already_running(
    db_session, make_repository, queue, setting_repository
):
    """Capacity is `limit − running`, computed per dispatch. Counting only what this
    call starts would let three dispatches launch nine scans under a limit of three."""
    from zanshin.models.setting import Setting

    run, submitted = queue
    setting_repository.save(Setting(key="scan_max_concurrent", value="3"))
    repo = make_repository()
    db_session.add_all([
        Scan(repo_id=repo.id, branch="main", status=STATUS_RUNNING, findings_count=0),
        Scan(repo_id=repo.id, branch="main", status=STATUS_RUNNING, findings_count=0),
    ])
    db_session.commit()
    _queued(db_session, make_repository, count=4)

    assert run() == 1
    assert count_running(db_session) == 3


def test_dispatch_does_nothing_when_the_limit_is_reached(
    db_session, make_repository, queue, setting_repository
):
    from zanshin.models.setting import Setting

    run, submitted = queue
    setting_repository.save(Setting(key="scan_max_concurrent", value="1"))
    repo = make_repository()
    db_session.add(Scan(repo_id=repo.id, branch="main", status=STATUS_RUNNING, findings_count=0))
    db_session.commit()
    _queued(db_session, make_repository, count=3)

    assert run() == 0
    assert submitted == []
    assert count_queued(db_session) == 3


def test_dispatch_drains_the_queue_across_calls(
    db_session, make_repository, queue, setting_repository
):
    """What happens in production as each scan finishes and frees its slot."""
    from zanshin.models.setting import Setting

    run, submitted = queue
    setting_repository.save(Setting(key="scan_max_concurrent", value="2"))
    _queued(db_session, make_repository, count=4)

    run()
    # Simulate the two running scans finishing.
    for scan in db_session.query(Scan).filter(Scan.status == STATUS_RUNNING).all():
        scan.status = "completed"
    db_session.commit()
    run()

    assert len(submitted) == 4
    assert count_queued(db_session) == 0


# --- Survival ---

def test_a_scan_queued_before_a_restart_is_still_dispatched(
    db_session, make_repository, queue
):
    """The property the old design could not have: the queue was a thread pool, so a
    restart lost everything waiting in it and left the rows `pending` forever."""
    run, submitted = queue
    scans = _queued(db_session, make_repository, count=2)

    # Nothing has ever been submitted for these rows — exactly the state a restart
    # leaves behind.
    assert run() == 2
    assert [args[1] for args in submitted] == [s.id for s in scans]


def test_what_is_submitted_carries_the_repository_details(db_session, make_repository, queue):
    """The dispatcher reads them from the row, because whoever queued the scan may be
    long gone."""
    run, submitted = queue
    repo = make_repository(url="git@example.com:org/app.git")
    scan = Scan(
        repo_id=repo.id, branch="release", sub_path="services/api",
        status=STATUS_QUEUED, findings_count=0,
    )
    db_session.add(scan)
    db_session.commit()

    run()

    _processor, scan_id, repo_url, branch, sub_path, _key = submitted[0]
    assert (scan_id, repo_url, branch, sub_path) == (
        scan.id, "git@example.com:org/app.git", "release", "services/api"
    )


def test_a_container_scan_has_no_repository_url(db_session, make_container, queue):
    run, submitted = queue
    image = make_container()
    db_session.add(
        Scan(container_id=image.id, branch="latest", status=STATUS_QUEUED, findings_count=0)
    )
    db_session.commit()

    run()

    _processor, _scan_id, repo_url, _branch, _sub_path, ssh_key_id = submitted[0]
    assert repo_url is None
    assert ssh_key_id is None


# --- Position ---

def test_the_position_is_one_based_and_in_service_order(db_session, make_repository):
    scans = _queued(db_session, make_repository, count=3)

    assert [position_of(db_session, s) for s in scans] == [1, 2, 3]


def test_a_running_scan_has_no_position(db_session, make_repository):
    scans = _queued(db_session, make_repository, count=2)
    claim_next(db_session, limit=1)

    assert position_of(db_session, scans[0]) is None
    # And the one still waiting moves up.
    assert position_of(db_session, scans[1]) == 1


def test_dispatch_never_raises(db_session, monkeypatch, make_repository):
    """It runs from a request, from a worker thread and from the scheduler tick; an
    exception in any of those would be someone else's failure."""
    def boom(*args, **kwargs):
        raise RuntimeError("simulated")

    monkeypatch.setattr(scan_queue, "claim_next", boom)

    assert dispatch(session_factory=lambda: db_session, container_factory=lambda db: None) == 0
