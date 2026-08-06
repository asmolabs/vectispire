"""Tests for scan recovery.

The bug these close was visible in the real deployment: three scans stuck in
`scanning` since a restart, which is not only a wrong badge — "the latest scan of
this target" is what issue resolution reads, so an orphan row distorts the
lifecycle too.
"""
from datetime import datetime, timedelta

from zanshin.clock import utcnow

from zanshin.models.scan import Scan
from zanshin.services.scan_queue import MAX_ATTEMPTS
from zanshin.services.scan_recovery import (
    INTERRUPTED_MESSAGE,
    fail_stalled_scans,
    reconcile_interrupted_scans,
)


def _scan(db, status, created_at=None):
    scan = Scan(
        branch="main",
        status=status,
        findings_count=0,
        created_at=created_at or utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def test_an_interrupted_scan_goes_back_into_the_queue(db_session):
    """It used to be failed. That was right when `pending` meant "about to run in
    this process", and wrong once the queue moved into the database: the work was
    never done, and the row *is* the queue entry."""
    scanning = _scan(db_session, "scanning")

    count = reconcile_interrupted_scans(db_session)

    assert count == 1
    db_session.refresh(scanning)
    assert scanning.status == "pending"
    assert scanning.claimed_by is None
    assert scanning.lease_expires_at is None


def test_a_queued_scan_is_left_alone(db_session):
    """The defect this closes: startup failed every `pending` row, destroying the
    one property the database-backed queue exists for — that a request survives the
    process that accepted it."""
    queued = _scan(db_session, "pending")

    assert reconcile_interrupted_scans(db_session) == 0

    db_session.refresh(queued)
    assert queued.status == "pending"


def test_a_scan_held_by_another_worker_under_a_valid_lease_is_not_touched(db_session):
    """ADR-002 §2.3: with one process, assuming every in-flight scan was orphaned
    was correct. With a remote agent it is destructive — starting the web instance
    would fail the scans that agent is busy running."""
    scan = _scan(db_session, "scanning")
    scan.claimed_by = "a" * 32  # some other agent
    scan.lease_expires_at = utcnow() + timedelta(minutes=10)
    db_session.commit()

    assert reconcile_interrupted_scans(db_session, local_worker="b" * 32) == 0

    db_session.refresh(scan)
    assert scan.status == "scanning"


def test_this_hosts_own_scan_is_reclaimed_even_under_a_valid_lease(db_session):
    """Its lease may not have lapsed yet, but the thread holding it died with the
    process that just restarted — waiting for the lease to expire would leave the
    scan stuck for twenty minutes for no reason."""
    scan = _scan(db_session, "scanning")
    scan.claimed_by = "local-worker"
    scan.lease_expires_at = utcnow() + timedelta(minutes=10)
    db_session.commit()

    assert reconcile_interrupted_scans(db_session, local_worker="local-worker") == 1

    db_session.refresh(scan)
    assert scan.status == "pending"


def test_a_scan_that_used_up_its_attempts_is_failed_rather_than_re_queued(db_session):
    """Otherwise a target that wedges whatever picks it up cycles forever, and the
    operator only ever sees a scan that is about to start."""
    scan = _scan(db_session, "scanning")
    scan.attempts = MAX_ATTEMPTS
    db_session.commit()

    assert reconcile_interrupted_scans(db_session) == 1

    db_session.refresh(scan)
    assert scan.status == "failed"
    # The operator should be able to tell this apart from a scanner failure.
    assert scan.error == INTERRUPTED_MESSAGE


def test_finished_scans_are_left_alone(db_session):
    completed = _scan(db_session, "completed")
    failed = _scan(db_session, "failed")
    failed.error = "grype a échoué"
    db_session.commit()

    assert reconcile_interrupted_scans(db_session) == 0

    db_session.refresh(completed)
    db_session.refresh(failed)
    assert completed.status == "completed"
    assert failed.error == "grype a échoué"


def test_reconciling_an_empty_database_is_a_no_op(db_session):
    assert reconcile_interrupted_scans(db_session) == 0


def test_stalled_scans_are_failed_only_past_the_cutoff(db_session):
    fresh = _scan(db_session, "scanning", created_at=utcnow())
    old = _scan(db_session, "scanning", created_at=utcnow() - timedelta(hours=3))

    count = fail_stalled_scans(db_session, max_age_seconds=3600)

    assert count == 1
    db_session.refresh(fresh)
    db_session.refresh(old)
    assert fresh.status == "scanning"  # still legitimately running
    assert old.status == "failed"


def test_a_long_running_but_healthy_scan_is_not_cut_short(db_session):
    """The cutoff exists to catch a wedged worker, not to cap a slow scan: one
    scan runs several scanners in sequence."""
    scan = _scan(db_session, "scanning", created_at=utcnow() - timedelta(minutes=20))

    assert fail_stalled_scans(db_session, max_age_seconds=5400) == 0
    db_session.refresh(scan)
    assert scan.status == "scanning"
