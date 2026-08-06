"""Tests for scan recovery.

The bug these close was visible in the real deployment: three scans stuck in
`scanning` since a restart, which is not only a wrong badge — "the latest scan of
this target" is what issue resolution reads, so an orphan row distorts the
lifecycle too.
"""
from datetime import datetime, timedelta

from zanshin.clock import utcnow

from zanshin.models.scan import Scan
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


def test_interrupted_scans_are_failed_with_an_explanation(db_session):
    pending = _scan(db_session, "pending")
    scanning = _scan(db_session, "scanning")

    count = reconcile_interrupted_scans(db_session)

    assert count == 2
    db_session.refresh(pending)
    db_session.refresh(scanning)
    assert pending.status == "failed"
    assert scanning.status == "failed"
    # The operator should be able to tell this apart from a scanner failure.
    assert scanning.error == INTERRUPTED_MESSAGE


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
