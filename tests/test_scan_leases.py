"""Tests for scan ownership and leases.

`status = 'scanning'` used to be the whole story about a running scan, which left
two questions unanswerable: who is running it, and is that worker still alive.
Everything here is about those two — and about the property they buy, which is
that a worker can disappear without either losing the work or corrupting somebody
else's.
"""
from datetime import timedelta

import pytest

from zanshin.clock import utcnow
from zanshin.models.scan import Scan
from zanshin.repositories.agent_repository import AgentRepository
from zanshin.services.agent_service import AgentService
from zanshin.services.scan_queue import (
    LEASE_SECONDS,
    MAX_ATTEMPTS,
    STATUS_QUEUED,
    STATUS_RUNNING,
    claim_next,
    count_running,
    dispatch,
    reclaim_expired_leases,
    renew_lease,
    still_owned,
)

WORKER_A = "a" * 32
WORKER_B = "b" * 32


def _queued(db, repo_id=None):
    scan = Scan(repo_id=repo_id, branch="main", status=STATUS_QUEUED, findings_count=0,
                created_at=utcnow())
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# --- Claiming -----------------------------------------------------------------

def test_a_claim_records_the_owner_and_takes_a_lease(db_session, make_repository):
    scan = _queued(db_session, make_repository().id)

    claimed = claim_next(db_session, limit=1, worker=WORKER_A)

    assert claimed[0].claimed_by == WORKER_A
    assert claimed[0].claimed_at is not None
    assert claimed[0].lease_expires_at > utcnow()
    # Counted from the row: how many times *this scan* has been picked up.
    assert claimed[0].attempts == 1


def test_attempts_accumulate_across_claims(db_session, make_repository):
    scan = _queued(db_session, make_repository().id)

    claim_next(db_session, limit=1, worker=WORKER_A)
    reclaim_expired_leases(db_session, now=utcnow() + timedelta(seconds=LEASE_SECONDS + 1))
    claim_next(db_session, limit=1, worker=WORKER_B)

    db_session.refresh(scan)
    assert scan.attempts == 2
    assert scan.claimed_by == WORKER_B


def test_the_concurrency_limit_is_per_worker(db_session, make_repository):
    """Counting every running scan would have meant that adding a remote agent
    *reduced* what the host itself was allowed to do."""
    repo = make_repository()
    first = _queued(db_session, repo.id)
    claim_next(db_session, limit=1, worker=WORKER_A)

    assert count_running(db_session, worker=WORKER_A) == 1
    assert count_running(db_session, worker=WORKER_B) == 0
    # And globally, for the dashboard.
    assert count_running(db_session) == 1


def test_an_unowned_running_scan_counts_towards_the_builtin_agent(db_session, make_repository):
    """What a scan claimed before the lease columns existed looks like. Counted for
    the local worker, deliberately: the risk of over-counting is a scan waiting a
    little, the risk of under-counting is a host running more scanners than it was
    told to."""
    repo = make_repository()
    db_session.add(Scan(repo_id=repo.id, branch="main", status=STATUS_RUNNING, findings_count=0))
    db_session.commit()

    assert count_running(db_session, worker=WORKER_A) == 0
    assert count_running(db_session, worker=WORKER_A, include_unowned=True) == 1


# --- Renewal ------------------------------------------------------------------

def test_renewing_pushes_the_lease_out(db_session, make_repository):
    scan = _queued(db_session, make_repository().id)
    claim_next(db_session, limit=1, worker=WORKER_A)
    db_session.refresh(scan)
    before = scan.lease_expires_at

    # Force the lease into the past so the renewal is observable.
    scan.lease_expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    assert renew_lease(db_session, scan.id, WORKER_A) is True
    db_session.refresh(scan)
    assert scan.lease_expires_at > utcnow()


def test_a_worker_cannot_renew_a_scan_it_does_not_hold(db_session, make_repository):
    """Otherwise an agent whose lease lapsed could resurrect its claim on work that
    has already been handed to someone else."""
    scan = _queued(db_session, make_repository().id)
    claim_next(db_session, limit=1, worker=WORKER_A)

    assert renew_lease(db_session, scan.id, WORKER_B) is False


def test_renewing_without_a_worker_is_refused_rather_than_applied_to_everyone(db_session):
    assert renew_lease(db_session, 1, "") is False


# --- Ownership on the way out -------------------------------------------------

def test_still_owned_is_what_stops_a_late_worker_overwriting_a_result(
    db_session, make_repository
):
    scan = _queued(db_session, make_repository().id)
    claim_next(db_session, limit=1, worker=WORKER_A)

    assert still_owned(db_session, scan.id, WORKER_A) is True
    assert still_owned(db_session, scan.id, WORKER_B) is False


def test_a_scan_with_no_recorded_owner_accepts_its_result(db_session, make_repository):
    """Refusing it would strand rows queued before ownership existed: nothing else
    is ever going to finish them."""
    repo = make_repository()
    scan = Scan(repo_id=repo.id, branch="main", status=STATUS_RUNNING, findings_count=0)
    db_session.add(scan)
    db_session.commit()

    assert still_owned(db_session, scan.id, WORKER_A) is True


def test_results_for_a_scan_that_no_longer_exists_are_refused(db_session):
    assert still_owned(db_session, 4242, WORKER_A) is False


# --- Reclaiming ---------------------------------------------------------------

def test_a_lapsed_lease_returns_the_scan_to_the_queue(db_session, make_repository):
    scan = _queued(db_session, make_repository().id)
    claim_next(db_session, limit=1, worker=WORKER_A)

    reclaimed = reclaim_expired_leases(
        db_session, now=utcnow() + timedelta(seconds=LEASE_SECONDS + 1)
    )

    assert [s.id for s in reclaimed] == [scan.id]
    db_session.refresh(scan)
    assert scan.status == STATUS_QUEUED
    assert scan.claimed_by is None
    assert scan.lease_expires_at is None


def test_a_live_lease_is_left_alone(db_session, make_repository):
    scan = _queued(db_session, make_repository().id)
    claim_next(db_session, limit=1, worker=WORKER_A)

    assert reclaim_expired_leases(db_session) == []
    db_session.refresh(scan)
    assert scan.status == STATUS_RUNNING


def test_a_scan_out_of_attempts_is_failed_instead_of_re_queued(db_session, make_repository):
    """A target that wedges whatever picks it up would otherwise cycle through the
    whole fleet forever, and the operator would only ever see "about to start"."""
    scan = _queued(db_session, make_repository().id)
    claim_next(db_session, limit=1, worker=WORKER_A)
    scan.attempts = MAX_ATTEMPTS
    db_session.commit()

    reclaim_expired_leases(db_session, now=utcnow() + timedelta(seconds=LEASE_SECONDS + 1))

    db_session.refresh(scan)
    assert scan.status == "failed"
    assert str(MAX_ATTEMPTS) in scan.error


# --- Through the dispatcher ---------------------------------------------------

def test_the_builtin_agent_claims_scans_in_its_own_name(db_session, make_repository, queue_env):
    run, submitted, agent_service = queue_env
    scan = _queued(db_session, make_repository().id)

    assert run() == 1

    db_session.refresh(scan)
    assert scan.claimed_by == agent_service.ensure_builtin_agent().worker_id
    assert scan.lease_expires_at is not None


def test_disabling_the_builtin_agent_stops_this_instance_claiming_anything(
    db_session, make_repository, queue_env
):
    """The point of the feature: an operator says "run nothing here", and the queue
    waits for a remote agent instead of quietly using the web instance."""
    run, submitted, agent_service = queue_env
    agent = agent_service.ensure_builtin_agent()
    agent_service.set_enabled(agent.id, False)
    scan = _queued(db_session, make_repository().id)

    assert run() == 0
    assert submitted == []

    db_session.refresh(scan)
    assert scan.status == STATUS_QUEUED  # still waiting, not failed
    assert scan.claimed_by is None


@pytest.fixture()
def queue_env(db_session, settings_service, monkeypatch):
    """`dispatch` pointed at this session, with a real agent registry."""
    from zanshin.services import scan_queue

    submitted = []
    agent_service = AgentService(
        AgentRepository(db_session), settings_service=settings_service
    )

    class ImmediateExecutor:
        @staticmethod
        def submit(fn, *args, **kwargs):
            submitted.append(args)

    class FakeContainer:
        def __init__(self, db):
            self.settings_service = settings_service
            self.scan_processor = None
            self.agent_service = agent_service

    class NonClosing:
        def __init__(self, session):
            self._session = session

        def __getattr__(self, name):
            return getattr(self._session, name)

        def close(self):
            return None

    monkeypatch.setattr(scan_queue, "executor", ImmediateExecutor)

    def run():
        return dispatch(
            session_factory=lambda: NonClosing(db_session), container_factory=FakeContainer
        )

    return run, submitted, agent_service
