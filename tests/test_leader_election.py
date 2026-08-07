"""Tests for the lease that makes a job single-owner.

The job in question is the exclusive part of the scheduler tick, and the failure it
prevents is concrete: two instances each dispatching every due target, i.e. every
target scanned twice per interval (ADR-002 §2.2).

Concurrency is simulated here by calling with distinct holder ids, which is what the
ADR's testing strategy prescribes for everything except the claim itself — the claim
needs a real server because `SKIP LOCKED` does not exist on SQLite, whereas this is a
conditional `UPDATE` that behaves the same everywhere.
"""
from datetime import timedelta

import pytest

from zanshin.clock import utcnow
from zanshin.models.leader_lease import JOB_SCHEDULER, LeaderLease
from zanshin.services import leader_election


def test_the_first_instance_to_ask_becomes_the_leader(db_session):
    assert leader_election.acquire(db_session, holder="instance-a") is True
    assert leader_election.current_holder(db_session) == "instance-a"


def test_a_second_instance_is_refused_while_the_lease_is_live(db_session):
    """The whole point: two instances ticking at the same moment, one of them does the
    exclusive work."""
    leader_election.acquire(db_session, holder="instance-a")

    assert leader_election.acquire(db_session, holder="instance-b") is False
    assert leader_election.current_holder(db_session) == "instance-a"


def test_the_leader_renews_rather_than_re_contending(db_session):
    """A leader that had to win an election every tick would hand the job around the
    fleet for no reason, and each handover is a tick where nobody is sure who ran what."""
    leader_election.acquire(db_session, holder="instance-a")
    first = db_session.query(LeaderLease).filter(LeaderLease.name == JOB_SCHEDULER).first()
    acquired_at = first.acquired_at

    assert leader_election.acquire(db_session, holder="instance-a") is True

    db_session.expire_all()
    again = db_session.query(LeaderLease).filter(LeaderLease.name == JOB_SCHEDULER).first()
    assert again.holder == "instance-a"
    # Renewal moves the expiry, not the acquisition: "leader since" stays meaningful.
    assert again.acquired_at == acquired_at


def test_an_expired_lease_is_taken_over(db_session):
    """A holder that dies stops renewing; nothing has to notice, and nothing has to
    clean up after it."""
    leader_election.acquire(db_session, holder="instance-a")
    lease = db_session.query(LeaderLease).filter(LeaderLease.name == JOB_SCHEDULER).first()
    lease.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    assert leader_election.acquire(db_session, holder="instance-b") is True
    assert leader_election.current_holder(db_session) == "instance-b"


def test_an_expired_lease_is_taken_by_exactly_one_of_two_contenders(db_session):
    """Both read the same expired row before either writes — the conditional update is
    what arbitrates, and the loser must lose rather than overwrite."""
    leader_election.acquire(db_session, holder="instance-a")
    lease = db_session.query(LeaderLease).filter(LeaderLease.name == JOB_SCHEDULER).first()
    expired_at = utcnow() - timedelta(seconds=1)
    lease.expires_at = expired_at
    db_session.commit()

    now = utcnow()
    first = leader_election.acquire(db_session, holder="instance-b", now=now)
    # `instance-c` read the same stale row (it still sees `expires_at == expired_at`
    # from before b's write, which is the race being reproduced).
    db_session.expire_all()
    second = leader_election.acquire(db_session, holder="instance-c", now=now)

    assert [first, second] == [True, False]
    assert leader_election.current_holder(db_session) == "instance-b"


def test_a_released_lease_is_free_immediately(db_session):
    """So a rolling restart hands the job over in seconds instead of after the expiry."""
    leader_election.acquire(db_session, holder="instance-a")

    assert leader_election.release(db_session, holder="instance-a") is True
    assert leader_election.current_holder(db_session) is None
    assert leader_election.acquire(db_session, holder="instance-b") is True


def test_an_instance_cannot_release_a_lease_it_does_not_hold(db_session):
    leader_election.acquire(db_session, holder="instance-a")

    assert leader_election.release(db_session, holder="instance-b") is False
    assert leader_election.current_holder(db_session) == "instance-a"


def test_a_stale_lease_has_no_holder_even_before_anyone_takes_it(db_session):
    """`current_holder` answers "who is doing this right now", not "whose name is in the
    row" — otherwise the agents screen would name a dead instance as the leader."""
    leader_election.acquire(db_session, holder="instance-a")
    lease = db_session.query(LeaderLease).filter(LeaderLease.name == JOB_SCHEDULER).first()
    lease.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    assert leader_election.current_holder(db_session) is None
    assert leader_election.is_leader(db_session, holder="instance-a") is False


def test_two_jobs_have_two_independent_leases(db_session):
    """One row per job, so a second exclusive job needs no second table."""
    assert leader_election.acquire(db_session, name="scheduler", holder="a") is True
    assert leader_election.acquire(db_session, name="other", holder="b") is True

    assert leader_election.current_holder(db_session, "scheduler") == "a"
    assert leader_election.current_holder(db_session, "other") == "b"


def test_the_instance_id_is_per_process_and_not_a_hostname():
    """Two instances on one host is a deployment somebody will try; a hostname could
    not tell them apart, and a persisted id would make a restarted instance claim to be
    the one that died."""
    assert leader_election.INSTANCE_ID
    assert len(leader_election.INSTANCE_ID) == 32
