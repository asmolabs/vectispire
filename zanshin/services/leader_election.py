"""Taking, holding and losing the lease that makes a job single-owner.

Three operations, all built on the same primitive: a conditional `UPDATE` whose row
count decides the winner. That primitive is weaker than `SELECT … FOR UPDATE SKIP
LOCKED` (see `scan_queue`) and here it is enough, because the thing being protected is
idempotent-ish and periodic: two instances briefly believing they are the leader would
mean one duplicated tick, not a corrupted row, and the next tick settles it.

**What "leader" covers, and what it deliberately does not.** The exclusive work is the
part of the scheduler tick that has an effect *per period* — dispatching due targets,
retention, triage expiry, the outbox relay, the ticket sweep, reclaiming abandoned
scans. Not the part that is per-instance by nature: every instance must keep claiming
work for its own built-in agent and refreshing its own liveness, or a fleet would idle
behind whichever instance happens to hold the lease.
"""
import logging
import os
import uuid
from datetime import timedelta
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zanshin.clock import utcnow
from zanshin.models.leader_lease import JOB_SCHEDULER, LeaderLease

logger = logging.getLogger(__name__)

# How long a lease is held without renewal. Comfortably longer than the tick that
# renews it (60s), so a slow tick does not hand the job to somebody else, and short
# enough that a dead leader is replaced within a couple of minutes rather than an hour.
LEASE_SECONDS = int(os.getenv("ZANSHIN_LEADER_LEASE_SECONDS", "180"))

# This process, for the lifetime of this process. Not the hostname: two instances on
# one host is a deployment somebody will try, and a hostname could not tell them apart.
# Not persisted either — a restarted instance is a new holder, which is exactly right,
# since it has forgotten whatever it was in the middle of.
INSTANCE_ID = uuid.uuid4().hex


def acquire(db: Session, name: str = JOB_SCHEDULER, holder: Optional[str] = None,
            now=None) -> bool:
    """Take or renew the lease. Returns whether this process holds it.

    Three cases, in one function because the caller does not care which it was: nobody
    has ever held it, somebody holds it but let it expire, or we already hold it and
    are renewing. The renewal is what makes the leader stable — a leader that had to
    re-contend every tick would hand the job around the fleet for no reason.
    """
    holder = holder or INSTANCE_ID
    now = now or utcnow()
    expires_at = now + timedelta(seconds=LEASE_SECONDS)

    lease = db.query(LeaderLease).filter(LeaderLease.name == name).first()
    if lease is None:
        return _create(db, name, holder, now, expires_at)

    is_mine = lease.holder == holder
    is_expired = lease.expires_at is None or lease.expires_at <= now
    if not is_mine and not is_expired:
        return False

    # Conditional on the holder *and* the expiry we just read: if another instance took
    # the lease between the read and this update, its row count is zero and we lose,
    # rather than stealing a lease somebody else legitimately holds.
    updated = (
        db.query(LeaderLease)
        .filter(
            LeaderLease.name == name,
            LeaderLease.holder == lease.holder,
            *([] if is_mine else [LeaderLease.expires_at == lease.expires_at]),
        )
        .update(
            {
                LeaderLease.holder: holder,
                LeaderLease.expires_at: expires_at,
                LeaderLease.updated_at: now,
                **({} if is_mine else {LeaderLease.acquired_at: now}),
            },
            synchronize_session=False,
        )
    )
    db.commit()
    if updated and not is_mine:
        logger.info("Instance %s took the '%s' lease", holder, name)
    return bool(updated)


def _create(db: Session, name: str, holder: str, now, expires_at) -> bool:
    """First ever acquisition. Two instances starting together both try this, and the
    primary key is what arbitrates — the loser catches the constraint and re-reads."""
    db.add(LeaderLease(
        name=name, holder=holder, acquired_at=now, expires_at=expires_at, updated_at=now
    ))
    try:
        db.commit()
        logger.info("Instance %s took the '%s' lease", holder, name)
        return True
    except IntegrityError:
        db.rollback()
        return False


def release(db: Session, name: str = JOB_SCHEDULER, holder: Optional[str] = None) -> bool:
    """Give the lease up, so a successor can take it now instead of after the expiry.

    Called on shutdown. Best-effort by nature — a process that is killed cannot release
    anything, which is why the expiry exists and why nothing depends on this being
    reached.
    """
    holder = holder or INSTANCE_ID
    released = (
        db.query(LeaderLease)
        .filter(LeaderLease.name == name, LeaderLease.holder == holder)
        .update(
            {LeaderLease.holder: None, LeaderLease.expires_at: None,
             LeaderLease.updated_at: utcnow()},
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(released)


def current_holder(db: Session, name: str = JOB_SCHEDULER, now=None) -> Optional[str]:
    """Who holds the lease right now, or `None` if it is free or stale.

    For display and diagnosis: "nothing is happening" is a question this answers.
    """
    now = now or utcnow()
    lease = db.query(LeaderLease).filter(LeaderLease.name == name).first()
    if lease is None or lease.holder is None:
        return None
    if lease.expires_at is None or lease.expires_at <= now:
        return None
    return lease.holder


def is_leader(db: Session, name: str = JOB_SCHEDULER, holder: Optional[str] = None,
              now=None) -> bool:
    """Whether this process holds the lease, without taking it."""
    return current_holder(db, name, now) == (holder or INSTANCE_ID)
