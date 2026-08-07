"""Which instance owns a job that must have exactly one owner.

The scheduler tick does six things, and most of them are only correct if a single
process does them. The clearest is periodic rescanning: `last_scheduled_scan_at` is
stamped before dispatch, which protects against one process ticking twice and not at
all against two processes ticking at the same moment. Two instances would mean two
scans per due target — double the containers, double the registry traffic, double the
enrichment calls, and two scan rows where an operator expects one (ADR-002 §2.2).

So the exclusive part of the tick is taken under a **lease** held in this table: one
row per job name, holding the instance's id and an expiry. A holder that dies simply
stops renewing, and the next tick to run after the expiry takes over.

**Why a lease row rather than an advisory lock.** `pg_advisory_lock` and MySQL's
`GET_LOCK` are per-engine, differently named and differently scoped, and neither
exists on SQLite — so the mono-instance deployment would have to special-case itself.
A row works identically on all three, keeps working when the "fleet" is one process,
and — the reason that decided it — is *observable*: when something has stopped
happening, `SELECT * FROM leader_lease` says who was supposed to be doing it and
until when. An advisory lock answers no question after the fact.

**Why an expiry rather than a heartbeat table.** The two are the same mechanism; an
expiry is the one that fails safe. Nothing has to notice a dead holder and clean up
after it: the row goes stale on its own, and the taking of it is a conditional
`UPDATE` whose row count decides the winner.
"""
from sqlalchemy import Column, String

from zanshin.clock import utcnow
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

# The one job that needs an owner today. Named rather than implicit so a second
# exclusive job can be added without inventing a second table.
JOB_SCHEDULER = "scheduler"


class LeaderLease(Base):
    __tablename__ = "leader_lease"

    # The job, not the holder: there is one row per thing that needs exactly one
    # owner, and holders come and go through it.
    name = Column(String(64), primary_key=True)

    # Who holds it. An instance id, not a hostname: two instances on one host are a
    # legitimate (if unsupported) deployment, and a hostname could not tell them apart.
    holder = Column(String(64), nullable=True)

    acquired_at = Column(SafeDateTime, nullable=True)
    # Renewed by the holder on every tick. Past this, anybody may take the lease —
    # which is what makes a dead holder self-correcting rather than something an
    # operator has to notice.
    expires_at = Column(SafeDateTime, nullable=True)

    updated_at = Column(SafeDateTime, default=utcnow, nullable=False)
