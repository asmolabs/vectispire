"""Recovery of scans that will never finish on their own.

A scan's state lives in the database while the work happens in a worker thread.
Nothing reconciled the two, so any scan whose worker vanished — process
restarted, container killed, thread wedged — stayed `pending`/`scanning`
forever. The real deployment this was written against had three such rows, and
they were poisoning more than the display: "the latest scan of this target" is
what the issue lifecycle reads to decide whether a problem is still observed.

Two entry points, because there are two distinct failure modes:

- `reconcile_interrupted_scans` at startup: any in-flight scan is orphaned by
  definition, since the threads that owned them died with the previous process.
- `fail_stalled_scans`, called periodically by the scheduler: a worker still
  alive but stuck past every timeout the scanners allow.
"""
import logging
from datetime import timedelta
from typing import List, Optional

from sqlalchemy.orm import Session

from zanshin.clock import utcnow
from zanshin.models.scan import Scan
from zanshin.services.scan_queue import MAX_ATTEMPTS, STATUS_QUEUED, STATUS_RUNNING

logger = logging.getLogger(__name__)

IN_FLIGHT_STATUSES = ("pending", "scanning")

INTERRUPTED_MESSAGE = "Scan interrompu : le processus Zanshin a redémarré pendant l'analyse."
STALLED_MESSAGE = "Scan abandonné : aucune progression au-delà du délai maximum autorisé."


def reconcile_interrupted_scans(db: Session, local_worker: Optional[str] = None) -> int:
    """Recover the scans a previous run of *this* process left behind.

    Returns how many rows were touched. Two things changed here when scans became
    ownable (ADR-002), and both were defects rather than preferences:

    **Queued scans are no longer failed.** `pending` stopped meaning "accepted, about
    to run in this process" when the queue moved into the database — it now means
    "waiting in line". Failing those at startup destroyed exactly the property the
    queue was built for: that a request survives the process that accepted it. A
    queued scan is left alone; `scan_queue.dispatch` will pick it up.

    **A running scan is only reclaimed if nobody else holds it.** The old version
    failed every in-flight scan on the assumption that its worker died with the
    previous process. True with one worker; destructive with two — starting the web
    instance would have failed the scans a remote agent was running (ADR-002 §2.3).
    So a scan is reclaimed when it has no owner, when its owner is this host's
    built-in agent (whose threads did die with the previous process), or when its
    lease has lapsed; otherwise it belongs to somebody who is still reporting, and
    it is left alone.

    Reclaiming means **re-queueing**, not failing: the work was never done, and the
    row is the queue entry. A scan that has already used up its attempts is failed
    instead, so a target that wedges every worker it touches does not cycle forever.
    """
    now = utcnow()
    running: List[Scan] = db.query(Scan).filter(Scan.status == STATUS_RUNNING).all()

    reclaimed, exhausted = [], []
    for scan in running:
        if not _is_orphaned(scan, local_worker, now):
            continue
        if (scan.attempts or 0) >= MAX_ATTEMPTS:
            scan.status = "failed"
            scan.error = INTERRUPTED_MESSAGE
            exhausted.append(scan)
        else:
            scan.status = STATUS_QUEUED
            scan.claimed_by = None
            scan.claimed_at = None
            scan.lease_expires_at = None
            reclaimed.append(scan)

    if not reclaimed and not exhausted:
        return 0

    db.commit()
    if reclaimed:
        logger.warning(
            "Re-queued %d interrupted scan(s) at startup: %s",
            len(reclaimed), ", ".join(str(scan.id) for scan in reclaimed),
        )
    if exhausted:
        logger.warning(
            "Failed %d interrupted scan(s) that had used up their attempts: %s",
            len(exhausted), ", ".join(str(scan.id) for scan in exhausted),
        )
    return len(reclaimed) + len(exhausted)


def _is_orphaned(scan: Scan, local_worker: Optional[str], now) -> bool:
    """Whether nobody is plausibly still working on this scan."""
    if scan.claimed_by is None:
        # Claimed before leases existed, or by a path that does not record an
        # owner: there is nothing that could still be reporting on it.
        return True
    if local_worker and scan.claimed_by == local_worker:
        # This host's built-in agent — i.e. the process that just restarted.
        return True
    # Compared in Python, like `fail_stalled_scans` below: `SafeDateTime`
    # tolerates legacy string values, which don't compare reliably in SQL.
    return scan.lease_expires_at is None or scan.lease_expires_at < now


def fail_stalled_scans(db: Session, max_age_seconds: int) -> int:
    """Fail scans still in flight well past any legitimate duration.

    `max_age_seconds` should be comfortably larger than a single scanner's
    timeout, since one scan runs several of them in sequence — the goal is to
    catch a wedged worker, not to cut short a slow but healthy scan.
    """
    cutoff = utcnow() - timedelta(seconds=max_age_seconds)
    stalled = [
        scan
        for scan in db.query(Scan).filter(Scan.status.in_(IN_FLIGHT_STATUSES)).all()
        # Compared in Python: `SafeDateTime` tolerates legacy string values,
        # which don't compare reliably in SQL (see ScanRepository).
        if scan.created_at and scan.created_at < cutoff
    ]
    if not stalled:
        return 0

    for scan in stalled:
        scan.status = "failed"
        scan.error = STALLED_MESSAGE
    db.commit()
    logger.warning(
        "Marked %d stalled scan(s) as failed: %s",
        len(stalled), ", ".join(str(scan.id) for scan in stalled),
    )
    return len(stalled)
