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
from typing import List

from sqlalchemy.orm import Session

from zanshin.clock import utcnow
from zanshin.models.scan import Scan

logger = logging.getLogger(__name__)

IN_FLIGHT_STATUSES = ("pending", "scanning")

INTERRUPTED_MESSAGE = "Scan interrompu : le processus Zanshin a redémarré pendant l'analyse."
STALLED_MESSAGE = "Scan abandonné : aucune progression au-delà du délai maximum autorisé."


def reconcile_interrupted_scans(db: Session) -> int:
    """Fail every scan left in flight by a previous process. Returns the count."""
    orphans: List[Scan] = (
        db.query(Scan).filter(Scan.status.in_(IN_FLIGHT_STATUSES)).all()
    )
    if not orphans:
        return 0

    for scan in orphans:
        scan.status = "failed"
        scan.error = INTERRUPTED_MESSAGE
    db.commit()
    logger.warning(
        "Marked %d interrupted scan(s) as failed at startup: %s",
        len(orphans), ", ".join(str(scan.id) for scan in orphans),
    )
    return len(orphans)


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
