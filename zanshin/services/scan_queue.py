"""The scan queue: first in, first out, with a configurable number running at once.

Before this, `trigger_scan` created a row and handed the work straight to a
`ThreadPoolExecutor`. That bounded concurrency — the pool had five workers — but it made
the pool the owner of the queue, with three consequences:

* **The queue was invisible.** A caller who triggered twelve scans got twelve `pending`
  rows and no way to know which would run when, or whether any of them still would.
* **A restart lost it.** The rows survived; the queued futures did not. Those scans
  stayed `pending` forever, and nothing ever looked at them again.
* **The limit was not configurable where it matters.** `ZANSHIN_SCAN_WORKERS` is read at
  import, so changing how many scans run at once meant restarting the application.

So the queue moves into the database, where the rows already were. `pending` means
queued, `scanning` means claimed and running — no new vocabulary — and the concurrency
limit becomes a property of the *claim* rather than of the executor: capacity is
`max_concurrent − running`, computed per dispatch. The pool goes back to being what a
pool should be, a supply of threads.

Order is creation order, no priority. A priority column would be easy to add later and
is deliberately not here: "in the order they were asked for" is a rule an operator can
predict, and the first thing a priority scheme costs is that predictability.

**Single instance.** The claim is a conditional `UPDATE ... WHERE status = 'pending'`
whose row count decides the winner, which is correct for the several threads of one
process and *not* for two processes on a server database — that needs
`SELECT … FOR UPDATE SKIP LOCKED`, and it is the one function to change when it does
(see ADR-002, étape 1).
"""
import concurrent.futures
import logging
import os
from typing import List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from zanshin.models.scan import Scan

logger = logging.getLogger(__name__)

STATUS_QUEUED = "pending"
STATUS_RUNNING = "scanning"

SETTING_KEY_MAX_CONCURRENT = "scan_max_concurrent"

# The default for the setting, kept on the old environment variable so an existing
# deployment behaves exactly as before until someone changes it in the UI.
DEFAULT_MAX_CONCURRENT = int(os.getenv("ZANSHIN_SCAN_WORKERS", "5"))

# The pool is a supply of threads, not the limit. Sized well above any sensible
# concurrency setting because each thread spends its life blocked on a clone or a
# container, and because the queue is what enforces the limit now — a pool smaller than
# the setting would silently cap it and make the setting a lie.
POOL_THREADS = int(os.getenv("ZANSHIN_SCAN_POOL_THREADS", "32"))

executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=POOL_THREADS, thread_name_prefix="zanshin-scan"
)


def max_concurrent(settings_service) -> int:
    """How many scans may run at once. At least one, whatever is stored."""
    raw = settings_service.get_setting(SETTING_KEY_MAX_CONCURRENT, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MAX_CONCURRENT
    return max(1, min(value, POOL_THREADS))


def count_running(db: Session) -> int:
    return (
        db.query(func.count(Scan.id)).filter(Scan.status == STATUS_RUNNING).scalar() or 0
    )


def count_queued(db: Session) -> int:
    return db.query(func.count(Scan.id)).filter(Scan.status == STATUS_QUEUED).scalar() or 0


def position_of(db: Session, scan: Scan) -> Optional[int]:
    """1-based place in the queue, or `None` if this scan is not waiting.

    Returned to a polling pipeline: "queued, 3 ahead of you" is the difference between
    waiting and wondering whether anything is going to happen.
    """
    if scan.status != STATUS_QUEUED:
        return None
    ahead = (
        db.query(func.count(Scan.id))
        .filter(
            Scan.status == STATUS_QUEUED,
            # Ties broken by id, exactly as the claim orders them, so the number a
            # caller is shown is the number it will actually be served in.
            (Scan.created_at < scan.created_at)
            | ((Scan.created_at == scan.created_at) & (Scan.id < scan.id)),
        )
        .scalar()
        or 0
    )
    return ahead + 1


def claim_next(db: Session, limit: int) -> List[Scan]:
    """Take up to `limit` queued scans, oldest first, and mark them running.

    The conditional update is what makes this safe against two dispatchers racing: the
    row count tells the caller whether *it* won, and a loser simply moves on. Without
    it, two threads reading the same `pending` row would both submit it and the target
    would be scanned twice concurrently — the exact thing the in-flight guard exists to
    prevent.
    """
    if limit <= 0:
        return []

    candidates = (
        db.query(Scan)
        .filter(Scan.status == STATUS_QUEUED)
        .order_by(Scan.created_at, Scan.id)
        .limit(limit)
        .all()
    )

    claimed: List[Scan] = []
    for scan in candidates:
        won = (
            db.query(Scan)
            .filter(Scan.id == scan.id, Scan.status == STATUS_QUEUED)
            .update({Scan.status: STATUS_RUNNING}, synchronize_session=False)
        )
        db.commit()
        if won:
            db.refresh(scan)
            claimed.append(scan)
    return claimed


def dispatch(session_factory=None, container_factory=None) -> int:
    """Start as many queued scans as capacity allows. Returns how many were started.

    Called from three places, and all three are needed:

    * after a scan is queued, so a single scan starts now rather than at the next tick;
    * when a scan finishes, so the next one starts as a slot frees instead of waiting
      up to a minute — a queue of twenty would otherwise take twenty ticks to drain;
    * on the scheduler tick, which is the safety net: it is what picks up scans left
      queued by a restart, and the only path that runs when nothing else happens.

    Never raises. It opens its own session because two of its callers are background
    threads that own no session, and because the work it submits must not inherit one.
    """
    from zanshin.container import IoCContainer
    from zanshin.database import SessionLocal

    session_factory = session_factory or SessionLocal
    db = session_factory()
    started = 0
    try:
        container = (container_factory or IoCContainer)(db)
        capacity = max_concurrent(container.settings_service) - count_running(db)
        if capacity <= 0:
            return 0

        for scan in claim_next(db, capacity):
            repo_url, ssh_key_id = None, None
            if scan.repo_id and scan.repository:
                repo_url = scan.repository.url
                ssh_key_id = scan.repository.ssh_key_id
            executor.submit(
                _run,
                container.scan_processor,
                scan.id,
                repo_url,
                scan.branch,
                scan.sub_path or "",
                ssh_key_id,
            )
            started += 1

        if started:
            logger.info(
                "Dispatched %d queued scan(s); %d still waiting", started, count_queued(db)
            )
        return started
    except Exception:
        logger.exception("Scan dispatch failed — will retry on the next tick")
        return started
    finally:
        db.close()


def _run(scan_processor, scan_id, repo_url, branch, sub_path, ssh_key_id) -> None:
    """Run one scan, then look for the next.

    The follow-up dispatch is here rather than in `process_scan` so that the queue's
    behaviour stays in the queue's module, and so a scan that raises still frees its
    slot for the next one — `process_scan` already writes its own failure state.
    """
    try:
        scan_processor.process_scan(scan_id, repo_url, branch, sub_path, ssh_key_id)
    finally:
        dispatch()
