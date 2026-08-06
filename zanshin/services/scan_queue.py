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

**Claiming is transactional where the database allows it.** On PostgreSQL and MySQL the
claim is `SELECT … FOR UPDATE SKIP LOCKED` followed by the status change in the *same*
transaction: either a claimant holds the row and the row says so, or neither (ADR-002
D1). On SQLite, which has neither `SKIP LOCKED` nor more than one writer, it falls back
to a conditional `UPDATE ... WHERE status = 'pending'` whose row count decides the
winner — correct for the several threads of one process, which is all SQLite supports
anyway (D6).

The two paths exist because the guarantee differs, not because the code was easier that
way: `SKIP LOCKED` makes two *processes* safe, and the fallback does not. The fallback's
failure mode is subtle enough to be worth naming — two processes reading the same
`pending` row would both see one row updated, because each `UPDATE` runs in its own
transaction and the second one sees the first's commit only if it happens to serialise
after it.
"""
import concurrent.futures
import logging
import os
import time
from datetime import timedelta
from typing import List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from zanshin.clock import utcnow
from zanshin.models.scan import Scan

logger = logging.getLogger(__name__)

STATUS_QUEUED = "pending"
STATUS_RUNNING = "scanning"

SETTING_KEY_MAX_CONCURRENT = "scan_max_concurrent"

# How long a claim holds without being renewed. Generous on purpose: a single
# step (pulling a large image, running Grype over a big SBOM) can take minutes,
# and `ZANSHIN_SCAN_TIMEOUT_SECONDS` already allows 900s per tool — a lease
# shorter than one step would declare healthy workers dead. Remote agents renew
# on a timer, the built-in one renews between steps, so both stay well inside it.
LEASE_SECONDS = int(os.getenv("ZANSHIN_SCAN_LEASE_SECONDS", "1200"))

# How many times a scan may be claimed before it is failed instead of re-queued.
# Three, because the interesting case is a target that wedges whatever picks it
# up: retried forever it would occupy the whole fleet, and an operator would see
# a scan permanently "about to start".
MAX_ATTEMPTS = int(os.getenv("ZANSHIN_SCAN_MAX_ATTEMPTS", "3"))

# How many times a transactional claim re-reads the queue when it came back short while
# work was still waiting. Needed because of a measured difference between the two server
# backends — see `_claim_locked`. Small: each retry is one indexed read, and the locks it
# is waiting on are released by a commit that happens microseconds later.
# Twelve, measured rather than guessed: with ten claimants contending on one queue, four
# attempts left three of them empty-handed on MySQL and twelve left none (see
# `tests/test_queue_concurrency_backends.py`). Each attempt is one indexed read plus the
# sleep below, so the worst case is a fraction of a second against a scan that takes
# minutes.
CLAIM_ATTEMPTS = int(os.getenv("ZANSHIN_SCAN_CLAIM_ATTEMPTS", "12"))
# Long enough for a competing claimant to commit, short enough to be invisible next to a
# scan that takes minutes.
CLAIM_RETRY_SECONDS = float(os.getenv("ZANSHIN_SCAN_CLAIM_RETRY_SECONDS", "0.01"))
LEASE_EXHAUSTED_MESSAGE = (
    "Scan abandonné : l'exécutant a cessé de répondre à chacune des {attempts} tentatives."
)

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


def count_running(db: Session, worker: Optional[str] = None, include_unowned: bool = False) -> int:
    """Scans currently running — everywhere, or for one worker.

    The concurrency limit became **per worker** when agents arrived, and it had to:
    counting every running scan would have let three scans on a remote agent
    silently consume the built-in agent's capacity, so adding an agent would have
    *reduced* what the host could do.

    `include_unowned` folds in rows with no `claimed_by`, which is what a scan
    claimed before the lease columns existed looks like. Those are counted for the
    built-in agent only, on the assumption that an unowned running scan belongs to
    this process — conservative in the right direction: the risk of over-counting
    is a scan waiting a little, the risk of under-counting is a host running more
    scanners than it was told to.
    """
    query = db.query(func.count(Scan.id)).filter(Scan.status == STATUS_RUNNING)
    if worker is not None:
        if include_unowned:
            query = query.filter((Scan.claimed_by == worker) | (Scan.claimed_by.is_(None)))
        else:
            query = query.filter(Scan.claimed_by == worker)
    return query.scalar() or 0


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


def claim_next(
    db: Session,
    limit: int,
    worker: Optional[str] = None,
    required_label: Optional[str] = None,
) -> List[Scan]:
    """Take up to `limit` queued scans, oldest first, and mark them running.

    Two claimants must never receive the same scan: the target would be scanned twice
    at once, which is the very thing the in-flight guard exists to prevent. How that is
    guaranteed depends on the database — see `supports_skip_locked` and the module
    docstring.

    `worker` is the `Agent.worker_id` taking ownership, and with it comes a lease
    (see `LEASE_SECONDS`). Optional so that a caller with no notion of agents — the
    tests that predate them, mainly — still works, but every production path passes
    one: without an owner, "running" means "some thread, somewhere, maybe", which is
    what made startup recovery destructive (ADR-002 §2.3).

    `required_label` is accepted for symmetry with agent labels; `None` (the
    default) means the queue is not filtered. There is no per-scan label column
    yet, so today this only ever excludes everything or nothing — it is here so
    the claim signature does not change when routing arrives (ADR-002, étape 4).
    """
    if limit <= 0:
        return []
    if supports_skip_locked(db):
        return _claim_locked(db, limit, worker)
    return _claim_conditional(db, limit, worker)


def supports_skip_locked(db: Session) -> bool:
    """Whether this database can lock rows and skip the ones already locked.

    PostgreSQL and MySQL 8 can; SQLite cannot, and SQLAlchemy's SQLite dialect
    *silently drops* `FOR UPDATE` rather than refusing it — so asking without checking
    would produce a claim that looks transactional, passes every test on a developer's
    machine, and hands the same scan to two processes in production. Hence the explicit
    check, and the honest fallback below.
    """
    return db.bind.dialect.name in ("postgresql", "mysql", "mariadb")


def _claim_locked(db: Session, limit: int, worker: Optional[str]) -> List[Scan]:
    """The transactional claim (ADR-002 D1).

    `FOR UPDATE SKIP LOCKED` gives this transaction exclusive hold on the rows it
    selected, and lets a concurrent claimant *skip past them* instead of blocking —
    which is what makes several instances share one queue without serialising on the
    oldest row. The status change and the lock release happen in the same commit, so
    there is no window in which a row is claimed but not marked.

    **Why it retries when it comes back short.** The two server backends disagree about
    how `LIMIT` and `SKIP LOCKED` interact: PostgreSQL keeps scanning until it has
    `LIMIT` unlocked rows, while MySQL counts skipped rows against the limit and returns
    short. Measured rather than assumed — with `LIMIT 1`, ten concurrent claimants on a
    queue of twenty scans left six of them empty-handed on MySQL 8.4
    (`tests/test_queue_concurrency_backends.py`). Nothing was claimed twice, so this was
    never a safety problem; it was a throughput one, and the shape it takes in production
    is an agent long-polling for thirty seconds while work sits in the queue.

    The fix is a **bounded retry**: every claimant commits within microseconds, so a row
    that is locked now is either gone or free on the next read, and on MySQL each read
    advances roughly one row past the contention. `CLAIM_ATTEMPTS` is sized from the
    measurement, not from taste.

    Two things were tried first and are worth recording, because both are the obvious
    idea. Selecting a *wider window* than needed and trimming it made PostgreSQL fail the
    very tests MySQL was failing — a claimant that locks rows it will not claim starves
    the others for as long as it holds them. A window on MySQL only then worked, but
    turned out to be unnecessary once the retry budget was right, so it is gone: asking
    for exactly what you need, and retrying, is both simpler and the correct behaviour on
    every backend.
    """
    claimed: List[Scan] = []
    for attempt in range(CLAIM_ATTEMPTS):
        wanted = limit - len(claimed)
        batch = (
            db.query(Scan)
            .filter(Scan.status == STATUS_QUEUED)
            .order_by(Scan.created_at, Scan.id)
            .limit(wanted)
            .with_for_update(skip_locked=True)
            .all()
        )[:wanted]
        if batch:
            now = utcnow()
            for scan in batch:
                scan.status = STATUS_RUNNING
                scan.claimed_by = worker
                scan.claimed_at = now
                scan.lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
                # Counted from the row rather than from the claimant: what matters is how
                # many times *this scan* has been picked up, including by workers that
                # have since vanished.
                scan.attempts = (scan.attempts or 0) + 1
            # Committed per batch, which is what releases the locks: holding them while
            # asking for more would turn this claimant into the one starving everybody
            # else.
            db.commit()
            claimed.extend(batch)
            if len(claimed) >= limit:
                break
            continue

        # Nothing came back. Either the queue is empty — in which case there is nothing
        # to wait for — or every row this read could see is held by a claimant that is
        # about to commit.
        db.rollback()
        if count_queued(db) == 0:
            break
        if attempt < CLAIM_ATTEMPTS - 1:
            time.sleep(CLAIM_RETRY_SECONDS)
    return claimed


def _claim_conditional(db: Session, limit: int, worker: Optional[str]) -> List[Scan]:
    """The SQLite claim: a conditional update per row, its row count deciding the winner.

    Safe for the several threads of one process — which is the only concurrency SQLite
    offers, since it has a single writer. Not safe for two processes, and that is not a
    gap to fill here: SQLite is documented as single-instance (D6), and the check in
    `zanshin/startup_guard.py` refuses the deployment that would need more.
    """
    now = utcnow()
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
            .update(
                {
                    Scan.status: STATUS_RUNNING,
                    Scan.claimed_by: worker,
                    Scan.claimed_at: now,
                    Scan.lease_expires_at: now + timedelta(seconds=LEASE_SECONDS),
                    Scan.attempts: (scan.attempts or 0) + 1,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        if won:
            db.refresh(scan)
            claimed.append(scan)
    return claimed


def renew_lease(db: Session, scan_id: int, worker: str) -> bool:
    """Push a scan's lease out, on behalf of the worker holding it.

    Returns whether the renewal applied. `False` means the worker no longer owns
    this scan — its lease lapsed and somebody else took over, or an operator
    intervened. A worker that sees `False` should stop: whatever it computes from
    here on will be refused anyway.

    Filtered on `claimed_by` and not just on the id, so an agent cannot extend
    (or resurrect) a scan that is not its own.
    """
    if not worker:
        return False
    now = utcnow()
    updated = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.claimed_by == worker,
            Scan.status == STATUS_RUNNING,
        )
        .update(
            {Scan.lease_expires_at: now + timedelta(seconds=LEASE_SECONDS)},
            synchronize_session=False,
        )
    )
    db.commit()
    return bool(updated)


def still_owned(db: Session, scan_id: int, worker: Optional[str]) -> bool:
    """Whether `worker` may still write results for this scan.

    Checked before ingesting, locally and over the API alike. This is what stops
    a worker whose lease lapsed from overwriting the results of the worker that
    took over its scan — the failure mode that makes reclaiming safe in the first
    place. A scan with no owner recorded (`claimed_by` null, e.g. queued before
    this existed) is accepted: refusing it would strand rows that nothing else
    will ever finish.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        return False
    if scan.claimed_by is None:
        return True
    return scan.claimed_by == worker


def reclaim_expired_leases(db: Session, now=None) -> List[Scan]:
    """Return abandoned scans to the queue, or fail them for good.

    A lease lapses when a worker stops reporting: the process died, the machine
    went away, the network partitioned. The work itself may still be running
    somewhere — nothing here can kill a thread on another host — so this does not
    stop anything; it makes the row claimable again, and `still_owned` then
    refuses the results of the worker that lost it.

    After `MAX_ATTEMPTS` the scan fails instead of being re-queued. Otherwise a
    target that reliably wedges its worker would cycle between agents forever,
    consuming the whole fleet's capacity, and the operator would see a scan that
    is permanently "about to start".

    Returns the scans it touched, so a caller can log or count them.
    """
    now = now or utcnow()
    stalled = [
        scan
        for scan in db.query(Scan).filter(Scan.status == STATUS_RUNNING).all()
        # Compared in Python, like `scan_recovery.fail_stalled_scans`:
        # `SafeDateTime` tolerates legacy string values, which do not compare
        # reliably in SQL.
        if scan.lease_expires_at is not None and scan.lease_expires_at < now
    ]
    if not stalled:
        return []

    for scan in stalled:
        if (scan.attempts or 0) >= MAX_ATTEMPTS:
            scan.status = "failed"
            scan.error = LEASE_EXHAUSTED_MESSAGE.format(attempts=scan.attempts or 0)
        else:
            scan.status = STATUS_QUEUED
            scan.claimed_by = None
            scan.claimed_at = None
            scan.lease_expires_at = None
    db.commit()
    logger.warning(
        "Reclaimed %d scan(s) whose worker stopped reporting: %s",
        len(stalled), ", ".join(str(scan.id) for scan in stalled),
    )
    return stalled


def dispatch(session_factory=None, container_factory=None) -> int:
    """Start as many queued scans as this instance's capacity allows.

    Returns how many were started. Called from three places, and all three are needed:

    * after a scan is queued, so a single scan starts now rather than at the next tick;
    * when a scan finishes, so the next one starts as a slot frees instead of waiting
      up to a minute — a queue of twenty would otherwise take twenty ticks to drain;
    * on the scheduler tick, which is the safety net: it is what picks up scans left
      queued by a restart, and the only path that runs when nothing else happens.

    This is the **built-in agent** at work: the web process claiming queued scans for
    itself (ADR-002 étape 3). It is also why the default single-process deployment
    needs no configuration — and why an operator who disables the built-in agent gets
    what they asked for here, immediately: nothing is claimed, and the queue waits for
    a remote agent.

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
        agent_service = container.agent_service
        # Refreshed here rather than only at startup: dispatching *is* a sign of
        # life, so the built-in agent shows as online exactly while it is working,
        # with no separate heartbeat to keep in step.
        agent = agent_service.ensure_builtin_agent()
        worker = agent.worker_id

        capacity = agent_service.capacity_of(agent) - count_running(
            db, worker=worker, include_unowned=True
        )
        if capacity <= 0:
            if not agent.enabled and count_queued(db):
                # Worth a line: from the operator's side the queue simply stops
                # moving, and this is the reason.
                logger.info(
                    "Built-in agent disabled: %d queued scan(s) are waiting for a remote agent",
                    count_queued(db),
                )
            return 0

        for scan in claim_next(db, capacity, worker=worker):
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
                worker,
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


def _run(scan_processor, scan_id, repo_url, branch, sub_path, ssh_key_id, worker=None) -> None:
    """Run one scan, then look for the next.

    The follow-up dispatch is here rather than in `process_scan` so that the queue's
    behaviour stays in the queue's module, and so a scan that raises still frees its
    slot for the next one — `process_scan` already writes its own failure state.
    """
    try:
        scan_processor.process_scan(scan_id, repo_url, branch, sub_path, ssh_key_id, worker=worker)
    finally:
        dispatch()
