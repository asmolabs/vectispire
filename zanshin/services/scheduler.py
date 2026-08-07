"""Periodic rescanning.

`scan_interval_minutes`, `scan_cron` and `last_scheduled_scan_at` have existed on
`repository` and `container` since the beginning; the UI collects an interval for
every target added. Nothing ever read them, so every scan was manual — in a tool
whose whole premise is that *new vulnerabilities appear in unchanged code*. A
weekly manual scan is not posture management; this is the loop that makes the
rest of the product mean something.

Design notes:

- One daemon thread, waking on a fixed tick. Not APScheduler/Celery: a single
  process with a SQLite database doesn't need a distributed scheduler, and adding
  one would introduce a broker to operate.
- Due targets are dispatched through the same `RepositoryService`/
  `ContainerService.trigger_scan` the UI calls, so a scheduled scan and a manual
  one are indistinguishable downstream — same pool, same processor, same issue
  sync. No second code path to keep in step.
- A target carries either an interval or a cron expression, and the expression wins
  when both are set (see `is_target_due` and `zanshin/services/cron.py`).
- `last_scheduled_scan_at` is stamped *before* dispatch. Stamping afterwards
  would re-dispatch the same target on the next tick whenever a scan takes
  longer than one interval.
- The tick also reaps stalled scans and prunes raw scanner payloads, since it is
  the only thing already running on a timer (see scan_recovery, retention_service).
"""
import logging
import os
import threading
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from zanshin.container import IoCContainer
from zanshin.database import SessionLocal
from zanshin.models.container import Container
from zanshin.models.repository import ZanshinRepository
from zanshin.clock import utcnow
from zanshin.services import cron, leader_election
from zanshin.services.outbox_service import prune_sent as prune_sent_messages, relay as outbox_relay
from zanshin.services.scan_queue import dispatch as dispatch_queued_scans
from zanshin.services.scan_queue import reclaim_expired_leases
from zanshin.services.scan_recovery import fail_stalled_scans
from zanshin.services.ticket_service import sweep as ticket_sweep

logger = logging.getLogger(__name__)

# How often to look for due targets. A minute is fine: the query is two indexed
# reads, and it bounds how late a scan can be relative to its interval.
TICK_SECONDS = int(os.getenv("ZANSHIN_SCHEDULER_TICK_SECONDS", "60"))

# A scan still in flight after this long is considered wedged. Deliberately much
# larger than one scanner's timeout (`ZANSHIN_SCAN_TIMEOUT_SECONDS`, 900s by
# default): a single scan runs SBOM, vulnerabilities, secrets and IaC in
# sequence, so exceeding one tool's timeout is not the same as being stuck.
STALLED_SCAN_MAX_AGE_SECONDS = int(os.getenv("ZANSHIN_STALLED_SCAN_MAX_AGE_SECONDS", "5400"))

# Retention runs on its own, much slower cadence: it walks every scan carrying a
# payload and may VACUUM, so doing it every minute would be waste for a job whose
# input changes on the scale of days.
RETENTION_INTERVAL_SECONDS = int(os.getenv("ZANSHIN_RETENTION_INTERVAL_SECONDS", str(6 * 3600)))

# Enabled by default: an operator who configures an interval expects it to be
# honoured. Set to "false" for a deployment that only ever scans on demand.
SCHEDULER_ENABLED = os.getenv("ZANSHIN_SCHEDULER_ENABLED", "true").lower() != "false"

_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()
# When retention last ran, so the fast tick can host a slow job without a second
# thread. In memory on purpose: after a restart, running it once early is
# harmless, and persisting it would mean a settings row to keep in sync.
_last_retention_run: Optional[datetime] = None


def is_due(
    interval_minutes: Optional[int],
    last_scheduled_at: Optional[datetime],
    now: datetime,
) -> bool:
    """Whether a target's interval has elapsed.

    A target with no interval is never scheduled (manual only). A target that has
    never been scanned automatically is due immediately — otherwise enabling the
    scheduler would leave it waiting one full interval before its first run,
    which for the default of 1440 minutes means a day of silence.
    """
    if not interval_minutes or interval_minutes <= 0:
        return False
    if last_scheduled_at is None:
        return True
    return now - last_scheduled_at >= timedelta(minutes=interval_minutes)


def is_target_due(target, now: datetime) -> bool:
    """Whether this target is due, by whichever schedule it carries.

    A cron expression takes precedence over the interval: it is the more specific of the
    two, and an interval cannot express "every night at two" — it drifts a little each
    run, so a scan configured for the quiet hours ends up running in the middle of the
    day. Clearing the expression returns the target to its interval.
    """
    expression = getattr(target, "scan_cron", None)
    if expression:
        return cron.is_due(expression, target.last_scheduled_scan_at, now)
    return is_due(target.scan_interval_minutes, target.last_scheduled_scan_at, now)


def find_due_targets(
    repositories: List[ZanshinRepository],
    containers: List[Container],
    now: datetime,
) -> Tuple[List[ZanshinRepository], List[Container]]:
    """Split targets into due and not due. Pure, so the policy is testable
    without a database or a running thread."""
    due_repos = [r for r in repositories if is_target_due(r, now)]
    due_containers = [c for c in containers if is_target_due(c, now)]
    return due_repos, due_containers


def run_once(now: Optional[datetime] = None) -> int:
    """One scheduler pass. Returns how many scans were dispatched.

    Split in two by what each job *is*, not by cost:

    - **per-instance**, always: refreshing this instance's built-in agent, and
      dispatching queued scans to it. A fleet whose instances only claimed work while
      holding the lease would idle behind whichever one holds it.
    - **exclusive**, only for the leader: everything whose effect is once per period.
      Chief among them is dispatching due targets — `last_scheduled_scan_at` is stamped
      before dispatch, which protects against one process ticking twice and not at all
      against two processes ticking together, so two instances would scan every target
      twice per interval (ADR-002 §2.2).

    Never raises: an exception here would kill the scheduler thread and silently
    end all automatic scanning.
    """
    now = now or utcnow()
    dispatched = 0
    db = SessionLocal()
    try:
        container = IoCContainer(db)

        # Per-instance, and first: an instance that cannot take the lease must still
        # be a working scan agent.
        _refresh_builtin_agent(container)
        # The queue's safety net: this is what starts scans left waiting by a restart,
        # and the only dispatch that runs when nothing else is happening.
        dispatch_queued_scans()

        if not _hold_leadership(db):
            return 0

        _reclaim_abandoned_scans(db)
        fail_stalled_scans(db, STALLED_SCAN_MAX_AGE_SECONDS)
        _prune_raw_payloads(container, db, now)
        _expire_stale_triages(container, db)
        _relay_notifications(container, db)
        _open_tracker_tickets(container, db)

        due_repos, due_containers = find_due_targets(
            container.repository_repository.find_all(),
            container.container_repository.find_all(),
            now,
        )

        for repo in due_repos:
            try:
                # Stamped before dispatch: see the module docstring.
                repo.last_scheduled_scan_at = now
                db.commit()
                container.repository_service.trigger_scan(repo.id)
                dispatched += 1
                logger.info("Scheduled scan dispatched for repository %s", repo.id)
            except Exception:
                logger.exception("Could not dispatch scheduled scan for repository %s", repo.id)

        for image in due_containers:
            try:
                image.last_scheduled_scan_at = now
                db.commit()
                container.container_service.trigger_scan(image.id)
                dispatched += 1
                logger.info("Scheduled scan dispatched for container %s", image.id)
            except Exception:
                logger.exception("Could not dispatch scheduled scan for container %s", image.id)

        return dispatched
    except Exception:
        logger.exception("Scheduler tick failed — will retry on the next tick")
        return dispatched
    finally:
        db.close()


def _hold_leadership(db) -> bool:
    """Take or renew the lease on the exclusive part of the tick.

    Never raises, and **fails closed**: an instance that cannot reach the lease table
    does not get to assume it is alone. Skipping a tick costs a minute of latency;
    assuming leadership wrongly costs a duplicated scan of every due target.
    """
    try:
        return leader_election.acquire(db)
    except Exception:
        logger.exception("Could not take the scheduler lease — skipping the exclusive work")
        return False


def _reclaim_abandoned_scans(db) -> None:
    """Return to the queue the scans whose worker stopped reporting.

    On the tick because that is the only thing already running on a timer, and
    because the observer of a lapsed lease is either an operator looking at the
    queue or the next dispatch — neither of which can be relied on to happen.

    Distinct from `fail_stalled_scans` just below, and both are needed: this one
    catches a worker that *vanished* (its lease lapsed) and gives the scan another
    chance, while that one catches a worker still faithfully renewing its lease on
    a scan that will plainly never finish, and gives up on it.

    Never raises: the tick has five other jobs.
    """
    try:
        reclaim_expired_leases(db)
    except Exception:
        logger.exception("Lease reclaim pass failed — will retry on the next tick")


def _refresh_builtin_agent(container) -> None:
    """Keep this instance's built-in agent showing as online.

    Dispatching already refreshes it, but an idle instance dispatches nothing —
    and an operator looking at the agents screen of a quiet system should not be
    told that the very process serving them the page is offline.
    """
    try:
        container.agent_service.ensure_builtin_agent()
    except Exception:
        logger.exception("Could not refresh the built-in agent — continuing the tick")


def _expire_stale_triages(container, db) -> None:
    """Bring triage decisions back for review when their date arrives.

    On the tick and not on a page load: a suppression that expires overnight has to
    stop suppressing whether or not anyone opens the issues screen — including in
    the VEX document a customer downloads and in the gate a pipeline calls at 3am.

    Cheap enough to run every tick (an indexed query that normally returns nothing),
    so unlike retention it gets no interval of its own.
    """
    try:
        expired = container.issue_service.expire_stale_triages(db)
        if expired:
            logger.info("%d triage decision(s) returned to review", len(expired))
    except Exception:
        logger.exception("Triage expiry pass failed — will retry on the next tick")


def _relay_notifications(container, db) -> None:
    """Drain the notification outbox: deliver what is due, retry what failed.

    Before the outbox, a webhook that was briefly unreachable lost its message with a
    single log line, and a crash between the scan's commit and the POST lost it with
    none at all. The relay is the half of that fix that lives outside the scan.
    """
    try:
        outbox_relay(
            db,
            outbox_repository=container.outbox_repository,
            notification_service=container.notification_service,
            audit_log_service=container.audit_log_service,
        )
    except Exception:
        logger.exception("Notification relay failed — will retry on the next tick")


def _open_tracker_tickets(container, db) -> None:
    """Open tracker tickets for issues that would fail their target's gate.

    On the tick rather than inline after a scan, because the sweep is idempotent by
    construction — the ticket reference lives on the issue — so a tracker that was
    unreachable is simply retried here instead of losing the ticket. That is also why
    this needs no outbox: the state to reconcile is already a column.
    """
    try:
        ticket_sweep(
            db,
            issue_repository=container.issue_repository,
            gate_policy_service=container.gate_policy_service,
            ticket_service=container.ticket_service,
            audit_log_service=container.audit_log_service,
        )
    except Exception:
        logger.exception("Ticket sweep failed — will retry on the next tick")


def _prune_raw_payloads(container, db, now: datetime) -> None:
    """Run retention at most every `RETENTION_INTERVAL_SECONDS`.

    Never raises: dropping stale payloads is housekeeping, and a failure here
    must not stop scans from being dispatched.
    """
    global _last_retention_run
    if _last_retention_run is not None:
        elapsed = (now - _last_retention_run).total_seconds()
        if elapsed < RETENTION_INTERVAL_SECONDS:
            return
    _last_retention_run = now
    try:
        # Delivered notifications are pruned on the same schedule as the raw scanner
        # payloads: both grow with every scan and neither is worth keeping for long.
        removed = prune_sent_messages(container.outbox_repository)
        if removed:
            logger.info("Pruned %d delivered notification(s)", removed)
        container.retention_service.prune(db)
    except Exception:
        logger.exception("Retention pass failed — will retry on a later tick")


def _loop() -> None:
    logger.info("Scan scheduler started (tick: %ss)", TICK_SECONDS)
    while not _stop_event.is_set():
        run_once()
        # `wait` rather than `sleep`: makes shutdown immediate instead of taking
        # up to a full tick.
        _stop_event.wait(TICK_SECONDS)
    logger.info("Scan scheduler stopped")


def start() -> None:
    """Start the scheduler thread, unless disabled or already running."""
    global _thread
    if not SCHEDULER_ENABLED:
        logger.info("Scan scheduler disabled by ZANSHIN_SCHEDULER_ENABLED")
        return
    if _thread is not None and _thread.is_alive():
        return
    _stop_event.clear()
    # Daemon: the scheduler must never keep a shutting-down process alive.
    _thread = threading.Thread(target=_loop, name="zanshin-scheduler", daemon=True)
    _thread.start()


def stop() -> None:
    """Stop the tick, and hand the lease back if this instance held it.

    Best-effort by construction: a process that is killed releases nothing, which is
    why the lease expires on its own. Releasing when we *can* just means a successor
    picks the job up in seconds instead of after the expiry.
    """
    _stop_event.set()
    db = SessionLocal()
    try:
        if leader_election.release(db):
            logger.info("Released the scheduler lease")
    except Exception:
        logger.exception("Could not release the scheduler lease — it will expire on its own")
    finally:
        db.close()
