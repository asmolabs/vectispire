"""Tests for periodic rescanning.

`run_once` is exercised against a stub container so no real scan is ever
dispatched: the point under test is the scheduling policy and the bookkeeping
that keeps a slow scan from being launched twice, not the pipeline behind it.
"""
from datetime import datetime, timedelta

import pytest

import zanshin.services.scheduler as scheduler_module
from zanshin.repositories.audit_log_repository import AuditLogRepository
from zanshin.repositories.gate_policy_repository import GatePolicyRepository
from zanshin.repositories.issue_repository import IssueRepository
from zanshin.repositories.outbox_repository import OutboxRepository
from zanshin.repositories.setting_repository import SettingRepository
from zanshin.services.audit_log_service import AuditLogService
from zanshin.services.gate_policy_service import GatePolicyService
from zanshin.services.issue_service import IssueService
from zanshin.services.notification_service import NotificationService
from zanshin.services.settings_service import SettingsService
from zanshin.services.ticket_service import TicketService
from zanshin.models.container import Container
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
from zanshin.services import leader_election
from zanshin.services.scheduler import find_due_targets, is_due, run_once

NOW = datetime(2026, 8, 6, 12, 0, 0)


# --- Policy ---

def test_a_target_without_an_interval_is_never_scheduled():
    assert is_due(None, None, NOW) is False
    assert is_due(0, None, NOW) is False
    assert is_due(-30, None, NOW) is False


def test_a_never_scheduled_target_is_due_immediately():
    """Otherwise enabling the scheduler means waiting a full interval — a day,
    at the UI's default of 1440 minutes — before anything happens."""
    assert is_due(1440, None, NOW) is True


def test_due_exactly_at_the_interval_boundary():
    assert is_due(60, NOW - timedelta(minutes=59, seconds=59), NOW) is False
    assert is_due(60, NOW - timedelta(minutes=60), NOW) is True
    assert is_due(60, NOW - timedelta(days=3), NOW) is True


def test_find_due_targets_splits_both_kinds():
    due_repo = ZanshinRepository(url="git@example.com:org/a.git", scan_interval_minutes=60)
    due_repo.last_scheduled_scan_at = NOW - timedelta(hours=2)
    idle_repo = ZanshinRepository(url="git@example.com:org/b.git", scan_interval_minutes=60)
    idle_repo.last_scheduled_scan_at = NOW - timedelta(minutes=5)
    manual_repo = ZanshinRepository(url="git@example.com:org/c.git", scan_interval_minutes=None)

    due_image = Container(image_name="nginx", tag="latest", scan_interval_minutes=30)
    due_image.last_scheduled_scan_at = None

    repos, containers = find_due_targets([due_repo, idle_repo, manual_repo], [due_image], NOW)

    assert repos == [due_repo]
    assert containers == [due_image]


# --- One pass ---

class FakeScanService:
    def __init__(self, fail_for=()):
        self.calls = []
        self.fail_for = set(fail_for)

    def trigger_scan(self, target_id):
        self.calls.append(target_id)
        if target_id in self.fail_for:
            raise RuntimeError("dispatch boom")


@pytest.fixture()
def scheduler_env(monkeypatch, isolated_session_local):  # noqa: D401
    """Point the scheduler at an isolated database and stub the two services it
    dispatches through, so nothing reaches Docker or the thread pool."""
    monkeypatch.setattr(scheduler_module, "SessionLocal", isolated_session_local)

    services = {"repository": FakeScanService(), "container": FakeScanService(), "posts": []}

    def recording_post(url, **kwargs):
        """Injected rather than monkeypatched onto `httpx`: these services take
        `http_post` as a default argument, which is bound at import time, so patching
        the module afterwards has no effect on them."""
        services["posts"].append(url)

        class _Response:
            def raise_for_status(self):
                return None

        return _Response()

    class FakeContainer:
        def __init__(self, db):
            from zanshin.repositories.container_repository import ContainerRepository
            from zanshin.repositories.repository_repository import RepositoryRepository

            self.repository_repository = RepositoryRepository(db)
            self.container_repository = ContainerRepository(db)
            self.repository_service = services["repository"]
            self.container_service = services["container"]
            # Real, not a stub: the tick is where triage review dates actually
            # fire, and that they fire without anyone opening the UI is the point.
            self.issue_service = IssueService()
            self.issue_repository = IssueRepository(db)
            self.outbox_repository = OutboxRepository(db)
            self.notification_service = NotificationService(
                SettingsService(SettingRepository(db)), http_post=recording_post
            )
            self.audit_log_service = AuditLogService(AuditLogRepository(db))
            self.gate_policy_service = GatePolicyService(GatePolicyRepository(db))
            self.ticket_service = TicketService(SettingsService(SettingRepository(db)))

    monkeypatch.setattr(scheduler_module, "IoCContainer", FakeContainer)
    session = isolated_session_local()
    yield session, services
    session.close()


def _repo(session, **kwargs):
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main", **kwargs)
    session.add(repo)
    session.commit()
    session.refresh(repo)
    return repo


def _image(session, **kwargs):
    image = Container(image_name="nginx", tag="latest", **kwargs)
    session.add(image)
    session.commit()
    session.refresh(image)
    return image


def test_dispatches_due_targets_and_skips_the_others(scheduler_env):
    session, services = scheduler_env
    due = _repo(session, scan_interval_minutes=60)
    idle = _repo(session, scan_interval_minutes=60)
    idle.last_scheduled_scan_at = NOW - timedelta(minutes=1)
    manual = _repo(session, scan_interval_minutes=None)
    due_image = _image(session, scan_interval_minutes=30)
    session.commit()

    dispatched = run_once(now=NOW)

    assert dispatched == 2
    assert services["repository"].calls == [due.id]
    assert services["container"].calls == [due_image.id]
    assert idle.id not in services["repository"].calls
    assert manual.id not in services["repository"].calls


def test_stamps_the_target_before_dispatching(scheduler_env):
    """Stamping after dispatch would re-launch the same target on every tick
    while a scan longer than one interval is still running."""
    session, _ = scheduler_env
    repo = _repo(session, scan_interval_minutes=60)

    run_once(now=NOW)

    session.refresh(repo)
    assert repo.last_scheduled_scan_at == NOW


def test_a_target_is_not_dispatched_twice_within_its_interval(scheduler_env):
    session, services = scheduler_env
    _repo(session, scan_interval_minutes=60)

    run_once(now=NOW)
    run_once(now=NOW + timedelta(minutes=30))

    assert len(services["repository"].calls) == 1


def test_dispatched_again_once_the_interval_has_elapsed(scheduler_env):
    session, services = scheduler_env
    _repo(session, scan_interval_minutes=60)

    run_once(now=NOW)
    run_once(now=NOW + timedelta(minutes=61))

    assert len(services["repository"].calls) == 2


def test_one_failing_dispatch_does_not_stop_the_others(scheduler_env):
    session, services = scheduler_env
    first = _repo(session, scan_interval_minutes=60)
    second = _repo(session, scan_interval_minutes=60)
    services["repository"].fail_for = {first.id}

    dispatched = run_once(now=NOW)

    assert set(services["repository"].calls) == {first.id, second.id}
    assert dispatched == 1  # only the one that actually started


def test_the_tick_also_fails_stalled_scans(scheduler_env):
    """The scheduler is the only thing already running on a timer, so it carries
    the reaper (see scan_recovery)."""
    session, _ = scheduler_env
    stalled = Scan(
        branch="main",
        status="scanning",
        findings_count=0,
        created_at=NOW - timedelta(days=1),
    )
    session.add(stalled)
    session.commit()

    run_once(now=NOW)

    session.refresh(stalled)
    assert stalled.status == "failed"


def test_a_broken_tick_returns_instead_of_killing_the_thread(monkeypatch, scheduler_env):
    """An exception escaping `run_once` would end the scheduler thread, silently
    stopping every automatic scan for the lifetime of the process."""
    session, _ = scheduler_env

    def boom(db, max_age_seconds):
        raise RuntimeError("database gone")

    monkeypatch.setattr(scheduler_module, "fail_stalled_scans", boom)

    assert run_once(now=NOW) == 0


def test_the_tick_returns_expired_triage_decisions_to_review(scheduler_env):
    """On the tick and not on a page load: a suppression that expires overnight has
    to stop suppressing whether or not anyone opens the issues screen — including in
    the VEX document a customer downloads and the gate a pipeline calls at 3am."""
    from zanshin.clock import utcnow
    from zanshin.models.issue import TRIAGE_NOT_AFFECTED, TRIAGE_UNDER_REVIEW, Issue

    session, _ = scheduler_env
    issue = Issue(
        fingerprint="fp-expiry",
        type="vulnerability",
        identifier="CVE-2024-0001",
        severity="high",
        state="open",
        triage_status=TRIAGE_NOT_AFFECTED,
        triage_justification="component_not_present",
        triage_expires_at=utcnow() - timedelta(days=1),
        is_kev=False,
    )
    session.add(issue)
    session.commit()

    run_once()

    session.expire_all()
    assert session.query(Issue).one().triage_status == TRIAGE_UNDER_REVIEW


def test_the_tick_delivers_a_pending_notification(scheduler_env):
    """The other half of the outbox: the scan enqueues, the tick sends.

    Also a guard against a whole tick step going missing — an earlier version of this
    file lost `_open_tracker_tickets` to a bad edit, and because every step catches its
    own exceptions the only visible symptom was that no scan was ever dispatched.
    """
    from zanshin.models.outbox_message import STATUS_SENT, OutboxMessage
    from zanshin.models.setting import Setting
    from zanshin.repositories.outbox_repository import OutboxRepository
    from zanshin.services.outbox_service import enqueue

    session, services = scheduler_env
    session.add(Setting(key="notification_webhook_url", value="https://hooks.example.com/abc"))
    session.commit()

    enqueue(OutboxRepository(session), {"text": "3 nouveaux problèmes", "scan_id": 1})
    session.commit()

    run_once()

    session.expire_all()
    assert services["posts"] == ["https://hooks.example.com/abc"]
    assert session.query(OutboxMessage).one().status == STATUS_SENT


# --- Leadership (docs/architecture/04) ---
#
# The tick is split by what each job *is*: the exclusive work happens once per period
# across the whole fleet, the per-instance work happens on every instance. Getting that
# split wrong is expensive in one direction (every target scanned twice per interval)
# and paralysing in the other (a fleet idling behind whichever instance holds the lease).

def test_only_one_of_two_instances_dispatches_a_due_target(scheduler_env, monkeypatch):
    """The defect this closes. `last_scheduled_scan_at` is stamped before dispatch,
    which protects against one process ticking twice and not at all against two
    processes ticking together."""
    session, services = scheduler_env
    _repo(session, scan_interval_minutes=60)

    monkeypatch.setattr(leader_election, "INSTANCE_ID", "instance-a")
    assert run_once() == 1

    monkeypatch.setattr(leader_election, "INSTANCE_ID", "instance-b")
    assert run_once() == 0

    assert services["repository"].calls == [1], "the target was dispatched twice"


def test_a_follower_still_claims_queued_scans_for_its_own_agent(scheduler_env, monkeypatch):
    """Per-instance, and it has to be: a fleet whose instances only claimed work while
    holding the lease would idle behind whichever one holds it."""
    session, _ = scheduler_env
    dispatched = []
    monkeypatch.setattr(
        scheduler_module, "dispatch_queued_scans", lambda: dispatched.append(True)
    )
    refreshed = []
    monkeypatch.setattr(
        scheduler_module, "_refresh_builtin_agent", lambda container: refreshed.append(True)
    )

    monkeypatch.setattr(leader_election, "INSTANCE_ID", "instance-a")
    run_once()
    monkeypatch.setattr(leader_election, "INSTANCE_ID", "instance-b")
    run_once()

    assert len(dispatched) == 2, "the follower stopped claiming work"
    assert len(refreshed) == 2, "the follower stopped reporting itself as alive"


def test_the_leader_keeps_the_lease_across_ticks(scheduler_env, monkeypatch):
    session, services = scheduler_env
    _repo(session, scan_interval_minutes=60)
    monkeypatch.setattr(leader_election, "INSTANCE_ID", "instance-a")

    run_once()
    run_once()

    assert leader_election.current_holder(session) == "instance-a"


def test_leadership_passes_on_when_the_holder_stops_renewing(scheduler_env, monkeypatch):
    from datetime import timedelta

    from zanshin.clock import utcnow
    from zanshin.models.leader_lease import JOB_SCHEDULER, LeaderLease

    session, services = scheduler_env
    _repo(session, scan_interval_minutes=60)

    monkeypatch.setattr(leader_election, "INSTANCE_ID", "instance-a")
    run_once()

    lease = session.query(LeaderLease).filter(LeaderLease.name == JOB_SCHEDULER).first()
    lease.expires_at = utcnow() - timedelta(seconds=1)
    session.commit()

    monkeypatch.setattr(leader_election, "INSTANCE_ID", "instance-b")
    run_once()

    session.expire_all()
    assert leader_election.current_holder(session) == "instance-b"


def test_a_tick_that_cannot_reach_the_lease_does_not_assume_it_is_alone(
    scheduler_env, monkeypatch
):
    """Fails closed. Skipping a tick costs a minute of latency; assuming leadership
    wrongly costs a duplicated scan of every due target."""
    session, services = scheduler_env
    _repo(session, scan_interval_minutes=60)

    def unreachable(*args, **kwargs):
        raise RuntimeError("lease table unreachable")

    monkeypatch.setattr(leader_election, "acquire", unreachable)

    assert run_once() == 0
    assert services["repository"].calls == []


# --- Cron ---
#
# The expression was collected by the repository screen and ignored by this module,
# with a log warning as its only trace. These pin down that it is honoured, and that it
# wins over the interval when both are set.

def test_a_cron_expression_is_honoured(scheduler_env):
    from datetime import datetime

    session, services = scheduler_env
    # Never scanned: due immediately, like the interval path.
    _repo(session, scan_cron="0 2 * * *")

    assert run_once(now=datetime(2026, 8, 7, 0, 0)) == 1
    assert services["repository"].calls == [1]


def test_a_cron_target_is_not_dispatched_again_before_its_next_occurrence(scheduler_env):
    from datetime import datetime

    session, services = scheduler_env
    _repo(session, scan_cron="0 2 * * *")

    run_once(now=datetime(2026, 8, 7, 2, 0))     # first run, stamps 02:00
    run_once(now=datetime(2026, 8, 7, 23, 0))    # same day, next occurrence not reached

    assert services["repository"].calls == [1]


def test_a_cron_target_is_dispatched_again_at_the_next_occurrence(scheduler_env):
    from datetime import datetime

    session, services = scheduler_env
    _repo(session, scan_cron="0 2 * * *")

    run_once(now=datetime(2026, 8, 7, 2, 0))
    run_once(now=datetime(2026, 8, 8, 2, 1))

    assert services["repository"].calls == [1, 1]


def test_the_cron_expression_wins_over_the_interval(scheduler_env):
    """One target, one schedule. The expression is the more specific of the two, and an
    interval cannot say "every night at two"."""
    from datetime import datetime

    session, services = scheduler_env
    # An interval that would fire hourly, and an expression that would not fire today.
    repo = _repo(session, scan_interval_minutes=60, scan_cron="0 2 * * *")
    repo.last_scheduled_scan_at = datetime(2026, 8, 7, 2, 0)
    session.commit()

    assert run_once(now=datetime(2026, 8, 7, 20, 0)) == 0
    assert services["repository"].calls == []


def test_clearing_the_expression_returns_the_target_to_its_interval(scheduler_env):
    from datetime import datetime

    session, services = scheduler_env
    repo = _repo(session, scan_interval_minutes=60, scan_cron=None)
    repo.last_scheduled_scan_at = datetime(2026, 8, 7, 2, 0)
    session.commit()

    assert run_once(now=datetime(2026, 8, 7, 4, 0)) == 1


def test_an_unschedulable_expression_dispatches_nothing(scheduler_env):
    """It can only get here by being hand-edited — the screen refuses it — and when it
    does, the target stops being scheduled rather than firing once."""
    from datetime import datetime

    session, services = scheduler_env
    _repo(session, scan_cron="tous les soirs")

    assert run_once(now=datetime(2026, 8, 7, 0, 0)) == 0
    assert services["repository"].calls == []
