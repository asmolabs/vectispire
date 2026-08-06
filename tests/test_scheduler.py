"""Tests for periodic rescanning.

`run_once` is exercised against a stub container so no real scan is ever
dispatched: the point under test is the scheduling policy and the bookkeeping
that keeps a slow scan from being launched twice, not the pipeline behind it.
"""
from datetime import datetime, timedelta

import pytest

import zanshin.services.scheduler as scheduler_module
from zanshin.services.issue_service import IssueService
from zanshin.models.container import Container
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
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

    services = {"repository": FakeScanService(), "container": FakeScanService()}

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
