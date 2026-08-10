"""Tests for the startup check on unsafe deployments.

What is being pinned down is a judgement call as much as a mechanism: which
configurations stop the process, which only produce a warning, and — the part that
would hurt most if it were wrong — which produce nothing at all. A check that refused
to start a perfectly ordinary single-instance install would be worse than the problem
it looks for.
"""
from datetime import timedelta

import pytest

from zanshin.clock import utcnow
from zanshin.models.agent import KIND_BUILTIN, KIND_REMOTE, Agent
from zanshin import startup_guard
from zanshin.startup_guard import UnsafeDeployment, check, find_other_live_instances


def _builtin(db, hostname, seen_secs_ago=0, kind=KIND_BUILTIN):
    agent = Agent(
        name=f"Agent intégré ({hostname})",
        kind=kind,
        hostname=hostname,
        credentials_mode="local",
        enabled=True,
        last_seen_at=utcnow() - timedelta(seconds=seen_secs_ago),
        created_at=utcnow(),
    )
    db.add(agent)
    db.commit()
    return agent


@pytest.fixture(autouse=True)
def _sqlite_and_no_hatch(monkeypatch):
    """The suite runs on SQLite, which is the case the check refuses; the escape hatch
    is off unless a test turns it on."""
    monkeypatch.setattr(startup_guard, "ALLOW_MULTI_INSTANCE_SQLITE", False)


# --- Nothing to say -------------------------------------------------------------

def test_a_lone_instance_passes_silently(db_session):
    """The overwhelmingly common case, and the one this check must never break."""
    _builtin(db_session, "scanner-01")

    assert check(db_session, hostname="scanner-01") == []


def test_an_empty_database_passes(db_session):
    assert check(db_session, hostname="scanner-01") == []


def test_an_instance_that_stopped_long_ago_is_not_counted(db_session):
    """Otherwise every redeployment would leave a tombstone that blocks the next one."""
    _builtin(db_session, "old-host", seen_secs_ago=3600)

    assert check(db_session, hostname="scanner-01") == []


def test_a_remote_agent_is_not_another_instance(db_session):
    """Agents are the whole point of the feature: they are live, they are on other
    hosts, and they must not look like a second control plane."""
    _builtin(db_session, "runner-7", kind=KIND_REMOTE)

    assert check(db_session, hostname="scanner-01") == []


def test_a_builtin_row_with_no_hostname_is_ignored(db_session):
    agent = _builtin(db_session, "scanner-02")
    agent.hostname = None
    db_session.commit()

    assert check(db_session, hostname="scanner-01") == []


# --- The refusal ----------------------------------------------------------------

def test_two_instances_on_sqlite_are_refused(db_session):
    """Not slow — corrupt. SQLite has one writer, and the claim cannot be made safe
    there because `FOR UPDATE SKIP LOCKED` does not exist (décision 0004)."""
    _builtin(db_session, "scanner-02", seen_secs_ago=5)

    with pytest.raises(UnsafeDeployment) as refusal:
        check(db_session, hostname="scanner-01")

    message = str(refusal.value)
    # The message has to name the reason and the way out, or an operator at 3am
    # learns nothing from it.
    assert "SQLite" in message
    assert "scanner-02" in message
    assert "PostgreSQL" in message
    assert "ZANSHIN_ALLOW_MULTI_INSTANCE_SQLITE" in message


def test_the_escape_hatch_turns_the_refusal_off(db_session, monkeypatch):
    """Its only purpose: a restart under a new hostname within the liveness window,
    which is what a Kubernetes rolling restart looks like."""
    monkeypatch.setattr(startup_guard, "ALLOW_MULTI_INSTANCE_SQLITE", True)
    _builtin(db_session, "scanner-02", seen_secs_ago=5)

    warnings = check(db_session, hostname="scanner-01")

    assert isinstance(warnings, list)  # started, with warnings rather than a refusal


# --- The warnings ---------------------------------------------------------------

def test_a_server_database_warns_about_unshared_reflex_state(db_session, monkeypatch):
    """§2.4: without shared state a client that lands on the other instance is logged
    out intermittently, with nothing in the logs anybody can act on."""
    monkeypatch.setattr(startup_guard, "is_sqlite", lambda *a, **k: False)
    monkeypatch.setattr(startup_guard, "_shared_state_configured", lambda: False)
    monkeypatch.setattr(startup_guard, "_auto_migrate_enabled", lambda: False)
    _builtin(db_session, "scanner-02", seen_secs_ago=5)

    warnings = check(db_session, hostname="scanner-01")

    assert any("redis" in warning.lower() for warning in warnings)


def test_shared_state_configured_produces_no_such_warning(db_session, monkeypatch):
    monkeypatch.setattr(startup_guard, "is_sqlite", lambda *a, **k: False)
    monkeypatch.setattr(startup_guard, "_shared_state_configured", lambda: True)
    monkeypatch.setattr(startup_guard, "_auto_migrate_enabled", lambda: False)
    _builtin(db_session, "scanner-02", seen_secs_ago=5)

    assert check(db_session, hostname="scanner-01") == []


def test_automatic_migration_in_a_fleet_is_warned_about(db_session, monkeypatch):
    """§2.6: the migration lock is a file lock, so it serialises the processes of one
    host and coordinates nothing between two."""
    monkeypatch.setattr(startup_guard, "is_sqlite", lambda *a, **k: False)
    monkeypatch.setattr(startup_guard, "_shared_state_configured", lambda: True)
    monkeypatch.setattr(startup_guard, "_auto_migrate_enabled", lambda: True)
    _builtin(db_session, "scanner-02", seen_secs_ago=5)

    warnings = check(db_session, hostname="scanner-01")

    assert any("ZANSHIN_AUTO_MIGRATE" in warning for warning in warnings)


# --- Resilience -----------------------------------------------------------------

def test_a_broken_check_does_not_stop_the_application(db_session, monkeypatch):
    """A startup check that fails on its own bug would be worse than the problem it
    looks for."""
    def boom(*args, **kwargs):
        raise RuntimeError("query exploded")

    monkeypatch.setattr(startup_guard, "find_other_live_instances", boom)

    assert check(db_session, hostname="scanner-01") == []


def test_unknown_reflex_configuration_stays_quiet(monkeypatch):
    """Warning about a configuration that may well be correct trains people to ignore
    warnings."""
    monkeypatch.setattr(
        "reflex.config.get_config", lambda: (_ for _ in ()).throw(RuntimeError("no config"))
    )

    assert startup_guard._shared_state_configured() is True


# --- Detection ------------------------------------------------------------------

def test_only_other_hosts_count_as_other_instances(db_session):
    _builtin(db_session, "scanner-01", seen_secs_ago=1)
    _builtin(db_session, "scanner-02", seen_secs_ago=1)

    others = find_other_live_instances(db_session, hostname="scanner-01")

    assert [agent.hostname for agent in others] == ["scanner-02"]
