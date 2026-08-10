"""Tests for the agent registry.

The registry answers three questions the application could not answer before:
what workers exist, which are alive, and how much capacity each has. The
built-in agent is the interesting one — it is the reason a single-process
install keeps working with no configuration, and the switch that moves execution
off the web instance.
"""
from datetime import timedelta

import pytest

from zanshin.clock import utcnow
from zanshin.models.agent import (
    CREDENTIALS_DELEGATED,
    CREDENTIALS_LOCAL,
    KIND_BUILTIN,
    KIND_REMOTE,
    ONLINE_TTL_SECONDS,
    STATUS_DISABLED,
    STATUS_OFFLINE,
    STATUS_ONLINE,
)
from zanshin.models.api_key import SCOPE_AGENT, SCOPE_READ
from zanshin.repositories.agent_repository import AgentRepository
from zanshin.services.agent_service import (
    AgentService,
    agent_matches_label,
    normalize_labels,
    validate_credentials_mode,
)
from zanshin.services.api_key_service import ApiKeyService


@pytest.fixture()
def agent_service(db_session, settings_service, api_key_repository):
    return AgentService(
        AgentRepository(db_session),
        api_key_service=ApiKeyService(api_key_repository),
        settings_service=settings_service,
    )


# --- The built-in agent -------------------------------------------------------

def test_the_builtin_agent_is_created_once_and_refreshed_afterwards(agent_service):
    first = agent_service.ensure_builtin_agent(hostname="scanner-01")
    second = agent_service.ensure_builtin_agent(hostname="scanner-01")

    assert first.id == second.id
    assert second.kind == KIND_BUILTIN
    assert "scanner-01" in second.name
    # Calling in is what "online" means, and registering is calling in.
    assert second.last_seen_at is not None
    assert len(agent_service.find_all()) == 1


def test_a_restart_does_not_re_enable_a_disabled_builtin_agent(agent_service):
    """The operator turned it off so that scans go to remote agents. A restart
    silently undoing that would send the work straight back to the web instance,
    with nothing in the UI to explain why."""
    agent = agent_service.ensure_builtin_agent(hostname="scanner-01")
    agent_service.set_enabled(agent.id, False)
    agent_service.update_agent(agent.id, labels="gpu")

    refreshed = agent_service.ensure_builtin_agent(hostname="scanner-01")

    assert refreshed.enabled is False
    assert refreshed.labels == "gpu"


def test_the_builtin_agent_cannot_be_deleted(agent_service):
    """It would come back on the next startup, minus the operator's settings — so
    deleting it would really mean "re-enable it and forget my configuration"."""
    agent = agent_service.ensure_builtin_agent(hostname="scanner-01")

    with pytest.raises(ValueError, match="intégré"):
        agent_service.delete_agent(agent.id)


def test_the_builtin_agent_refuses_delegated_credentials(agent_service):
    """There is nothing to delegate to a process that already holds the key store;
    accepting the value would imply otherwise."""
    agent = agent_service.ensure_builtin_agent(hostname="scanner-01")

    with pytest.raises(ValueError, match="délégué"):
        agent_service.update_agent(agent.id, credentials_mode=CREDENTIALS_DELEGATED)


def test_one_builtin_agent_per_host(agent_service):
    """Not supported as a deployment yet, but the model must not pretend two hosts
    are one — that is how a shared row would start lying about who is online."""
    first = agent_service.ensure_builtin_agent(hostname="scanner-01")
    second = agent_service.ensure_builtin_agent(hostname="scanner-02")

    assert first.id != second.id


# --- Remote agents ------------------------------------------------------------

def test_creating_a_remote_agent_issues_a_credential_scoped_to_agent_work(
    agent_service, api_key_repository
):
    agent, raw_key = agent_service.create_remote_agent(name="paris-01", labels="Linux, GPU")

    assert agent.kind == KIND_REMOTE
    assert raw_key.startswith("zsk_")
    # Shown once, like any other key: only the hash is stored.
    assert raw_key not in [k.key_hash for k in api_key_repository.find_all()]

    key = api_key_repository.find_by_id(agent.api_key_id)
    assert key.scope_list == [SCOPE_AGENT]
    # A leaked agent credential must not also read the issue history or export a
    # customer's VEX document.
    assert not key.has_scope(SCOPE_READ)
    assert agent.labels == "gpu,linux" or agent.labels == "linux,gpu"


def test_two_agents_cannot_share_a_name(agent_service):
    """The name is what a launch command and the queue's log refer to."""
    agent_service.create_remote_agent(name="paris-01")

    with pytest.raises(ValueError, match="existe déjà"):
        agent_service.create_remote_agent(name="paris-01")


def test_an_agent_needs_a_name(agent_service):
    with pytest.raises(ValueError):
        agent_service.create_remote_agent(name="   ")


def test_a_remote_agent_can_be_deleted(agent_service):
    agent, _ = agent_service.create_remote_agent(name="paris-01")

    assert agent_service.delete_agent(agent.id) is True
    assert agent_service.find_by_id(agent.id) is None


def test_credentials_mode_defaults_to_sending_no_secret(agent_service):
    """décision 0003: the safe mode is the default, and the other one has to be asked
    for."""
    agent, _ = agent_service.create_remote_agent(name="paris-01")

    assert agent.credentials_mode == CREDENTIALS_LOCAL
    assert agent.sends_credentials is False

    updated = agent_service.update_agent(agent.id, credentials_mode=CREDENTIALS_DELEGATED)
    assert updated.sends_credentials is True


def test_an_unknown_credentials_mode_is_refused():
    with pytest.raises(ValueError):
        validate_credentials_mode("trust-me")


# --- Liveness -----------------------------------------------------------------

def test_status_reflects_recent_contact_rather_than_a_stored_flag(agent_service):
    agent, _ = agent_service.create_remote_agent(name="paris-01")

    # Never seen.
    assert agent_service.status_of(agent) == STATUS_OFFLINE

    agent_service.touch(agent)
    assert agent_service.status_of(agent) == STATUS_ONLINE

    agent.last_seen_at = utcnow() - timedelta(seconds=ONLINE_TTL_SECONDS + 5)
    assert agent_service.status_of(agent) == STATUS_OFFLINE


def test_a_disabled_agent_reads_as_disabled_even_while_it_is_still_calling_in(agent_service):
    """It may well still be running — it just is not being given anything new."""
    agent, _ = agent_service.create_remote_agent(name="paris-01")
    agent_service.touch(agent)

    agent_service.set_enabled(agent.id, False)

    assert agent_service.status_of(agent) == STATUS_DISABLED
    assert agent_service.find_available() == []


def test_touch_records_what_the_agent_reports_about_itself(agent_service):
    agent, _ = agent_service.create_remote_agent(name="paris-01")

    agent_service.touch(agent, {
        "hostname": "runner-7",
        "platform": "Linux-6.1",
        "version": "1.2.3",
        "scanner_engine": "docker",
        "capabilities": {"docker": True},
    })

    assert agent.hostname == "runner-7"
    assert agent.scanner_engine == "docker"
    assert agent.capabilities == {"docker": True}


# --- Capacity -----------------------------------------------------------------

def test_the_builtin_agents_capacity_is_the_existing_concurrency_setting(
    agent_service, settings_service
):
    """One number for "how many scans this host runs at once", not two that can
    disagree."""
    agent = agent_service.ensure_builtin_agent(hostname="scanner-01")
    settings_service.update_setting("scan_max_concurrent", "4")

    assert agent_service.capacity_of(agent) == 4


def test_a_disabled_agent_has_no_capacity_at_all(agent_service):
    """This is the switch that moves execution off the web instance."""
    agent = agent_service.ensure_builtin_agent(hostname="scanner-01")
    agent_service.set_enabled(agent.id, False)

    assert agent_service.capacity_of(agent) == 0


def test_a_remote_agent_carries_its_own_limit(agent_service):
    agent, _ = agent_service.create_remote_agent(name="paris-01", max_concurrent=3)

    assert agent_service.capacity_of(agent) == 3


# --- Labels -------------------------------------------------------------------

def test_labels_are_normalized_on_write():
    assert normalize_labels(" Linux , GPU ,linux") == "linux,gpu"
    assert normalize_labels(None) == ""
    assert normalize_labels("a;b") == "a,b"


def test_a_job_with_no_required_label_matches_any_agent(agent_service):
    agent, _ = agent_service.create_remote_agent(name="paris-01", labels="linux")

    assert agent_matches_label(agent, "") is True
    assert agent_matches_label(agent, None) is True
    assert agent_matches_label(agent, "linux") is True
    assert agent_matches_label(agent, "windows") is False


def test_label_matching_ignores_case_and_spacing(agent_service):
    agent, _ = agent_service.create_remote_agent(name="paris-01", labels="GPU")

    assert agent_matches_label(agent, " gpu ") is True


def test_has_agent_for_label_only_counts_agents_that_could_take_work(agent_service):
    offline, _ = agent_service.create_remote_agent(name="offline", labels="gpu")
    online, _ = agent_service.create_remote_agent(name="online", labels="cpu")
    agent_service.touch(online)

    assert agent_service.has_agent_for_label("cpu") is True
    # Right label, but nobody is listening.
    assert agent_service.has_agent_for_label("gpu") is False
