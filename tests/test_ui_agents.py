"""State-level tests for the agents screen.

Same approach as `tests/test_ui_pages.py`: the loader is where the typed rows are
built, and the template that consumes them is checked by `reflex compile`.

The screen has one job that matters — telling an operator why nothing is happening —
so these tests are mostly about that: is anything waiting, is anybody able to pick
it up, and does the page say so.
"""
from datetime import timedelta

import pytest

from zanshin.clock import utcnow
from zanshin.models.agent import (
    CREDENTIALS_DELEGATED,
    CREDENTIALS_LOCAL,
    STATUS_DISABLED,
    STATUS_OFFLINE,
    STATUS_ONLINE,
)
from zanshin.models.api_key import SCOPE_AGENT
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
from zanshin.repositories.agent_repository import AgentRepository
from zanshin.repositories.api_key_repository import ApiKeyRepository
from zanshin.services.agent_service import AgentService
from zanshin.services.api_key_service import ApiKeyService
from zanshin.services.settings_service import SettingsService
from zanshin.repositories.setting_repository import SettingRepository
from zanshin.ui.pages.agents import AgentsState


def _agent_service(session) -> AgentService:
    return AgentService(
        AgentRepository(session),
        api_key_service=ApiKeyService(ApiKeyRepository(session)),
        settings_service=SettingsService(SettingRepository(session)),
    )


def _repo(db, name="App"):
    repo = ZanshinRepository(url="git@example.com:org/app.git", branch="main", name=name)
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


def _scan(db, repo_id, status="pending", claimed_by=None, lease_expires_at=None, attempts=0):
    scan = Scan(
        repo_id=repo_id, branch="main", status=status, findings_count=0,
        created_at=utcnow(), claimed_by=claimed_by, lease_expires_at=lease_expires_at,
        attempts=attempts,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


# --- The agent list -----------------------------------------------------------

def test_the_loader_always_shows_this_instance_as_an_agent(ui, ui_session):
    """Even on a database that has never seen one: the process serving the page is a
    worker, and a page that omitted it would suggest scans run nowhere."""
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert len(state.agents) == 1
    builtin = state.agents[0]
    assert builtin.is_builtin is True
    assert builtin.status == STATUS_ONLINE  # it just registered itself
    assert builtin.credentials_mode == CREDENTIALS_LOCAL


def test_a_remote_agent_that_has_not_called_in_reads_as_offline(ui, ui_session):
    _agent_service(ui_session).create_remote_agent(name="paris-01")
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    remote = next(row for row in state.agents if not row.is_builtin)
    assert remote.status == STATUS_OFFLINE
    assert remote.last_seen_at == "Jamais"


def test_a_stale_agent_reads_as_offline_rather_than_online(ui, ui_session):
    service = _agent_service(ui_session)
    agent, _ = service.create_remote_agent(name="paris-01")
    service.touch(agent)
    agent.last_seen_at = utcnow() - timedelta(hours=1)
    ui_session.commit()
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert next(row for row in state.agents if not row.is_builtin).status == STATUS_OFFLINE


def test_a_disabled_agent_shows_no_capacity(ui, ui_session):
    """Which is the whole point of disabling it, and the number an operator checks
    when scans stop moving."""
    service = _agent_service(ui_session)
    agent, _ = service.create_remote_agent(name="paris-01", max_concurrent=4)
    service.set_enabled(agent.id, False)
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    remote = next(row for row in state.agents if not row.is_builtin)
    assert remote.status == STATUS_DISABLED
    assert remote.max_concurrent == 0


def test_the_credentials_mode_is_visible_per_agent(ui, ui_session):
    service = _agent_service(ui_session)
    agent, _ = service.create_remote_agent(
        name="paris-01", credentials_mode=CREDENTIALS_DELEGATED
    )
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    remote = next(row for row in state.agents if not row.is_builtin)
    assert remote.sends_credentials is True


# --- The queue ----------------------------------------------------------------

def test_a_waiting_scan_shows_its_place_in_line(ui, ui_session):
    repo = _repo(ui_session)
    first = _scan(ui_session, repo.id)
    second = _scan(ui_session, repo.id)
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert state.queued_count == 2
    positions = {row.scan_id: row.position for row in state.queue}
    assert positions[first.id] == 1
    assert positions[second.id] == 2


def test_a_running_scan_names_the_agent_holding_it(ui, ui_session):
    service = _agent_service(ui_session)
    agent, _ = service.create_remote_agent(name="paris-01")
    repo = _repo(ui_session)
    _scan(
        ui_session, repo.id, status="scanning", claimed_by=agent.worker_id,
        lease_expires_at=utcnow() + timedelta(minutes=10),
    )
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    row = state.queue[0]
    assert row.agent_name == "paris-01"
    assert row.lease_expired is False
    assert state.running_count == 1


def test_a_scan_whose_agent_row_is_gone_keeps_its_provenance(ui, ui_session):
    """More useful than pretending nobody ran it — which is why `claimed_by` is not a
    foreign key that would have been nulled on delete."""
    service = _agent_service(ui_session)
    agent, _ = service.create_remote_agent(name="paris-01")
    worker_id = agent.worker_id
    repo = _repo(ui_session)
    _scan(
        ui_session, repo.id, status="scanning", claimed_by=worker_id,
        lease_expires_at=utcnow() + timedelta(minutes=10),
    )
    service.delete_agent(agent.id)
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert state.queue[0].agent_name == "exécutant inconnu"


def test_loading_the_page_reclaims_a_scan_whose_agent_stopped_reporting(ui, ui_session):
    """There is no scheduler in a test, and in production the tick might be minutes
    away: an operator looking at the queue is a legitimate moment to notice."""
    repo = _repo(ui_session)
    scan = _scan(
        ui_session, repo.id, status="scanning", claimed_by="dead-worker",
        lease_expires_at=utcnow() - timedelta(minutes=1),
    )
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    ui_session.expire_all()
    refreshed = ui_session.query(Scan).filter(Scan.id == scan.id).first()
    assert refreshed.status == "pending"
    assert refreshed.claimed_by is None


def test_the_page_warns_when_nothing_can_pick_work_up(ui, ui_session):
    """From the operator's side the only symptom is a queue that stopped moving, so
    the page has to say it out loud."""
    service = _agent_service(ui_session)
    builtin = service.ensure_builtin_agent()
    service.set_enabled(builtin.id, False)
    repo = _repo(ui_session)
    _scan(ui_session, repo.id)
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert state.no_worker_available is True
    assert state.queued_count == 1


def test_no_warning_when_the_builtin_agent_is_working(ui, ui_session):
    repo = _repo(ui_session)
    _scan(ui_session, repo.id)
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert state.no_worker_available is False


# --- Registration -------------------------------------------------------------

def test_creating_an_agent_shows_its_key_once_and_scopes_it_to_agent_work(ui, ui_session):
    state = ui.state(AgentsState)
    state.new_name = "paris-01"
    state.new_labels = "Linux, GPU"
    state.new_max_concurrent = "3"

    ui.run(state, "create_agent")
    # The handler yields the loader rather than calling it, and the harness leaves a
    # yielded generator alone on purpose (see `UIHarness._drain`), so the refresh is
    # explicit here.
    ui.run(state, "load_agents_data")

    assert state.created_key_raw.startswith("zsk_")
    assert state.display_dialog_open is True
    key = ApiKeyRepository(ui_session).find_all()[0]
    assert key.scope_list == [SCOPE_AGENT]
    remote = next(row for row in state.agents if not row.is_builtin)
    assert remote.max_concurrent == 3
    assert "gpu" in remote.labels


def test_a_duplicate_name_is_refused_without_issuing_a_key(ui, ui_session):
    _agent_service(ui_session).create_remote_agent(name="paris-01")
    state = ui.state(AgentsState)
    state.new_name = "paris-01"

    ui.run(state, "create_agent")

    assert state.created_key_raw == ""
    assert state.display_dialog_open is False


def test_closing_the_key_dialog_forgets_the_secret(ui, ui_session):
    state = ui.state(AgentsState)
    state.new_name = "paris-01"
    ui.run(state, "create_agent")

    ui.run(state, "close_display_dialog")

    assert state.created_key_raw == ""


# --- Lifecycle ----------------------------------------------------------------

def test_disabling_the_builtin_agent_from_the_page_takes_this_instance_out(ui, ui_session):
    state = ui.state(AgentsState)
    ui.run(state, "load_agents_data")
    builtin = state.agents[0]

    ui.run(state, "toggle_agent", builtin.id, False)
    ui.run(state, "load_agents_data")

    assert state.agents[0].status == STATUS_DISABLED
    assert state.agents[0].max_concurrent == 0


def test_the_builtin_agent_cannot_be_deleted_from_the_page(ui, ui_session):
    state = ui.state(AgentsState)
    ui.run(state, "load_agents_data")
    builtin = state.agents[0]

    ui.run(state, "delete_agent", builtin.id)

    ui.run(state, "load_agents_data")
    assert any(row.is_builtin for row in state.agents)


def test_switching_an_agent_to_delegated_credentials(ui, ui_session):
    agent, _ = _agent_service(ui_session).create_remote_agent(name="paris-01")
    state = ui.state(AgentsState)

    ui.run(state, "set_credentials_mode", str(agent.id), CREDENTIALS_DELEGATED)
    ui.run(state, "load_agents_data")

    remote = next(row for row in state.agents if not row.is_builtin)
    assert remote.sends_credentials is True


def test_a_non_admin_cannot_register_an_agent(ui, ui_session):
    """Registering an agent issues a credential that may submit scan results, and
    results are what a gate is evaluated against."""
    state = ui.state(AgentsState, role="USER")
    state.new_name = "paris-01"

    ui.run(state, "create_agent")

    assert state.created_key_raw == ""
    assert ApiKeyRepository(ui_session).find_all() == []


# --- Who owns the periodic work -----------------------------------------------

def test_the_page_names_this_instance_when_it_owns_the_scheduled_work(ui, ui_session):
    """"Why did nothing run last night" is the question this answers — and answering it
    is why the lease is a table rather than an engine advisory lock."""
    from zanshin.services import leader_election

    leader_election.acquire(ui_session)
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert state.scheduler_owner == leader_election.INSTANCE_ID
    assert state.scheduler_is_this_instance is True


def test_the_page_says_another_instance_owns_it(ui, ui_session):
    from zanshin.services import leader_election

    leader_election.acquire(ui_session, holder="another-instance")
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert state.scheduler_owner == "another-instance"
    assert state.scheduler_is_this_instance is False


def test_an_expired_lease_names_nobody(ui, ui_session):
    """A dead instance must not still be shown as the one doing the work."""
    from datetime import timedelta

    from zanshin.models.leader_lease import JOB_SCHEDULER, LeaderLease
    from zanshin.services import leader_election

    leader_election.acquire(ui_session, holder="dead-instance")
    lease = ui_session.query(LeaderLease).filter(LeaderLease.name == JOB_SCHEDULER).first()
    lease.expires_at = utcnow() - timedelta(seconds=1)
    ui_session.commit()
    state = ui.state(AgentsState)

    ui.run(state, "load_agents_data")

    assert state.scheduler_owner == ""
