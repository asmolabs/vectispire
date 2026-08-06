"""Tests for tracker ticket creation.

Two properties matter more than the HTTP payloads: the sweep is **idempotent** (a
tracker outage must be retried, never duplicated) and it is driven by the **gate
policy** rather than by a threshold of its own — so "serious enough to act on" is
defined in exactly one place, and nobody has to explain why something got a ticket but
not a build failure.
"""
import pytest

from zanshin.models.issue import STATE_OPEN, TRIAGE_NOT_AFFECTED, Issue
from zanshin.repositories.gate_policy_repository import GatePolicyRepository
from zanshin.repositories.issue_repository import IssueRepository
from zanshin.services.gate_policy_service import GatePolicyService
from zanshin.services.ticket_service import (
    PROVIDER_GITLAB,
    PROVIDER_JIRA,
    TicketService,
    build_body,
    build_title,
    sweep,
)

_next_fingerprint = iter(range(1, 10_000))


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture()
def configure(setting_repository):
    """Write the settings a configured tracker needs."""
    from zanshin.models.setting import Setting

    def _configure(**overrides):
        values = {
            "ticket_provider": PROVIDER_GITLAB,
            "ticket_base_url": "https://gitlab.example.com",
            "ticket_project": "group/app",
            "ticket_token": "glpat-secret",
            "ticket_allow_private_url": "false",
        }
        values.update(overrides)
        for key, value in values.items():
            setting_repository.save(Setting(key=key, value=value))

    return _configure


@pytest.fixture()
def gitlab_calls():
    return []


@pytest.fixture()
def service(settings_service, gitlab_calls):
    def fake_post(url, **kwargs):
        gitlab_calls.append({"url": url, **kwargs})
        if "/api/v4/" in url:
            return FakeResponse({"iid": 42, "web_url": "https://gitlab.example.com/g/app/-/issues/42"})
        return FakeResponse({"key": "SEC-7"})

    # No encryption service: the token is then read as stored, which keeps these tests
    # about ticket behaviour rather than about AES.
    return TicketService(settings_service, encryption_service=None, http_post=fake_post)


def _issue(db, **kwargs):
    defaults = dict(
        fingerprint=f"fp-{next(_next_fingerprint)}",
        type="vulnerability",
        identifier="CVE-2024-0001",
        severity="critical",
        state=STATE_OPEN,
        is_kev=False,
    )
    defaults.update(kwargs)
    issue = Issue(**defaults)
    db.add(issue)
    db.commit()
    db.refresh(issue)
    return issue


# --- Configuration ---

def test_the_service_is_inert_until_it_is_configured(service):
    assert service.is_enabled() is False


def test_every_field_is_required_before_it_activates(service, configure):
    configure(ticket_project="")

    assert service.is_enabled() is False


def test_a_configured_provider_is_enabled(service, configure):
    configure()

    assert service.is_enabled() is True


def test_an_unknown_provider_is_treated_as_none(service, configure):
    configure(ticket_provider="bugzilla")

    assert service.provider() == "none"
    assert service.is_enabled() is False


def test_the_token_is_stored_encrypted(settings_service, encryption_service):
    """It grants write access to the tracker — a different class of secret from a
    webhook URL, so it goes through the encryption service like an SSH key."""
    service = TicketService(settings_service, encryption_service=encryption_service)

    service.set_token("glpat-very-secret")

    stored = settings_service.get_setting("ticket_token")
    assert "glpat-very-secret" not in stored
    assert service.token() == "glpat-very-secret"


def test_an_undecryptable_token_disables_creation_rather_than_raising(
    settings_service, encryption_service, setting_repository
):
    """A rotated `ENCRYPTION_KEY` must not break the scheduler tick this runs on."""
    from zanshin.models.setting import Setting

    setting_repository.save(Setting(key="ticket_token", value="not-a-ciphertext"))
    service = TicketService(settings_service, encryption_service=encryption_service)

    assert service.token() == ""


def test_a_public_base_url_is_refused_when_private_is_required(service, configure):
    from zanshin.services.url_guard import UnsafeUrlError

    configure()
    with pytest.raises(UnsafeUrlError):
        service.set_base_url("http://169.254.169.254/latest/meta-data")


# --- Payloads ---

def test_the_title_is_searchable_and_the_body_leads_with_the_fix(db_session):
    issue = _issue(db_session, fix_versions="1.2.3", package_name="libfoo", package_version="1.0.0")

    title = build_title(issue, "app")
    body = build_body(issue, "app")

    assert "CVE-2024-0001" in title and "CRITICAL" in title and "app" in title
    # The difference between a ticket somebody closes today and one carried across
    # three sprints.
    assert "1.2.3" in body
    assert issue.fingerprint in body


def test_the_body_states_when_no_fix_exists(db_session):
    issue = _issue(db_session, fix_state="not-fixed")

    assert "Aucun correctif" in build_body(issue, "app")


def test_the_body_carries_the_signals_that_change_the_decision(db_session):
    issue = _issue(db_session, is_kev=True, epss_score=0.87, is_direct_dependency=True)

    body = build_body(issue, "app")

    assert "CISA KEV" in body
    assert "87" in body
    assert "directe" in body


def test_gitlab_receives_a_private_token_and_returns_a_reference(service, configure, gitlab_calls, db_session):
    configure()
    issue = _issue(db_session)

    ticket = service.create_for_issue(issue, "app")

    assert ticket.reference == "#42"
    assert ticket.url.endswith("/issues/42")
    call = gitlab_calls[0]
    assert call["headers"]["PRIVATE-TOKEN"] == "glpat-secret"
    # A project path has to be encoded, which is how most people have it to hand.
    assert "group%2Fapp" in call["url"]


def test_jira_receives_the_document_format_it_demands(service, configure, gitlab_calls, db_session):
    """Jira Cloud's v3 API refuses a plain string for `description`."""
    configure(ticket_provider=PROVIDER_JIRA, ticket_base_url="https://x.atlassian.net",
              ticket_project="SEC", ticket_user="bot@example.com")
    issue = _issue(db_session)

    ticket = service.create_for_issue(issue, "app")

    assert ticket.reference == "SEC-7"
    assert ticket.url.endswith("/browse/SEC-7")
    fields = gitlab_calls[-1]["json"]["fields"]
    assert fields["description"]["type"] == "doc"
    assert fields["project"] == {"key": "SEC"}


def test_a_tracker_failure_returns_none_rather_than_raising(settings_service, configure, db_session):
    def broken_post(url, **kwargs):
        raise ConnectionError("simulated: tracker down")

    configure()
    service = TicketService(settings_service, http_post=broken_post)

    assert service.create_for_issue(_issue(db_session), "app") is None


# --- The sweep ---

@pytest.fixture()
def sweep_context(db_session, service, configure):
    configure()
    policies = GatePolicyService(GatePolicyRepository(db_session))

    def run(**kwargs):
        return sweep(
            db_session,
            issue_repository=IssueRepository(db_session),
            gate_policy_service=policies,
            ticket_service=service,
            **kwargs,
        )

    return run, policies


def test_an_issue_that_would_fail_the_gate_gets_a_ticket(db_session, sweep_context):
    run, _ = sweep_context
    issue = _issue(db_session, severity="critical", repo_id=None, container_id=None)

    created = run()

    assert [i.id for i in created] == [issue.id]
    assert issue.ticket_ref == "#42"
    assert issue.ticket_url


def test_an_issue_below_the_policy_gets_none(db_session, sweep_context):
    """One threshold, defined in one place: whatever fails a build is what gets a
    ticket."""
    run, policies = sweep_context
    policies.save_policy(fail_on_severity="critical", fail_on_kev=False, actor="a")
    _issue(db_session, severity="medium")

    assert run() == []


def test_tightening_the_policy_makes_a_skipped_issue_a_candidate_again(db_session, sweep_context):
    """No marker is written when an issue is below the bar, on purpose: the policy may
    be tightened tomorrow."""
    run, policies = sweep_context
    policies.save_policy(fail_on_severity="critical", fail_on_kev=False, actor="a")
    issue = _issue(db_session, severity="high")
    assert run() == []

    policies.save_policy(fail_on_severity="high", fail_on_kev=False, actor="a")

    assert [i.id for i in run()] == [issue.id]


def test_a_second_sweep_creates_nothing_new(db_session, sweep_context, gitlab_calls):
    """Idempotent by construction — the reference on the issue *is* the deduplication
    key, which is why this needs no outbox."""
    run, _ = sweep_context
    _issue(db_session)

    run()
    run()

    assert len(gitlab_calls) == 1


def test_a_failed_creation_is_retried_on_the_next_sweep(db_session, settings_service, configure):
    """A tracker in maintenance must not lose the ticket silently."""
    attempts = []

    def flaky_post(url, **kwargs):
        attempts.append(url)
        if len(attempts) == 1:
            raise ConnectionError("simulated: tracker down")
        return FakeResponse({"iid": 7, "web_url": "https://gitlab.example.com/i/7"})

    configure()
    service = TicketService(settings_service, http_post=flaky_post)
    issue = _issue(db_session)
    policies = GatePolicyService(GatePolicyRepository(db_session))

    def run():
        return sweep(
            db_session,
            issue_repository=IssueRepository(db_session),
            gate_policy_service=policies,
            ticket_service=service,
        )

    assert run() == []
    assert issue.ticket_ref is None

    assert [i.id for i in run()] == [issue.id]
    assert issue.ticket_ref == "#7"


def test_a_triaged_issue_gets_no_ticket(db_session, sweep_context):
    run, _ = sweep_context
    _issue(
        db_session,
        triage_status=TRIAGE_NOT_AFFECTED,
        triage_justification="component_not_present",
    )

    assert run() == []


def test_a_target_policy_governs_its_own_issues(db_session, sweep_context, make_repository):
    """The threshold that applies is the one that would fail *that* target's build."""
    run, policies = sweep_context
    strict_repo = make_repository()
    lax_repo = make_repository()
    policies.save_policy(fail_on_severity="critical", fail_on_kev=False, actor="a")
    policies.save_policy(
        target_kind="repository", target_id=strict_repo.id,
        fail_on_severity="medium", fail_on_kev=False, actor="a",
    )
    strict_issue = _issue(db_session, severity="high", repo_id=strict_repo.id)
    _issue(db_session, severity="high", repo_id=lax_repo.id)

    created = run()

    assert [i.id for i in created] == [strict_issue.id]


def test_the_sweep_is_capped(db_session, sweep_context):
    """A first run against a mature backlog would otherwise open hundreds of tickets
    in one burst — a rate-limit problem and a social one."""
    run, _ = sweep_context
    for _ in range(5):
        _issue(db_session)

    created = run(limit=2)

    assert len(created) == 2


def test_nothing_happens_when_no_tracker_is_configured(db_session, settings_service):
    service = TicketService(settings_service)
    _issue(db_session)

    created = sweep(
        db_session,
        issue_repository=IssueRepository(db_session),
        gate_policy_service=GatePolicyService(GatePolicyRepository(db_session)),
        ticket_service=service,
    )

    assert created == []


def test_ticket_creation_is_audited(db_session, sweep_context, audit_log_repository):
    """The scheduler writes into an external tracker with no human in the loop, so the
    trail is the only record that Zanshin did it."""
    from zanshin.services.audit_log_service import AuditLogService

    run, _ = sweep_context
    _issue(db_session)

    run(audit_log_service=AuditLogService(audit_log_repository))

    entry = audit_log_repository.find_latest()
    assert entry.operation_type == "TICKET_CREATED"
    assert "#42" in entry.description
