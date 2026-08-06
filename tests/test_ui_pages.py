"""State-level tests for the page loaders.

The UI layer was untested — excluded from coverage with the note that `rx.State`
classes need Reflex's own harness. `reflex.testing.AppHarness` starts a server and
a browser; these tests use the lighter path documented in `tests/conftest.py`
(`UIHarness`), which instantiates a state and calls its handlers directly.

What that buys, concretely: the loaders are where the typed view models are built,
and the templates that consume them are already checked by `reflex compile`. So
the two halves of the UI are covered by different means, and neither is left to
"it looked right when I clicked it".
"""
from datetime import timedelta

import pytest
from zanshin.models.container import Container
from zanshin.models.finding import Finding
from zanshin.models.issue import STATE_OPEN, STATE_RESOLVED, TRIAGE_NOT_AFFECTED, Issue
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
from zanshin.ui.pages.change_password import ChangePasswordState
from zanshin.ui.state import LoginState
from zanshin.ui.pages.containers import ContainersState
from zanshin.ui.pages.depots import DepotsState
from zanshin.ui.pages.issues import IssuesState
# Every page state must be imported before the harness builds the root state:
# Reflex registers substates at class-definition time, and the root only knows
# about the ones that exist when it is created.
from zanshin.clock import utcnow
from zanshin.models.audit_log import AuditLog
from zanshin.models.setting import Setting
from zanshin.models.ssh_key import SSHKey
from zanshin.models.user import User
from zanshin.repositories.api_key_repository import ApiKeyRepository
from zanshin.repositories.user_repository import UserRepository
from zanshin.services.api_key_service import ApiKeyService
from zanshin.services.auth_service import AuthService
from zanshin.services.retention_service import SETTING_KEY_RETENTION_KEEP_PER_TARGET
from zanshin.ui.pages.api_keys import ApiKeysState
from zanshin.ui.pages.audit_log import AuditLogState
from zanshin.ui.pages.login import LoginState
from zanshin.ui.pages.settings import SettingsState
from zanshin.ui.pages.ssh_keys import SSHKeysState
from zanshin.ui.pages.users import UsersState
from zanshin.ui.state import BaseState

_fingerprints = iter(range(1, 10_000))


def _repo(db, name="App", url="git@example.com:org/app.git"):
    repo = ZanshinRepository(url=url, branch="main", name=name)
    db.add(repo)
    db.commit()
    db.refresh(repo)
    return repo


def _scan(db, *, repo_id=None, container_id=None, status="completed", summary=None,
          findings_count=0, new_issues=0, resolved_issues=0, sbom=None, cves=None, age_days=0):
    scan = Scan(
        repo_id=repo_id,
        container_id=container_id,
        branch="main",
        status=status,
        findings_count=findings_count,
        summary=summary,
        new_issues_count=new_issues,
        resolved_issues_count=resolved_issues,
        sbom=sbom,
        cves=cves,
        created_at=utcnow() - timedelta(days=age_days),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _issue(db, **kwargs):
    defaults = dict(
        fingerprint=f"fp-{next(_fingerprints)}",
        type="vulnerability",
        identifier="CVE-2024-0001",
        severity="high",
        state=STATE_OPEN,
        is_kev=False,
    )
    defaults.update(kwargs)
    issue = Issue(**defaults)
    db.add(issue)
    db.commit()
    db.refresh(issue)
    return issue


# --- Repositories list ---

def test_repository_rows_carry_numbers_not_strings(ui, ui_session):
    """The whole point of the typed rows: a template can ask "more than zero",
    which `"0" != "0"` never allowed."""
    repo = _repo(ui_session)
    _scan(
        ui_session, repo_id=repo.id, findings_count=7,
        summary={"critical": 1, "high": 2, "medium": 3, "low": 1, "total": 7},
    )
    state = ui.state(DepotsState)

    ui.run(state, "load_repos_list")

    assert len(state.repositories) == 1
    row = state.repositories[0]
    assert row.id == repo.id and isinstance(row.id, int)
    assert row.findings == 7
    assert row.counts.critical == 1 and row.counts.high == 2
    assert row.status == "completed"
    assert row.name == "App"


def test_a_repository_never_scanned_reads_as_such(ui, ui_session):
    _repo(ui_session)
    state = ui.state(DepotsState)

    ui.run(state, "load_repos_list")

    row = state.repositories[0]
    assert row.status == "Non scanné"
    assert row.findings == 0
    assert row.counts.critical == 0


def test_outstanding_issue_count_excludes_triaged_ones(ui, ui_session):
    """The number that shrinks when the team works, unlike the finding count."""
    repo = _repo(ui_session)
    _scan(ui_session, repo_id=repo.id)
    _issue(ui_session, repo_id=repo.id)
    _issue(ui_session, repo_id=repo.id, triage_status=TRIAGE_NOT_AFFECTED)
    _issue(ui_session, repo_id=repo.id, state=STATE_RESOLVED)
    state = ui.state(DepotsState)

    ui.run(state, "load_repos_list")

    assert state.repositories[0].open_issues == 1


def test_the_kpi_row_totals_across_repositories(ui, ui_session):
    first = _repo(ui_session, name="A", url="git@example.com:org/a.git")
    second = _repo(ui_session, name="B", url="git@example.com:org/b.git")
    _scan(ui_session, repo_id=first.id, findings_count=2, summary={"critical": 1, "high": 1, "total": 2})
    _scan(ui_session, repo_id=second.id, findings_count=1, summary={"critical": 1, "total": 1})
    state = ui.state(DepotsState)

    ui.run(state, "load_repos_list")

    assert state.critical_count == 2
    assert state.high_count == 1
    assert state.total_vulns == 3
    # The donut stays dict-shaped because Recharts' prop type demands it.
    assert state.severity_chart_data[0] == {"name": "Critique", "value": 2, "color": "var(--red-9)"}


# --- History ---

def test_history_rows_report_the_delta_and_the_target(ui, ui_session):
    repo = _repo(ui_session)
    container = Container(image_name="nginx", tag="1.25", registry="registry.internal")
    ui_session.add(container)
    ui_session.commit()
    _scan(ui_session, repo_id=repo.id, new_issues=13, resolved_issues=8, age_days=1)
    _scan(ui_session, container_id=container.id, age_days=0)
    state = ui.state(DepotsState)

    ui.run(state, "load_history_list")

    by_target = {row.target_name: row for row in state.scan_history}
    assert by_target["App"].new_issues == 13
    assert by_target["App"].resolved_issues == 8
    assert by_target["App"].repo_id == str(repo.id)  # rescannable
    assert by_target["registry.internal/nginx:1.25"].repo_id == ""  # not rescannable
    assert by_target["registry.internal/nginx:1.25"].branch == "—"


def test_history_search_filters_on_target_branch_and_status(ui, ui_session):
    repo = _repo(ui_session, name="Zanshin")
    other = _repo(ui_session, name="Autre", url="git@example.com:org/other.git")
    _scan(ui_session, repo_id=repo.id)
    _scan(ui_session, repo_id=other.id)
    state = ui.state(DepotsState, search_history_query="zansh")

    ui.run(state, "load_history_list")

    assert [row.target_name for row in state.scan_history] == ["Zanshin"]


# --- Scan detail: independent of the raw blobs ---

def test_the_detail_dialog_is_built_from_findings_not_from_the_raw_blob(ui, ui_session):
    """This is what lets retention drop `Scan.cves`: every field the dialog shows
    already lives on the normalized findings."""
    repo = _repo(ui_session)
    scan = _scan(
        ui_session, repo_id=repo.id, findings_count=1,
        summary={"critical": 1, "total": 1},
        sbom=None, cves=None,  # already pruned
    )
    ui_session.add(
        Finding(
            scan_id=scan.id, type="vulnerability", identifier="CVE-2024-1234",
            severity="critical", package_name="libcurl", package_version="8.4.0",
            source="grype", cvss_score=9.8, epss_score=0.42, is_kev=True,
            fix_versions="8.5.0", link="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        )
    )
    ui_session.commit()
    state = ui.state(DepotsState)

    ui.run(state, "show_cves", scan.id)

    assert state.cve_dialog_open is True
    assert len(state.selected_scan_cves) == 1
    row = state.selected_scan_cves[0]
    assert row.identifier == "CVE-2024-1234"
    assert row.severity == "CRITICAL"
    assert row.severity_color == "red"
    assert row.cvss == "9.8"
    assert row.epss == "42.0%"
    assert row.is_kev is True
    assert row.fix == "8.5.0"
    assert state.selected_scan_summary.critical == 1


def test_a_reference_url_that_is_not_http_is_not_linked(ui, ui_session):
    """Reference URLs come from advisory feeds and package metadata. A
    `javascript:` URL rendered into `rx.link(href=...)` would be one click from
    executing in the analyst's browser."""
    repo = _repo(ui_session)
    scan = _scan(ui_session, repo_id=repo.id)
    ui_session.add(
        Finding(scan_id=scan.id, type="vulnerability", identifier="CVE-EVIL",
                severity="high", source="osv", link="javascript:alert(document.cookie)")
    )
    ui_session.commit()
    state = ui.state(DepotsState)

    ui.run(state, "show_cves", scan.id)

    assert state.selected_scan_cves[0].link == ""


def test_a_missing_fix_is_stated_rather_than_left_blank(ui, ui_session):
    repo = _repo(ui_session)
    scan = _scan(ui_session, repo_id=repo.id)
    ui_session.add_all([
        Finding(scan_id=scan.id, type="vulnerability", identifier="CVE-A", severity="high",
                source="grype", fix_state="not-fixed"),
        Finding(scan_id=scan.id, type="vulnerability", identifier="CVE-B", severity="high",
                source="grype", fix_state="unknown"),
    ])
    ui_session.commit()
    state = ui.state(DepotsState)

    ui.run(state, "show_cves", scan.id)

    fixes = {row.identifier: row.fix for row in state.selected_scan_cves}
    assert fixes["CVE-A"] == "Aucun correctif"
    assert fixes["CVE-B"] == "—"


def test_the_ai_review_block_knows_when_there_is_nothing_to_show(ui, ui_session):
    repo = _repo(ui_session)
    scan = _scan(ui_session, repo_id=repo.id)
    state = ui.state(DepotsState)

    ui.run(state, "show_cves", scan.id)

    assert state.selected_scan_ai_review.present is False


# --- Containers ---

def test_container_rows_are_typed(ui, ui_session):
    container = Container(image_name="nginx", tag="1.25", registry="registry.internal",
                          scan_interval_minutes=720)
    ui_session.add(container)
    ui_session.commit()
    _scan(ui_session, container_id=container.id, findings_count=4,
          summary={"critical": 2, "high": 2, "total": 4})
    _issue(ui_session, container_id=container.id)
    state = ui.state(ContainersState)

    ui.run(state, "load_container_data")

    row = state.containers[0]
    assert row.id == container.id
    assert row.vulns == 4
    assert row.counts.critical == 2
    assert row.open_issues == 1
    assert row.interval == 720


# --- Issues backlog ---

def test_issue_rows_and_pagination(ui, ui_session):
    repo = _repo(ui_session)
    for index in range(4):
        _issue(ui_session, repo_id=repo.id, identifier=f"CVE-{index}")
    state = ui.state(IssuesState)

    ui.run(state, "load_issues")

    assert state.total == 4
    assert len(state.issues) == 4
    assert state.page_label == "1–4 sur 4"
    assert state.has_next is False
    assert state.has_previous is False


def test_the_backlog_reports_the_total_even_when_a_page_is_shorter(ui, ui_session, monkeypatch):
    """A paginated view that hides the total is the same trap as a truncated one."""
    import zanshin.ui.pages.issues as issues_module

    monkeypatch.setattr(issues_module, "PAGE_SIZE", 2)
    repo = _repo(ui_session)
    for index in range(5):
        _issue(ui_session, repo_id=repo.id, identifier=f"CVE-{index}")
    state = ui.state(IssuesState)

    ui.run(state, "load_issues")

    assert len(state.issues) == 2
    assert state.total == 5
    assert state.page_label == "1–2 sur 5"
    assert state.has_next is True


def test_filters_reset_the_page(ui, ui_session, monkeypatch):
    """Page 3 of the previous filter is meaningless under a new one, and would
    show an empty table with rows available."""
    import zanshin.ui.pages.issues as issues_module

    monkeypatch.setattr(issues_module, "PAGE_SIZE", 2)
    repo = _repo(ui_session)
    for index in range(5):
        _issue(ui_session, repo_id=repo.id, identifier=f"CVE-{index}")
    state = ui.state(IssuesState, offset=4)

    ui.run(state, "set_filter_severity", "critical")

    assert state.offset == 0


def test_a_triaged_issue_shows_its_decision_and_author(ui, ui_session):
    repo = _repo(ui_session)
    _issue(
        ui_session, repo_id=repo.id, triage_status=TRIAGE_NOT_AFFECTED,
        triage_justification="component_not_present", triaged_by="alice",
        triage_comment="pas embarqué",
    )
    state = ui.state(IssuesState)

    ui.run(state, "load_issues")

    row = state.issues[0]
    assert row.triage == "Non affecté"
    assert row.triage_color == "blue"
    assert row.triaged_by == "alice"


# --- Login (the one state everything else depends on) ---

def test_a_correct_password_authenticates_and_records_it(ui, ui_session):

    auth = AuthService(UserRepository(ui_session))

    ui_session.add(User(username="alice", password=auth.hash_password("un-mot-de-passe"),
                        role="ADMIN", is_active=True))
    ui_session.commit()
    state = ui.state(LoginState, logged_in=False, username="")

    ui.run(state, "handle_login", {"username": "alice", "password": "un-mot-de-passe"})

    assert state.logged_in is True
    assert state.username == "alice"
    assert state.user_role == "ADMIN"
    operations = [row.operation_type for row in ui_session.query(AuditLog).all()]
    assert "LOGIN_SUCCESS" in operations


def test_a_wrong_password_does_not_authenticate_and_is_audited(ui, ui_session):
    """The audit trail of failures is what a lockout would eventually read."""

    auth = AuthService(UserRepository(ui_session))
    ui_session.add(User(username="alice", password=auth.hash_password("le-bon"), role="USER"))
    ui_session.commit()
    state = ui.state(LoginState, logged_in=False, username="")

    ui.run(state, "handle_login", {"username": "alice", "password": "le-mauvais"})

    assert state.logged_in is False
    operations = [row.operation_type for row in ui_session.query(AuditLog).all()]
    assert operations == ["LOGIN_FAILURE"]


def test_an_inactive_account_cannot_log_in(ui, ui_session):

    auth = AuthService(UserRepository(ui_session))
    ui_session.add(User(username="bob", password=auth.hash_password("motdepasse"),
                        role="USER", is_active=False))
    ui_session.commit()
    state = ui.state(LoginState, logged_in=False, username="")

    ui.run(state, "handle_login", {"username": "bob", "password": "motdepasse"})

    assert state.logged_in is False


def test_logout_clears_the_session_vars(ui):

    state = ui.state(BaseState)
    ui.run(state, "logout")

    assert state.logged_in is False
    assert state.username == ""
    assert state.user_role == ""


# --- Administration pages ---

def test_users_loader_builds_typed_rows(ui, ui_session):

    ui_session.add_all([
        User(username="alice", password="h", role="SUPERUSER", is_active=True, email="a@x.tld"),
        User(username="bob", password="h", role="USER", is_active=False),
    ])
    ui_session.commit()
    state = ui.state(UsersState)

    ui.run(state, "load_users")

    by_name = {row.username: row for row in state.users}
    assert by_name["alice"].is_active is True
    assert by_name["alice"].email == "a@x.tld"
    assert by_name["bob"].is_active is False
    assert by_name["bob"].email == "—"  # not blank: the table shows a dash


def test_api_keys_loader_shows_a_prefix_and_never_a_secret(ui, ui_session):
    """The raw secret is returned once at creation and never stored; the list can
    only ever show the prefix."""

    _, raw = ApiKeyService(ApiKeyRepository(ui_session)).create_key("ci")
    state = ui.state(ApiKeysState)

    ui.run(state, "load_keys_data")

    row = state.keys[0]
    assert row.name == "ci"
    assert row.prefix.endswith("...")
    assert raw not in row.prefix
    assert row.last_used_at == "Jamais"


def test_ssh_keys_loader_truncates_the_public_key_and_never_exposes_the_private_one(ui, ui_session):

    ui_session.add(SSHKey(name="deploy", private_key="chiffré", public_key="ssh-rsa " + "A" * 200))
    ui_session.commit()
    state = ui.state(SSHKeysState)

    ui.run(state, "load_keys_data")

    row = state.keys[0]
    assert row.name == "deploy"
    assert row.public_key.endswith("...")
    assert len(row.public_key) < 60
    assert not hasattr(row, "private_key")


def test_audit_log_loader_labels_system_actions(ui, ui_session):

    ui_session.add_all([
        AuditLog(operation_type="LOGIN_FAILURE", resource_id="alice", description="échec"),
        AuditLog(operation_type="SETTING_UPDATED", resource_id="scan_backend",
                 description="changé", user_id="bob"),
    ])
    ui_session.commit()
    state = ui.state(AuditLogState)

    ui.run(state, "load_entries")

    authors = {row.operation_type: row.user_id for row in state.entries}
    assert authors["LOGIN_FAILURE"] == "Système"  # no actor recorded
    assert authors["SETTING_UPDATED"] == "bob"


# --- Settings ---

def test_settings_loader_reads_every_section(ui, ui_session):

    state = ui.state(SettingsState)

    ui.run(state, "load_settings")

    assert state.scan_backend == "docker"
    assert state.enrichment_enabled is True
    assert state.retention_keep_input == "10"
    assert state.retention_max_age_input == "90"
    assert state.notification_webhook_url_input == ""


def test_retention_settings_reject_a_non_integer(ui, ui_session):
    """Rejected loudly rather than stored: RetentionService silently falls back to
    its default on a bad value, which would look like the save had worked."""

    state = ui.state(SettingsState, retention_keep_input="beaucoup", retention_max_age_input="90")

    ui.run(state, "save_retention_config")

    stored = ui_session.query(Setting).filter(
        Setting.key == SETTING_KEY_RETENTION_KEEP_PER_TARGET
    ).first()
    assert stored is None


def test_retention_settings_are_saved_and_audited(ui, ui_session):
    from zanshin.services.retention_service import (
        SETTING_KEY_RETENTION_KEEP_PER_TARGET,
        SETTING_KEY_RETENTION_MAX_AGE_DAYS,
    )

    state = ui.state(SettingsState, retention_keep_input="3", retention_max_age_input="30")

    ui.run(state, "save_retention_config")

    settings = {s.key: s.value for s in ui_session.query(Setting).all()}
    assert settings[SETTING_KEY_RETENTION_KEEP_PER_TARGET] == "3"
    assert settings[SETTING_KEY_RETENTION_MAX_AGE_DAYS] == "30"
    assert ui_session.query(AuditLog).count() == 1


def test_the_webhook_url_is_never_written_to_the_audit_log(ui, ui_session):
    """Slack, Teams and Discord all encode a token in the URL, and the audit log
    is readable by every admin."""

    secret_url = "https://hooks.slack.com/services/T000/B000/tres-secret"
    state = ui.state(SettingsState, notification_webhook_url_input=secret_url)

    ui.run(state, "save_notification_config")

    entry = ui_session.query(AuditLog).one()
    assert "tres-secret" not in entry.description
    assert "hooks.slack.com" not in entry.description


# --- R8: a session that never ends ---

def test_a_session_older_than_the_ttl_is_logged_out(ui):
    """`logged_in` lived in the state and was only ever cleared by an explicit
    logout, so a browser left open kept a valid session indefinitely — including on
    the account whose password had since been changed."""
    from datetime import timedelta

    from zanshin.clock import utcnow
    from zanshin.ui.state import SESSION_TTL, BaseState

    state = ui.state(
        BaseState,
        authenticated_at=(utcnow() - SESSION_TTL - timedelta(minutes=1)).isoformat(),
    )

    events = ui.run(state, "check_auth")

    assert state.logged_in is False
    assert state.username == ""
    assert events


def test_a_recent_session_is_left_alone(ui):
    from zanshin.clock import utcnow
    from zanshin.ui.state import BaseState

    state = ui.state(BaseState, authenticated_at=utcnow().isoformat())

    ui.run(state, "check_auth")

    assert state.logged_in is True


def test_a_session_that_cannot_prove_its_age_is_expired(ui):
    """Sessions predating this field, and anything unparseable: failing open would
    make the check decorative, and the cost of failing closed is one login."""
    from zanshin.ui.state import BaseState

    for stamp in ("", "not-a-date"):
        state = ui.state(BaseState, authenticated_at=stamp)
        ui.run(state, "check_auth")
        assert state.logged_in is False, stamp


# --- R7: the provisioning password blocks everything else ---

def test_login_with_a_provisional_password_lands_on_the_change_form(ui, ui_session):
    from zanshin.models.user import User
    from zanshin.services.auth_service import AuthService

    ui_session.add(
        User(
            username="admin",
            display_name="Admin",
            password=AuthService(None).hash_password("provisioning-secret"),
            role="SUPERUSER",
            must_change_password=True,
        )
    )
    ui_session.commit()

    state = ui.state(LoginState, logged_in=False, username="")
    events = ui.run(
        state, "handle_login", {"username": "admin", "password": "provisioning-secret"}
    )

    assert state.logged_in is True
    assert state.must_change_password is True
    redirects = [str(getattr(e, "args", e)) for e in events]
    assert any("/change-password" in r for r in redirects)


def test_changing_the_password_clears_the_flag_and_lets_the_user_through(ui, ui_session):
    from zanshin.models.user import User
    from zanshin.services.auth_service import AuthService

    ui_session.add(
        User(
            username="admin",
            display_name="Admin",
            password=AuthService(None).hash_password("provisioning-secret"),
            role="SUPERUSER",
            must_change_password=True,
        )
    )
    ui_session.commit()

    state = ui.state(
        ChangePasswordState,
        username="admin",
        must_change_password=True,
        current_password="provisioning-secret",
        new_password="choisi-par-moi",
        confirm_password="choisi-par-moi",
    )
    events = ui.run(state, "submit")

    assert state.must_change_password is False
    assert any("/dashboard" in str(getattr(e, "args", e)) for e in events)


def test_the_current_password_is_required_even_when_already_signed_in(ui, ui_session):
    """A session left open on an unlocked laptop must not be enough to take the
    account over."""
    from zanshin.models.user import User
    from zanshin.services.auth_service import AuthService

    ui_session.add(
        User(
            username="admin",
            display_name="Admin",
            password=AuthService(None).hash_password("le-vrai"),
            role="SUPERUSER",
        )
    )
    ui_session.commit()

    state = ui.state(
        ChangePasswordState,
        username="admin",
        current_password="mauvais",
        new_password="assez-long-ici",
        confirm_password="assez-long-ici",
    )
    ui.run(state, "submit")

    session_user = ui_session.query(User).one()
    assert AuthService(None).verify_password("le-vrai", session_user.password)


# --- Issues screen: directness filter and triage review dates ---

def test_the_direct_only_filter_narrows_the_backlog(ui, ui_session):
    from zanshin.models.issue import Issue

    for identifier, direct in (("CVE-D", True), ("CVE-T", False), ("CVE-U", None)):
        ui_session.add(Issue(
            fingerprint=f"fp-{identifier}", type="vulnerability", identifier=identifier,
            severity="high", state="open", is_kev=False, is_direct_dependency=direct,
        ))
    ui_session.commit()

    state = ui.state(IssuesState)
    ui.run(state, "load_issues")
    assert {row.identifier for row in state.issues} == {"CVE-D", "CVE-T", "CVE-U"}

    ui.run(state, "toggle_only_direct", True)
    ui.run(state, "load_issues")

    assert [row.identifier for row in state.issues] == ["CVE-D"]


def test_the_row_labels_directness_and_says_nothing_when_unknown(ui, ui_session):
    from zanshin.models.issue import Issue

    for identifier, direct in (("CVE-D", True), ("CVE-T", False), ("CVE-U", None)):
        ui_session.add(Issue(
            fingerprint=f"fp2-{identifier}", type="vulnerability", identifier=identifier,
            severity="high", state="open", is_kev=False, is_direct_dependency=direct,
        ))
    ui_session.commit()

    state = ui.state(IssuesState)
    ui.run(state, "load_issues")
    by_id = {row.identifier: row for row in state.issues}

    assert by_id["CVE-D"].dependency == "Directe"
    assert by_id["CVE-T"].dependency == "Transitive"
    assert by_id["CVE-U"].dependency == ""


def test_a_triage_can_be_given_a_review_date(ui, ui_session):
    from zanshin.models.issue import TRIAGE_NOT_AFFECTED, Issue

    issue = Issue(
        fingerprint="fp-triage-expiry", type="vulnerability", identifier="CVE-2024-1",
        severity="high", state="open", is_kev=False,
    )
    ui_session.add(issue)
    ui_session.commit()

    state = ui.state(
        IssuesState,
        triage_issue_id=issue.id,
        triage_status=TRIAGE_NOT_AFFECTED,
        triage_justification="component_not_present",
        triage_expires_in_days="90",
    )
    ui.run(state, "submit_triage")

    ui_session.expire_all()
    assert ui_session.query(Issue).one().triage_expires_at is not None


def test_a_typo_in_the_optional_delay_does_not_lose_the_decision(ui, ui_session):
    """The dialog's real subject is the triage decision. Refusing to save a
    considered decision over a typo in an optional box would be the wrong trade."""
    from zanshin.models.issue import TRIAGE_AFFECTED, Issue

    issue = Issue(
        fingerprint="fp-triage-typo", type="vulnerability", identifier="CVE-2024-2",
        severity="high", state="open", is_kev=False,
    )
    ui_session.add(issue)
    ui_session.commit()

    state = ui.state(
        IssuesState,
        triage_issue_id=issue.id,
        triage_status=TRIAGE_AFFECTED,
        triage_expires_in_days="quatre-vingt-dix",
    )
    ui.run(state, "submit_triage")

    ui_session.expire_all()
    saved = ui_session.query(Issue).one()
    assert saved.triage_status == TRIAGE_AFFECTED
    assert saved.triage_expires_at is None


# --- Settings: gate policy, tickets, end-of-life ---

def test_the_settings_screen_shows_the_effective_gate_policy(ui, ui_session):
    from zanshin.repositories.gate_policy_repository import GatePolicyRepository
    from zanshin.services.gate_policy_service import GatePolicyService

    GatePolicyService(GatePolicyRepository(ui_session)).save_policy(
        fail_on_severity="medium", fail_on_kev=False, actor="alice", note="durci"
    )

    state = ui.state(SettingsState)
    ui.run(state, "load_settings")

    assert state.gate_fail_on_severity == "medium"
    assert state.gate_fail_on_kev is False
    assert state.gate_policy_version == 1
    assert [row.rules for row in state.gate_policy_rows] == ["seuil medium"]


def test_saving_the_policy_creates_a_version_and_audits_it(ui, ui_session):
    from zanshin.models.audit_log import AuditLog
    from zanshin.models.gate_policy import StoredGatePolicy

    state = ui.state(SettingsState, gate_fail_on_severity="low", gate_note_input="on durcit")
    ui.run(state, "save_gate_policy")
    ui.run(state, "save_gate_policy")

    versions = [p.version for p in ui_session.query(StoredGatePolicy).all()]
    assert sorted(versions) == [1, 2]
    operations = [a.operation_type for a in ui_session.query(AuditLog).all()]
    assert operations.count("GATE_POLICY_UPDATED") == 2


def test_the_no_severity_choice_stores_no_rule(ui, ui_session):
    """A legitimate policy for a gate that only fails on known-exploited
    vulnerabilities — and the select needs a concrete value to represent it."""
    from zanshin.models.gate_policy import StoredGatePolicy

    state = ui.state(SettingsState, gate_fail_on_severity="aucune", gate_fail_on_kev=True)
    ui.run(state, "save_gate_policy")

    assert ui_session.query(StoredGatePolicy).one().fail_on_severity is None


def test_a_per_target_policy_is_listed_with_its_target_name(ui, ui_session):
    """`repository:7` is not what an operator recognises when checking which rules
    apply where."""
    from zanshin.models.repository import ZanshinRepository
    from zanshin.repositories.gate_policy_repository import GatePolicyRepository
    from zanshin.services.gate_policy_service import GatePolicyService

    repo = ZanshinRepository(name="mon-appli", url="git@example.com:org/a.git", branch="main")
    ui_session.add(repo)
    ui_session.commit()
    GatePolicyService(GatePolicyRepository(ui_session)).save_policy(
        target_kind="repository", target_id=repo.id, fail_on_severity="critical", actor="a"
    )

    state = ui.state(SettingsState)
    ui.run(state, "load_settings")

    scopes = [row.scope for row in state.gate_policy_rows]
    assert "mon-appli" in scopes


@pytest.fixture()
def encryption_key(monkeypatch):
    """The settings screen saves through the container's own `EncryptionService`,
    which refuses to encrypt without a key — by design."""
    from tests.conftest import TEST_ENCRYPTION_KEY

    monkeypatch.setenv("ENCRYPTION_KEY", TEST_ENCRYPTION_KEY)


def test_the_ticket_token_is_never_echoed_back_to_the_form(ui, ui_session, encryption_key):
    state = ui.state(
        SettingsState,
        ticket_provider="gitlab",
        ticket_base_url_input="https://gitlab.example.com",
        ticket_project_input="group/app",
        ticket_token_input="glpat-secret",
    )
    ui.run(state, "save_ticket_config")

    assert state.ticket_token_input == ""
    assert state.ticket_token_present is True


def test_an_empty_token_field_keeps_the_stored_one(ui, ui_session, encryption_key):
    """The form never shows the token, so blanking it on every save would silently
    disable ticketing the first time somebody edited the project name."""
    state = ui.state(
        SettingsState,
        ticket_provider="gitlab",
        ticket_base_url_input="https://gitlab.example.com",
        ticket_project_input="group/app",
        ticket_token_input="glpat-secret",
    )
    ui.run(state, "save_ticket_config")

    state.ticket_project_input = "group/other"
    state.ticket_token_input = ""
    ui.run(state, "save_ticket_config")

    assert state.ticket_token_present is True


def test_a_dangerous_tracker_url_is_refused(ui, ui_session, encryption_key):
    """The cloud metadata endpoint, which is what an SSRF attempt reaches for. Allowed
    private addresses are the default here because self-hosted GitLab and Jira are
    routinely internal — so the deployment that forbids it must be obeyed."""
    from zanshin.models.setting import Setting

    ui_session.add(Setting(key="ticket_allow_private_url", value="false"))
    ui_session.commit()

    state = ui.state(
        SettingsState,
        ticket_provider="gitlab",
        ticket_base_url_input="http://169.254.169.254/latest/meta-data",
        ticket_project_input="group/app",
    )
    ui.run(state, "save_ticket_config")

    stored = ui_session.query(Setting).filter(Setting.key == "ticket_base_url").one_or_none()
    assert stored is None or stored.value == ""


def test_the_end_of_life_window_is_validated(ui, ui_session):
    state = ui.state(SettingsState, eol_warn_days_input="-5")
    ui.run(state, "save_eol_config")

    from zanshin.models.setting import Setting

    stored = ui_session.query(Setting).filter(Setting.key == "eol_warn_days").one_or_none()
    assert stored is None


def test_the_end_of_life_window_is_stored(ui, ui_session):
    from zanshin.models.setting import Setting

    state = ui.state(SettingsState, eol_warn_days_input="90")
    ui.run(state, "save_eol_config")

    assert ui_session.query(Setting).filter(Setting.key == "eol_warn_days").one().value == "90"


# --- Issues screen: end-of-life and tickets ---

def test_an_end_of_life_issue_is_labelled(ui, ui_session):
    from zanshin.models.issue import Issue

    ui_session.add(Issue(
        fingerprint="fp-eol", type="eol", identifier="EOL-rhel-7", severity="high",
        state="open", is_kev=False, package_name="Red Hat Enterprise Linux",
        package_version="7.9", fix_versions="9.7",
    ))
    ui_session.commit()

    state = ui.state(IssuesState)
    ui.run(state, "load_issues")

    row = state.issues[0]
    assert row.type == "Fin de vie"
    assert row.fix == "9.7"


def test_the_ticket_reference_reaches_the_row(ui, ui_session):
    from zanshin.models.issue import Issue

    ui_session.add(Issue(
        fingerprint="fp-ticket", type="vulnerability", identifier="CVE-2024-1",
        severity="high", state="open", is_kev=False,
        ticket_ref="#42", ticket_url="https://gitlab.example.com/g/app/-/issues/42",
    ))
    ui_session.commit()

    state = ui.state(IssuesState)
    ui.run(state, "load_issues")

    assert state.issues[0].ticket_ref == "#42"
    assert state.issues[0].ticket_url.endswith("/issues/42")
