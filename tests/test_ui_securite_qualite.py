"""State-level tests for the two overview screens.

Same approach as the other UI tests: the loader builds the typed rows, and the template
that consumes them is checked by `reflex compile`. What the loaders here have to get
right is not layout — it is the two sentences a reader will take away.

For Sécurité: *"this target passes"* must never be said about a target nobody has
scanned. For Qualité: the page must rank, because a four-figure backlog listed
alphabetically tells nobody what to do, and it must state that none of it blocks a build.
"""
from zanshin.clock import utcnow
from zanshin.models.container import Container
from zanshin.models.issue import STATE_OPEN, Issue
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
from zanshin.ui.pages.qualite import QualiteState
from zanshin.ui.pages.securite import SecuriteState


def _repository(session, url="git@example.com:org/app.git", name="App"):
    repo = ZanshinRepository(url=url, branch="main", name=name)
    session.add(repo)
    session.commit()
    session.refresh(repo)
    return repo


def _scan(session, repo_id, status="completed"):
    scan = Scan(
        repo_id=repo_id, branch="main", status=status, findings_count=0, created_at=utcnow()
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


_next_fingerprint = iter(range(1, 100000))


def _issue(session, **kwargs):
    defaults = dict(
        fingerprint=f"fp-{next(_next_fingerprint)}",
        type="vulnerability",
        identifier="CVE-2024-1",
        severity="high",
        state=STATE_OPEN,
        triage_status="under_review",
        is_kev=False,
    )
    defaults.update(kwargs)
    issue = Issue(**defaults)
    session.add(issue)
    session.commit()
    return issue


# --- Sécurité ---------------------------------------------------------------------

def test_the_overview_lists_every_target_with_its_verdict(ui, ui_session):
    repo = _repository(ui_session)
    _scan(ui_session, repo.id)
    _issue(ui_session, repo_id=repo.id, severity="critical")

    state = ui.state(SecuriteState)
    ui.run(state, "load_overview")

    assert len(state.targets) == 1
    row = state.targets[0]
    assert row.name == "App"
    assert row.passed is False
    assert row.verdict_label == "Non conforme"
    assert "seuil de sévérité" in row.reason


def test_a_passing_target_says_which_policy_it_passed(ui, ui_session):
    """A verdict without its provenance is unactionable: a team told only that it failed
    widens its own settings, which changes nothing when the rule came from elsewhere."""
    repo = _repository(ui_session)
    _scan(ui_session, repo.id)

    state = ui.state(SecuriteState)
    ui.run(state, "load_overview")

    assert state.targets[0].passed is True
    assert state.targets[0].policy_label


def test_a_never_scanned_target_is_not_presented_as_clean(ui, ui_session):
    """The failure mode this page must not have. An empty backlog satisfies every
    policy, so a bare green badge would say the opposite of the truth."""
    _repository(ui_session)

    state = ui.state(SecuriteState)
    ui.run(state, "load_overview")

    row = state.targets[0]
    assert row.observed is False
    assert row.observation_label == "Jamais scanné"
    assert state.never_scanned_count == 1


def test_a_failed_last_scan_is_surfaced(ui, ui_session):
    """A failed scan is an absence of observation, not an absence of problems — and
    nothing else in the application says so."""
    repo = _repository(ui_session)
    _scan(ui_session, repo.id, status="failed")

    state = ui.state(SecuriteState)
    ui.run(state, "load_overview")

    assert state.targets[0].observation_label == "Dernier scan en échec"
    assert state.last_scan_failed_count == 1


def test_containers_appear_beside_repositories(ui, ui_session):
    container = Container(image_name="nginx", tag="1.25")
    ui_session.add(container)
    ui_session.commit()
    ui_session.refresh(container)
    _repository(ui_session)

    state = ui.state(SecuriteState)
    ui.run(state, "load_overview")

    assert {row.kind for row in state.targets} == {"repository", "container"}
    assert any(row.name == "nginx:1.25" for row in state.targets)


def test_quality_issues_do_not_turn_the_overview_red(ui, ui_session):
    repo = _repository(ui_session)
    _scan(ui_session, repo.id)
    _issue(ui_session, repo_id=repo.id, type="quality", severity="critical")

    state = ui.state(SecuriteState)
    ui.run(state, "load_overview")

    assert state.targets[0].passed is True
    assert state.failing_count == 0


def test_the_kpi_band_counts_what_needs_attention(ui, ui_session):
    failing = _repository(ui_session, url="a", name="Failing")
    passing = _repository(ui_session, url="b", name="Passing")
    _scan(ui_session, failing.id)
    _scan(ui_session, passing.id)
    _issue(ui_session, repo_id=failing.id, severity="medium", is_kev=True)

    state = ui.state(SecuriteState)
    ui.run(state, "load_overview")

    assert (state.total_count, state.failing_count, state.kev_count) == (2, 1, 1)


# --- Qualité ----------------------------------------------------------------------

def test_the_quality_page_ranks_rules_by_how_often_they_fire(ui, ui_session):
    """The reason this page exists rather than being a filter: in front of a four-figure
    backlog, "these few rules are most of it" is the only actionable framing."""
    repo = _repository(ui_session)
    for _ in range(5):
        _issue(ui_session, repo_id=repo.id, type="quality", identifier="console-log")
    for _ in range(2):
        _issue(ui_session, repo_id=repo.id, type="quality", identifier="empty-catch")

    state = ui.state(QualiteState)
    ui.run(state, "load_quality")

    assert [row.label for row in state.top_rules] == ["console-log", "empty-catch"]
    assert [row.count for row in state.top_rules] == [5, 2]
    # Shares are computed in the loader, like every other view model here.
    assert state.top_rules[0].share > state.top_rules[1].share


def test_it_also_ranks_files_and_repositories(ui, ui_session):
    first = _repository(ui_session, url="a", name="Front")
    second = _repository(ui_session, url="b", name="Back")
    _issue(ui_session, repo_id=first.id, type="quality", file_path="app.js")
    _issue(ui_session, repo_id=first.id, type="quality", file_path="app.js")
    _issue(ui_session, repo_id=second.id, type="quality", file_path="main.py")

    state = ui.state(QualiteState)
    ui.run(state, "load_quality")

    assert state.top_files[0].label == "app.js"
    assert state.top_files[0].count == 2
    # Repository ids are resolved to names — a number would say nothing.
    assert state.top_repositories[0].label == "Front"


def test_security_findings_never_appear_on_the_quality_page(ui, ui_session):
    repo = _repository(ui_session)
    _issue(ui_session, repo_id=repo.id, type="sast", identifier="eval")
    _issue(ui_session, repo_id=repo.id, type="vulnerability", identifier="CVE-2024-9")

    state = ui.state(QualiteState)
    ui.run(state, "load_quality")

    assert state.open_count == 0
    assert state.top_rules == []


def test_a_resolved_quality_issue_is_not_counted(ui, ui_session):
    repo = _repository(ui_session)
    _issue(ui_session, repo_id=repo.id, type="quality", identifier="console-log")
    _issue(
        ui_session, repo_id=repo.id, type="quality", identifier="console-log",
        state="resolved",
    )

    state = ui.state(QualiteState)
    ui.run(state, "load_quality")

    assert state.open_count == 1


def test_an_empty_backlog_loads_without_dividing_by_zero(ui, ui_session):
    _repository(ui_session)

    state = ui.state(QualiteState)
    ui.run(state, "load_quality")

    assert (state.open_count, state.rule_count, state.file_count) == (0, 0, 0)
    assert state.top_rules == []
