"""Tests for the issue queries behind the backlog screen and the list badges."""
from datetime import datetime, timedelta

import pytest

from zanshin.models.issue import (
    STATE_OPEN,
    STATE_RESOLVED,
    TRIAGE_AFFECTED,
    TRIAGE_FIXED,
    TRIAGE_NOT_AFFECTED,
    TRIAGE_UNDER_REVIEW,
    Issue,
)
from zanshin.repositories.issue_repository import IssueRepository

NOW = datetime(2026, 8, 6, 12, 0)


@pytest.fixture()
def issue_repository(db_session):
    return IssueRepository(db_session)


def _issue(db, fingerprint, **kwargs):
    defaults = dict(
        fingerprint=fingerprint,
        type="vulnerability",
        identifier=f"CVE-{fingerprint}",
        severity="medium",
        state=STATE_OPEN,
        triage_status=TRIAGE_UNDER_REVIEW,
        first_seen_at=NOW,
        last_seen_at=NOW,
        times_seen=1,
        is_kev=False,
    )
    defaults.update(kwargs)
    issue = Issue(**defaults)
    db.add(issue)
    db.commit()
    db.refresh(issue)
    return issue


# --- Prioritisation ---

def test_ordering_puts_known_exploited_first_then_severity_then_epss(
    db_session, issue_repository, make_repository
):
    """The ordering the EPSS/KEV enrichment exists for: a medium that is being
    exploited in the wild outranks a critical nobody has ever weaponised."""
    repo = make_repository()
    _issue(db_session, "a", repo_id=repo.id, severity="critical", epss_score=0.01)
    _issue(db_session, "b", repo_id=repo.id, severity="medium", is_kev=True, epss_score=0.5)
    _issue(db_session, "c", repo_id=repo.id, severity="high", epss_score=0.9)
    _issue(db_session, "d", repo_id=repo.id, severity="high", epss_score=0.1)

    ordered = issue_repository.find_filtered()

    assert [i.fingerprint for i in ordered] == ["b", "a", "c", "d"]


def test_severity_ordering_is_by_gravity_not_alphabetical(
    db_session, issue_repository, make_repository
):
    repo = make_repository()
    for name, severity in [
        ("neg", "negligible"), ("low", "low"), ("med", "medium"),
        ("high", "high"), ("crit", "critical"), ("none", None),
    ]:
        _issue(db_session, name, repo_id=repo.id, severity=severity)

    ordered = issue_repository.find_filtered()

    assert [i.fingerprint for i in ordered] == ["crit", "high", "med", "low", "neg", "none"]


# --- Filters ---

def test_filters_combine(db_session, issue_repository, make_repository, make_container):
    repo = make_repository()
    container = make_container()
    _issue(db_session, "a", repo_id=repo.id, severity="high", type="vulnerability")
    _issue(db_session, "b", repo_id=repo.id, severity="low", type="secret")
    _issue(db_session, "c", container_id=container.id, severity="high", type="vulnerability")
    _issue(db_session, "d", repo_id=repo.id, severity="high", state=STATE_RESOLVED)

    assert {i.fingerprint for i in issue_repository.find_filtered(state=STATE_OPEN)} == {"a", "b", "c"}
    assert {i.fingerprint for i in issue_repository.find_filtered(severity="high", state=STATE_OPEN)} == {"a", "c"}
    assert {i.fingerprint for i in issue_repository.find_filtered(issue_type="secret")} == {"b"}
    assert {i.fingerprint for i in issue_repository.find_filtered(repo_id=repo.id, state=STATE_RESOLVED)} == {"d"}
    assert {i.fingerprint for i in issue_repository.find_filtered(container_id=container.id)} == {"c"}


def test_search_matches_identifier_package_or_file_case_insensitively(
    db_session, issue_repository, make_repository
):
    repo = make_repository()
    _issue(db_session, "a", repo_id=repo.id, identifier="CVE-2024-1234")
    _issue(db_session, "b", repo_id=repo.id, identifier="GHSA-x", package_name="libcurl")
    _issue(db_session, "c", repo_id=repo.id, identifier="aws-key", file_path="src/App.py")
    _issue(db_session, "d", repo_id=repo.id, identifier="unrelated")

    assert {i.fingerprint for i in issue_repository.find_filtered(search="cve-2024")} == {"a"}
    assert {i.fingerprint for i in issue_repository.find_filtered(search="LIBCURL")} == {"b"}
    assert {i.fingerprint for i in issue_repository.find_filtered(search="app.py")} == {"c"}
    assert issue_repository.find_filtered(search="nothing-here") == []


def test_limit_is_applied(db_session, issue_repository, make_repository):
    repo = make_repository()
    for i in range(5):
        _issue(db_session, f"f{i}", repo_id=repo.id)

    assert len(issue_repository.find_filtered(limit=2)) == 2


# --- Lookups used by the pipeline ---

def test_find_by_fingerprints_returns_a_keyed_map(db_session, issue_repository, make_repository):
    repo = make_repository()
    _issue(db_session, "a", repo_id=repo.id)
    _issue(db_session, "b", repo_id=repo.id)

    found = issue_repository.find_by_fingerprints(["a", "missing"])

    assert set(found) == {"a"}
    assert found["a"].fingerprint == "a"


def test_find_by_fingerprints_with_nothing_to_look_up_does_not_query(issue_repository):
    assert issue_repository.find_by_fingerprints([]) == {}


def test_find_open_by_target_restricts_to_the_given_types(
    db_session, issue_repository, make_repository
):
    """How resolution stays honest — see IssueService."""
    repo = make_repository()
    _issue(db_session, "vuln", repo_id=repo.id, type="vulnerability")
    _issue(db_session, "secret", repo_id=repo.id, type="secret")
    _issue(db_session, "resolved", repo_id=repo.id, type="vulnerability", state=STATE_RESOLVED)

    found = issue_repository.find_open_by_target(repo_id=repo.id, types={"vulnerability"})

    assert [i.fingerprint for i in found] == ["vuln"]


def test_find_open_by_target_with_an_empty_type_set_finds_nothing(
    db_session, issue_repository, make_repository
):
    """An empty set means "this scan looked for nothing", which must not be read
    as "no type filter" — that would resolve the target's whole backlog."""
    repo = make_repository()
    _issue(db_session, "vuln", repo_id=repo.id)

    assert issue_repository.find_open_by_target(repo_id=repo.id, types=set()) == []


# --- Counters for badges and KPIs ---

def test_actionable_counts_exclude_settled_and_resolved_issues(
    db_session, issue_repository, make_repository, make_container
):
    """"À traiter" must shrink when the team works — otherwise it is just the
    finding count under another name."""
    repo = make_repository()
    container = make_container()
    _issue(db_session, "a", repo_id=repo.id, triage_status=TRIAGE_UNDER_REVIEW)
    _issue(db_session, "b", repo_id=repo.id, triage_status=TRIAGE_AFFECTED)
    _issue(db_session, "c", repo_id=repo.id, triage_status=TRIAGE_NOT_AFFECTED)
    _issue(db_session, "d", repo_id=repo.id, triage_status=TRIAGE_FIXED)
    _issue(db_session, "e", repo_id=repo.id, state=STATE_RESOLVED)
    _issue(db_session, "f", container_id=container.id)

    assert issue_repository.count_actionable_by_repo_ids([repo.id]) == {repo.id: 2}
    assert issue_repository.count_actionable_by_container_ids([container.id]) == {container.id: 1}


def test_counters_with_no_ids_do_not_query(issue_repository):
    assert issue_repository.count_actionable_by_repo_ids([]) == {}
    assert issue_repository.count_actionable_by_container_ids([]) == {}


def test_count_by_state_and_triage(db_session, issue_repository, make_repository):
    repo = make_repository()
    _issue(db_session, "a", repo_id=repo.id, triage_status=TRIAGE_UNDER_REVIEW)
    _issue(db_session, "b", repo_id=repo.id, triage_status=TRIAGE_AFFECTED)
    _issue(db_session, "c", repo_id=repo.id, triage_status=TRIAGE_NOT_AFFECTED)
    _issue(db_session, "d", repo_id=repo.id, state=STATE_RESOLVED)

    counts = issue_repository.count_by_state_and_triage()

    assert counts["total"] == 4
    assert counts["open"] == 3
    assert counts["resolved"] == 1
    assert counts["actionable"] == 2
    assert counts[f"triage_{TRIAGE_NOT_AFFECTED}"] == 1


def test_count_open_by_severity_ignores_resolved_and_buckets_nulls(
    db_session, issue_repository, make_repository
):
    repo = make_repository()
    _issue(db_session, "a", repo_id=repo.id, severity="critical")
    _issue(db_session, "b", repo_id=repo.id, severity="critical")
    _issue(db_session, "c", repo_id=repo.id, severity=None)
    _issue(db_session, "d", repo_id=repo.id, severity="high", state=STATE_RESOLVED)

    counts = issue_repository.count_open_by_severity()

    assert counts == {"critical": 2, "unknown": 1}


def test_last_seen_breaks_ties_so_ordering_is_stable(
    db_session, issue_repository, make_repository
):
    repo = make_repository()
    _issue(db_session, "old", repo_id=repo.id, severity="high", last_seen_at=NOW - timedelta(days=2))
    _issue(db_session, "new", repo_id=repo.id, severity="high", last_seen_at=NOW)

    assert [i.fingerprint for i in issue_repository.find_filtered()] == ["new", "old"]


# --- Pagination (wave 3) ---

def test_count_filtered_matches_the_filters_not_the_page(db_session, issue_repository, make_repository):
    repo = make_repository()
    for index in range(7):
        _issue(db_session, f"p{index}", repo_id=repo.id, severity="high")
    _issue(db_session, "other", repo_id=repo.id, severity="low")

    assert issue_repository.count_filtered(severity="high") == 7
    assert len(issue_repository.find_filtered(severity="high", limit=3)) == 3
    assert issue_repository.count_filtered() == 8


def test_paging_visits_every_row_once(db_session, issue_repository, make_repository):
    """Requires a total order in the query: without one, a row can show up on two
    pages or on none."""
    repo = make_repository()
    for index in range(10):
        # Same severity and no EPSS, so only the tie-breaker distinguishes them.
        _issue(db_session, f"t{index}", repo_id=repo.id, severity="high", last_seen_at=NOW)

    seen = []
    for offset in range(0, 10, 4):
        seen += [i.fingerprint for i in issue_repository.find_filtered(limit=4, offset=offset)]

    assert len(seen) == 10
    assert len(set(seen)) == 10


def test_offset_past_the_end_returns_an_empty_page(db_session, issue_repository, make_repository):
    repo = make_repository()
    _issue(db_session, "only", repo_id=repo.id)

    assert issue_repository.find_filtered(limit=50, offset=50) == []
