"""Tests for the cross-scan issue lifecycle and triage.

The behaviours that matter here are the ones that make the feature trustworthy:
an issue keeps its identity (and its triage decision) across scans, disappears
only when a scan actually looked for it, and comes back — losing a stale "fixed"
verdict — when it reappears.
"""
from datetime import timedelta

import pytest

from zanshin.clock import utcnow
from zanshin.models.finding import Finding
from zanshin.models.issue import (
    STATE_OPEN,
    STATE_RESOLVED,
    TRIAGE_AFFECTED,
    TRIAGE_FIXED,
    TRIAGE_NOT_AFFECTED,
    TRIAGE_UNDER_REVIEW,
    Issue,
    build_fingerprint,
)
from zanshin.services.issue_service import IssueService, scanned_types_for, summarize_issues

ALL_REPO_TYPES = {"vulnerability", "secret", "iac", "license"}


@pytest.fixture()
def service():
    return IssueService()


def _finding(scan, **kwargs):
    defaults = dict(
        scan_id=scan.id,
        type="vulnerability",
        severity="high",
        identifier="CVE-2024-0001",
        package_name="libfoo",
        package_version="1.0.0",
        purl="pkg:deb/libfoo@1.0.0",
        source="grype",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _sync(service, db, scan, findings, types=ALL_REPO_TYPES, **kwargs):
    db.add_all(findings)
    db.commit()
    return service.sync_from_scan(db, scan, findings, types, **kwargs)


def _issues(db):
    return db.query(Issue).all()


@pytest.fixture()
def make_issue(db_session, service, make_repository, make_scan):
    """One synced issue, ready to be triaged."""

    def factory(**kwargs):
        repo = make_repository()
        scan = make_scan(repo_id=repo.id, status="completed")
        _sync(service, db_session, scan, [_finding(scan, **kwargs)])
        return db_session.query(Issue).order_by(Issue.id.desc()).first()

    return factory


# --- First sighting ---

def test_first_scan_creates_one_open_issue_per_finding(db_session, service, make_repository, make_scan):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")

    result = _sync(service, db_session, scan, [
        _finding(scan, identifier="CVE-2024-0001"),
        _finding(scan, identifier="CVE-2024-0002"),
    ])

    assert result.new == 2
    assert result.resolved == 0
    issues = _issues(db_session)
    assert len(issues) == 2
    assert {i.state for i in issues} == {STATE_OPEN}
    assert {i.triage_status for i in issues} == {TRIAGE_UNDER_REVIEW}
    assert {i.times_seen for i in issues} == {1}
    assert {i.first_seen_scan_id for i in issues} == {scan.id}
    assert scan.new_issues_count == 2


def test_findings_are_linked_to_their_issue(db_session, service, make_repository, make_scan):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")

    findings = [_finding(scan)]
    _sync(service, db_session, scan, findings)

    issue = _issues(db_session)[0]
    assert findings[0].issue_id == issue.id
    assert [f.id for f in issue.findings] == [findings[0].id]


def test_repeated_findings_within_one_scan_collapse_into_one_issue(
    db_session, service, make_repository, make_scan
):
    """The same CVE reported for two locations of one package is one problem
    with two occurrences, not two problems."""
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")

    findings = [
        _finding(scan, file_path=None),
        _finding(scan, file_path=None),
    ]
    result = _sync(service, db_session, scan, findings)

    assert result.new == 1
    issue = _issues(db_session)[0]
    assert issue.times_seen == 1
    assert {f.issue_id for f in findings} == {issue.id}


def test_carries_the_actionable_data_onto_the_issue(db_session, service, make_repository, make_scan):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")

    _sync(service, db_session, scan, [
        _finding(
            scan,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            fix_state="fixed",
            fix_versions="1.0.1, 1.1.0",
            link="https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
            epss_score=0.42,
            is_kev=True,
        )
    ], descriptions={"CVE-2024-0001": "Heap overflow in libfoo"})

    issue = _issues(db_session)[0]
    assert issue.cvss_score == 9.8
    assert issue.fix_versions == "1.0.1, 1.1.0"
    assert issue.fix_state == "fixed"
    assert issue.link.endswith("CVE-2024-0001")
    assert issue.epss_score == 0.42
    assert issue.is_kev is True
    assert issue.description == "Heap overflow in libfoo"


# --- Second sighting ---

def test_second_scan_updates_the_same_issue_without_creating_one(
    db_session, service, make_repository, make_scan
):
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [_finding(first)])

    second = make_scan(repo_id=repo.id, status="completed")
    result = _sync(service, db_session, second, [_finding(second)])

    assert result.new == 0
    assert result.still_open == 1
    issue = _issues(db_session)[0]
    assert issue.times_seen == 2
    assert issue.first_seen_scan_id == first.id
    assert issue.last_seen_scan_id == second.id
    assert second.new_issues_count == 0


def test_a_package_version_bump_is_the_same_issue(db_session, service, make_repository, make_scan):
    """A dependency that stays vulnerable through a patch release must not lose
    its history (nor its triage) — the fingerprint excludes the version."""
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [_finding(first, package_version="1.0.0")])

    second = make_scan(repo_id=repo.id, status="completed")
    result = _sync(service, db_session, second, [_finding(second, package_version="1.0.1")])

    assert result.new == 0
    issue = _issues(db_session)[0]
    assert issue.times_seen == 2
    # ...and the issue reflects the version currently in use.
    assert issue.package_version == "1.0.1"


def test_enrichment_data_is_not_erased_by_a_later_unenriched_sighting(
    db_session, service, make_repository, make_scan
):
    """Enrichment runs after the sync for a fresh finding, so the next scan's
    finding arrives with a null EPSS before enrichment fills it in. That must not
    wipe what a previous scan established."""
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [_finding(first, epss_score=0.9, is_kev=True)])

    second = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, second, [_finding(second, epss_score=None)])

    issue = _issues(db_session)[0]
    assert issue.epss_score == 0.9


# --- Resolution ---

def test_a_finding_that_disappears_is_resolved(db_session, service, make_repository, make_scan):
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [
        _finding(first, identifier="CVE-2024-0001"),
        _finding(first, identifier="CVE-2024-0002"),
    ])

    second = make_scan(repo_id=repo.id, status="completed")
    result = _sync(service, db_session, second, [_finding(second, identifier="CVE-2024-0001")])

    assert result.resolved == 1
    assert second.resolved_issues_count == 1
    resolved = [i for i in _issues(db_session) if i.state == STATE_RESOLVED]
    assert len(resolved) == 1
    assert resolved[0].identifier == "CVE-2024-0002"
    assert resolved[0].resolved_at is not None


def test_a_type_that_was_not_scanned_is_never_resolved(
    db_session, service, make_repository, make_scan
):
    """The crux of honest resolution: a container scan produces no secrets, so it
    must not conclude that a repository's secret issues are gone. Deriving the
    scanned types from the findings present cannot make this distinction."""
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [
        _finding(first, type="secret", identifier="aws-key", file_path="app.py", purl=None),
        _finding(first, identifier="CVE-2024-0001"),
    ])

    second = make_scan(repo_id=repo.id, status="completed")
    result = _sync(
        service, db_session, second,
        [_finding(second, identifier="CVE-2024-0001")],
        types={"vulnerability"},  # secrets were not looked for this time
    )

    assert result.resolved == 0
    assert {i.state for i in _issues(db_session)} == {STATE_OPEN}


def test_a_scanner_that_finds_nothing_does_resolve_its_type(
    db_session, service, make_repository, make_scan
):
    """The mirror image: the secrets scanner ran and reported nothing, which *is*
    evidence the secret is gone."""
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [
        _finding(first, type="secret", identifier="aws-key", file_path="app.py", purl=None)
    ])

    second = make_scan(repo_id=repo.id, status="completed")
    result = _sync(service, db_session, second, [], types={"secret"})

    assert result.resolved == 1
    assert _issues(db_session)[0].state == STATE_RESOLVED


def test_resolution_is_scoped_to_the_scanned_target(
    db_session, service, make_repository, make_scan, make_container
):
    """Scanning one target must never resolve another's issues."""
    repo = make_repository()
    container = make_container()
    repo_scan = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, repo_scan, [_finding(repo_scan)])

    container_scan = make_scan(container_id=container.id, status="completed")
    result = _sync(service, db_session, container_scan, [], types={"vulnerability"})

    assert result.resolved == 0
    assert _issues(db_session)[0].state == STATE_OPEN


# --- Reappearance ---

def test_a_resolved_issue_that_reappears_is_reopened(db_session, service, make_repository, make_scan):
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [_finding(first)])
    second = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, second, [])
    assert _issues(db_session)[0].state == STATE_RESOLVED

    third = make_scan(repo_id=repo.id, status="completed")
    result = _sync(service, db_session, third, [_finding(third)])

    assert result.reopened == 1
    assert result.new == 0  # a regression, not a discovery
    issue = _issues(db_session)[0]
    assert issue.state == STATE_OPEN
    assert issue.resolved_at is None


def test_reappearing_clears_a_fixed_verdict_but_keeps_not_affected(
    db_session, service, make_repository, make_scan
):
    """A "fixed" decision is factually contradicted by the issue coming back, so
    it must not keep hiding it. A "not affected" decision is about the code's
    exposure, not the package's presence, so it survives."""
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [
        _finding(first, identifier="CVE-FIXED"),
        _finding(first, identifier="CVE-NOT-AFFECTED"),
    ])
    by_id = {i.identifier: i for i in _issues(db_session)}
    service.triage(db_session, by_id["CVE-FIXED"].id, TRIAGE_FIXED, actor="alice")
    service.triage(
        db_session, by_id["CVE-NOT-AFFECTED"].id, TRIAGE_NOT_AFFECTED,
        actor="alice", justification="vulnerable_code_not_present",
    )

    second = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, second, [])
    third = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, third, [
        _finding(third, identifier="CVE-FIXED"),
        _finding(third, identifier="CVE-NOT-AFFECTED"),
    ])

    by_id = {i.identifier: i for i in _issues(db_session)}
    assert by_id["CVE-FIXED"].triage_status == TRIAGE_UNDER_REVIEW
    assert by_id["CVE-FIXED"].triaged_by is None
    assert by_id["CVE-NOT-AFFECTED"].triage_status == TRIAGE_NOT_AFFECTED
    assert by_id["CVE-NOT-AFFECTED"].triage_justification == "vulnerable_code_not_present"


def test_triage_survives_an_ordinary_rescan(db_session, service, make_repository, make_scan):
    """The reason this whole table exists: a decision recorded against a finding
    used to be orphaned by the very next scan."""
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [_finding(first)])
    issue_id = _issues(db_session)[0].id
    service.triage(
        db_session, issue_id, TRIAGE_NOT_AFFECTED,
        actor="alice", justification="inline_mitigations_already_exist", comment="derrière un WAF",
    )

    second = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, second, [_finding(second)])

    issue = _issues(db_session)[0]
    assert issue.id == issue_id
    assert issue.triage_status == TRIAGE_NOT_AFFECTED
    assert issue.triage_comment == "derrière un WAF"
    assert issue.triaged_by == "alice"


# --- Triage rules ---

def test_triage_records_who_and_when(db_session, service, make_repository, make_scan):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, scan, [_finding(scan)])
    issue_id = _issues(db_session)[0].id

    issue = service.triage(db_session, issue_id, TRIAGE_AFFECTED, actor="bob", comment="à corriger")

    assert issue.triage_status == TRIAGE_AFFECTED
    assert issue.triaged_by == "bob"
    assert issue.triaged_at is not None
    assert issue.is_actionable is True


def test_not_affected_requires_a_justification(db_session, service, make_repository, make_scan):
    """A VEX `not_affected` statement without a justification is invalid, and
    exporting one would produce an invalid document."""
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, scan, [_finding(scan)])
    issue_id = _issues(db_session)[0].id

    with pytest.raises(ValueError, match="justification"):
        service.triage(db_session, issue_id, TRIAGE_NOT_AFFECTED, actor="alice")


def test_triage_rejects_an_unknown_status_or_justification(
    db_session, service, make_repository, make_scan
):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, scan, [_finding(scan)])
    issue_id = _issues(db_session)[0].id

    with pytest.raises(ValueError):
        service.triage(db_session, issue_id, "wont_fix", actor="alice")
    with pytest.raises(ValueError):
        service.triage(
            db_session, issue_id, TRIAGE_NOT_AFFECTED, actor="alice", justification="parce que"
        )


def test_triage_of_an_unknown_issue_raises(db_session, service):
    with pytest.raises(ValueError):
        service.triage(db_session, 4242, TRIAGE_AFFECTED, actor="alice")


def test_a_triaged_issue_stops_being_actionable(db_session, service, make_repository, make_scan):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, scan, [_finding(scan)])
    issue_id = _issues(db_session)[0].id

    issue = service.triage(
        db_session, issue_id, TRIAGE_NOT_AFFECTED,
        actor="alice", justification="component_not_present",
    )

    assert issue.state == STATE_OPEN  # still observed...
    assert issue.is_actionable is False  # ...but settled


# --- Helpers ---

def test_fingerprint_identity_rules():
    base = dict(
        repo_id=1, container_id=None, finding_type="vulnerability",
        identifier="CVE-1", purl="pkg:deb/foo@1.0", package_name="foo", file_path=None,
    )
    same = build_fingerprint(**base)

    assert build_fingerprint(**base) == same
    # Different target, different issue.
    assert build_fingerprint(**{**base, "repo_id": 2}) != same
    assert build_fingerprint(**{**base, "repo_id": None, "container_id": 1}) != same
    # Different vulnerability or package, different issue.
    assert build_fingerprint(**{**base, "identifier": "CVE-2"}) != same
    assert build_fingerprint(**{**base, "purl": "pkg:deb/bar@1.0"}) != same
    # No purl (secrets, IaC): the package name carries identity instead.
    without_purl = dict(base, purl=None)
    assert build_fingerprint(**without_purl) != same
    assert build_fingerprint(**{**without_purl, "package_name": "other"}) != build_fingerprint(**without_purl)


def test_scanned_types_mirror_the_pipeline_branches():
    repo_full = scanned_types_for(is_container=False, ai_review_ran=True, license_policy_ran=True)
    assert repo_full == {"vulnerability", "secret", "iac", "license", "ai_review"}

    # Images have no source on disk: no secrets, no IaC, no AI review
    # (ADR-001 section 5) — but Syft still yields licenses.
    image = scanned_types_for(is_container=True, ai_review_ran=False, license_policy_ran=True)
    assert image == {"vulnerability", "license"}

    minimal = scanned_types_for(is_container=False, ai_review_ran=False, license_policy_ran=False)
    assert minimal == {"vulnerability", "secret", "iac"}


def test_summarize_issues_counts_by_severity():
    issues = [Issue(severity="critical"), Issue(severity="high"), Issue(severity=None)]

    summary = summarize_issues(issues)

    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["unknown"] == 1
    assert summary["total"] == 3


# --- Direct versus transitive dependencies ---

def test_directness_is_carried_from_the_finding_to_the_issue(
    db_session, service, make_repository, make_scan
):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="completed")

    _sync(service, db_session, scan, [
        _finding(scan, identifier="CVE-2024-1", is_direct_dependency=True),
        _finding(scan, identifier="CVE-2024-2", is_direct_dependency=False),
        _finding(scan, identifier="CVE-2024-3"),
    ])

    by_id = {i.identifier: i for i in _issues(db_session)}
    assert by_id["CVE-2024-1"].is_direct_dependency is True
    assert by_id["CVE-2024-2"].is_direct_dependency is False
    assert by_id["CVE-2024-3"].is_direct_dependency is None


def test_a_scan_that_cannot_tell_does_not_erase_what_is_known(
    db_session, service, make_repository, make_scan
):
    """A container image has no manifests, so its SBOM cannot answer this. Letting
    a null overwrite a previous answer would make the flag flicker between scans."""
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [_finding(first, is_direct_dependency=True)])

    second = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, second, [_finding(second, is_direct_dependency=None)])

    assert _issues(db_session)[0].is_direct_dependency is True


def test_a_package_that_becomes_transitive_is_updated(
    db_session, service, make_repository, make_scan
):
    """Removing a declaration from the manifest while something else still requires
    the package is a real change, and the flag has to follow it."""
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [_finding(first, is_direct_dependency=True)])

    second = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, second, [_finding(second, is_direct_dependency=False)])

    issue = _issues(db_session)[0]
    assert issue.is_direct_dependency is False
    # Same issue, not a new one: directness is deliberately outside the fingerprint.
    assert issue.times_seen == 2


def test_the_line_number_follows_the_finding(db_session, service, make_repository, make_scan):
    repo = make_repository()
    first = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, first, [
        _finding(first, type="secret", identifier="aws-key", file_path="app.py", line=12)
    ], types={"secret"})

    second = make_scan(repo_id=repo.id, status="completed")
    _sync(service, db_session, second, [
        _finding(second, type="secret", identifier="aws-key", file_path="app.py", line=57)
    ], types={"secret"})

    issue = _issues(db_session)[0]
    assert issue.line == 57
    # A secret that moved down the file is the same secret; re-fingerprinting it
    # would have reset its triage.
    assert issue.times_seen == 2


# --- Triage review dates ---

def test_a_triage_without_a_delay_has_no_review_date(db_session, service, make_issue):
    issue = make_issue()

    service.triage(db_session, issue.id, TRIAGE_AFFECTED, actor="alice")

    assert issue.triage_expires_at is None


def test_a_delay_sets_a_review_date(db_session, service, make_issue):
    issue = make_issue()

    service.triage(
        db_session, issue.id, TRIAGE_NOT_AFFECTED, actor="alice",
        justification="vulnerable_code_not_in_execute_path", expires_in_days=90,
    )

    assert issue.triage_expires_at is not None
    assert 89 <= (issue.triage_expires_at - utcnow()).days <= 90


def test_returning_to_under_review_clears_any_review_date(db_session, service, make_issue):
    """A date whose job is to bring the issue back would fire on an issue already
    back."""
    issue = make_issue()
    service.triage(
        db_session, issue.id, TRIAGE_FIXED, actor="alice", expires_in_days=30
    )

    service.triage(db_session, issue.id, TRIAGE_UNDER_REVIEW, actor="alice")

    assert issue.triage_expires_at is None


def test_a_zero_or_negative_delay_is_refused(db_session, service, make_issue):
    issue = make_issue()

    with pytest.raises(ValueError, match="au moins un jour"):
        service.triage(db_session, issue.id, TRIAGE_FIXED, actor="alice", expires_in_days=0)


def test_an_expired_decision_returns_to_review(db_session, service, make_issue):
    """The point of the whole feature: a suppression recorded for a context that has
    since changed stops suppressing, in the dashboard and in the exports alike."""
    issue = make_issue()
    service.triage(
        db_session, issue.id, TRIAGE_NOT_AFFECTED, actor="alice",
        justification="component_not_present", comment="Pas livré en production",
        expires_in_days=30,
    )
    issue.triage_expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    expired = service.expire_stale_triages(db_session)

    assert [i.id for i in expired] == [issue.id]
    assert issue.triage_status == TRIAGE_UNDER_REVIEW
    assert issue.triage_expires_at is None


def test_the_reason_for_the_original_decision_is_kept(db_session, service, make_issue):
    """Whoever reviews it needs to see what was decided and why. Clearing the text
    would turn a scheduled re-examination into an investigation from nothing, which
    is how a review date becomes something people stop setting."""
    issue = make_issue()
    service.triage(
        db_session, issue.id, TRIAGE_NOT_AFFECTED, actor="alice",
        justification="component_not_present", comment="Pas livré en production",
        expires_in_days=30,
    )
    issue.triage_expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    service.expire_stale_triages(db_session)

    assert issue.triage_comment == "Pas livré en production"
    assert issue.triage_justification == "component_not_present"
    assert issue.triaged_by == "alice"
    assert issue.triaged_at is not None


def test_a_decision_that_has_not_reached_its_date_is_left_alone(
    db_session, service, make_issue
):
    issue = make_issue()
    service.triage(
        db_session, issue.id, TRIAGE_FIXED, actor="alice", expires_in_days=30
    )

    assert service.expire_stale_triages(db_session) == []
    assert issue.triage_status == TRIAGE_FIXED


def test_a_decision_without_a_date_never_expires(db_session, service, make_issue):
    """The behaviour every existing decision already had, which is why the column
    is nullable rather than backfilled."""
    issue = make_issue()
    service.triage(db_session, issue.id, TRIAGE_FIXED, actor="alice")

    assert service.expire_stale_triages(db_session) == []
    assert issue.triage_status == TRIAGE_FIXED


def test_an_expired_decision_becomes_actionable_again(db_session, service, make_issue):
    """What the dashboards, the gate and the badges all read."""
    issue = make_issue()
    service.triage(
        db_session, issue.id, TRIAGE_NOT_AFFECTED, actor="alice",
        justification="component_not_present", expires_in_days=1,
    )
    assert issue.is_actionable is False

    issue.triage_expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()
    service.expire_stale_triages(db_session)

    assert issue.is_actionable is True
