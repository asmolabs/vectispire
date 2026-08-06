"""Tests for the CI policy gate.

The gate's job is to be trusted enough that nobody disables it, so the cases that
matter are the ones where a naive implementation would either cry wolf (failing on
a triaged finding) or stay silent when it shouldn't (an actively-exploited
vulnerability with no published fix).
"""
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
from zanshin.services.policy_gate import (
    GatePolicy,
    evaluate,
    is_at_least,
    severity_rank,
)

_next_id = iter(range(1, 10_000))


def _issue(**kwargs):
    defaults = dict(
        id=next(_next_id),
        type="vulnerability",
        identifier="CVE-2024-0001",
        severity="high",
        state=STATE_OPEN,
        triage_status=TRIAGE_UNDER_REVIEW,
        is_kev=False,
        fix_versions=None,
        package_name="libfoo",
    )
    defaults.update(kwargs)
    return Issue(**defaults)


# --- Severity comparison ---

def test_severity_ranking_is_by_gravity():
    assert severity_rank("critical") < severity_rank("high") < severity_rank("medium")
    assert severity_rank("medium") < severity_rank("low") < severity_rank("negligible")


def test_unknown_severity_ranks_below_low():
    """The OSV backend reports "unknown" whenever an advisory has no normalized
    severity. Treating that as worst-case would fail every build on that
    backend."""
    assert severity_rank("unknown") > severity_rank("low")
    assert is_at_least("unknown", "high") is False


def test_is_at_least_is_inclusive():
    assert is_at_least("high", "high") is True
    assert is_at_least("critical", "high") is True
    assert is_at_least("medium", "high") is False


# --- Default policy ---

def test_passes_with_no_issues():
    verdict = evaluate([], GatePolicy())
    assert verdict.passed is True
    assert verdict.violations == []
    assert verdict.evaluated == 0


def test_fails_on_a_high_severity_issue_by_default():
    verdict = evaluate([_issue(severity="high")], GatePolicy())

    assert verdict.passed is False
    assert [v.rule for v in verdict.violations] == ["severity"]
    assert "seuil high" in verdict.violations[0].reason


def test_passes_when_everything_is_below_the_threshold():
    verdict = evaluate([_issue(severity="medium"), _issue(severity="low")], GatePolicy())
    assert verdict.passed is True
    assert verdict.evaluated == 2  # considered, just not violating


def test_kev_fails_regardless_of_severity():
    """The reason the enrichment step exists: a "medium" being exploited in the
    wild outranks a "critical" that never has been."""
    verdict = evaluate([_issue(severity="medium", is_kev=True)], GatePolicy())

    assert verdict.passed is False
    assert verdict.violations[0].rule == "kev"


def test_kev_can_be_the_only_rule():
    policy = GatePolicy(fail_on_severity=None, fail_on_kev=True)

    assert evaluate([_issue(severity="critical")], policy).passed is True
    assert evaluate([_issue(severity="low", is_kev=True)], policy).passed is False


def test_one_violation_per_issue_even_when_both_rules_match():
    """A build fails once; reporting the same issue twice makes the output harder
    to act on, not more informative."""
    verdict = evaluate([_issue(severity="critical", is_kev=True)], GatePolicy())

    assert len(verdict.violations) == 1
    assert verdict.violations[0].rule == "kev"


# --- Interaction with state and triage ---

def test_resolved_issues_never_fail_a_build():
    verdict = evaluate(
        [_issue(severity="critical", state=STATE_RESOLVED, is_kev=True)], GatePolicy()
    )
    assert verdict.passed is True
    assert verdict.evaluated == 0


@pytest.mark.parametrize("triage", [TRIAGE_NOT_AFFECTED, TRIAGE_FIXED])
def test_triaged_issues_are_excluded_by_default(triage):
    """A gate that ignores triage pushes teams straight back to disabling the
    gate — which is worse than a gate with judgment in it."""
    verdict = evaluate([_issue(severity="critical", triage_status=triage)], GatePolicy())

    assert verdict.passed is True
    assert verdict.evaluated == 0


@pytest.mark.parametrize("triage", [TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED])
def test_untriaged_and_affected_issues_still_count(triage):
    verdict = evaluate([_issue(severity="critical", triage_status=triage)], GatePolicy())
    assert verdict.passed is False


def test_include_triaged_gives_the_raw_picture():
    policy = GatePolicy(include_triaged=True)

    verdict = evaluate([_issue(severity="critical", triage_status=TRIAGE_NOT_AFFECTED)], policy)

    assert verdict.passed is False
    assert verdict.evaluated == 1


# --- Fixable-only ---

def test_fixable_only_ignores_issues_without_a_published_fix():
    policy = GatePolicy(fixable_only=True)
    issues = [_issue(severity="critical", fix_versions=None), _issue(severity="high", fix_versions="1.2.3")]

    verdict = evaluate(issues, policy)

    assert verdict.evaluated == 1
    assert len(verdict.violations) == 1
    assert verdict.violations[0].fix_versions == "1.2.3"


def test_fixable_only_is_not_the_default():
    """Defaulting to it would silently tolerate an actively-exploited
    vulnerability with no patch — the situation that most needs a human."""
    assert GatePolicy().fixable_only is False

    verdict = evaluate([_issue(severity="critical", is_kev=True, fix_versions=None)], GatePolicy())
    assert verdict.passed is False


# --- Reporting ---

def test_verdict_counts_by_severity_over_considered_issues_only():
    issues = [
        _issue(severity="critical"),
        _issue(severity="high"),
        _issue(severity="high"),
        _issue(severity="critical", state=STATE_RESOLVED),  # not considered
    ]

    verdict = evaluate(issues, GatePolicy())

    assert verdict.counts_by_severity == {"critical": 1, "high": 2}
    assert verdict.evaluated == 3


def test_violation_carries_what_a_developer_needs():
    issue = _issue(
        identifier="CVE-2024-1234", severity="critical", package_name="libcurl", fix_versions="8.5.0"
    )

    violation = evaluate([issue], GatePolicy()).violations[0]

    assert violation.identifier == "CVE-2024-1234"
    assert violation.package == "libcurl"
    assert violation.fix_versions == "8.5.0"
    assert violation.issue_id == issue.id
