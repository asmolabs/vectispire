"""Pass/fail evaluation of a target's issue backlog against a policy.

This is the piece that makes Zanshin usable from a pipeline rather than only
from a browser: a CI job asks "given what you know about this target, should this
build fail?" and gets a verdict with reasons.

Kept as pure functions over a list of `Issue` objects — no HTTP, no session — so
the policy semantics can be tested exhaustively, and so the same evaluation can
back an endpoint today and a UI badge or a notification threshold later.

Design decisions worth stating:

- **Triaged issues don't fail a build by default.** A `not_affected` judgment with
  a VEX justification is the whole reason triage exists; a gate that ignores it
  would push teams straight back to disabling the gate. `include_triaged` exists
  for the audit case where you want the raw picture.
- **"Fixable only" is offered, and not the default.** Failing only on issues with
  a published fix is the pragmatic setting (you can't act on the others), but as a
  default it would silently tolerate an actively-exploited vulnerability with no
  patch — which is precisely the situation that needs a human decision, not a
  green build.
- **KEV is evaluated independently of severity.** A "medium" that is being
  exploited in the wild outranks a "critical" that never has been; that is what
  the enrichment step is for, so the gate reads it directly.
- **AI-review findings are excluded by default.** They come from a local model
  prompted with the repository's own source code, so a hostile repository can
  steer them — and one invented "critical" would fail somebody's build. Their
  reverse is just as bad: LLM noise in a gate teaches people to disable the gate.
  They stay visible in the backlog, where a human weighs them; they do not get a
  vote on a build. `include_ai_review` exists for a team that decides otherwise.
"""
from typing import Iterable, List, NamedTuple, Optional

from zanshin.models.issue import STATE_OPEN, TRIAGE_AFFECTED, TRIAGE_UNDER_REVIEW, Issue

# Ordered worst-first; the index is the comparison rank.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "negligible", "unknown")
DEFAULT_FAIL_ON_SEVERITY = "high"


# Finding types produced by a deterministic scanner. `ai_review` is deliberately
# absent — see the module docstring.
DETERMINISTIC_TYPES = ("vulnerability", "secret", "iac", "license")
AI_REVIEW_TYPE = "ai_review"


class GatePolicy(NamedTuple):
    """What the caller considers unacceptable."""

    # Fail when an open issue is at least this severe. `None` disables the
    # severity rule entirely (useful when gating only on KEV).
    fail_on_severity: Optional[str] = DEFAULT_FAIL_ON_SEVERITY
    # Fail on any open issue in the CISA KEV catalogue, whatever its severity.
    fail_on_kev: bool = True
    # Fail only on issues with a published fix.
    fixable_only: bool = False
    # Count issues already settled by triage (`not_affected` / `fixed`).
    include_triaged: bool = False
    # Let findings produced by the AI review influence the verdict.
    include_ai_review: bool = False


class Violation(NamedTuple):
    rule: str
    issue_id: int
    identifier: Optional[str]
    severity: Optional[str]
    package: Optional[str]
    fix_versions: Optional[str]
    reason: str


class GateVerdict(NamedTuple):
    passed: bool
    violations: List[Violation]
    evaluated: int
    counts_by_severity: dict


def severity_rank(severity: Optional[str]) -> int:
    """Position in `SEVERITY_ORDER`; unknown values sort last.

    Note that "unknown" ranks *below* "low" on purpose: the OSV backend reports
    it whenever an advisory carries no normalized severity, so treating it as
    worst-case would fail every build on that backend.
    """
    try:
        return SEVERITY_ORDER.index((severity or "unknown").lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def is_at_least(severity: Optional[str], threshold: str) -> bool:
    return severity_rank(severity) <= severity_rank(threshold)


def evaluate(issues: Iterable[Issue], policy: GatePolicy) -> GateVerdict:
    """Apply `policy` to a target's issues and explain the outcome."""
    considered = [issue for issue in issues if _is_considered(issue, policy)]

    counts: dict = {}
    for issue in considered:
        key = (issue.severity or "unknown").lower()
        counts[key] = counts.get(key, 0) + 1

    violations: List[Violation] = []
    for issue in considered:
        if policy.fail_on_kev and issue.is_kev:
            violations.append(
                _violation(
                    issue,
                    "kev",
                    "vulnérabilité activement exploitée (catalogue CISA KEV)",
                )
            )
            # One violation per issue is enough to fail the build; reporting the
            # KEV rule rather than also the severity rule keeps the output
            # actionable instead of duplicated.
            continue
        if policy.fail_on_severity and is_at_least(issue.severity, policy.fail_on_severity):
            violations.append(
                _violation(
                    issue,
                    "severity",
                    f"sévérité {(issue.severity or 'unknown')} ≥ seuil {policy.fail_on_severity}",
                )
            )

    return GateVerdict(
        passed=not violations,
        violations=violations,
        evaluated=len(considered),
        counts_by_severity=counts,
    )


def _is_considered(issue: Issue, policy: GatePolicy) -> bool:
    if issue.state != STATE_OPEN:
        return False
    if issue.type == AI_REVIEW_TYPE and not policy.include_ai_review:
        return False
    if not policy.include_triaged and issue.triage_status not in (
        TRIAGE_UNDER_REVIEW,
        TRIAGE_AFFECTED,
    ):
        return False
    if policy.fixable_only and not issue.fix_versions:
        return False
    return True


def _violation(issue: Issue, rule: str, reason: str) -> Violation:
    return Violation(
        rule=rule,
        issue_id=issue.id,
        identifier=issue.identifier,
        severity=(issue.severity or "unknown").lower(),
        package=issue.package_name,
        fix_versions=issue.fix_versions,
        reason=reason,
    )
