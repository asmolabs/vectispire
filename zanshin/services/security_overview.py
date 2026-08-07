"""Where every target stands, in one picture.

**The gate verdict has always been computed and never shown.** `policy_gate.evaluate`
backs `POST /api/v1/gate`, and its module docstring says in as many words that the same
evaluation should back "a UI badge or a notification threshold later". Until now a team
could only learn whether a repository passed by running a build against it — the
application knew the answer and kept it to itself.

**Two rules shape the implementation.**

*The verdict here must be the verdict the API gives.* So this module does not compute
pass/fail — it calls `evaluate` with the same policy resolution the endpoint uses, on the
same issues. A SQL aggregate that recomputed "count of open issues at or above the
threshold" would agree today and diverge the first time `GatePolicy` grows a flag, and
nobody would notice until a pipeline and a screen disagreed about the same repository.

*A screen listing N targets must not cost N queries.* Both traps are real: resolving a
policy per target issues one or two queries each, and loading a target's issues per target
issues another. Everything is therefore fetched once and matched in memory here, which is
also why this is a pure function over already-fetched data rather than something holding a
session.

**A target that was never scanned, or whose last scan failed, is not a passing target.**
It is a target nobody has looked at, which is the worst posture state there is and the one
no existing screen names. Those two counts are part of the summary for that reason, and a
failed or missing scan is reported next to the verdict rather than hidden behind a green
badge computed from an empty backlog.
"""
from typing import Dict, Iterable, List, NamedTuple, Optional

from zanshin.models.gate_policy import (
    GLOBAL_SCOPE_KIND,
    TARGET_CONTAINER,
    TARGET_REPOSITORY,
)
# The source constants are imported rather than restated: `ResolvedPolicy.description`
# renders them into the sentence the screen shows ("politique de la cible v3"), so two
# copies would eventually disagree about what a verdict was based on.
from zanshin.services.gate_policy_service import (
    BUILT_IN,
    SOURCE_BUILT_IN,
    SOURCE_GLOBAL,
    SOURCE_TARGET,
    ResolvedPolicy,
    to_gate_policy,
)
from zanshin.services.policy_gate import GateVerdict, evaluate

# What a target's last scan says about whether the verdict can be trusted.
OBSERVATION_OK = "ok"
OBSERVATION_NEVER_SCANNED = "never_scanned"
OBSERVATION_LAST_SCAN_FAILED = "last_scan_failed"
OBSERVATION_IN_PROGRESS = "in_progress"

_IN_FLIGHT_STATUSES = ("pending", "scanning")


class TargetPosture(NamedTuple):
    """One repository or container, and everything the overview says about it."""

    kind: str  # TARGET_REPOSITORY | TARGET_CONTAINER
    target_id: int
    name: str
    verdict: GateVerdict
    policy: ResolvedPolicy
    observation: str
    last_scan_at: Optional[object] = None
    last_scan_id: Optional[int] = None

    @property
    def passed(self) -> bool:
        return self.verdict.passed

    @property
    def observed(self) -> bool:
        """Whether the verdict rests on an actual observation.

        A target nobody has successfully scanned produces an empty backlog, and an empty
        backlog passes every policy. Saying so without this qualifier would be the single
        most misleading thing this screen could do."""
        return self.observation == OBSERVATION_OK


class SecurityOverview(NamedTuple):
    targets: List[TargetPosture]
    failing_count: int
    total_count: int
    kev_count: int
    never_scanned_count: int
    last_scan_failed_count: int


def build_overview(
    *,
    repositories: Iterable,
    containers: Iterable,
    policies: Iterable,
    open_issues: Iterable,
    latest_scan_by_repository: Dict[int, object],
    latest_scan_by_container: Dict[int, object],
) -> SecurityOverview:
    """Assemble the overview from data already read. No queries here, by design."""
    by_scope = _policies_by_scope(policies)
    issues_by_target = _issues_by_target(open_issues)

    targets: List[TargetPosture] = []
    for repository in repositories:
        targets.append(
            _posture(
                TARGET_REPOSITORY,
                repository.id,
                repository.name or repository.url,
                by_scope,
                issues_by_target.get((TARGET_REPOSITORY, repository.id), []),
                latest_scan_by_repository.get(repository.id),
            )
        )
    for container in containers:
        targets.append(
            _posture(
                TARGET_CONTAINER,
                container.id,
                _container_name(container),
                by_scope,
                issues_by_target.get((TARGET_CONTAINER, container.id), []),
                latest_scan_by_container.get(container.id),
            )
        )

    # Failing first, then unobserved, then by name: the reading order of the screen is
    # the order somebody should work in.
    targets.sort(key=lambda target: (target.passed, target.observed, target.name.lower()))

    return SecurityOverview(
        targets=targets,
        failing_count=sum(1 for target in targets if not target.passed),
        total_count=len(targets),
        kev_count=sum(1 for issue in open_issues if getattr(issue, "is_kev", False)),
        never_scanned_count=sum(
            1 for target in targets if target.observation == OBSERVATION_NEVER_SCANNED
        ),
        last_scan_failed_count=sum(
            1 for target in targets if target.observation == OBSERVATION_LAST_SCAN_FAILED
        ),
    )


def _posture(kind, target_id, name, by_scope, issues, latest_scan) -> TargetPosture:
    policy = _resolve(by_scope, kind, target_id)
    return TargetPosture(
        kind=kind,
        target_id=target_id,
        name=name,
        verdict=evaluate(issues, policy.policy),
        policy=policy,
        observation=_observation(latest_scan),
        last_scan_at=getattr(latest_scan, "created_at", None),
        last_scan_id=getattr(latest_scan, "id", None),
    )


def _resolve(by_scope, kind, target_id) -> ResolvedPolicy:
    """Target policy, then global, then built-in — in memory.

    Mirrors `GatePolicyService.resolve`, which does the same thing with one or two
    queries per call. Calling it per target is what would turn this screen into 2N
    queries, so the same precedence is applied here over policies fetched once.
    """
    stored = by_scope.get((kind, int(target_id)))
    if stored is not None:
        return ResolvedPolicy(to_gate_policy(stored), SOURCE_TARGET, stored.version)
    stored = by_scope.get(_GLOBAL_KEY)
    if stored is not None:
        return ResolvedPolicy(to_gate_policy(stored), SOURCE_GLOBAL, stored.version)
    return ResolvedPolicy(BUILT_IN, SOURCE_BUILT_IN)


_GLOBAL_KEY = (GLOBAL_SCOPE_KIND, 0)


def _policies_by_scope(policies) -> Dict[tuple, object]:
    return {(policy.target_kind, int(policy.target_id)): policy for policy in policies}


def _issues_by_target(open_issues) -> Dict[tuple, List]:
    grouped: Dict[tuple, List] = {}
    for issue in open_issues:
        if issue.repo_id is not None:
            grouped.setdefault((TARGET_REPOSITORY, issue.repo_id), []).append(issue)
        elif issue.container_id is not None:
            grouped.setdefault((TARGET_CONTAINER, issue.container_id), []).append(issue)
    return grouped


def _observation(latest_scan) -> str:
    if latest_scan is None:
        return OBSERVATION_NEVER_SCANNED
    status = getattr(latest_scan, "status", None)
    if status == "failed":
        return OBSERVATION_LAST_SCAN_FAILED
    if status in _IN_FLIGHT_STATUSES:
        return OBSERVATION_IN_PROGRESS
    return OBSERVATION_OK


def _container_name(container) -> str:
    registry = (getattr(container, "registry", "") or "").strip()
    image = f"{container.image_name}:{container.tag}"
    return f"{registry}/{image}" if registry else image
