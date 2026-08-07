"""The Sécurité overview.

Two properties are worth more than everything else in this file.

**The screen and the API must agree.** A pipeline that fails on a repository the
dashboard shows as green is worse than having no dashboard: it destroys trust in both.
`test_the_overview_agrees_with_the_gate_endpoint` is the guarantee, and the reason the
overview calls `evaluate` rather than reimplementing the verdict as a SQL aggregate.

**The cost must not grow with the number of targets.** The two traps are per-target
policy resolution and per-target issue loading; both are easy to write and invisible
until somebody has thirty repositories. `test_the_query_count_does_not_grow_with_targets`
counts real SQL statements rather than trusting the shape of the code.
"""
import pytest
from sqlalchemy import event

from zanshin.models.gate_policy import TARGET_CONTAINER, TARGET_REPOSITORY
from zanshin.models.issue import STATE_OPEN, TRIAGE_NOT_AFFECTED, Issue
from zanshin.services.security_overview import (
    OBSERVATION_LAST_SCAN_FAILED,
    OBSERVATION_NEVER_SCANNED,
    OBSERVATION_OK,
    build_overview,
)


class _Scan:
    def __init__(self, status="completed", id=1, created_at=None):
        self.status = status
        self.id = id
        self.created_at = created_at


def _overview(repositories=(), containers=(), policies=(), issues=(), scans=None, container_scans=None):
    return build_overview(
        repositories=repositories,
        containers=containers,
        policies=policies,
        open_issues=issues,
        latest_scan_by_repository=scans if scans is not None else {},
        latest_scan_by_container=container_scans if container_scans is not None else {},
    )


def _issue(repo_id=None, container_id=None, **kwargs):
    defaults = dict(
        id=kwargs.pop("id", 1),
        type="vulnerability",
        state=STATE_OPEN,
        triage_status="under_review",
        severity="high",
        is_kev=False,
        fix_versions=None,
        identifier="CVE-2024-1",
        package_name="libfoo",
    )
    defaults.update(kwargs)
    issue = Issue(repo_id=repo_id, container_id=container_id, **defaults)
    return issue


# --- The verdict ------------------------------------------------------------------

def test_a_target_with_a_blocking_issue_is_reported_as_failing(make_repository):
    repo = make_repository()

    overview = _overview(
        repositories=[repo],
        issues=[_issue(repo_id=repo.id, severity="critical")],
        scans={repo.id: _Scan()},
    )

    target = overview.targets[0]
    assert target.passed is False
    assert target.verdict.violations[0].rule == "severity"
    assert overview.failing_count == 1


def test_quality_issues_never_make_a_target_fail(make_repository):
    """The same exclusion the gate applies, verified through the screen that displays
    it — a quality backlog must not turn a dashboard red either."""
    repo = make_repository()

    overview = _overview(
        repositories=[repo],
        issues=[_issue(repo_id=repo.id, type="quality", severity="critical")],
        scans={repo.id: _Scan()},
    )

    assert overview.targets[0].passed is True
    assert overview.targets[0].verdict.evaluated == 0


def test_issues_of_one_target_do_not_reach_another(make_repository):
    """Everything is fetched in one query and matched here, so the grouping is this
    module's responsibility rather than the database's."""
    first, second = make_repository(url="a"), make_repository(url="b")

    overview = _overview(
        repositories=[first, second],
        issues=[_issue(repo_id=first.id, severity="critical")],
        scans={first.id: _Scan(), second.id: _Scan()},
    )

    by_name = {target.target_id: target for target in overview.targets}
    assert by_name[first.id].passed is False
    assert by_name[second.id].passed is True


def test_containers_are_evaluated_alongside_repositories(make_container):
    container = make_container(image_name="nginx", tag="1.25")

    overview = _overview(
        containers=[container],
        issues=[_issue(container_id=container.id, severity="critical")],
        container_scans={container.id: _Scan()},
    )

    assert overview.targets[0].kind == TARGET_CONTAINER
    assert overview.targets[0].name == "nginx:1.25"
    assert overview.targets[0].passed is False


# --- "Passing" versus "nobody looked" ---------------------------------------------

def test_a_target_that_was_never_scanned_is_flagged_as_such(make_repository):
    """An empty backlog satisfies every policy, so a green badge alone would say the
    opposite of the truth about a repository nobody has scanned."""
    repo = make_repository()

    overview = _overview(repositories=[repo], scans={})

    target = overview.targets[0]
    assert target.passed is True
    assert target.observed is False
    assert target.observation == OBSERVATION_NEVER_SCANNED
    assert overview.never_scanned_count == 1


def test_a_target_whose_last_scan_failed_is_flagged_too(make_repository):
    """A failed scan is an absence of observation, not an absence of problems — and no
    other screen in the application says so."""
    repo = make_repository()

    overview = _overview(repositories=[repo], scans={repo.id: _Scan(status="failed")})

    assert overview.targets[0].observation == OBSERVATION_LAST_SCAN_FAILED
    assert overview.targets[0].observed is False
    assert overview.last_scan_failed_count == 1


def test_a_completed_scan_counts_as_an_observation(make_repository):
    repo = make_repository()

    overview = _overview(repositories=[repo], scans={repo.id: _Scan(status="completed")})

    assert overview.targets[0].observation == OBSERVATION_OK
    assert overview.targets[0].observed is True
    assert (overview.never_scanned_count, overview.last_scan_failed_count) == (0, 0)


def test_failing_targets_are_listed_first(make_repository):
    """Reading order is working order: what fails, then what nobody has looked at."""
    passing = make_repository(url="a-passing")
    failing = make_repository(url="b-failing")
    unscanned = make_repository(url="c-unscanned")

    overview = _overview(
        repositories=[passing, failing, unscanned],
        issues=[_issue(repo_id=failing.id, severity="critical")],
        scans={passing.id: _Scan(), failing.id: _Scan()},
    )

    assert [target.target_id for target in overview.targets] == [
        failing.id, unscanned.id, passing.id
    ]


# --- Which policy applied ---------------------------------------------------------

def test_a_target_policy_wins_over_the_global_one(db_session, make_repository):
    from zanshin.repositories.gate_policy_repository import GatePolicyRepository
    from zanshin.services.gate_policy_service import GatePolicyService

    repo = make_repository()
    service = GatePolicyService(GatePolicyRepository(db_session))
    service.save_policy(fail_on_severity="critical")  # global: only critical fails
    service.save_policy(
        target_kind=TARGET_REPOSITORY, target_id=repo.id, fail_on_severity="high"
    )

    overview = _overview(
        repositories=[repo],
        policies=service.active_policies(),
        issues=[_issue(repo_id=repo.id, severity="high")],
        scans={repo.id: _Scan()},
    )

    assert overview.targets[0].passed is False
    assert overview.targets[0].policy.description.startswith("politique de la cible")


def test_a_target_without_its_own_policy_falls_back_to_the_global_one(
    db_session, make_repository
):
    from zanshin.repositories.gate_policy_repository import GatePolicyRepository
    from zanshin.services.gate_policy_service import GatePolicyService

    repo = make_repository()
    service = GatePolicyService(GatePolicyRepository(db_session))
    service.save_policy(fail_on_severity="critical")

    overview = _overview(
        repositories=[repo],
        policies=service.active_policies(),
        issues=[_issue(repo_id=repo.id, severity="high")],
        scans={repo.id: _Scan()},
    )

    assert overview.targets[0].passed is True
    assert overview.targets[0].policy.description.startswith("politique globale")


def test_with_no_stored_policy_the_built_in_one_applies(make_repository):
    repo = make_repository()

    overview = _overview(
        repositories=[repo],
        issues=[_issue(repo_id=repo.id, severity="high")],
        scans={repo.id: _Scan()},
    )

    assert overview.targets[0].passed is False
    assert overview.targets[0].policy.description == "politique par défaut de l'application"


# --- Agreement with the endpoint ---------------------------------------------------

@pytest.mark.parametrize(
    "issue_kwargs",
    [
        {"severity": "critical"},
        {"severity": "low"},
        {"severity": "medium", "is_kev": True},
        {"severity": "critical", "triage_status": TRIAGE_NOT_AFFECTED},
        {"severity": "critical", "type": "quality"},
        {"severity": "critical", "type": "ai_review"},
    ],
    ids=["critical", "low", "kev-medium", "triaged-away", "quality", "ai-review"],
)
def test_the_overview_agrees_with_the_gate_endpoint(db_session, make_repository, issue_kwargs):
    """The property this screen lives or dies by.

    A dashboard that shows green while the pipeline fails — or the reverse — is worse
    than no dashboard, because it makes both untrustworthy. Both sides here go through
    `evaluate` with the same resolved policy; this test is what keeps it that way if
    somebody ever decides the overview would be faster as a SQL aggregate.
    """
    from zanshin.repositories.gate_policy_repository import GatePolicyRepository
    from zanshin.repositories.issue_repository import IssueRepository
    from zanshin.services.gate_policy_service import GatePolicyService

    repo = make_repository()
    stored = dict(
        fingerprint="fp-agreement",
        type="vulnerability",
        identifier="CVE-2024-1",
        state=STATE_OPEN,
        triage_status="under_review",
        is_kev=False,
    )
    stored.update(issue_kwargs)
    if stored["triage_status"] == TRIAGE_NOT_AFFECTED:
        stored["triage_justification"] = "component_not_present"
    db_session.add(Issue(repo_id=repo.id, **stored))
    db_session.commit()

    policy_service = GatePolicyService(GatePolicyRepository(db_session))
    issue_repository = IssueRepository(db_session)

    # What the endpoint does: resolve, then evaluate the target's open issues.
    from zanshin.services.policy_gate import evaluate

    endpoint_policy = policy_service.resolve(TARGET_REPOSITORY, repo.id)
    endpoint_verdict = evaluate(
        issue_repository.find_open_by_target(repo_id=repo.id), endpoint_policy.policy
    )

    overview = _overview(
        repositories=[repo],
        policies=policy_service.active_policies(),
        issues=issue_repository.find_open_for_gate(),
        scans={repo.id: _Scan()},
    )
    screen_verdict = overview.targets[0].verdict

    assert screen_verdict.passed == endpoint_verdict.passed
    assert screen_verdict.evaluated == endpoint_verdict.evaluated
    assert screen_verdict.counts_by_severity == endpoint_verdict.counts_by_severity
    assert [v.rule for v in screen_verdict.violations] == [
        v.rule for v in endpoint_verdict.violations
    ]


def test_the_lightweight_issue_rows_carry_everything_the_gate_reads(db_session, make_repository):
    """`find_open_for_gate` returns a NamedTuple, not an `Issue`. It only works because
    the attribute names match — so a field added to the gate's reasoning has to be added
    there too, and this is what says so out loud."""
    from zanshin.repositories.issue_repository import IssueRepository

    repo = make_repository()
    db_session.add(Issue(
        repo_id=repo.id, fingerprint="fp-shape", type="vulnerability",
        identifier="CVE-2024-1", severity="high", state=STATE_OPEN,
        triage_status="under_review", is_kev=True, fix_versions="1.2.3",
        package_name="libfoo",
    ))
    db_session.commit()

    lightweight = IssueRepository(db_session).find_open_for_gate()[0]

    for attribute in (
        "id", "type", "state", "triage_status", "severity", "is_kev",
        "fix_versions", "identifier", "package_name",
    ):
        assert hasattr(lightweight, attribute), attribute


# --- Cost --------------------------------------------------------------------------

def test_the_query_count_does_not_grow_with_targets(db_session, make_repository):
    """Counted, not reasoned about.

    Resolving a policy costs one or two queries per call and loading a target's issues
    costs another, so the natural way to write this screen is 2N+ queries — invisible
    with three repositories, and thirty of them turn one page into ninety round trips.
    """
    from zanshin.repositories.gate_policy_repository import GatePolicyRepository
    from zanshin.repositories.issue_repository import IssueRepository
    from zanshin.repositories.scan_repository import ScanRepository
    from zanshin.services.gate_policy_service import GatePolicyService

    from zanshin.repositories.repository_repository import RepositoryRepository

    def render():
        """Exactly the sequence the page runs, measured end to end."""
        statements = []

        def record(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        engine = db_session.get_bind()
        event.listen(engine, "before_cursor_execute", record)
        try:
            repositories = RepositoryRepository(db_session).find_all()
            _overview(
                repositories=repositories,
                policies=GatePolicyService(GatePolicyRepository(db_session)).active_policies(),
                issues=IssueRepository(db_session).find_open_for_gate(),
                scans=ScanRepository(db_session).find_latest_summary_by_repository_ids(
                    [r.id for r in repositories]
                ),
            )
        finally:
            event.remove(engine, "before_cursor_execute", record)
        return len(statements)

    for index in range(3):
        make_repository(url=f"https://example.test/small-{index}.git")
    with_three = render()

    for index in range(27):
        make_repository(url=f"https://example.test/large-{index}.git")
    with_thirty = render()

    assert with_three == with_thirty, (
        f"{with_three} requête(s) pour 3 cibles, {with_thirty} pour 30 — le coût suit le "
        "nombre de cibles"
    )
