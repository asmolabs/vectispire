"""The HTTP API surface.

Every route is a thin adapter: it validates input, calls the same service the UI
calls, and shapes the result. No business logic lives here — that is what keeps a
scan triggered from CI identical to one triggered from a button.

Mounted onto the Reflex app through `api_transformer` (zanshin/zanshin.py), which
means it is served from the same process and port as the UI. Reflex reserves
`/ping`, `/_event` and `/_upload`; everything here lives under `/api/v1`.
"""
import json
import logging
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.openapi.docs import get_swagger_ui_html

from zanshin.api.deps import (
    get_container,
    require_api_key,
    require_scope,
    require_target_access,
)
from zanshin.api.schemas import (
    GatePolicyOut,
    StoredGatePolicyOut,
    GateRequest,
    GateResponse,
    IssueOut,
    IssuePage,
    ScanCreated,
    ScanStatus,
    TargetOut,
    TargetRef,
    ViolationOut,
)
from zanshin.clock import utcnow
from zanshin.container import IoCContainer
from zanshin.models.api_key import SCOPE_EXPORT, SCOPE_READ, SCOPE_SCAN, ApiKey
from zanshin.models.issue import STATE_OPEN, Issue
from zanshin.services.audit_log_service import AuditOperation
from zanshin.services.exports import (
    build_issues_csv,
    build_openvex_document,
    build_sarif_document,
)
from zanshin.services.policy_gate import GatePolicy, evaluate
from zanshin.services.repository_service import ScanAlreadyRunningError
from zanshin.services.scan_queue import position_of

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 500

api_app = FastAPI(
    title="Zanshin API",
    version="1.0",
    description=(
        "Programmatic access for CI/CD and scripting: trigger scans, read issues, "
        "evaluate a policy gate, export VEX. Authenticate with an API key created "
        "on the /api-keys page: `Authorization: Bearer zsk_...`."
    ),
    # Served behind the same key as everything else, from the routes below. FastAPI
    # would otherwise publish both anonymously, handing an unauthenticated attacker
    # the complete map of the attack surface. Not a secret, but no reason to give it
    # away on an internal tool.
    docs_url=None,
    openapi_url=None,
    redoc_url=None,
)


@api_app.get("/api/v1/openapi.json", include_in_schema=False)
def openapi_schema(api_key: ApiKey = Depends(require_api_key)):
    return api_app.openapi()


@api_app.get("/api/v1/docs", include_in_schema=False)
def swagger_ui(api_key: ApiKey = Depends(require_api_key)):
    """Interactive reference.

    Note the practical consequence of putting it behind a bearer token: the page
    itself loads, but the browser will not attach the key to the schema request, so
    use `Authorize` in the UI or fetch `/api/v1/openapi.json` with curl. A cookie
    session would be friendlier and would also mean the API accepts cookies, which
    is how an API becomes CSRF-able.
    """
    return get_swagger_ui_html(
        openapi_url="/api/v1/openapi.json", title="Zanshin API"
    )


@api_app.get("/api/v1/health", tags=["meta"])
def health():
    """Unauthenticated liveness probe. Says nothing about the data."""
    return {"status": "ok"}


# --- Targets ---

@api_app.get("/api/v1/targets", response_model=List[TargetOut], tags=["targets"])
def list_targets(
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_READ)),
):
    """Everything scannable, with its outstanding issue count.

    Lets a pipeline resolve "the repository I'm building" to an id without
    hardcoding one.
    """
    repositories = container.repository_repository.find_all()
    containers = container.container_repository.find_all()
    if api_key.target_kind == "repository":
        repositories = [r for r in repositories if api_key.covers("repository", r.id)]
        containers = []
    elif api_key.target_kind == "container":
        containers = [c for c in containers if api_key.covers("container", c.id)]
        repositories = []

    repo_issues = container.issue_repository.count_actionable_by_repo_ids(
        [r.id for r in repositories]
    )
    container_issues = container.issue_repository.count_actionable_by_container_ids(
        [c.id for c in containers]
    )
    repo_scans = container.scan_repository.find_latest_summary_by_repository_ids(
        [r.id for r in repositories]
    )
    container_scans = container.scan_repository.find_latest_summary_by_container_ids(
        [c.id for c in containers]
    )

    out: List[TargetOut] = []
    for repo in repositories:
        out.append(
            _target_out("repository", repo.id, repo.name or repo.url,
                        repo_issues.get(repo.id, 0), repo_scans.get(repo.id))
        )
    for image in containers:
        out.append(
            _target_out("container", image.id, image.image_string,
                        container_issues.get(image.id, 0), container_scans.get(image.id))
        )
    return out


def _target_out(kind, target_id, name, open_issues, scan) -> TargetOut:
    return TargetOut(
        kind=kind,
        id=target_id,
        name=name,
        open_issues=open_issues,
        last_scan_id=scan.id if scan else None,
        last_scan_status=scan.status if scan else None,
        last_scan_at=scan.created_at.isoformat() if scan and scan.created_at else None,
    )


# --- Scans ---

@api_app.post(
    "/api/v1/scans",
    response_model=ScanCreated,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["scans"],
)
def trigger_scan(
    body: TargetRef,
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_SCAN)),
):
    """Queue a scan. 202, not 201: the scan runs on the background pool, so the
    row returned is `pending` and the caller polls `GET /api/v1/scans/{id}`."""
    if body.repository_id is not None:
        require_target_access(api_key, "repository", body.repository_id)
    else:
        require_target_access(api_key, "container", body.container_id)

    try:
        if body.repository_id is not None:
            scan = container.repository_service.trigger_scan(body.repository_id)
        else:
            scan = container.container_service.trigger_scan(body.container_id)
    except ScanAlreadyRunningError as e:
        # 409, not 404 or 500: the request is well-formed and the target exists —
        # the current state refuses it. A pipeline retrying on 409 is doing the
        # right thing, which it cannot know from a 500.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e
    except RuntimeError as e:
        # Both services raise RuntimeError("… not found") for an unknown target.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e

    logger.info("Scan %s triggered via API by key '%s'", scan.id, api_key.name)
    container.audit_log_service.record(
        AuditOperation.SCAN_TRIGGERED,
        resource_id=str(scan.id),
        description=(
            f"Scan {scan.id} déclenché via l'API "
            f"({'dépôt ' + str(scan.repo_id) if scan.repo_id else 'conteneur ' + str(scan.container_id)})"
        ),
        # The key's name, not a username: an API caller has no user identity, and
        # writing one in would be a lie in the trail.
        user_id=f"api-key:{api_key.name}",
    )
    return ScanCreated(
        scan_id=scan.id,
        status=scan.status,
        repository_id=scan.repo_id,
        container_id=scan.container_id,
    )


@api_app.get("/api/v1/scans/{scan_id}", response_model=ScanStatus, tags=["scans"])
def get_scan(
    scan_id: int,
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_READ)),
):
    scan = container.scan_repository.find_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan introuvable.")
    _require_scan_access(api_key, scan)
    return ScanStatus(
        scan_id=scan.id,
        status=scan.status,
        queue_position=position_of(container.db, scan),
        created_at=scan.created_at.isoformat() if scan.created_at else None,
        duration_ms=scan.duration_ms,
        findings_count=scan.findings_count or 0,
        new_issues=scan.new_issues_count or 0,
        resolved_issues=scan.resolved_issues_count or 0,
        summary=scan.summary or {},
        error=scan.error,
    )


@api_app.get("/api/v1/scans/{scan_id}/sbom", tags=["scans"])
def get_scan_sbom(
    scan_id: int,
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_EXPORT)),
):
    """The SBOM exactly as Syft produced it.

    Served verbatim rather than converted: CycloneDX or SPDX output would mean
    asking Syft for a second format at scan time, and a conversion written here
    would be a lossy re-derivation of data the tool can emit natively. Noted as a
    scan-time option rather than faked at export time.
    """
    scan = container.scan_repository.find_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan introuvable.")
    _require_scan_access(api_key, scan)
    if not scan.sbom:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ce scan n'a pas de SBOM (échec, ou scan antérieur à cette fonctionnalité).",
        )
    return scan.sbom


# --- Issues ---

@api_app.get("/api/v1/issues", response_model=IssuePage, tags=["issues"])
def list_issues(
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_READ)),
    repository_id: Optional[int] = None,
    container_id: Optional[int] = None,
    state: Optional[str] = STATE_OPEN,
    triage_status: Optional[str] = None,
    severity: Optional[str] = None,
    type: Optional[str] = None,
    search: Optional[str] = None,
    only_direct: bool = Query(
        default=False,
        description=(
            "Ne renvoyer que les dépendances déclarées par le projet. Les problèmes "
            "dont la directivité est inconnue sont exclus : une réponse absente n'est "
            "pas une réponse positive."
        ),
    ),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
):
    """A page of issues, plus the total so the caller knows what it is missing."""
    # A target-restricted key is *narrowed* here rather than refused: asking for
    # "all issues" with such a key is a reasonable request, and the honest answer is
    # its own target's issues — not everyone's, and not an error.
    if api_key.target_kind == "repository":
        repository_id, container_id = api_key.target_id, None
    elif api_key.target_kind == "container":
        repository_id, container_id = None, api_key.target_id

    filters = dict(
        state=state or None,
        triage_status=triage_status,
        severity=severity,
        issue_type=type,
        repo_id=repository_id,
        container_id=container_id,
        search=search,
        only_direct=only_direct,
    )
    issues = container.issue_repository.find_filtered(limit=limit, offset=offset, **filters)
    return IssuePage(
        items=[_issue_out(issue) for issue in issues],
        total=container.issue_repository.count_filtered(**filters),
        limit=limit,
        offset=offset,
    )


def _require_scan_access(api_key: ApiKey, scan) -> None:
    """A scan belongs to a target, so a target-restricted key inherits the limit."""
    kind = "repository" if scan.repo_id else "container"
    require_target_access(api_key, kind, scan.repo_id or scan.container_id)


def _issue_out(issue: Issue) -> IssueOut:
    return IssueOut(
        id=issue.id,
        type=issue.type,
        identifier=issue.identifier,
        severity=issue.severity,
        cvss_score=issue.cvss_score,
        epss_score=issue.epss_score,
        is_kev=bool(issue.is_kev),
        package_name=issue.package_name,
        package_version=issue.package_version,
        purl=issue.purl,
        is_direct_dependency=issue.is_direct_dependency,
        file_path=issue.file_path,
        line=issue.line,
        fix_state=issue.fix_state,
        fix_versions=issue.fix_versions,
        link=issue.link,
        state=issue.state,
        triage_status=issue.triage_status,
        triage_justification=issue.triage_justification,
        triage_expires_at=issue.triage_expires_at.isoformat() if issue.triage_expires_at else None,
        first_seen_at=issue.first_seen_at.isoformat() if issue.first_seen_at else None,
        last_seen_at=issue.last_seen_at.isoformat() if issue.last_seen_at else None,
        times_seen=issue.times_seen or 1,
        repository_id=issue.repo_id,
        container_id=issue.container_id,
    )


# --- Policy gate ---

@api_app.post("/api/v1/gate", response_model=GateResponse, tags=["gate"])
def policy_gate(
    body: GateRequest,
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_READ)),
):
    """Should this build fail?

    The endpoint a CI job calls after a scan. Returns 200 with `passed: false`
    rather than an error status: the request succeeded, the answer is "no". Making
    the verdict an HTTP error would conflate "your policy is violated" with "the
    call went wrong", and pipelines routinely treat those differently.
    """
    if body.repository_id is not None:
        require_target_access(api_key, "repository", body.repository_id)
    else:
        require_target_access(api_key, "container", body.container_id)

    kind = "repository" if body.repository_id is not None else "container"
    # `exclude_unset` is what separates "no opinion" from "explicitly asked for": a
    # caller who omits a field must not be told their request was refused, and a
    # caller who explicitly sends `fail_on_severity: null` is asking to remove the
    # rule, which is a loosening.
    requested = body.policy.model_dump(exclude_unset=True) if body.policy else None
    resolved = container.gate_policy_service.resolve(
        kind, body.repository_id or body.container_id, requested=requested
    )
    if resolved.ignored_relaxations:
        logger.info(
            "Gate for %s:%s ignored an attempt to relax %s (applied %s)",
            kind, body.repository_id or body.container_id,
            ",".join(resolved.ignored_relaxations), resolved.description,
        )

    issues = container.issue_repository.find_open_by_target(
        repo_id=body.repository_id, container_id=body.container_id
    )
    verdict = evaluate(issues, resolved.policy)
    return GateResponse(
        passed=verdict.passed,
        evaluated=verdict.evaluated,
        counts_by_severity=verdict.counts_by_severity,
        violations=[ViolationOut(**v._asdict()) for v in verdict.violations],
        policy=GatePolicyOut(
            source=resolved.source,
            version=resolved.version,
            ignored_relaxations=list(resolved.ignored_relaxations),
            **resolved.policy._asdict(),
        ),
    )


@api_app.get(
    "/api/v1/gate/policies",
    response_model=List[StoredGatePolicyOut],
    tags=["gate"],
)
def list_gate_policies(
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_READ)),
):
    """Every policy currently in force, global first.

    Readable with `read` and writable only from the UI by an administrator: a policy
    is what decides whether a build fails, so an API key that can queue scans must not
    be able to lower the bar those scans are judged against.
    """
    policies = container.gate_policy_service.active_policies()
    if api_key.target_kind:
        # A target-restricted key sees its own target's policy and the global default
        # it inherits from — not other teams' rules.
        policies = [
            policy for policy in policies
            if policy.is_global
            or (policy.target_kind == api_key.target_kind and policy.target_id == api_key.target_id)
        ]
    return [_stored_policy_out(policy) for policy in policies]


@api_app.get(
    "/api/v1/gate/policies/history",
    response_model=List[StoredGatePolicyOut],
    tags=["gate"],
)
def gate_policy_history(
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_READ)),
    kind: Optional[str] = None,
    target_id: Optional[int] = None,
):
    """Every version of one scope, newest first — "which policy failed that build in
    March" needs an answer."""
    if kind is not None:
        require_target_access(api_key, kind, target_id)
    elif api_key.target_kind:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cette clé est restreinte à une cible : précisez 'kind' et 'target_id'.",
        )
    return [
        _stored_policy_out(policy)
        for policy in container.gate_policy_service.history(kind, target_id)
    ]


def _stored_policy_out(policy) -> StoredGatePolicyOut:
    return StoredGatePolicyOut(
        id=policy.id,
        scope=policy.scope_label,
        target_kind=None if policy.is_global else policy.target_kind,
        target_id=None if policy.is_global else policy.target_id,
        version=policy.version,
        is_active=bool(policy.is_active),
        fail_on_severity=policy.fail_on_severity,
        fail_on_kev=bool(policy.fail_on_kev),
        fixable_only=bool(policy.fixable_only),
        include_triaged=bool(policy.include_triaged),
        include_ai_review=bool(policy.include_ai_review),
        note=policy.note,
        created_by=policy.created_by,
        created_at=policy.created_at.isoformat() if policy.created_at else None,
    )


# --- Exports ---

@api_app.get("/api/v1/targets/{kind}/{target_id}/vex", tags=["exports"])
def export_vex(
    kind: str,
    target_id: int,
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_EXPORT)),
):
    """An OpenVEX document for one target, built from its triage decisions.

    This is the payoff of storing triage in the standard's vocabulary: a
    serialization, not a translation.
    """
    require_target_access(api_key, kind, target_id)
    repo_id, container_id, product_id = _resolve_target(container, kind, target_id)
    issues = container.issue_repository.find_filtered(
        repo_id=repo_id, container_id=container_id, state=None, limit=MAX_PAGE_SIZE
    )
    document = build_openvex_document(
        issues,
        author="Zanshin",
        product_id=product_id,
        document_id=f"https://zanshin.local/vex/{kind}/{target_id}",
        timestamp=utcnow().isoformat(),
    )
    return document


@api_app.get("/api/v1/targets/{kind}/{target_id}/issues.sarif", tags=["exports"])
def export_sarif(
    kind: str,
    target_id: int,
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_EXPORT)),
):
    """A SARIF 2.1.0 log, for upload to GitHub code scanning / GitLab / Azure.

    This is the endpoint that gets a finding out of Zanshin and onto the pull
    request that introduced it. Served as `application/json` with a download
    filename, because both consumers exist: `curl -o` in a pipeline step, and a
    person clicking the link.

    Open issues only, triaged ones marked as suppressed rather than removed — see
    `build_sarif_document` for why that distinction matters to the receiving
    platform.
    """
    require_target_access(api_key, kind, target_id)
    repo_id, container_id, product_id = _resolve_target(container, kind, target_id)
    issues = container.issue_repository.find_filtered(
        repo_id=repo_id, container_id=container_id, state=STATE_OPEN, limit=MAX_PAGE_SIZE
    )
    return Response(
        content=json.dumps(
            build_sarif_document(issues, target_name=product_id), ensure_ascii=False
        ),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="zanshin-{kind}-{target_id}.sarif"'
        },
    )


@api_app.get("/api/v1/targets/{kind}/{target_id}/issues.csv", tags=["exports"])
def export_issues_csv(
    kind: str,
    target_id: int,
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_EXPORT)),
    state: Optional[str] = None,
):
    require_target_access(api_key, kind, target_id)
    repo_id, container_id, _ = _resolve_target(container, kind, target_id)
    issues = container.issue_repository.find_filtered(
        repo_id=repo_id, container_id=container_id, state=state or None, limit=MAX_PAGE_SIZE
    )
    return Response(
        content=build_issues_csv(issues),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="zanshin-{kind}-{target_id}-issues.csv"'
        },
    )


def _resolve_target(container: IoCContainer, kind: str, target_id: int):
    """Map `(kind, id)` to filter arguments and a product identifier.

    The product id is what a VEX consumer matches against, so it is the target's
    real identity — a git URL or an image reference — not an internal row id.
    """
    if kind == "repository":
        repo = container.repository_repository.find_by_id(target_id)
        if not repo:
            raise HTTPException(status_code=404, detail="Dépôt introuvable.")
        return repo.id, None, repo.url
    if kind == "container":
        image = container.container_repository.find_by_id(target_id)
        if not image:
            raise HTTPException(status_code=404, detail="Conteneur introuvable.")
        return None, image.id, f"pkg:oci/{image.image_name}"
    raise HTTPException(
        status_code=400, detail="'kind' doit être 'repository' ou 'container'."
    )
