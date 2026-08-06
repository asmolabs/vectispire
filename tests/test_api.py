"""Tests for the HTTP API.

Driven through FastAPI's `TestClient`, with the session dependency pointed at an
in-memory database and the scan services stubbed — so nothing here reaches Docker
or the background pool. What is being tested is the contract a CI pipeline
depends on: authentication, status codes, and the shape of the payloads.
"""
import pytest
from fastapi.testclient import TestClient

from zanshin.api import rate_limit
from zanshin.api.app import api_app
from zanshin.api.deps import get_container
from zanshin.models.container import Container
from zanshin.models.issue import (
    STATE_OPEN,
    STATE_RESOLVED,
    TRIAGE_NOT_AFFECTED,
    Issue,
)
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan
from zanshin.repositories.api_key_repository import ApiKeyRepository
from zanshin.repositories.audit_log_repository import AuditLogRepository
from zanshin.repositories.container_repository import ContainerRepository
from zanshin.repositories.issue_repository import IssueRepository
from zanshin.repositories.repository_repository import RepositoryRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.services.api_key_service import ApiKeyService
from zanshin.services.audit_log_service import AuditLogService

_next_fingerprint = iter(range(1, 10_000))


class FakeScanService:
    """Stands in for RepositoryService/ContainerService: records the call and
    returns a pending scan, without touching the thread pool."""

    def __init__(self, db, *, container_id=None, repo_id=None, missing=False):
        self.db = db
        self.container_id = container_id
        self.repo_id = repo_id
        self.missing = missing
        self.calls = []

    def trigger_scan(self, target_id):
        self.calls.append(target_id)
        if self.missing:
            raise RuntimeError("Repository not found")
        scan = Scan(
            branch="main",
            status="pending",
            findings_count=0,
            repo_id=self.repo_id,
            container_id=self.container_id,
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan


@pytest.fixture()
def api(db_session):
    """A client whose requests all share one in-memory session, plus the raw
    secret of a valid API key."""
    api_key_service = ApiKeyService(ApiKeyRepository(db_session))
    _, raw_key = api_key_service.create_key("ci")

    class StubContainer:
        def __init__(self):
            self.db = db_session
            self.api_key_service = api_key_service
            self.issue_repository = IssueRepository(db_session)
            self.scan_repository = ScanRepository(db_session)
            self.repository_repository = RepositoryRepository(db_session)
            self.container_repository = ContainerRepository(db_session)
            self.repository_service = FakeScanService(db_session, repo_id=None)
            self.container_service = FakeScanService(db_session, container_id=None)
            # Real, not a stub: triggering a scan is audited, and that the trail is
            # written is part of the contract being tested.
            self.audit_log_service = AuditLogService(AuditLogRepository(db_session))

    stub = StubContainer()
    # The limiter is a per-process singleton keyed on the key's id, and every test
    # here issues id 1 into a fresh database — without this, quotas would carry over
    # between unrelated tests.
    rate_limit.limiter.reset()
    api_app.dependency_overrides[get_container] = lambda: stub
    client = TestClient(api_app)
    client.headers.update({"Authorization": f"Bearer {raw_key}"})
    yield client, stub, raw_key
    api_app.dependency_overrides.clear()


def _issue(db, **kwargs):
    defaults = dict(
        fingerprint=f"fp-{next(_next_fingerprint)}",
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


# --- Authentication ---

def test_health_needs_no_key():
    client = TestClient(api_app)
    assert client.get("/api/v1/health").json() == {"status": "ok"}


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Basic zsk_x", "zsk_no-scheme", "Bearer zsk_wrong-secret"],
)
def test_every_bad_credential_is_the_same_401(api, header):
    """Distinguishing "malformed" from "wrong" would confirm which prefixes
    exist."""
    client, _, _ = api

    response = client.get("/api/v1/issues", headers={"Authorization": header})

    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"


def test_a_request_with_no_authorization_header_is_401(api):
    client, _, _ = api
    # The fixture's client carries a valid key by default; drop it entirely.
    del client.headers["Authorization"]

    assert client.get("/api/v1/issues").status_code == 401


def test_a_valid_key_is_accepted_and_its_use_recorded(api, db_session):
    client, stub, raw_key = api
    key_before = ApiKeyRepository(db_session).find_all()[0]
    assert key_before.last_used_at is None

    assert client.get("/api/v1/issues").status_code == 200

    db_session.refresh(key_before)
    # The column existed from the start and nothing could ever write it: there
    # was no endpoint to present a key to.
    assert key_before.last_used_at is not None


# --- Scans ---

def test_triggering_a_scan_returns_202_and_the_scan_id(api, db_session):
    client, stub, _ = api
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main")
    db_session.add(repo)
    db_session.commit()

    response = client.post("/api/v1/scans", json={"repository_id": repo.id})

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "pending"
    assert body["scan_id"] is not None
    assert stub.repository_service.calls == [repo.id]
    # A scan reads the repository with its deploy key, so who asked is auditable —
    # attributed to the key, not to a user the API caller does not have.
    from zanshin.models.audit_log import AuditLog

    entry = db_session.query(AuditLog).filter(AuditLog.operation_type == "SCAN_TRIGGERED").one()
    assert entry.user_id == "api-key:ci"


def test_triggering_a_scan_for_an_unknown_target_is_404(api):
    client, stub, _ = api
    stub.repository_service.missing = True

    response = client.post("/api/v1/scans", json={"repository_id": 4242})

    assert response.status_code == 404


def test_a_request_must_name_exactly_one_target(api):
    client, _, _ = api

    assert client.post("/api/v1/scans", json={}).status_code == 422
    assert client.post(
        "/api/v1/scans", json={"repository_id": 1, "container_id": 2}
    ).status_code == 422


def test_scan_status_reports_the_delta(api, db_session):
    client, _, _ = api
    scan = Scan(
        branch="main", status="completed", findings_count=421,
        new_issues_count=13, resolved_issues_count=8,
        summary={"critical": 0, "high": 32, "total": 421},
    )
    db_session.add(scan)
    db_session.commit()

    body = client.get(f"/api/v1/scans/{scan.id}").json()

    assert body["status"] == "completed"
    assert body["new_issues"] == 13
    assert body["resolved_issues"] == 8
    assert body["summary"]["high"] == 32


def test_unknown_scan_is_404(api):
    client, _, _ = api
    assert client.get("/api/v1/scans/4242").status_code == 404


def test_sbom_is_served_verbatim_and_404s_when_absent(api, db_session):
    client, _, _ = api
    with_sbom = Scan(branch="main", status="completed", findings_count=0, sbom={"artifacts": [1]})
    without = Scan(branch="main", status="failed", findings_count=0)
    db_session.add_all([with_sbom, without])
    db_session.commit()

    assert client.get(f"/api/v1/scans/{with_sbom.id}/sbom").json() == {"artifacts": [1]}
    assert client.get(f"/api/v1/scans/{without.id}/sbom").status_code == 404


# --- Issues ---

def test_issues_are_paginated_and_report_the_total(api, db_session):
    client, _, _ = api
    for _ in range(5):
        _issue(db_session)

    body = client.get("/api/v1/issues", params={"limit": 2, "offset": 0}).json()

    assert len(body["items"]) == 2
    assert body["total"] == 5
    assert body["limit"] == 2
    assert body["offset"] == 0


def test_paging_covers_every_row_exactly_once(api, db_session):
    """A total order in the query is what makes this true; without it rows can
    appear on two pages or on none."""
    client, _, _ = api
    for index in range(7):
        _issue(db_session, identifier=f"CVE-{index}")

    seen = []
    for offset in (0, 3, 6):
        seen += [item["id"] for item in
                 client.get("/api/v1/issues", params={"limit": 3, "offset": offset}).json()["items"]]

    assert len(seen) == 7
    assert len(set(seen)) == 7


def test_issues_default_to_open_only(api, db_session):
    client, _, _ = api
    _issue(db_session, state=STATE_OPEN)
    _issue(db_session, state=STATE_RESOLVED)

    assert client.get("/api/v1/issues").json()["total"] == 1
    assert client.get("/api/v1/issues", params={"state": "resolved"}).json()["total"] == 1


def test_issue_payload_carries_the_actionable_fields(api, db_session):
    client, _, _ = api
    _issue(
        db_session,
        identifier="CVE-2024-1234",
        cvss_score=9.8,
        epss_score=0.42,
        is_kev=True,
        fix_versions="1.2.3",
        link="https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    )

    item = client.get("/api/v1/issues").json()["items"][0]

    assert item["cvss_score"] == 9.8
    assert item["epss_score"] == 0.42
    assert item["is_kev"] is True
    assert item["fix_versions"] == "1.2.3"
    assert item["link"].endswith("CVE-2024-1234")


def test_limit_is_bounded(api):
    client, _, _ = api
    assert client.get("/api/v1/issues", params={"limit": 10_000}).status_code == 422


# --- Gate ---

def test_gate_returns_200_with_a_negative_verdict(api, db_session):
    """Not an error status: the request succeeded, the answer is "no". Pipelines
    treat "policy violated" and "the call broke" very differently."""
    client, _, _ = api
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    _issue(db_session, repo_id=repo.id, severity="critical")

    response = client.post("/api/v1/gate", json={"repository_id": repo.id})

    assert response.status_code == 200
    body = response.json()
    assert body["passed"] is False
    assert body["violations"][0]["rule"] == "severity"


def test_gate_passes_when_the_backlog_is_triaged(api, db_session):
    client, _, _ = api
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    _issue(
        db_session, repo_id=repo.id, severity="critical",
        triage_status=TRIAGE_NOT_AFFECTED, triage_justification="component_not_present",
    )

    body = client.post("/api/v1/gate", json={"repository_id": repo.id}).json()

    assert body["passed"] is True


def test_gate_policy_is_configurable_per_request(api, db_session):
    client, _, _ = api
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    _issue(db_session, repo_id=repo.id, severity="medium")

    strict = client.post(
        "/api/v1/gate",
        json={"repository_id": repo.id, "policy": {"fail_on_severity": "medium"}},
    ).json()
    lenient = client.post(
        "/api/v1/gate",
        json={"repository_id": repo.id, "policy": {"fail_on_severity": "critical"}},
    ).json()

    assert strict["passed"] is False
    assert lenient["passed"] is True


def test_gate_rejects_an_unknown_severity_threshold(api):
    client, _, _ = api
    response = client.post(
        "/api/v1/gate", json={"repository_id": 1, "policy": {"fail_on_severity": "catastrophic"}}
    )
    assert response.status_code == 422


# --- Exports ---

def test_vex_export_names_the_repository_as_the_product(api, db_session):
    client, _, _ = api
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    _issue(db_session, repo_id=repo.id, identifier="CVE-2024-0001")

    document = client.get(f"/api/v1/targets/repository/{repo.id}/vex").json()

    assert document["@context"].startswith("https://openvex.dev/")
    assert document["statements"][0]["products"][0]["@id"] == "git@example.com:org/a.git"


def test_vex_export_for_a_container_uses_an_oci_purl(api, db_session):
    client, _, _ = api
    image = Container(image_name="nginx", tag="1.25")
    db_session.add(image)
    db_session.commit()
    _issue(db_session, container_id=image.id)

    document = client.get(f"/api/v1/targets/container/{image.id}/vex").json()

    assert document["statements"][0]["products"][0]["@id"].startswith("pkg:oci/nginx")


def test_csv_export_is_served_as_an_attachment(api, db_session):
    client, _, _ = api
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    _issue(db_session, repo_id=repo.id)

    response = client.get(f"/api/v1/targets/repository/{repo.id}/issues.csv")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    assert response.text.startswith("id,type,identifier")


def test_export_of_an_unknown_target_is_404_and_a_bad_kind_is_400(api):
    client, _, _ = api

    assert client.get("/api/v1/targets/repository/4242/vex").status_code == 404
    assert client.get("/api/v1/targets/banana/1/vex").status_code == 400


# --- Targets ---

def test_targets_list_both_kinds_with_their_outstanding_counts(api, db_session):
    client, _, _ = api
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main", name="App")
    image = Container(image_name="nginx", tag="1.25", registry="registry.internal")
    db_session.add_all([repo, image])
    db_session.commit()
    _issue(db_session, repo_id=repo.id)
    _issue(db_session, repo_id=repo.id)
    _issue(db_session, container_id=image.id)

    targets = client.get("/api/v1/targets").json()

    by_name = {t["name"]: t for t in targets}
    assert by_name["App"]["kind"] == "repository"
    assert by_name["App"]["open_issues"] == 2
    assert by_name["registry.internal/nginx:1.25"]["open_issues"] == 1


# --- One scan in flight per target (security review M15) ---

def test_the_api_answers_409_for_a_scan_already_running(api, db_session):
    """Not 404 and not 500: the request is well-formed and the target exists, the
    current state refuses it. A pipeline can retry a 409 knowingly."""
    from zanshin.models.repository import ZanshinRepository
    from zanshin.services.repository_service import ScanAlreadyRunningError

    client, stub, _ = api
    repo = ZanshinRepository(url="git@example.com:org/a.git", branch="main")
    db_session.add(repo)
    db_session.commit()

    def refuse(target_id):
        raise ScanAlreadyRunningError("Un scan est déjà en cours pour ce dépôt (scan 7).")

    stub.repository_service.trigger_scan = refuse

    response = client.post("/api/v1/scans", json={"repository_id": repo.id})

    assert response.status_code == 409
    assert "déjà en cours" in response.json()["detail"]


# --- R3: what a key may do, and to what ---

def _issue_key(db_session, **kwargs):
    """A second key alongside the fixture's wide-open one."""
    service = ApiKeyService(ApiKeyRepository(db_session))
    _, raw = service.create_key(**kwargs)
    return {"Authorization": f"Bearer {raw}"}


def test_a_read_only_key_cannot_queue_a_scan(api, db_session):
    """The realistic key is a CI token that only publishes results. Before this,
    every key could trigger scans, delete nothing but read everything, and export the
    full inventory — one credential, the whole API."""
    client, stub, _ = api
    repo = ZanshinRepository(name="app", url="git@example.com:app.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    headers = _issue_key(db_session, name="lecture", scopes=["read"])

    response = client.post("/api/v1/scans", json={"repository_id": repo.id}, headers=headers)

    assert response.status_code == 403
    assert "portée" in response.json()["detail"]
    assert stub.repository_service.calls == []


def test_a_read_only_key_can_still_read(api, db_session):
    client, _, _ = api
    headers = _issue_key(db_session, name="lecture", scopes=["read"])

    assert client.get("/api/v1/issues", headers=headers).status_code == 200


def test_a_scan_key_without_export_cannot_export(api, db_session):
    client, _, _ = api
    repo = ZanshinRepository(name="app", url="git@example.com:app.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    headers = _issue_key(db_session, name="ci", scopes=["read", "scan"])

    response = client.get(f"/api/v1/targets/repository/{repo.id}/vex", headers=headers)

    assert response.status_code == 403


def test_a_key_bound_to_one_repository_cannot_scan_another(api, db_session):
    """A pipeline's key belongs to that pipeline's project. Without a target
    restriction, the key issued for project A queues scans on B, reads B's findings
    and exports B's VEX document."""
    client, stub, _ = api
    mine = ZanshinRepository(name="mine", url="git@example.com:mine.git", branch="main")
    theirs = ZanshinRepository(name="theirs", url="git@example.com:theirs.git", branch="main")
    db_session.add_all([mine, theirs])
    db_session.commit()
    headers = _issue_key(db_session, name="projet-a", target_kind="repository", target_id=mine.id)

    mine_scan = client.post("/api/v1/scans", json={"repository_id": mine.id}, headers=headers)
    refused = client.post("/api/v1/scans", json={"repository_id": theirs.id}, headers=headers)

    assert mine_scan.status_code == 202

    assert refused.status_code == 403
    assert stub.repository_service.calls == [mine.id]


def test_a_repository_key_cannot_reach_a_container_with_the_same_id(api, db_session):
    """Ids are per-table, so "restricted to id 1" is meaningless without the kind."""
    client, _, _ = api
    container = Container(image_name="nginx", tag="latest")
    db_session.add(container)
    db_session.commit()
    headers = _issue_key(
        db_session, name="dépôt", target_kind="repository", target_id=container.id
    )

    refused = client.post(
        "/api/v1/gate", json={"container_id": container.id}, headers=headers
    )

    assert refused.status_code == 403


def test_a_restricted_key_only_sees_its_own_issues(api, db_session):
    """The listing had to be narrowed too: refusing the per-target routes while
    `/issues` still returned everything would have restricted nothing."""
    client, _, _ = api
    mine = ZanshinRepository(name="mine", url="git@example.com:mine.git", branch="main")
    theirs = ZanshinRepository(name="theirs", url="git@example.com:theirs.git", branch="main")
    db_session.add_all([mine, theirs])
    db_session.commit()
    _issue(db_session, repo_id=mine.id, identifier="CVE-2024-1111")
    _issue(db_session, repo_id=theirs.id, identifier="CVE-2024-2222")
    headers = _issue_key(db_session, name="projet-a", target_kind="repository", target_id=mine.id)

    page = client.get("/api/v1/issues", headers=headers).json()
    identifiers = [i["identifier"] for i in page["items"]]

    assert identifiers == ["CVE-2024-1111"]
    assert page["total"] == 1


def test_an_expired_key_is_refused(api, db_session):
    from datetime import timedelta

    from zanshin.clock import utcnow

    client, _, _ = api
    service = ApiKeyService(ApiKeyRepository(db_session))
    key, raw = service.create_key("temporaire", expires_in_days=1)
    key.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    response = client.get("/api/v1/issues", headers={"Authorization": f"Bearer {raw}"})

    assert response.status_code == 401


def test_an_unknown_scope_is_refused_at_creation(db_session):
    service = ApiKeyService(ApiKeyRepository(db_session))

    with pytest.raises(ValueError, match="inconnue"):
        service.create_key("ci", scopes=["read", "admin"])


def test_a_target_restriction_needs_both_a_kind_and_an_id(db_session):
    service = ApiKeyService(ApiKeyRepository(db_session))

    with pytest.raises(ValueError, match="Restriction de cible"):
        service.create_key("ci", target_kind="repository")


# --- R5: quota ---

def test_a_loop_is_cut_off_with_a_retry_after(api):
    """`/gate` loads a target's whole open backlog on every call, so an unbounded
    loop against it is a denial of service using a legitimate credential."""
    client, _, _ = api
    rate_limit.limiter.max_requests = 3
    try:
        responses = [client.get("/api/v1/issues") for _ in range(5)]
    finally:
        rate_limit.limiter.max_requests = rate_limit.MAX_REQUESTS_PER_WINDOW

    assert [r.status_code for r in responses] == [200, 200, 200, 429, 429]
    assert int(responses[-1].headers["Retry-After"]) > 0


def test_the_quota_is_per_key(api, db_session):
    """Keyed on the credential, not the address: the credential is the accountable
    identity, and it is what an operator can actually revoke."""
    client, _, _ = api
    other = _issue_key(db_session, name="autre")
    rate_limit.limiter.max_requests = 1
    try:
        assert client.get("/api/v1/issues").status_code == 200
        assert client.get("/api/v1/issues").status_code == 429
        assert client.get("/api/v1/issues", headers=other).status_code == 200
    finally:
        rate_limit.limiter.max_requests = rate_limit.MAX_REQUESTS_PER_WINDOW


# --- R6: the API's own documentation was public ---

def test_the_schema_is_not_served_anonymously():
    """FastAPI's defaults published a complete map of the routes, parameters and
    response shapes to anyone who could reach the port — a free reconnaissance step."""
    client = TestClient(api_app)

    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/api/v1/openapi.json").status_code == 401


def test_the_schema_is_served_to_a_valid_key(api):
    client, _, _ = api

    schema = client.get("/api/v1/openapi.json")

    assert schema.status_code == 200
    assert "/api/v1/issues" in schema.json()["paths"]
    assert client.get("/api/v1/docs").status_code == 200


# --- SARIF export ---

def test_the_sarif_export_needs_the_export_scope(api, db_session):
    client, _, _ = api
    repo = ZanshinRepository(name="app", url="git@example.com:app.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    headers = _issue_key(db_session, name="ci", scopes=["read", "scan"])

    assert client.get(
        f"/api/v1/targets/repository/{repo.id}/issues.sarif", headers=headers
    ).status_code == 403


def test_the_sarif_export_is_a_downloadable_log(api, db_session):
    """The endpoint a pipeline pipes into `gh code-scanning upload` — hence the
    download filename as well as the JSON body."""
    client, _, _ = api
    repo = ZanshinRepository(name="app", url="git@example.com:app.git", branch="main")
    db_session.add(repo)
    db_session.commit()
    _issue(db_session, repo_id=repo.id, identifier="CVE-2024-9999", severity="critical")

    response = client.get(f"/api/v1/targets/repository/{repo.id}/issues.sarif")

    assert response.status_code == 200
    assert ".sarif" in response.headers["content-disposition"]
    document = response.json()
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["level"] == "error"
    # The target's real identity, not a row id: it is what the platform shows.
    assert document["runs"][0]["properties"]["target"] == "git@example.com:app.git"


def test_a_key_bound_elsewhere_cannot_export_sarif(api, db_session):
    client, _, _ = api
    mine = ZanshinRepository(name="mine", url="git@example.com:mine.git", branch="main")
    theirs = ZanshinRepository(name="theirs", url="git@example.com:theirs.git", branch="main")
    db_session.add_all([mine, theirs])
    db_session.commit()
    headers = _issue_key(db_session, name="projet-a", target_kind="repository", target_id=mine.id)

    assert client.get(
        f"/api/v1/targets/repository/{theirs.id}/issues.sarif", headers=headers
    ).status_code == 403


# --- Dependency directness on the listing ---

def test_the_listing_can_be_narrowed_to_direct_dependencies(api, db_session):
    """What a pipeline asks for when it wants the subset it can fix today."""
    client, _, _ = api
    _issue(db_session, identifier="CVE-DIRECT", is_direct_dependency=True)
    _issue(db_session, identifier="CVE-TRANSITIVE", is_direct_dependency=False)
    _issue(db_session, identifier="CVE-UNKNOWN")

    page = client.get("/api/v1/issues", params={"only_direct": True}).json()

    assert [i["identifier"] for i in page["items"]] == ["CVE-DIRECT"]
    assert page["total"] == 1


def test_directness_is_reported_on_each_issue(api, db_session):
    client, _, _ = api
    _issue(db_session, identifier="CVE-DIRECT", is_direct_dependency=True)
    _issue(db_session, identifier="CVE-UNKNOWN")

    by_id = {i["identifier"]: i for i in client.get("/api/v1/issues").json()["items"]}

    assert by_id["CVE-DIRECT"]["is_direct_dependency"] is True
    # Absent, not false: the SBOM said nothing about it.
    assert by_id["CVE-UNKNOWN"]["is_direct_dependency"] is None
