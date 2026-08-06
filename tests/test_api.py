"""Tests for the HTTP API.

Driven through FastAPI's `TestClient`, with the session dependency pointed at an
in-memory database and the scan services stubbed — so nothing here reaches Docker
or the background pool. What is being tested is the contract a CI pipeline
depends on: authentication, status codes, and the shape of the payloads.
"""
import pytest
from fastapi.testclient import TestClient

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
