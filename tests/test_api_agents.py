"""Tests for the agent protocol.

Driven through `TestClient` against an in-memory database, like `test_api.py`. The
scanners are never involved: an agent's whole contribution arrives as JSON, which
is exactly what makes this testable without Docker — and what makes a result from
a remote machine indistinguishable from a local one.

What matters here is the boundary, not the happy path: what an agent credential
may and may not do, who may report on which scan, and what a retry does.
"""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from zanshin.api import rate_limit
from zanshin.api.app import api_app
from zanshin.api.deps import get_container
from zanshin.models.agent import CREDENTIALS_DELEGATED
from zanshin.models.api_key import SCOPE_AGENT, SCOPE_READ, SCOPE_SCAN
from zanshin.models.finding import Finding
from zanshin.models.processed_message import ProcessedMessage
from zanshin.models.scan import Scan
from zanshin.repositories.agent_repository import AgentRepository
from zanshin.repositories.api_key_repository import ApiKeyRepository
from zanshin.repositories.audit_log_repository import AuditLogRepository
from zanshin.repositories.processed_message_repository import ProcessedMessageRepository
from zanshin.repositories.scan_repository import ScanRepository
from zanshin.scan_contract import CONTRACT_VERSION, TARGET_CONTAINER, TARGET_REPOSITORY
from zanshin.services.agent_job_service import AgentJobService
from zanshin.services.agent_service import AgentService
from zanshin.services.api_key_service import ApiKeyService
from zanshin.services.audit_log_service import AuditLogService
from zanshin.services.issue_service import IssueService
from zanshin.services.scan_ingestor import ScanIngestor
from zanshin.services.scan_queue import STATUS_QUEUED, STATUS_RUNNING
from zanshin.services.settings_service import SettingsService


ONE_CVE = {
    "matches": [
        {
            "vulnerability": {"id": "CVE-2024-1", "severity": "High"},
            "artifact": {"name": "requests", "version": "2.0.0", "purl": "pkg:pypi/requests@2.0.0"},
        }
    ]
}


class FakeSSHKeyService:
    def __init__(self):
        self.calls = []

    def get_decrypted_key(self, key_id):
        self.calls.append(key_id)
        return "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"


@pytest.fixture()
def agent_api(db_session, setting_repository, api_key_repository):
    """A client authenticated as a remote agent, plus the pieces to poke at."""
    settings_service = SettingsService(setting_repository)
    api_key_service = ApiKeyService(api_key_repository)
    agent_service = AgentService(
        AgentRepository(db_session),
        api_key_service=api_key_service,
        settings_service=settings_service,
    )
    audit_log_service = AuditLogService(AuditLogRepository(db_session))
    ssh_key_service = FakeSSHKeyService()
    # Real ingestion and a real issue service: "the same rows as a local scan" is
    # the property being tested, so stubbing them out would test nothing.
    ingestor = ScanIngestor(issue_service=IssueService())

    agent, raw_key = agent_service.create_remote_agent(name="paris-01", max_concurrent=2)

    job_service = AgentJobService(
        agent_service=agent_service,
        scan_repository=ScanRepository(db_session),
        ssh_key_service=ssh_key_service,
        scan_ingestor=ingestor,
        processed_message_repository=ProcessedMessageRepository(db_session),
        audit_log_service=audit_log_service,
    )

    class StubContainer:
        def __init__(self):
            self.db = db_session
            self.api_key_service = api_key_service
            self.agent_service = agent_service
            self.agent_job_service = job_service
            self.audit_log_service = audit_log_service
            self.scan_repository = ScanRepository(db_session)

    stub = StubContainer()
    rate_limit.limiter.reset()
    api_app.dependency_overrides[get_container] = lambda: stub
    client = TestClient(api_app)
    client.headers.update({"Authorization": f"Bearer {raw_key}"})
    yield client, stub, agent, ssh_key_service
    api_app.dependency_overrides.clear()


def _queued_scan(db, repo_id=None, container_id=None):
    scan = Scan(
        repo_id=repo_id, container_id=container_id, branch="main",
        status=STATUS_QUEUED, findings_count=0,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _result_body(**overrides):
    body = {
        "message_id": str(uuid.uuid4()),
        "status": "succeeded",
        "artifacts": {"sbom": {"artifacts": []}, "cves": ONE_CVE, "duration_ms": 5},
    }
    body.update(overrides)
    return body


# --- What an agent credential may do ------------------------------------------

def test_an_unauthenticated_agent_call_is_401(agent_api):
    client, _, _, _ = agent_api

    response = client.post("/api/v1/agents/hello", json={}, headers={"Authorization": ""})

    assert response.status_code == 401


def test_a_key_without_the_agent_scope_is_refused(agent_api, api_key_repository):
    """An agent credential is not a superset of the others, and the others are not a
    superset of it: a pipeline key that could submit scan results could rewrite the
    finding set its own gate is evaluated against."""
    client, _, _, _ = agent_api
    _, pipeline_key = ApiKeyService(api_key_repository).create_key(
        "ci", scopes=[SCOPE_READ, SCOPE_SCAN]
    )

    response = client.post(
        "/api/v1/agents/hello", json={}, headers={"Authorization": f"Bearer {pipeline_key}"}
    )

    assert response.status_code == 403
    assert SCOPE_AGENT in response.json()["detail"]


def test_an_agent_scoped_key_with_no_agent_row_is_refused(agent_api, api_key_repository):
    """Valid credential, right scope, but nothing to be: 403 rather than 401,
    because retrying with the same key will never work."""
    client, _, _, _ = agent_api
    _, orphan_key = ApiKeyService(api_key_repository).create_key(
        "orpheline", scopes=[SCOPE_AGENT]
    )

    response = client.post(
        "/api/v1/agents/hello", json={}, headers={"Authorization": f"Bearer {orphan_key}"}
    )

    assert response.status_code == 403
    assert "aucun agent" in response.json()["detail"]


def test_a_disabled_agent_is_refused_everywhere(agent_api):
    client, stub, agent, _ = agent_api
    stub.agent_service.set_enabled(agent.id, False)

    assert client.post("/api/v1/agents/hello", json={}).status_code == 403
    assert client.get("/api/v1/agents/jobs").status_code == 403


# --- Hello --------------------------------------------------------------------

def test_hello_reports_the_identity_the_control_plane_holds(agent_api):
    client, _, agent, _ = agent_api

    response = client.post("/api/v1/agents/hello", json={
        "hostname": "runner-7", "platform": "Linux-6.1", "version": "1.0",
        "scanner_engine": "docker", "contract_version": CONTRACT_VERSION,
    })

    body = response.json()
    assert response.status_code == 200
    assert body["name"] == "paris-01"
    assert body["agent_id"] == agent.worker_id
    assert body["max_concurrent"] == 2
    # The agent is told how to pace itself, so tuning a fleet does not mean editing
    # every machine.
    assert body["poll_wait_seconds"] > 0
    assert body["heartbeat_seconds"] > 0


def test_hello_records_what_the_agent_reported(agent_api):
    client, stub, agent, _ = agent_api

    client.post("/api/v1/agents/hello", json={"hostname": "runner-7", "scanner_engine": "docker"})

    refreshed = stub.agent_service.find_by_id(agent.id)
    assert refreshed.hostname == "runner-7"
    assert refreshed.last_seen_at is not None


def test_an_agent_speaking_another_contract_version_is_refused_with_both_numbers(agent_api):
    """Two artefacts deployed separately will eventually disagree; failing here
    beats a KeyError halfway through ingesting a result (docs/architecture/04)."""
    client, _, _, _ = agent_api

    response = client.post("/api/v1/agents/hello", json={"contract_version": "99"})

    assert response.status_code == 409
    assert "99" in response.json()["detail"]
    assert CONTRACT_VERSION in response.json()["detail"]


# --- Claiming work ------------------------------------------------------------

def test_an_empty_queue_answers_204_with_no_body(agent_api):
    client, _, _, _ = agent_api

    response = client.get("/api/v1/agents/jobs")

    assert response.status_code == 204
    assert not response.content


def test_claiming_hands_over_a_self_contained_task_and_takes_the_lease(
    agent_api, make_repository
):
    client, stub, agent, _ = agent_api
    repo = make_repository(url="https://example.com/org/app.git")
    scan = _queued_scan(stub.db, repo_id=repo.id)

    response = client.get("/api/v1/agents/jobs")

    task = response.json()
    assert response.status_code == 200
    assert task["scan_id"] == scan.id
    assert task["kind"] == TARGET_REPOSITORY
    assert task["repo_url"] == "https://example.com/org/app.git"

    stub.db.refresh(scan)
    assert scan.status == STATUS_RUNNING
    assert scan.claimed_by == agent.worker_id
    assert scan.lease_expires_at is not None


def test_a_container_task_carries_the_image_reference(agent_api, make_container):
    client, stub, _, _ = agent_api
    image = make_container(image_name="nginx", tag="1.27", registry="ghcr.io")
    _queued_scan(stub.db, container_id=image.id)

    task = client.get("/api/v1/agents/jobs").json()

    assert task["kind"] == TARGET_CONTAINER
    assert task["image"] == "ghcr.io/nginx:1.27"


def test_no_deploy_key_travels_to_an_agent_in_local_mode(
    agent_api, make_repository, ssh_key_repository, encryption_service
):
    """The default, and the recommendation of décision 0003: the control plane sends
    no secret, and the agent uses the git credentials its own machine holds."""
    client, stub, _, ssh_key_service = agent_api
    from zanshin.models.ssh_key import SSHKey

    key = SSHKey(name="deploy", private_key="chiffrée")
    stub.db.add(key)
    stub.db.commit()
    repo = make_repository()
    repo.ssh_key_id = key.id
    stub.db.commit()
    _queued_scan(stub.db, repo_id=repo.id)

    task = client.get("/api/v1/agents/jobs").json()

    assert task.get("ssh_private_key") is None
    # And the key store was never even asked.
    assert ssh_key_service.calls == []


def test_a_delegated_agent_receives_the_key_and_the_delivery_is_audited(
    agent_api, make_repository
):
    """The opt-in mode. The audit entry is not decoration: if this agent is later
    found compromised, it is the only record of which keys it was given."""
    client, stub, agent, ssh_key_service = agent_api
    from zanshin.models.ssh_key import SSHKey

    stub.agent_service.update_agent(agent.id, credentials_mode=CREDENTIALS_DELEGATED)
    key = SSHKey(name="deploy", private_key="chiffrée")
    stub.db.add(key)
    stub.db.commit()
    repo = make_repository()
    repo.ssh_key_id = key.id
    stub.db.commit()
    _queued_scan(stub.db, repo_id=repo.id)

    # `TestClient` speaks http://testserver, so the request has to look like what a
    # TLS-terminating proxy forwards — which is the only shape in which the control
    # plane will part with a key.
    task = client.get(
        "/api/v1/agents/jobs", headers={"X-Forwarded-Proto": "https"}
    ).json()

    assert "BEGIN OPENSSH PRIVATE KEY" in task["ssh_private_key"]
    assert ssh_key_service.calls == [key.id]
    entries = [e for e in AuditLogRepository(stub.db).find_recent(50)
               if e.operation_type == "AGENT_CREDENTIAL_SENT"]
    assert len(entries) == 1
    assert "paris-01" in entries[0].description


def test_a_delegated_agent_over_plain_http_is_refused_and_the_scan_is_released(
    agent_api, make_repository, monkeypatch
):
    """Silently scanning without the key would surface as a clone failure that looks
    like a network problem, and the operator would never learn that the mode they
    opted into was not in effect."""
    import zanshin.services.agent_job_service as job_module

    monkeypatch.setattr(job_module, "ALLOW_INSECURE_CREDENTIALS", False)
    client, stub, agent, _ = agent_api
    from zanshin.models.ssh_key import SSHKey

    stub.agent_service.update_agent(agent.id, credentials_mode=CREDENTIALS_DELEGATED)
    key = SSHKey(name="deploy", private_key="chiffrée")
    stub.db.add(key)
    stub.db.commit()
    repo = make_repository()
    repo.ssh_key_id = key.id
    stub.db.commit()
    scan = _queued_scan(stub.db, repo_id=repo.id)

    # TestClient speaks http://testserver, i.e. exactly the insecure case.
    response = client.get("/api/v1/agents/jobs")

    assert response.status_code == 412
    assert "HTTPS" in response.json()["detail"]
    stub.db.refresh(scan)
    # Released, not left holding a lease nobody will report on.
    assert scan.status == STATUS_QUEUED
    assert scan.claimed_by is None


def test_an_agent_at_its_limit_is_told_there_is_nothing_to_do(agent_api, make_repository):
    """Capacity is the agent's, and asking for work is how it exercises flow
    control — the control plane never has to guess how busy it is."""
    client, stub, agent, _ = agent_api
    stub.agent_service.update_agent(agent.id, max_concurrent=1)
    _queued_scan(stub.db, repo_id=make_repository().id)
    _queued_scan(stub.db, repo_id=make_repository(url="https://example.com/b.git").id)

    assert client.get("/api/v1/agents/jobs").status_code == 200
    assert client.get("/api/v1/agents/jobs").status_code == 204


# --- Heartbeat ----------------------------------------------------------------

def test_a_heartbeat_renews_the_lease(agent_api, make_repository):
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")
    stub.db.refresh(scan)
    from zanshin.clock import utcnow
    from datetime import timedelta

    scan.lease_expires_at = utcnow() - timedelta(seconds=1)
    stub.db.commit()

    response = client.post(
        f"/api/v1/agents/jobs/{scan.id}/heartbeat", json={"message": "Clonage"}
    )

    assert response.status_code == 204
    stub.db.refresh(scan)
    assert scan.lease_expires_at > utcnow()


def test_a_heartbeat_on_a_lost_job_is_409_so_the_agent_stops(agent_api, make_repository):
    """Better than letting it finish a scan whose result will be refused anyway."""
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)

    response = client.post(f"/api/v1/agents/jobs/{scan.id}/heartbeat", json={})

    assert response.status_code == 409


# --- Results ------------------------------------------------------------------

def test_a_reported_result_produces_the_same_rows_as_a_local_scan(agent_api, make_repository):
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")

    response = client.post(f"/api/v1/agents/jobs/{scan.id}/result", json=_result_body())

    assert response.status_code == 200
    assert response.json()["outcome"] == "applied"
    stub.db.refresh(scan)
    assert scan.status == "completed"
    assert scan.findings_count == 1
    findings = stub.db.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert [f.identifier for f in findings] == ["CVE-2024-1"]


def test_a_reported_failure_records_which_agent_failed(agent_api, make_repository):
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")

    response = client.post(f"/api/v1/agents/jobs/{scan.id}/result", json=_result_body(
        status="failed", artifacts=None, error="Clone impossible : accès refusé"
    ))

    assert response.status_code == 200
    stub.db.refresh(scan)
    assert scan.status == "failed"
    # Which machine could not do it matters when only one of them lacks access.
    assert "paris-01" in scan.error
    assert "accès refusé" in scan.error


def test_a_replayed_report_changes_nothing(agent_api, make_repository):
    """Delivery is at-least-once inbound too: an agent that loses the response has
    to retry. The damage a retry would do is not duplicate findings (fingerprints
    prevent those) but an inflated `times_seen` on every issue in the report."""
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")
    body = _result_body()

    first = client.post(f"/api/v1/agents/jobs/{scan.id}/result", json=body)
    second = client.post(f"/api/v1/agents/jobs/{scan.id}/result", json=body)

    assert first.json()["outcome"] == "applied"
    assert second.json()["outcome"] == "duplicate"

    issues = stub.db.query(__import__("zanshin.models.issue", fromlist=["Issue"]).Issue).all()
    assert len(issues) == 1
    assert issues[0].times_seen == 1
    assert stub.db.query(ProcessedMessage).count() == 1


def test_the_dedup_marker_and_the_results_are_committed_together(agent_api, make_repository):
    """Marking first and ingesting after would leave a scan stuck `scanning` that no
    retry could fix, because the retry would be recognised as a duplicate."""
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")

    client.post(f"/api/v1/agents/jobs/{scan.id}/result", json=_result_body())

    stub.db.refresh(scan)
    assert scan.status == "completed"
    assert stub.db.query(ProcessedMessage).count() == 1


def test_a_result_without_a_message_id_is_refused(agent_api, make_repository):
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")

    response = client.post(
        f"/api/v1/agents/jobs/{scan.id}/result", json=_result_body(message_id="")
    )

    assert response.status_code == 400


def test_an_agent_cannot_report_on_a_scan_it_does_not_hold(agent_api, make_repository):
    """The scan id is a small integer anyone could guess, and a report on somebody
    else's scan rewrites findings a gate is evaluated against."""
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)  # never claimed

    response = client.post(f"/api/v1/agents/jobs/{scan.id}/result", json=_result_body())

    assert response.status_code == 403
    stub.db.refresh(scan)
    assert scan.status == STATUS_QUEUED
    denied = [e for e in AuditLogRepository(stub.db).find_recent(50)
              if e.operation_type == "ACCESS_DENIED"]
    assert denied, "an agent reaching for another's scan must leave a trail"


def test_reporting_on_a_scan_that_does_not_exist_is_404(agent_api):
    client, _, _, _ = agent_api

    response = client.post("/api/v1/agents/jobs/4242/result", json=_result_body())

    assert response.status_code == 404


def test_a_successful_submission_is_audited(agent_api, make_repository):
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")

    client.post(f"/api/v1/agents/jobs/{scan.id}/result", json=_result_body())

    submitted = [e for e in AuditLogRepository(stub.db).find_recent(50)
                 if e.operation_type == "AGENT_RESULT_SUBMITTED"]
    assert len(submitted) == 1
    assert "paris-01" in submitted[0].description


# --- Large payloads -----------------------------------------------------------

def test_a_large_payload_can_arrive_in_slices(agent_api, make_repository):
    """An SBOM for a substantial image runs to megabytes and has to travel whole,
    because normalization happens on this side (décision 0003)."""
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")

    payload = json.dumps({"sbom": {"artifacts": []}, "cves": ONE_CVE, "duration_ms": 7})
    third = len(payload) // 3 + 1
    slices = [payload[i:i + third] for i in range(0, len(payload), third)]
    upload_id = str(uuid.uuid4())
    message_id = str(uuid.uuid4())

    responses = []
    for index, data in enumerate(slices):
        responses.append(client.post(f"/api/v1/agents/jobs/{scan.id}/result", json={
            "message_id": message_id,
            "status": "succeeded",
            "chunk": {
                "upload_id": upload_id, "index": index, "count": len(slices), "data": data,
            },
        }))

    assert [r.json()["outcome"] for r in responses[:-1]] == ["chunk_received"] * (len(slices) - 1)
    assert responses[-1].json()["outcome"] == "applied"
    stub.db.refresh(scan)
    assert scan.status == "completed"
    assert scan.duration_ms == 7


def test_slices_may_arrive_out_of_order(agent_api, make_repository):
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")

    payload = json.dumps({"sbom": {}, "cves": {"matches": []}, "duration_ms": 3})
    half = len(payload) // 2
    slices = {0: payload[:half], 1: payload[half:]}
    upload_id, message_id = str(uuid.uuid4()), str(uuid.uuid4())

    for index in (1, 0):
        response = client.post(f"/api/v1/agents/jobs/{scan.id}/result", json={
            "message_id": message_id, "status": "succeeded",
            "chunk": {"upload_id": upload_id, "index": index, "count": 2, "data": slices[index]},
        })

    assert response.json()["outcome"] == "applied"
    stub.db.refresh(scan)
    assert scan.status == "completed"


def test_a_nonsensical_slice_is_refused(agent_api, make_repository):
    client, stub, _, _ = agent_api
    scan = _queued_scan(stub.db, repo_id=make_repository().id)
    client.get("/api/v1/agents/jobs")

    response = client.post(f"/api/v1/agents/jobs/{scan.id}/result", json={
        "message_id": str(uuid.uuid4()), "status": "succeeded",
        "chunk": {"upload_id": "u1", "index": 5, "count": 2, "data": "{}"},
    })

    assert response.status_code == 400


def test_a_remote_agent_is_told_to_run_semgrep_when_the_setting_is_on(agent_api, make_repository, monkeypatch):
    """Régression : `build_task` posait `collect_code_sample` mais pas `run_sast`.

    Le champ retombait donc sur son défaut `False`, et **aucun agent distant
    n'exécutait jamais Semgrep**, quel que soit le réglage `sast_enabled`. Rien ne le
    signalait : le contrat traite l'absence de résultat SAST comme « l'étape n'a pas
    tourné », ce qui était exact et laissait le backlog intact — donc pas de constat
    résolu à tort, juste une fonctionnalité muette.

    Le réglage vit en base et un agent n'a pas de base (décision 0003) : c'est bien au
    plan de contrôle de trancher, comme il le fait déjà pour l'échantillon de code.
    """
    client, stub, _, _ = agent_api
    monkeypatch.setattr(stub.agent_job_service.scan_ingestor, "wants_sast", lambda is_container: True)
    _queued_scan(stub.db, repo_id=make_repository().id)

    task = client.get("/api/v1/agents/jobs").json()

    assert task["run_sast"] is True


def test_a_remote_agent_is_not_told_to_run_semgrep_when_the_setting_is_off(agent_api, make_repository, monkeypatch):
    client, stub, _, _ = agent_api
    monkeypatch.setattr(stub.agent_job_service.scan_ingestor, "wants_sast", lambda is_container: False)
    _queued_scan(stub.db, repo_id=make_repository().id)

    task = client.get("/api/v1/agents/jobs").json()

    # `response_model_exclude_none=True` retire les champs nuls ; `False` n'est pas nul.
    assert task.get("run_sast", False) is False
