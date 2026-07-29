"""Tests for ScanProcessor.

`process_scan` hardcodes `from zanshin.database import SessionLocal` and
opens its own session internally rather than accepting one via dependency
injection — so exercising it end-to-end requires monkeypatching that name
to point at an isolated in-memory database. This is the only place in this
test suite that needs monkeypatch for that reason; every other test uses
plain constructor injection.
"""
import os

import pytest

import zanshin.models  # noqa: F401
from zanshin.models.scan import Scan
from zanshin.models.repository import ZanshinRepository
from zanshin.models.container import Container
import zanshin.services.scan_processor as scan_processor_module
from zanshin.services.scan_processor import ScanProcessor


class FakeScannerEngine:
    def __init__(self, sbom=None, cves=None, secrets=None, iac=None, raise_on=None):
        self.sbom = sbom if sbom is not None else {"artifacts": []}
        self.cves = cves if cves is not None else {"matches": []}
        self.secrets = secrets if secrets is not None else []
        self.iac = iac if iac is not None else []
        self.raise_on = raise_on
        self.calls = []

    def get_workspace_root(self):
        return None

    def generate_sbom_for_image(self, image_string):
        self.calls.append(("generate_sbom_for_image", image_string))
        if self.raise_on == "generate_sbom_for_image":
            raise RuntimeError("boom")
        return self.sbom

    def generate_sbom_for_directory(self, work_dir, sub_path):
        self.calls.append(("generate_sbom_for_directory", sub_path))
        if self.raise_on == "generate_sbom_for_directory":
            raise RuntimeError("boom")
        return self.sbom

    def scan_sbom(self, work_dir, sbom):
        self.calls.append(("scan_sbom",))
        if self.raise_on == "scan_sbom":
            raise RuntimeError("boom")
        return self.cves

    def scan_secrets(self, work_dir, sub_path=""):
        self.calls.append(("scan_secrets",))
        return self.secrets

    def scan_iac(self, work_dir, sub_path=""):
        self.calls.append(("scan_iac",))
        return self.iac


class FakeLicenseComplianceService:
    def __init__(self, findings=None):
        self.findings = findings or []
        self.calls = 0

    def build_findings(self, scan_id, sbom):
        self.calls += 1
        return self.findings


class FakeEnrichmentService:
    def __init__(self):
        self.enrich_calls = []

    def enrich_findings(self, db, findings):
        self.enrich_calls.append(list(findings))


@pytest.fixture(autouse=True)
def patch_scan_processor_session(monkeypatch, isolated_session_local):
    monkeypatch.setattr(scan_processor_module, "SessionLocal", isolated_session_local)


@pytest.fixture()
def isolated_session(isolated_session_local):
    session = isolated_session_local()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def patch_git_clone(monkeypatch):
    """No real git remote is available in tests — replace `clone_from` with
    a no-op that just creates the destination directory, matching what a
    real (shallow) clone would leave behind for the rest of the pipeline."""

    def fake_clone_from(url, to_path, branch, depth, env):
        os.makedirs(to_path, exist_ok=True)

    monkeypatch.setattr(scan_processor_module.git.Repo, "clone_from", fake_clone_from)


# --- Pure helper methods (no DB, no filesystem) ---

def test_build_findings_maps_grype_matches_to_findings():
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=FakeScannerEngine())
    cves = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2024-0001", "severity": "Critical"},
                "artifact": {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/log4j/log4j-core@2.14.1", "locations": [{"path": "/app/lib/log4j-core.jar"}]},
            },
        ]
    }

    findings = sp._build_findings(scan_id=1, cves=cves)

    assert len(findings) == 1
    f = findings[0]
    assert f.type == "vulnerability"
    assert f.severity == "critical"
    assert f.identifier == "CVE-2024-0001"
    assert f.package_name == "log4j-core"
    assert f.file_path == "/app/lib/log4j-core.jar"
    assert f.source == "grype"


def test_build_findings_uses_engine_source_when_present_and_does_not_collide_with_grypes_own_source_key():
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=FakeScannerEngine())

    osv_shaped = {"matches": [{"vulnerability": {"id": "CVE-1", "severity": "high"}, "artifact": {}}], "engine_source": "osv"}
    assert sp._build_findings(1, osv_shaped)[0].source == "osv"

    # Real Grype JSON output has its OWN "source" key (an object describing
    # the scan target) — must not be mistaken for engine provenance.
    grype_shaped = {
        "matches": [{"vulnerability": {"id": "CVE-2", "severity": "high"}, "artifact": {}}],
        "source": {"type": "directory", "target": "/src"},
    }
    assert sp._build_findings(1, grype_shaped)[0].source == "grype"


def test_build_secret_findings_maps_gitleaks_report():
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=FakeScannerEngine())
    leaks = [{"RuleID": "aws-access-token", "File": "config/settings.py"}]

    findings = sp._build_secret_findings(scan_id=1, leaks=leaks)

    assert len(findings) == 1
    assert findings[0].type == "secret"
    assert findings[0].severity == "high"
    assert findings[0].identifier == "aws-access-token"
    assert findings[0].source == "gitleaks"


def test_build_iac_findings_defaults_missing_severity_to_medium():
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=FakeScannerEngine())
    checks = [
        {"check_id": "CKV_1", "resource": "aws_s3.foo", "file_path": "/main.tf", "severity": "HIGH"},
        {"check_id": "CKV_2", "resource": "aws_s3.bar", "file_path": "/main.tf"},
    ]

    findings = sp._build_iac_findings(scan_id=1, failed_checks=checks)

    assert findings[0].severity == "high"
    assert findings[1].severity == "medium"
    assert all(f.type == "iac" and f.source == "checkov" for f in findings)


def test_summarize_findings_counts_by_severity():
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=FakeScannerEngine())
    cves = {"matches": [
        {"vulnerability": {"severity": "Critical"}},
        {"vulnerability": {"severity": "critical"}},
        {"vulnerability": {"severity": "Medium"}},
    ]}

    summary = sp._summarize_findings(cves)

    assert summary == {"critical": 2, "high": 0, "medium": 1, "low": 0, "negligible": 0, "unknown": 0, "total": 3}


def test_validate_path_rejects_traversal():
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=FakeScannerEngine())
    with pytest.raises(ValueError):
        sp._validate_path("../etc/passwd")
    with pytest.raises(ValueError):
        sp._validate_path("/etc/passwd")


def test_validate_path_accepts_normal_relative_paths():
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=FakeScannerEngine())
    sp._validate_path("")
    sp._validate_path("src/main")


# --- process_scan orchestration (isolated in-memory DB) ---

def test_process_scan_repo_success_persists_findings_and_summary(isolated_session):
    repo = ZanshinRepository(url="git@example.com:org/repo.git", branch="main", sub_path="")
    isolated_session.add(repo)
    isolated_session.commit()

    scan = Scan(repo_id=repo.id, branch="main", sub_path="", status="pending", findings_count=0)
    isolated_session.add(scan)
    isolated_session.commit()

    engine = FakeScannerEngine(
        cves={"matches": [{"vulnerability": {"id": "CVE-1", "severity": "high"}, "artifact": {"name": "foo"}}]},
        secrets=[{"RuleID": "aws-key", "File": "a.py"}],
    )
    license_svc = FakeLicenseComplianceService()
    enrichment_svc = FakeEnrichmentService()
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=engine, enrichment_service=enrichment_svc, license_compliance_service=license_svc)

    sp.process_scan(scan.id, repo_url=repo.url, branch="main", sub_path="", ssh_key_id=None)

    isolated_session.refresh(scan)
    assert scan.status == "completed"
    assert scan.findings_count == 1
    assert scan.summary["high"] == 1

    findings = scan.findings
    types = {f.type for f in findings}
    assert types == {"vulnerability", "secret"}
    assert license_svc.calls == 1
    assert len(enrichment_svc.enrich_calls) == 1

    # Repo scans DO call scan_secrets/scan_iac.
    assert ("scan_secrets",) in engine.calls
    assert ("scan_iac",) in engine.calls


def test_process_scan_container_success_skips_secrets_but_still_applies_license_policy(isolated_session):
    container = Container(image_name="nginx", tag="latest")
    isolated_session.add(container)
    isolated_session.commit()

    scan = Scan(container_id=container.id, branch="latest", status="pending", findings_count=0)
    isolated_session.add(scan)
    isolated_session.commit()

    engine = FakeScannerEngine(cves={"matches": []})
    license_svc = FakeLicenseComplianceService(findings=[])
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=engine, license_compliance_service=license_svc)

    sp.process_scan(scan.id, repo_url=None, branch="latest", sub_path="", ssh_key_id=None)

    isolated_session.refresh(scan)
    assert scan.status == "completed"
    # Container scans must NOT call scan_secrets/scan_iac (source-code-only
    # scanners, see ADR-001 section 5).
    assert not any(c[0] in ("scan_secrets", "scan_iac") for c in engine.calls)
    # But license policy still runs — Syft produces license data for images too.
    assert license_svc.calls == 1


def test_process_scan_marks_scan_failed_on_scanner_error(isolated_session):
    repo = ZanshinRepository(url="git@example.com:org/repo.git", branch="main")
    isolated_session.add(repo)
    isolated_session.commit()
    scan = Scan(repo_id=repo.id, branch="main", status="pending", findings_count=0)
    isolated_session.add(scan)
    isolated_session.commit()

    engine = FakeScannerEngine(raise_on="scan_sbom")
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=engine)

    sp.process_scan(scan.id, repo_url=repo.url, branch="main", sub_path="", ssh_key_id=None)

    isolated_session.refresh(scan)
    assert scan.status == "failed"
    assert "boom" in scan.error


def test_process_scan_missing_scan_id_is_a_no_op(isolated_session):
    sp = ScanProcessor(ssh_key_service=None, scanner_engine=FakeScannerEngine())
    # Must not raise even though scan 9999 doesn't exist.
    sp.process_scan(9999, repo_url="git@example.com:org/repo.git", branch="main", sub_path="", ssh_key_id=None)
