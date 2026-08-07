"""Tests for ScanIngestor — the half of the pipeline that owns the database.

These exercise ingestion from `ScanArtifacts` handed in directly, which is the
remote-agent path: nothing here ran a scanner. That is the point of the split —
if these produce the same rows as `tests/test_scan_processor.py` does end to end,
then a result computed on another machine is genuinely indistinguishable from a
local one (ADR-002 §8.3).
"""
import pytest

import zanshin.models  # noqa: F401
from zanshin.models.ai_review_result import AiReviewResult
from zanshin.models.finding import Finding
from zanshin.scan_contract import ScanArtifacts
from zanshin.services.issue_service import IssueService
from zanshin.services.scan_ingestor import ScanIngestor


class FakeLicenseComplianceService:
    def __init__(self, findings=None):
        self.findings = findings or []
        self.calls = 0

    def build_findings(self, scan_id, sbom):
        self.calls += 1
        return self.findings


class FakeEnrichmentService:
    def __init__(self, raise_error=None):
        self.enrich_calls = []
        self.raise_error = raise_error

    def enrich_findings(self, db, findings):
        self.enrich_calls.append(list(findings))
        if self.raise_error:
            raise self.raise_error


class FakeAiReviewService:
    def __init__(self, enabled=True, model="gemma4:12b-it-qat", response="Looks fine.",
                 parsed_findings=None, raise_error=None):
        self.enabled = enabled
        self.model = model
        self.response = response
        self.parsed_findings = parsed_findings if parsed_findings is not None else []
        self.raise_error = raise_error
        self.review_calls = []

    def is_enabled(self):
        return self.enabled

    def get_selected_model(self):
        return self.model

    def review_code(self, code):
        self.review_calls.append(code)
        if self.raise_error:
            raise self.raise_error
        return self.response

    def parse_findings(self, response):
        return self.parsed_findings


ONE_CVE = {
    "matches": [
        {
            "vulnerability": {"id": "CVE-2024-1", "severity": "High"},
            "artifact": {"name": "requests", "version": "2.0.0", "purl": "pkg:pypi/requests@2.0.0"},
        }
    ]
}


def artifacts(**overrides) -> ScanArtifacts:
    payload = {"sbom": {"artifacts": []}, "cves": ONE_CVE, "duration_ms": 1234}
    payload.update(overrides)
    return ScanArtifacts(**payload)


# --- The success path ---------------------------------------------------------

def test_ingesting_artifacts_completes_the_scan_and_normalizes_every_finding_type(
    db_session, make_repository, make_scan
):
    repo = make_repository()
    scan = make_scan(repo_id=repo.id, status="scanning")
    license_svc = FakeLicenseComplianceService()

    ScanIngestor(license_compliance_service=license_svc).ingest(
        db_session,
        scan,
        artifacts(
            secrets=[{"RuleID": "aws-key", "File": "app.py", "StartLine": 12}],
            iac=[{"check_id": "CKV_AWS_1", "resource": "aws_s3_bucket.data", "file_path": "main.tf"}],
        ),
    )

    db_session.refresh(scan)
    assert scan.status == "completed"
    assert scan.findings_count == 1  # the summary counts vulnerabilities
    assert scan.summary["high"] == 1
    assert scan.duration_ms == 1234
    assert scan.cves == ONE_CVE

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert {f.type for f in findings} == {"vulnerability", "secret", "iac"}
    secret = next(f for f in findings if f.type == "secret")
    assert (secret.severity, secret.line) == ("high", 12)
    iac = next(f for f in findings if f.type == "iac")
    # checkov often omits severity; a misconfiguration is not low-priority by default.
    assert iac.severity == "medium"
    assert license_svc.calls == 1


def test_container_artifacts_skip_secret_and_iac_rows_but_keep_the_licence_policy(
    db_session, make_container, make_scan
):
    container = make_container()
    scan = make_scan(container_id=container.id, status="scanning")
    license_svc = FakeLicenseComplianceService()

    # An agent scanning an image reports empty lists for the source-code-only
    # steps; ingestion must not invent rows from them either way.
    ScanIngestor(license_compliance_service=license_svc).ingest(
        db_session, scan, artifacts(secrets=[{"RuleID": "x"}], iac=[{"check_id": "y"}])
    )

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert {f.type for f in findings} == {"vulnerability"}
    # Syft produces licence data for images just as much as for directories.
    assert license_svc.calls == 1


def test_enrichment_failure_never_downgrades_a_completed_scan(
    db_session, make_repository, make_scan
):
    scan = make_scan(repo_id=make_repository().id, status="scanning")
    enrichment = FakeEnrichmentService(raise_error=ConnectionError("first.org unreachable"))

    ScanIngestor(enrichment_service=enrichment).ingest(db_session, scan, artifacts())

    db_session.refresh(scan)
    assert scan.status == "completed"
    assert len(enrichment.enrich_calls) == 1


def test_record_failure_marks_the_scan_with_the_reported_message(
    db_session, make_repository, make_scan
):
    scan = make_scan(repo_id=make_repository().id, status="scanning")

    ScanIngestor().record_failure(db_session, scan, "Clone impossible : accès refusé")

    db_session.refresh(scan)
    assert scan.status == "failed"
    # A `local`-mode agent without git access produces exactly this: a readable
    # scan result, not a crash (ADR-002 §5).
    assert "accès refusé" in scan.error


def test_record_failure_falls_back_to_a_message_rather_than_storing_nothing(
    db_session, make_repository, make_scan
):
    scan = make_scan(repo_id=make_repository().id, status="scanning")

    ScanIngestor().record_failure(db_session, scan, "")

    db_session.refresh(scan)
    assert scan.status == "failed"
    assert scan.error


# --- The AI review, and the "did it run?" distinction -------------------------

def test_wants_code_sample_only_when_the_review_is_enabled_for_a_repository():
    enabled = ScanIngestor(ai_review_service=FakeAiReviewService(enabled=True))
    disabled = ScanIngestor(ai_review_service=FakeAiReviewService(enabled=False))

    assert enabled.wants_code_sample(is_container=False) is True
    # No checkout exists for an image, so there is nothing to sample.
    assert enabled.wants_code_sample(is_container=True) is False
    assert disabled.wants_code_sample(is_container=False) is False
    assert ScanIngestor().wants_code_sample(is_container=False) is False


def test_the_review_runs_on_the_sample_the_runner_collected(
    db_session, make_repository, make_scan
):
    scan = make_scan(repo_id=make_repository().id, status="scanning")
    ai_review = FakeAiReviewService(
        parsed_findings=[{"severity": "high", "title": "Secret codé en dur", "file_path": "app.py"}]
    )

    ScanIngestor(ai_review_service=ai_review).ingest(
        db_session, scan, artifacts(code_sample="# app.py\nAPI_KEY = 'x'\n")
    )

    # The control plane never had the checkout: the sample arrived in the artifacts.
    assert ai_review.review_calls == ["# app.py\nAPI_KEY = 'x'\n"]
    result = db_session.query(AiReviewResult).filter(AiReviewResult.scan_id == scan.id).first()
    assert result.status == "completed"
    ai_findings = (
        db_session.query(Finding)
        .filter(Finding.scan_id == scan.id, Finding.type == "ai_review")
        .all()
    )
    assert [f.identifier for f in ai_findings] == ["Secret codé en dur"]
    assert ai_findings[0].source == "ollama:gemma4:12b-it-qat"


def test_an_empty_sample_means_the_review_did_not_run_at_all(
    db_session, make_repository, make_scan
):
    """"Nothing reviewable" must not be recorded as "reviewed, found nothing":
    the latter resolves every past AI issue (see `scanned_types_for`)."""
    scan = make_scan(repo_id=make_repository().id, status="scanning")
    ai_review = FakeAiReviewService()

    ScanIngestor(ai_review_service=ai_review).ingest(db_session, scan, artifacts(code_sample=""))

    assert ai_review.review_calls == []
    assert db_session.query(AiReviewResult).filter(AiReviewResult.scan_id == scan.id).first() is None


def test_a_broken_review_is_recorded_without_failing_the_scan(
    db_session, make_repository, make_scan
):
    scan = make_scan(repo_id=make_repository().id, status="scanning")
    ai_review = FakeAiReviewService(raise_error=ConnectionError("ollama unreachable"))

    ScanIngestor(ai_review_service=ai_review).ingest(
        db_session, scan, artifacts(code_sample="# app.py\n")
    )

    db_session.refresh(scan)
    assert scan.status == "completed"
    result = db_session.query(AiReviewResult).filter(AiReviewResult.scan_id == scan.id).first()
    assert result.status == "failed"
    assert "ollama unreachable" in result.error


# --- Issue reconciliation -----------------------------------------------------

def test_issues_are_reconciled_from_ingested_artifacts(db_session, make_repository, make_scan):
    """The delta is what makes a scan result readable, and it must be produced by
    ingestion alone — an agent contributes nothing to it."""
    repo = make_repository()
    ingestor = ScanIngestor(issue_service=IssueService())

    first = make_scan(repo_id=repo.id, status="scanning")
    ingestor.ingest(db_session, first, artifacts())
    db_session.refresh(first)
    assert (first.new_issues_count, first.resolved_issues_count) == (1, 0)

    second = make_scan(repo_id=repo.id, status="scanning")
    ingestor.ingest(db_session, second, artifacts(cves={"matches": []}))
    db_session.refresh(second)
    assert (second.new_issues_count, second.resolved_issues_count) == (0, 1)


# --- "Did not run" versus "found nothing" -------------------------------------
#
# The failure these close destroys data rather than losing a feature: a type listed as
# scanned but absent from the findings is read as "the problem is gone", and its issues
# are resolved. A crashed scanner must therefore look different from a clean one.

SEMGREP_SECURITY_HIT = {
    "check_id": "zanshin-python-eval-exec",
    "path": "app/main.py",
    "start": {"line": 12},
    "extra": {
        "message": "Appel à eval sur une valeur non littérale",
        "severity": "ERROR",
        "metadata": {"category": "security", "confidence": "HIGH"},
    },
}
SEMGREP_QUALITY_HIT = {
    "check_id": "zanshin-python-bare-except",
    "path": "app/main.py",
    "start": {"line": 30},
    "extra": {
        "message": "except nu",
        "severity": "WARNING",
        "metadata": {"category": "best-practice", "confidence": "HIGH"},
    },
}


def _issue_types(db_session, repo_id):
    from zanshin.models.issue import STATE_OPEN, Issue

    return {
        issue.type
        for issue in db_session.query(Issue).filter(
            Issue.repo_id == repo_id, Issue.state == STATE_OPEN
        )
    }


def test_semgrep_results_split_into_security_and_quality_findings(
    db_session, make_repository, make_scan
):
    from zanshin.services.sast_service import SastService

    scan = make_scan(repo_id=make_repository().id, status="scanning")

    ScanIngestor(sast_service=SastService()).ingest(
        db_session, scan, artifacts(sast=[SEMGREP_SECURITY_HIT, SEMGREP_QUALITY_HIT])
    )

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    by_type = {f.type: f for f in findings}
    assert {"sast", "quality"} <= set(by_type)
    # The message is on the row, which is the whole reason `Finding.description` exists.
    assert by_type["sast"].description == "Appel à eval sur une valeur non littérale"
    assert by_type["sast"].severity == "high"
    assert by_type["quality"].severity == "medium"


def test_a_semgrep_failure_does_not_resolve_the_previous_findings(
    db_session, make_repository, make_scan
):
    """`sast=None` is a crashed or disabled step. Reading it as "clean" would mark a
    repository fixed on the strength of a scanner that never looked at it."""
    from zanshin.services.sast_service import SastService

    repo = make_repository()
    ingestor = ScanIngestor(issue_service=IssueService(), sast_service=SastService())

    first = make_scan(repo_id=repo.id, status="scanning")
    ingestor.ingest(db_session, first, artifacts(sast=[SEMGREP_SECURITY_HIT]))
    assert "sast" in _issue_types(db_session, repo.id)

    second = make_scan(repo_id=repo.id, status="scanning")
    ingestor.ingest(db_session, second, artifacts(sast=None))

    assert "sast" in _issue_types(db_session, repo.id)


def test_a_clean_semgrep_run_does_resolve_them(db_session, make_repository, make_scan):
    """The other half — without it the `None` distinction would just be a way of never
    resolving anything."""
    from zanshin.services.sast_service import SastService

    repo = make_repository()
    ingestor = ScanIngestor(issue_service=IssueService(), sast_service=SastService())

    first = make_scan(repo_id=repo.id, status="scanning")
    ingestor.ingest(db_session, first, artifacts(sast=[SEMGREP_SECURITY_HIT]))
    assert "sast" in _issue_types(db_session, repo.id)

    second = make_scan(repo_id=repo.id, status="scanning")
    ingestor.ingest(db_session, second, artifacts(sast=[]))

    assert "sast" not in _issue_types(db_session, repo.id)


def test_a_checkov_failure_does_not_resolve_the_previous_iac_findings(
    db_session, make_repository, make_scan
):
    """The same defect, which existed before this work: `scan_iac` swallowed any failure
    and returned `[]`, so a checkov crash declared the repository's infrastructure fixed."""
    repo = make_repository()
    ingestor = ScanIngestor(issue_service=IssueService())
    iac_hit = [{"check_id": "CKV_AWS_1", "resource": "aws_s3_bucket.data", "file_path": "main.tf"}]

    first = make_scan(repo_id=repo.id, status="scanning")
    ingestor.ingest(db_session, first, artifacts(iac=iac_hit))
    assert "iac" in _issue_types(db_session, repo.id)

    second = make_scan(repo_id=repo.id, status="scanning")
    ingestor.ingest(db_session, second, artifacts(iac=None))

    assert "iac" in _issue_types(db_session, repo.id)


def test_semgrep_findings_stay_out_of_the_scan_summary(db_session, make_repository, make_scan):
    """`summary` and `findings_count` count vulnerabilities: they feed `SeverityCounts`,
    the dashboard and the OpenVEX export. Three hundred style findings folded in would
    make a scan's headline number mean nothing."""
    from zanshin.services.sast_service import SastService

    scan = make_scan(repo_id=make_repository().id, status="scanning")

    ScanIngestor(sast_service=SastService()).ingest(
        db_session, scan, artifacts(sast=[SEMGREP_SECURITY_HIT, SEMGREP_QUALITY_HIT])
    )

    db_session.refresh(scan)
    assert scan.findings_count == scan.summary["total"] == 1  # the single CVE
