"""Ingestion of a scan's raw output into the control plane.

The other half of the old `ScanProcessor`: everything that happens *after* the
scanners have run — normalization into `Finding` rows, the licence policy,
end-of-life detection, EPSS/KEV enrichment, the optional AI review, folding
results into the cross-scan issue history, and the outbound notification.

None of it needs to run where the scan ran, and all of it needs the database, so
it lives on the control plane exclusively (ADR-002 §8.3). Two consequences worth
stating, because they are the reason for the split:

- a result produced by a remote agent is **indistinguishable** from a locally
  produced one, since both arrive here as `ScanArtifacts` and take this exact
  path;
- changing a rule (a licence blocklist, a severity default, how issues are
  reconciled) never requires redeploying an agent.
"""
import logging
from typing import Any, Dict, Optional

from zanshin.models.ai_review_result import AiReviewResult
from zanshin.models.finding import Finding
from zanshin.models.scan import Scan
from zanshin.repositories.outbox_repository import OutboxRepository
from zanshin.scan_contract import ScanArtifacts
from zanshin.services.ai_review_service import AiReviewService, SECURITY_ARCHITECT_PROMPT
from zanshin.services.dependency_graph import DependencyDirectness
from zanshin.services.enrichment_service import EnrichmentService
from zanshin.services.eol_service import EolService
from zanshin.services.issue_service import IssueService, scanned_types_for
from zanshin.services.license_compliance_service import LicenseComplianceService
from zanshin.services.notification_service import NotificationService
from zanshin.services.outbox_service import enqueue
from zanshin.services.remediation import extract_remediation
from zanshin.services.sast_service import SastService

logger = logging.getLogger(__name__)

def _descriptions_from_findings(findings) -> Dict[str, str]:
    """Per-identifier free text for the issue layer, taken from the findings themselves.

    `Issue.description` is filled from this map, keyed by identifier. That key cannot
    distinguish two hits of one Semgrep rule in different files, so the issue keeps one
    of their messages — acceptable, because those hits are one issue by fingerprint
    anyway, and every individual message survives on its own `Finding.description` row,
    which is what the per-scan detail panel reads.
    """
    if not findings:
        return {}
    return {
        finding.identifier: finding.description
        for finding in findings
        if finding.identifier and finding.description
    }


class ScanIngestor:
    """Turns `ScanArtifacts` into everything the application knows about a scan.

    Every optional collaborator follows the same resilience contract it did
    before the split: the scan's own results are committed first, and enrichment,
    the AI review and the issue sync are best-effort — none of them may turn an
    already-successful scan into a failure.
    """

    def __init__(
        self,
        enrichment_service: Optional[EnrichmentService] = None,
        license_compliance_service: Optional[LicenseComplianceService] = None,
        ai_review_service: Optional[AiReviewService] = None,
        issue_service: Optional[IssueService] = None,
        notification_service: Optional[NotificationService] = None,
        eol_service: Optional[EolService] = None,
        sast_service: Optional[SastService] = None,
    ):
        # Optional: EPSS/CISA-KEV scoring, run after a scan completes. Never
        # allowed to turn a successful scan into a failed one.
        self.enrichment_service = enrichment_service
        # Optional: license blocklist evaluation over the SBOM Syft already
        # produced — applies to both repo and container scans, unlike secrets
        # scanning (see ADR-001, section 5).
        self.license_compliance_service = license_compliance_service
        # Optional: local LLM code review via Ollama (see ADR-001, Phase 8).
        # Repository scans only, and only over the sample the runner collected —
        # this side never sees a checkout, which is exactly why the sample
        # travels in `ScanArtifacts`.
        self.ai_review_service = ai_review_service
        # Folds this scan's findings into the cross-scan issue history (new /
        # still open / resolved), which is what makes triage possible at all —
        # see IssueService.
        self.issue_service = issue_service
        # Optional: outbound webhook about what this scan *changed* — see
        # NotificationService for why the delta is the thing worth sending.
        self.notification_service = notification_service
        # Optional: end-of-life detection over the same SBOM. Applies to both
        # branches, like the licence policy.
        self.eol_service = eol_service
        # Optional: translation of the Semgrep step's output into `sast` and `quality`
        # findings, and the owner of the setting that decides whether that step runs at
        # all. Repository scans only — there is no source to read in an image.
        self.sast_service = sast_service

    def wants_sast(self, is_container: bool) -> bool:
        """Whether a runner should run the Semgrep step.

        Same split as `wants_code_sample`: the control plane holds the setting, the
        runner holds the checkout, and a remote agent has no database to ask.
        """
        return (
            not is_container
            and self.sast_service is not None
            and self.sast_service.is_enabled()
        )

    def wants_code_sample(self, is_container: bool) -> bool:
        """Whether a runner should bother collecting a source sample.

        Asked *before* the scan, so the decision that belongs to the control
        plane (is the feature enabled?) is made here while the work that belongs
        to the runner (walking the checkout) happens there.
        """
        return (
            not is_container
            and self.ai_review_service is not None
            and self.ai_review_service.is_enabled()
        )

    def ingest(self, db, scan: Scan, artifacts: ScanArtifacts) -> None:
        """Persist a successful scan. Raises only on a genuine ingestion error;
        the best-effort steps swallow their own failures."""
        is_container = scan.container_id is not None

        summary = self._summarize_findings(artifacts.cves)
        # Which packages the project declared, as opposed to what those packages
        # dragged in. Built once from the SBOM and applied to every finding that
        # names a package.
        directness = DependencyDirectness(artifacts.sbom)
        findings = self._build_findings(scan.id, artifacts.cves, directness)
        # `None` versus `[]` on the two lines below is the same distinction the
        # end-of-life step makes further down, and for the same reason: a scanner that
        # crashed observed nothing, and reading its silence as "clean" would resolve
        # every outstanding issue of that type. See `scanned_types_for`.
        sast_findings = None
        if not is_container:
            findings.extend(self._build_secret_findings(scan.id, artifacts.secrets))
            if artifacts.iac is not None:
                findings.extend(self._build_iac_findings(scan.id, artifacts.iac))
            if self.sast_service:
                sast_findings = self.sast_service.build_findings(scan.id, artifacts.sast)
                findings.extend(sast_findings or [])
        if self.license_compliance_service:
            # Applies to both branches: Syft produces license data for container
            # images just as much as for directories.
            license_findings = self.license_compliance_service.build_findings(scan.id, artifacts.sbom)
            for finding in license_findings:
                finding.is_direct_dependency = directness.of(
                    finding.purl, finding.package_name, finding.package_version
                )
            findings.extend(license_findings)

        eol_findings = None
        if self.eol_service:
            # `None` versus `[]` is the distinction that keeps resolution
            # honest: the catalogue being unreachable must not resolve every
            # past end-of-life issue (see `scanned_types_for`).
            eol_findings = self.eol_service.build_findings(scan.id, artifacts.sbom)
            for finding in eol_findings:
                finding.is_direct_dependency = directness.of(
                    finding.purl, finding.package_name, finding.package_version
                )
            findings.extend(eol_findings)

        scan.status = "completed"
        scan.sbom = artifacts.sbom
        scan.cves = artifacts.cves
        scan.summary = summary
        scan.findings_count = summary.get("total", 0)
        scan.duration_ms = artifacts.duration_ms
        db.add_all(findings)
        db.commit()

        logger.info(f"Scan completed for ID {scan.id}")

        if self.enrichment_service:
            try:
                self.enrichment_service.enrich_findings(db, findings)
            except Exception:
                # Best-effort only: enrichment failing must never turn an
                # already-completed scan into a failure.
                logger.exception(f"Enrichment failed for Scan ID {scan.id} (non-fatal)")

        # Optional AI code review (Ollama) — repo scans only, and only if
        # enabled. Best-effort like enrichment: a review failure is recorded
        # (status="failed") but never turns the scan itself into a failure.
        ai_findings = None
        if not is_container and self.ai_review_service and self.ai_review_service.is_enabled():
            ai_findings = self._run_ai_review(db, scan, artifacts.code_sample)

        # Fold everything into the cross-scan issue history — last, so issues
        # inherit the enrichment above and include the AI review's findings.
        # Best-effort, same contract as enrichment: the scan's own results are
        # already committed and valid.
        if self.issue_service:
            try:
                self.issue_service.sync_from_scan(
                    db,
                    scan,
                    findings + (ai_findings or []),
                    scanned_types_for(
                        is_container=is_container,
                        # A review that failed observed nothing, so its type must
                        # not be treated as scanned (which would resolve every
                        # past AI finding).
                        ai_review_ran=ai_findings is not None,
                        license_policy_ran=self.license_compliance_service is not None,
                        eol_ran=eol_findings is not None,
                        iac_ran=artifacts.iac is not None,
                        # One Semgrep run produces both types, so they enter together.
                        sast_ran=sast_findings is not None,
                    ),
                    descriptions={
                        **self._collect_vulnerability_descriptions(artifacts.cves),
                        **self._collect_eol_descriptions(eol_findings),
                        **_descriptions_from_findings(sast_findings),
                    },
                    # Enqueued inside the sync transaction: the notification
                    # becomes durable at the same instant as the issues it
                    # describes, so a crash before the webhook goes out no longer
                    # loses it silently.
                    before_commit=lambda result: self._enqueue_notification(db, scan, result),
                )
            except Exception:
                logger.exception(f"Issue sync failed for Scan ID {scan.id} (non-fatal)")

    def record_failure(self, db, scan: Scan, error: str) -> None:
        """Mark a scan as failed, wherever it failed.

        The message is whatever the runner raised — including, for a remote
        agent, a clone failure caused by that machine not having access to the
        repository. That is a readable scan result rather than a crash, which is
        the trade-off `credentials_mode=local` accepts (ADR-002 §5).
        """
        scan.status = "failed"
        scan.error = error or "Erreur inconnue"
        db.commit()

    # --- Normalization ---------------------------------------------------

    def _build_findings(
        self,
        scan_id: int,
        cves: Dict[str, Any],
        directness: Optional[DependencyDirectness] = None,
    ) -> list:
        """Turn a scanner engine's vulnerability-matching output into
        normalized `Finding` rows.

        `cves` is Grype-shaped (`{"matches": [...]}` ) regardless of which
        backend produced it — `DockerScannerEngine` returns Grype's own
        output, and `OsvScannerEngine` translates OSV.dev's response into
        the same shape (see its docstring) precisely so this code doesn't
        need to know which backend ran. The optional top-level
        "engine_source" key records which one actually did, for provenance
        on each Finding (not called "source": Grype's own JSON output
        already uses that key for something else entirely).

        Kept alongside the raw `cves`/`sbom` blobs (not instead of), so the
        UI/VEX workflow and future enrichment (EPSS/KEV) can query
        structured data instead of re-parsing tool-specific JSON — see
        ADR-001, section 4.
        """
        source = cves.get("engine_source", "grype")
        findings = []
        for match in cves.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            locations = artifact.get("locations", []) or []
            remediation = extract_remediation(match)
            findings.append(Finding(
                scan_id=scan_id,
                type="vulnerability",
                severity=vuln.get("severity", "unknown").lower(),
                identifier=vuln.get("id"),
                package_name=artifact.get("name"),
                package_version=artifact.get("version"),
                purl=artifact.get("purl"),
                file_path=locations[0].get("path") if locations else None,
                source=source,
                cvss_score=remediation.cvss_score,
                cvss_vector=remediation.cvss_vector,
                fix_state=remediation.fix_state,
                fix_versions=remediation.fix_versions,
                link=remediation.link,
                is_direct_dependency=directness.of(
                    artifact.get("purl"), artifact.get("name"), artifact.get("version")
                ) if directness else None,
            ))
        return findings

    def _build_secret_findings(self, scan_id: int, leaks: list) -> list:
        """Turn gitleaks' raw JSON report into normalized `Finding` rows.

        gitleaks doesn't grade severity — every hardcoded secret is treated
        as "high" by default, since a leaked credential is rarely a low-risk
        finding regardless of the rule that caught it.
        """
        findings = []
        for leak in leaks:
            findings.append(Finding(
                scan_id=scan_id,
                type="secret",
                severity="high",
                identifier=leak.get("RuleID"),
                file_path=leak.get("File"),
                line=leak.get("StartLine"),
                source="gitleaks",
            ))
        return findings

    def _build_iac_findings(self, scan_id: int, failed_checks: list) -> list:
        """Turn checkov's raw `failed_checks` entries into normalized
        `Finding` rows.

        checkov's own severity field is often absent depending on the
        policy/framework, so it defaults to "medium" rather than "unknown"
        — a misconfigured IaC resource (e.g. a public S3 bucket) is rarely
        genuinely low-priority even when unclassified.
        """
        findings = []
        for check in failed_checks:
            findings.append(Finding(
                scan_id=scan_id,
                type="iac",
                severity=(check.get("severity") or "medium").lower(),
                identifier=check.get("check_id"),
                package_name=check.get("resource"),
                file_path=check.get("file_path"),
                # checkov reports a [start, end] range; the start is where a
                # reviewer needs to look.
                line=(check.get("file_line_range") or [None])[0],
                source="checkov",
            ))
        return findings

    def _summarize_findings(self, cves: Dict[str, Any]) -> Dict[str, Any]:
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "negligible": 0,
            "unknown": 0,
            "total": 0
        }
        matches = cves.get("matches", [])
        total = 0
        for match in matches:
            vuln = match.get("vulnerability", {})
            severity = vuln.get("severity", "unknown").lower()
            summary[severity] = summary.get(severity, 0) + 1
            total += 1
        summary["total"] = total
        return summary

    # --- Notification ----------------------------------------------------

    def _enqueue_notification(self, db, scan: Scan, sync) -> None:
        """Write the scan's notification into the outbox, in the open transaction.

        Nothing is sent here. The relay on the scheduler tick delivers it, retries it
        on failure and abandons it after a while — which is what a webhook that was
        briefly unreachable needed and never had.
        """
        if not self.notification_service or not self.notification_service.is_enabled():
            return
        if not sync.new_issues and not sync.reopened_issues:
            return

        payload = self.notification_service.build_scan_delta_message(
            target_name=self._target_name(scan),
            scan_id=scan.id,
            new_issues=list(sync.new_issues),
            reopened_issues=list(sync.reopened_issues),
            resolved_count=sync.resolved,
        )
        if payload is None:
            return
        enqueue(OutboxRepository(db), payload)

    def _target_name(self, scan: Scan) -> str:
        """What the notification calls the thing that was scanned."""
        if scan.container_id and scan.container:
            return scan.container.image_string
        if scan.repository:
            return scan.repository.name or scan.repository.url
        return f"scan #{scan.id}"

    def _collect_vulnerability_descriptions(self, cves: Dict[str, Any]) -> Dict[str, str]:
        """CVE id → human description, harvested from the raw match.

        Lets an `Issue` carry the explanation without the issues screen having
        to re-parse (or even load) the scan's raw `cves` blob — the read pattern
        wave 1 removed everywhere else.
        """
        descriptions = {}
        for match in cves.get("matches", []):
            identifier = (match.get("vulnerability") or {}).get("id")
            if not identifier or identifier in descriptions:
                continue
            description = extract_remediation(match).description
            if description:
                descriptions[identifier] = description
        return descriptions

    def _collect_eol_descriptions(self, eol_findings) -> Dict[str, str]:
        """Free text for end-of-life issues, keyed by identifier.

        Routed through the same `descriptions` map as CVE descriptions because
        `Finding` has no free-text column and `Issue` does — so the explanation
        reaches the issue without a schema change.
        """
        if not eol_findings or not self.eol_service:
            return {}
        return {
            finding.identifier: self.eol_service.describe(finding)
            for finding in eol_findings
            if finding.identifier
        }

    # --- Semgrep ---------------------------------------------------------
    # `_build_sast_findings` deliberately does not exist here: the translation lives in
    # `SastService`, because deciding whether a rule is a security or a quality finding
    # is judgement rather than mapping, and it needs somewhere it can be explained.

    # --- AI review -------------------------------------------------------

    def _run_ai_review(self, db, scan: Scan, code_sample: str) -> Optional[list]:
        """Runs the optional AI code review over the sample the runner
        collected, persists an `AiReviewResult` row, and — when the model's
        response parses as the requested JSON array (see
        `AiReviewService.parse_findings`) — normalized
        `Finding(type="ai_review")` rows alongside it, one per parsed item.

        Returns the `Finding` rows it created (possibly empty) so the caller can
        fold them into the issue history, or `None` if the review failed — the
        difference matters: "reviewed, found nothing" resolves past AI issues,
        "review broke" must leave them untouched. An empty sample is the same
        "didn't run" case, which is what it was before the split too (there was
        nothing reviewable on disk).

        Never raises: a failure here (unreachable Ollama, model error, ...)
        is recorded on the result row itself (`status="failed"`,
        `error=...`) rather than propagated, so it can never turn an
        already-completed scan into a failure — same resilience contract
        as `EnrichmentService`. A response that doesn't parse into JSON
        still produces a completed `AiReviewResult` with the raw text (no
        `Finding` rows in that case) — the model not returning the exact
        requested shape is not treated as a review failure.
        """
        if not code_sample:
            logger.info(f"AI review skipped for Scan ID {scan.id}: no reviewable source files found")
            return None

        model = self.ai_review_service.get_selected_model()
        try:
            response = self.ai_review_service.review_code(code_sample)
            parsed = self.ai_review_service.parse_findings(response)

            db.add(AiReviewResult(
                scan_id=scan.id,
                model=model,
                prompt=SECURITY_ARCHITECT_PROMPT,
                response=self._format_ai_review_narrative(parsed, response),
                status="completed",
            ))
            ai_findings = self._build_ai_review_findings(scan.id, model, parsed)
            db.add_all(ai_findings)
            db.commit()
            return ai_findings
        except Exception as e:
            # Best-effort only, same contract as enrichment: never turn an
            # already-completed scan into a failure.
            logger.exception(f"AI code review failed for Scan ID {scan.id} (non-fatal)")
            db.add(AiReviewResult(
                scan_id=scan.id,
                model=model,
                prompt=SECURITY_ARCHITECT_PROMPT,
                response=None,
                status="failed",
                error=str(e)[:500],
            ))
            db.commit()
            return None

    def _build_ai_review_findings(self, scan_id: int, model: str, parsed: list) -> list:
        """Turns `AiReviewService.parse_findings()`'s output into normalized
        `Finding` rows — an index/summary entry per issue (severity, short
        title, file path), consistent with how secrets/IaC findings are
        kept lightweight. The fuller description/recommendation text stays
        in `AiReviewResult.response` (see `_format_ai_review_narrative`)
        rather than on `Finding`, which has no free-text description column.
        """
        return [
            Finding(
                scan_id=scan_id,
                type="ai_review",
                severity=item["severity"],
                identifier=item["title"],
                file_path=item.get("file_path"),
                source=f"ollama:{model}",
            )
            for item in parsed
        ]

    def _format_ai_review_narrative(self, parsed: list, raw_response: str) -> str:
        """Builds the human-readable text stored on `AiReviewResult.response`
        and shown in the scan-detail UI. Reformats the parsed findings when
        parsing succeeded (consistent severity/title/file layout); falls
        back to the model's raw text untouched when it didn't (still worth
        showing even though it couldn't be turned into `Finding` rows).
        """
        if not parsed:
            return raw_response
        lines = []
        for item in parsed:
            lines.append(f"[{item['severity'].upper()}] {item['title']}")
            if item.get("file_path"):
                lines.append(f"  Fichier : {item['file_path']}")
            if item.get("description"):
                lines.append(f"  {item['description']}")
            if item.get("recommendation"):
                lines.append(f"  Recommandation : {item['recommendation']}")
            lines.append("")
        return "\n".join(lines).strip()
