import logging
import os
import shutil
import tempfile
import time
import uuid
from typing import Dict, Any, Optional
import git

from zanshin.database import SessionLocal
from zanshin.models.scan import Scan
from zanshin.models.container import Container
from zanshin.models.finding import Finding
from zanshin.models.ai_review_result import AiReviewResult
from zanshin.services.ssh_key_service import SSHKeyService
from zanshin.services.scanners.base import ScannerEngine
from zanshin.services.enrichment_service import EnrichmentService
from zanshin.services.license_compliance_service import LicenseComplianceService
from zanshin.services.ai_review_service import AiReviewService, SECURITY_ARCHITECT_PROMPT
from zanshin.services.git_url import validate_repo_url
from zanshin.services.issue_service import IssueService, scanned_types_for
from zanshin.services.notification_service import NotificationService
from zanshin.services.remediation import extract_remediation

logger = logging.getLogger(__name__)

# Extensions considered "source code" for the optional AI review sample
# (§4bis, docs/TECHNICAL_DOCUMENTATION.md) — deliberately broad rather than
# exhaustive; this is a lightweight complement to the dedicated scanners,
# not a language-aware pipeline.
AI_REVIEW_TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".rs", ".kt", ".swift",
    ".yml", ".yaml", ".json", ".tf", ".sql", ".sh",
}
AI_REVIEW_EXCLUDED_DIRS = {".git", "node_modules", ".venv", "__pycache__", "dist", "build"}
# Sub-directory of the per-scan workspace that holds *only* the scan target
# (the git checkout). Every artifact Zanshin's own pipeline writes —
# `sbom.json` for Grype, gitleaks' JSON report — lands in the workspace root,
# i.e. deliberately *outside* this directory.
#
# The separation is structural rather than a filename blocklist because two
# of those artifacts are actively harmful to feed back into the pipeline:
# gitleaks' report contains every detected secret in cleartext (it would have
# been sent to the AI review model), and a Syft SBOM routinely exceeds
# AI_REVIEW_MAX_CHARS on its own (it would have consumed the entire review
# budget before the first source file, so the model reviewed the SBOM instead
# of the code). Keeping the target in its own directory means anything
# walking the source tree can never reach them, whatever gets added later.
SOURCE_SUBDIR = "source"
# Size cap for the source sample sent to the model: no chunking/RAG, just a
# straightforward "read files in order until the budget is used up" — good
# enough for the "minimal review" this feature is scoped to, but it means
# large repositories are silently truncated rather than reviewed in full.
AI_REVIEW_MAX_CHARS = 40000

class ScanProcessor:
    def __init__(
        self,
        ssh_key_service: SSHKeyService,
        scanner_engine: ScannerEngine,
        enrichment_service: Optional[EnrichmentService] = None,
        license_compliance_service: Optional[LicenseComplianceService] = None,
        ai_review_service: Optional[AiReviewService] = None,
        issue_service: Optional[IssueService] = None,
        notification_service: Optional[NotificationService] = None,
    ):
        self.ssh_key_service = ssh_key_service
        # `scanner_engine` decides *where* SBOM generation/vulnerability
        # scanning actually runs (local Docker today; local API / cloud API
        # backends are pluggable extensions — see ADR-001). ScanProcessor
        # only orchestrates the steps and never talks to Docker directly.
        self.scanner_engine = scanner_engine
        # Optional: EPSS/CISA-KEV scoring, run after a scan completes. Never
        # allowed to turn a successful scan into a failed one.
        self.enrichment_service = enrichment_service
        # Optional: license blocklist evaluation over the SBOM Syft already
        # produced — applies to both repo and container scans, unlike
        # secrets scanning (see ADR-001, section 5).
        self.license_compliance_service = license_compliance_service
        # Optional: local LLM code review via Ollama (see ADR-001, Phase 8).
        # Only runs for repository scans (needs source code on disk), same
        # reasoning as secrets/IaC. Never allowed to turn a successful scan
        # into a failed one, same as enrichment.
        self.ai_review_service = ai_review_service
        # Folds this scan's findings into the cross-scan issue history (new /
        # still open / resolved), which is what makes triage possible at all —
        # see IssueService. Optional so the pipeline stays constructible
        # without it; wired by default in IoCContainer.
        self.issue_service = issue_service
        # Optional: outbound webhook about what this scan *changed*. Replaces a
        # gateway that only logged "scan finished" — see NotificationService for
        # why the delta is the thing worth sending.
        self.notification_service = notification_service
        
    def process_scan(self, scan_id: int, repo_url: Optional[str], branch: str, sub_path: str, ssh_key_id: Optional[uuid.UUID]):
        logger.info(f"Processing scan job for Scan ID {scan_id} (Branch: {branch}, Path: {sub_path})")
        
        # Use a dedicated DB session for background processing
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                logger.error(f"Scan not found: {scan_id}")
                return
                
            scan.status = "scanning"
            db.commit()
            
            is_container = scan.container_id is not None
            start_time = time.time()
            # `get_workspace_root()` returns None for every backend except
            # LocalApiScannerEngine, which needs the workspace created
            # inside the volume it shares with its sidecar service instead
            # of the OS default temp location (see ADR-001 Phase 4).
            workspace_root = self.scanner_engine.get_workspace_root()
            if workspace_root:
                os.makedirs(workspace_root, exist_ok=True)
            temp_dir = tempfile.mkdtemp(prefix=f"zanshin_scan_{scan_id}_", dir=workspace_root)
            
            try:
                if is_container:
                    container_entity = scan.container
                    image_string = container_entity.image_string

                    # 1. Generate Container SBOM
                    logger.info(f"Generating SBOM for Docker image {image_string}")
                    sbom = self.scanner_engine.generate_sbom_for_image(image_string)

                    # 2. Scan SBOM with Grype
                    logger.info("Scanning SBOM for CVEs")
                    cves = self.scanner_engine.scan_sbom(temp_dir, sbom)
                else:
                    # 0. Validate Path
                    self._validate_path(sub_path)

                    # The checkout goes in its own sub-directory so that the
                    # artifacts the steps below write into the workspace root
                    # (sbom.json, gitleaks' report) stay out of the scanned
                    # tree — see SOURCE_SUBDIR. Everything handed to the
                    # engine is therefore addressed relative to the workspace
                    # root, prefixed with that sub-directory.
                    source_dir = os.path.join(temp_dir, SOURCE_SUBDIR)
                    scan_target = os.path.join(SOURCE_SUBDIR, sub_path) if sub_path else SOURCE_SUBDIR

                    # 1. Clone Git Repo
                    logger.info(f"Cloning {repo_url} branch {branch} into {source_dir}")
                    self._clone_repo(repo_url, branch, source_dir, ssh_key_id)

                    # 2. Generate Directory SBOM
                    logger.info(f"Generating SBOM for directory (Target: {sub_path})")
                    sbom = self.scanner_engine.generate_sbom_for_directory(temp_dir, scan_target)

                    # 3. Scan SBOM with Grype
                    logger.info("Scanning SBOM for CVEs")
                    cves = self.scanner_engine.scan_sbom(temp_dir, sbom)

                    # 4. Scan for hardcoded secrets (source code only — not
                    # run for container images, see ADR-001 section 5).
                    logger.info("Scanning for hardcoded secrets")
                    leaks = self.scanner_engine.scan_secrets(temp_dir, scan_target)

                    # 5. Scan Infrastructure-as-Code manifests (Terraform,
                    # Kubernetes, ...) — same "source code only" reasoning
                    # as secrets (ADR-001 section 5, Phase 6).
                    logger.info("Scanning Infrastructure-as-Code manifests")
                    iac_checks = self.scanner_engine.scan_iac(temp_dir, scan_target)

                duration_ms = int((time.time() - start_time) * 1000)
                summary = self._summarize_findings(cves)
                findings = self._build_findings(scan.id, cves)
                if not is_container:
                    findings.extend(self._build_secret_findings(scan.id, leaks))
                    findings.extend(self._build_iac_findings(scan.id, iac_checks))
                if self.license_compliance_service:
                    # Applies to both branches: Syft produces license data
                    # for container images just as much as for directories.
                    findings.extend(self.license_compliance_service.build_findings(scan.id, sbom))

                # Update Scan results
                scan.status = "completed"
                scan.sbom = sbom
                scan.cves = cves
                scan.summary = summary
                scan.findings_count = summary.get("total", 0)
                scan.duration_ms = duration_ms
                db.add_all(findings)
                db.commit()

                logger.info(f"Scan completed for ID {scan_id}")

                if self.enrichment_service:
                    try:
                        self.enrichment_service.enrich_findings(db, findings)
                    except Exception:
                        # Best-effort only: enrichment failing must never
                        # turn an already-completed scan into a failure.
                        logger.exception(f"Enrichment failed for Scan ID {scan_id} (non-fatal)")

                # Optional AI code review (Ollama) — repo scans only, and
                # only if enabled. Must run before `temp_dir` is removed in
                # the `finally` below, since it reads source files from it.
                # Best-effort like enrichment: a review failure is recorded
                # (status="failed") but never turns the scan itself into a
                # failure.
                ai_findings = None
                if not is_container and self.ai_review_service and self.ai_review_service.is_enabled():
                    # `source_dir`, not `temp_dir`: the review must only ever
                    # see the checkout, never the pipeline's own artifacts
                    # (see SOURCE_SUBDIR).
                    ai_findings = self._run_ai_review(db, scan, source_dir, sub_path)

                # Fold everything into the cross-scan issue history — last,
                # so issues inherit the enrichment above and include the AI
                # review's findings. Best-effort, same contract as enrichment:
                # the scan's own results are already committed and valid.
                if self.issue_service:
                    try:
                        sync = self.issue_service.sync_from_scan(
                            db,
                            scan,
                            findings + (ai_findings or []),
                            scanned_types_for(
                                is_container=is_container,
                                # A review that failed observed nothing, so its
                                # type must not be treated as scanned (which
                                # would resolve every past AI finding).
                                ai_review_ran=ai_findings is not None,
                                license_policy_ran=self.license_compliance_service is not None,
                            ),
                            descriptions=self._collect_vulnerability_descriptions(cves),
                        )
                        self._notify(scan, sync)
                    except Exception:
                        logger.exception(f"Issue sync failed for Scan ID {scan_id} (non-fatal)")

            except Exception as e:
                logger.exception(f"Scan failed for ID {scan_id}")
                scan.status = "failed"
                scan.error = str(e)
                db.commit()
            finally:
                # Clean up temp directory
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    
        finally:
            db.close()

    def _validate_path(self, path: str):
        if path and (".." in path or path.startswith("/") or "\\" in path):
            raise ValueError("Chemin invalide : la traversée de répertoire n'est pas autorisée.")

    def _clone_repo(self, repo_url: str, branch: str, work_dir: str, ssh_key_id: Optional[uuid.UUID]):
        # Re-validated here and not only at save time: this is the single
        # choke point every scan goes through, including for repository rows
        # that predate the validation (see zanshin/services/git_url.py for
        # why an unchecked URL is an RCE, not just a bad input).
        repo_url = validate_repo_url(repo_url)
        env = {}
        key_file_path = None
        try:
            if ssh_key_id:
                private_key = self.ssh_key_service.get_decrypted_key(ssh_key_id)
                # Create a temporary key file with strict permissions
                fd, key_file_path = tempfile.mkstemp()
                os.close(fd)
                with open(key_file_path, "w") as f:
                    f.write(private_key)
                os.chmod(key_file_path, 0o600)
                env["GIT_SSH_COMMAND"] = f"ssh -i {key_file_path} -o StrictHostKeyChecking=no -o BatchMode=yes"
            else:
                env["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=no -o BatchMode=yes"
                
            git.Repo.clone_from(
                url=repo_url,
                to_path=work_dir,
                branch=branch,
                depth=1,
                env=env
            )
        finally:
            if key_file_path and os.path.exists(key_file_path):
                os.remove(key_file_path)

    def _build_findings(self, scan_id: int, cves: Dict[str, Any]) -> list:
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

    def _notify(self, scan: Scan, sync) -> None:
        """Announce what this scan changed, if a webhook is configured.

        Best-effort by construction (`NotificationService` swallows its own
        failures), and called from inside the issue-sync `try` so that even an
        unexpected error here cannot affect a scan whose results are already
        committed.
        """
        if not self.notification_service or not self.notification_service.is_enabled():
            return
        if not sync.new_issues and not sync.reopened_issues:
            return
        self.notification_service.notify_scan_delta(
            target_name=self._target_name(scan),
            scan_id=scan.id,
            new_issues=list(sync.new_issues),
            reopened_issues=list(sync.reopened_issues),
            resolved_count=sync.resolved,
        )

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

    def _run_ai_review(self, db, scan: Scan, source_dir: str, sub_path: str) -> Optional[list]:
        """Runs the optional AI code review, persists an `AiReviewResult`
        row, and — when the model's response parses as the requested JSON
        array (see `AiReviewService.parse_findings`) — normalized
        `Finding(type="ai_review")` rows alongside it, one per parsed item.

        Returns the `Finding` rows it created (possibly empty) so the caller can
        fold them into the issue history, or `None` if the review failed — the
        difference matters: "reviewed, found nothing" resolves past AI issues,
        "review broke" must leave them untouched.

        Never raises: a failure here (unreachable Ollama, model error, ...)
        is recorded on the result row itself (`status="failed"`,
        `error=...`) rather than propagated, so it can never turn an
        already-completed scan into a failure — same resilience contract
        as `EnrichmentService`. A response that doesn't parse into JSON
        still produces a completed `AiReviewResult` with the raw text (no
        `Finding` rows in that case) — the model not returning the exact
        requested shape is not treated as a review failure.
        """
        model = self.ai_review_service.get_selected_model()
        try:
            code_sample = self._collect_ai_review_sample(source_dir, sub_path)
            if not code_sample:
                logger.info(f"AI review skipped for Scan ID {scan.id}: no reviewable source files found")
                # Nothing was reviewed, so this is the "didn't run" case.
                return None
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

    def _collect_ai_review_sample(self, source_dir: str, sub_path: str) -> str:
        """Best-effort, size-capped concatenation of source files for the
        optional AI review (see `AI_REVIEW_MAX_CHARS`) — deliberately simple
        (no chunking, no embeddings/RAG): walks the tree in sorted order and
        stops once the character budget is used up, so large repositories
        are silently truncated rather than exhaustively reviewed. Adequate
        for the "minimal review" this feature is scoped to (see ADR-001,
        Phase 8), not a substitute for a real SAST pipeline.

        `source_dir` is the checkout itself (`SOURCE_SUBDIR`), never the
        workspace root — that's what keeps the pipeline's own artifacts out
        of the sample, and it also makes the `# <path>` headers below
        repository-relative, which is the only form the model can usefully
        echo back in `file_path`.
        """
        root = os.path.join(source_dir, sub_path) if sub_path else source_dir
        chunks = []
        total = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in AI_REVIEW_EXCLUDED_DIRS)
            for filename in sorted(filenames):
                if not any(filename.endswith(ext) for ext in AI_REVIEW_TEXT_EXTENSIONS):
                    continue
                file_path = os.path.join(dirpath, filename)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except OSError:
                    continue
                rel_path = os.path.relpath(file_path, source_dir)
                chunk = f"# {rel_path}\n{content}\n"
                if total + len(chunk) > AI_REVIEW_MAX_CHARS:
                    remaining = AI_REVIEW_MAX_CHARS - total
                    if remaining > 0:
                        chunks.append(chunk[:remaining])
                    return "\n".join(chunks)
                chunks.append(chunk)
                total += len(chunk)
        return "\n".join(chunks)
