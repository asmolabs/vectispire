"""Local execution of a scan, end to end.

Historically this module *was* the pipeline. It now composes the two halves it
was split into (ADR-002 §8.3):

- [`ScanRunner`](scan_runner.py) — clone and run the scanners, no database;
- [`ScanIngestor`](scan_ingestor.py) — normalize, enrich, reconcile issues,
  notify; database only.

What is left here is the part that is *specific to running a scan in this
process*: opening a session, reading the `Scan` row, turning it into a
`ScanTask` (which includes decrypting the deploy key, something no agent can
do), and handing the artifacts to the ingestor. A remote agent replaces exactly
this middle piece and nothing else — which is why the two paths cannot drift.

The public entry point keeps its signature, because the queue
(`scan_queue._run`), the scheduler and the whole existing test suite call it:
`process_scan(scan_id, repo_url, branch, sub_path, ssh_key_id)`.
"""
import logging
import uuid
from typing import Any, Dict, Optional

import git  # noqa: F401 — re-exported for the test suite, which monkeypatches
# `scan_processor.git.Repo.clone_from`; the clone itself lives in `scan_runner`
# (same module object, so patching either name works).

from zanshin.database import SessionLocal
from zanshin.models.scan import Scan
from zanshin.scan_contract import TARGET_CONTAINER, TARGET_REPOSITORY, ScanTask
from zanshin.services.ai_review_service import AiReviewService
from zanshin.services.enrichment_service import EnrichmentService
from zanshin.services.eol_service import EolService
from zanshin.services.issue_service import IssueService
from zanshin.services.license_compliance_service import LicenseComplianceService
from zanshin.services.notification_service import NotificationService
from zanshin.services.scan_ingestor import ScanIngestor
from zanshin.services.scan_queue import renew_lease, still_owned
from zanshin.services.scan_runner import (
    AI_REVIEW_EXCLUDED_DIRS,
    AI_REVIEW_MAX_CHARS,
    AI_REVIEW_TEXT_EXTENSIONS,
    SOURCE_SUBDIR,
    ScanRunner,
    clone_repo,
    collect_ai_review_sample,
    validate_sub_path,
)
from zanshin.services.scanners.base import ScannerEngine
from zanshin.services.ssh_key_service import SSHKeyService

logger = logging.getLogger(__name__)

# Re-exported: these constants used to be defined here and are imported from
# this module by tests and by the technical documentation's references.
__all__ = [
    "AI_REVIEW_EXCLUDED_DIRS",
    "AI_REVIEW_MAX_CHARS",
    "AI_REVIEW_TEXT_EXTENSIONS",
    "SOURCE_SUBDIR",
    "ScanProcessor",
]

class ScanProcessor:
    """Runs a scan in this process and ingests its result.

    Constructor unchanged: it still takes the same collaborators, and passes the
    ingestion ones straight to `ScanIngestor`. Keeping the signature means the
    container, the queue and the tests did not have to learn about the split.
    """

    def __init__(
        self,
        ssh_key_service: SSHKeyService,
        scanner_engine: ScannerEngine,
        enrichment_service: Optional[EnrichmentService] = None,
        license_compliance_service: Optional[LicenseComplianceService] = None,
        ai_review_service: Optional[AiReviewService] = None,
        issue_service: Optional[IssueService] = None,
        notification_service: Optional[NotificationService] = None,
        eol_service: Optional[EolService] = None,
        sast_service=None,
    ):
        # Only needed to build a `ScanTask`: the deploy key has to be decrypted
        # before it reaches a runner, because a runner — local or remote — has no
        # key store (ADR-002 D3).
        self.ssh_key_service = ssh_key_service
        self.runner = ScanRunner(scanner_engine)
        self.ingestor = ScanIngestor(
            enrichment_service=enrichment_service,
            license_compliance_service=license_compliance_service,
            ai_review_service=ai_review_service,
            issue_service=issue_service,
            notification_service=notification_service,
            eol_service=eol_service,
            sast_service=sast_service,
        )

    # The collaborators stay readable as attributes: `IoCContainer`, the
    # settings screen and several tests inspect them.
    @property
    def scanner_engine(self):
        """Read *and* written through to the runner, which owns it.

        Not a plain attribute copy: the engine is chosen per scan in some
        deployments (and swapped between scans in the tests), so two copies of it
        would silently disagree — the processor would report one engine while the
        runner used another.
        """
        return self.runner.scanner_engine

    @scanner_engine.setter
    def scanner_engine(self, engine: ScannerEngine):
        self.runner.scanner_engine = engine

    @property
    def enrichment_service(self):
        return self.ingestor.enrichment_service

    @property
    def license_compliance_service(self):
        return self.ingestor.license_compliance_service

    @property
    def ai_review_service(self):
        return self.ingestor.ai_review_service

    @property
    def issue_service(self):
        return self.ingestor.issue_service

    @property
    def notification_service(self):
        return self.ingestor.notification_service

    @property
    def eol_service(self):
        return self.ingestor.eol_service

    def process_scan(
        self,
        scan_id: int,
        repo_url: Optional[str],
        branch: str,
        sub_path: str,
        ssh_key_id: Optional[uuid.UUID],
        worker: Optional[str] = None,
    ):
        """Run a scan here and ingest it.

        `worker` is the `Agent.worker_id` this run belongs to — the built-in agent,
        in practice, since a remote one never calls this. It is optional so the
        signature stays compatible with every existing caller and test, and when
        it is present two things happen that make lease-based recovery safe:
        progress renews the lease, and the result is discarded if the lease was
        lost in the meantime.
        """
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

            try:
                task = self.build_task(scan, repo_url, branch, sub_path, ssh_key_id)
                artifacts = self.runner.run(task, on_step=self._lease_renewer(db, scan_id, worker))

                if not still_owned(db, scan_id, worker):
                    # The lease lapsed while this scan ran (a long stall, a paused
                    # process) and the queue handed the work to someone else.
                    # Writing results now would overwrite theirs — see
                    # `scan_queue.still_owned`.
                    logger.warning(
                        "Discarding results for Scan ID %s: lease no longer held by %s",
                        scan_id, worker,
                    )
                    return
                self.ingestor.ingest(db, scan, artifacts)
            except Exception as e:
                logger.exception(f"Scan failed for ID {scan_id}")
                self.ingestor.record_failure(db, scan, str(e))
        finally:
            db.close()

    def _lease_renewer(self, db, scan_id: int, worker: Optional[str]):
        """A step callback that pushes the lease out as the scan progresses.

        Between steps rather than on a timer: the built-in agent runs in a thread
        of this process, and a second thread purely to renew a lease would be more
        moving parts than the guarantee is worth. A remote agent does use a timer
        (its steps are the same length, but its silence has to be detected faster
        than `LEASE_SECONDS` for the queue to react at all).
        """
        if not worker:
            return None

        def renew(_message: str) -> None:
            renew_lease(db, scan_id, worker)

        return renew

    def build_task(
        self,
        scan: Scan,
        repo_url: Optional[str],
        branch: str,
        sub_path: str,
        ssh_key_id: Optional[uuid.UUID],
    ) -> ScanTask:
        """Turn a `Scan` row into a self-contained `ScanTask`.

        The one place where a scan stops being a database row. Also used, in
        spirit, by the agent API when it builds the task it hands to a remote
        agent — the difference being whether the deploy key is included, which is
        a property of the agent, not of the task (ADR-002 §5).
        """
        if scan.container_id is not None:
            return ScanTask(
                scan_id=scan.id,
                kind=TARGET_CONTAINER,
                image=scan.container.image_string,
                branch=branch or scan.branch or "latest",
            )

        private_key = None
        if ssh_key_id and self.ssh_key_service:
            private_key = self.ssh_key_service.get_decrypted_key(ssh_key_id)
        return ScanTask(
            scan_id=scan.id,
            kind=TARGET_REPOSITORY,
            repo_url=repo_url,
            branch=branch,
            sub_path=sub_path or "",
            ssh_private_key=private_key,
            collect_code_sample=self.ingestor.wants_code_sample(is_container=False),
            run_sast=self.ingestor.wants_sast(is_container=False),
        )

    # --- Delegates -------------------------------------------------------
    # The pipeline's mechanics moved to `scan_runner` / `scan_ingestor`; these
    # keep this class the single documented entry point for scan behaviour, and
    # keep the existing tests calling the same names.

    def _validate_path(self, path: str):
        validate_sub_path(path)

    def _clone_repo(self, repo_url: str, branch: str, work_dir: str, ssh_key_id: Optional[uuid.UUID]):
        private_key = self.ssh_key_service.get_decrypted_key(ssh_key_id) if ssh_key_id else None
        clone_repo(repo_url, branch, work_dir, private_key)

    def _collect_ai_review_sample(self, source_dir: str, sub_path: str) -> str:
        return collect_ai_review_sample(source_dir, sub_path)

    def _build_findings(self, scan_id: int, cves: Dict[str, Any], directness=None) -> list:
        return self.ingestor._build_findings(scan_id, cves, directness)

    def _build_secret_findings(self, scan_id: int, leaks: list) -> list:
        return self.ingestor._build_secret_findings(scan_id, leaks)

    def _build_iac_findings(self, scan_id: int, failed_checks: list) -> list:
        return self.ingestor._build_iac_findings(scan_id, failed_checks)

    def _summarize_findings(self, cves: Dict[str, Any]) -> Dict[str, Any]:
        return self.ingestor._summarize_findings(cves)

    def _run_ai_review(self, db, scan: Scan, code_sample: str) -> Optional[list]:
        return self.ingestor._run_ai_review(db, scan, code_sample)

    def _build_ai_review_findings(self, scan_id: int, model: str, parsed: list) -> list:
        return self.ingestor._build_ai_review_findings(scan_id, model, parsed)

    def _format_ai_review_narrative(self, parsed: list, raw_response: str) -> str:
        return self.ingestor._format_ai_review_narrative(parsed, raw_response)

    def _target_name(self, scan: Scan) -> str:
        return self.ingestor._target_name(scan)
