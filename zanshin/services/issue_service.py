"""Cross-scan lifecycle and triage of findings.

This is what turns Zanshin from a scanner into a posture tool. Before it, every
scan produced a fresh set of `Finding` rows and nothing connected them: there
was no way to say "this is new since last week", no way to record that a finding
had been reviewed (the UI offered no such action, and `Finding.status` was
written once as "open" and never again), and no history to measure anything by.

Two axes, deliberately separate:

- **State** (`Issue.state`) is what the scanners observe: open while a scan
  still reports it, resolved once a *successful* scan of the same target no
  longer does. Only the pipeline writes it.
- **Triage** (`Issue.triage_status`) is what a human decided, in VEX
  vocabulary. Only `triage()` writes it.

Conflating them is the classic mistake: a suppressed finding that has actually
been fixed, and a fixed finding that someone once suppressed, must not look the
same — otherwise "resolved" stops meaning anything.
"""
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Set

from sqlalchemy.orm import Session

from zanshin.clock import utcnow
from zanshin.models.finding import Finding
from zanshin.models.issue import (
    STATE_OPEN,
    STATE_RESOLVED,
    TRIAGE_FIXED,
    TRIAGE_UNDER_REVIEW,
    VALID_TRIAGE_STATUSES,
    VEX_JUSTIFICATIONS,
    Issue,
    build_fingerprint,
)
from zanshin.models.scan import Scan
from zanshin.repositories.issue_repository import IssueRepository

logger = logging.getLogger(__name__)

# Fields refreshed on every sighting: the latest scan's assessment of a problem
# supersedes the previous one (a CVE's severity gets revised, an EPSS score
# moves, a fix gets published). Identity fields are *not* in here — those are
# what the fingerprint is made of, so they cannot change without producing a
# different issue.
_REFRESHED_FROM_FINDING = (
    "package_version",
    "severity",
    "source",
    "epss_score",
    "is_kev",
    "cvss_score",
    "cvss_vector",
    "fix_state",
    "fix_versions",
    "link",
)


class SyncResult(NamedTuple):
    new: int
    resolved: int
    reopened: int
    still_open: int
    # The issues themselves, not just the counts: notifications need to say
    # *what* appeared, and rebuilding that list from the database afterwards
    # would mean re-deriving "which of these are new" — the one thing this
    # method already knows for certain.
    new_issues: List[Issue] = []
    reopened_issues: List[Issue] = []


class IssueService:
    """Session-agnostic on purpose: `sync_from_scan` runs on the background
    scan session (`ScanProcessor` opens its own), while `triage` runs on a
    request session. Same contract as `EnrichmentService.enrich_findings` —
    the caller passes the session it owns."""

    def sync_from_scan(
        self,
        db: Session,
        scan: Scan,
        findings: List[Finding],
        scanned_types: Iterable[str],
        descriptions: Optional[Dict[str, str]] = None,
    ) -> SyncResult:
        """Fold a completed scan's findings into the issue history.

        `scanned_types` is supplied by the caller rather than derived from
        `findings`, and that distinction is the crux of resolution: "the secrets
        scanner ran and found nothing" must resolve secret issues, while "no
        secret findings because secrets were never scanned" must leave them
        alone. Deriving the set from the findings present cannot tell those two
        apart.

        Only ever called for a scan that completed — a failed or interrupted
        scan observed nothing, and treating that as evidence of absence would
        mark a target's entire backlog resolved.
        """
        repository = IssueRepository(db)
        scanned_types = set(scanned_types)
        now = utcnow()
        descriptions = descriptions or {}

        # Findings can repeat within one scan (the same CVE in two locations of
        # the same package); the issue is one, its occurrences are many.
        by_fingerprint: Dict[str, List[Finding]] = {}
        for finding in findings:
            fingerprint = build_fingerprint(
                repo_id=scan.repo_id,
                container_id=scan.container_id,
                finding_type=finding.type,
                identifier=finding.identifier,
                purl=finding.purl,
                package_name=finding.package_name,
                file_path=finding.file_path,
            )
            by_fingerprint.setdefault(fingerprint, []).append(finding)

        existing = repository.find_by_fingerprints(by_fingerprint)
        new_issues: List[Issue] = []
        reopened_issues: List[Issue] = []

        for fingerprint, occurrences in by_fingerprint.items():
            finding = occurrences[0]
            issue = existing.get(fingerprint)
            if issue is None:
                issue = self._create_issue(scan, fingerprint, finding, now)
                issue.description = descriptions.get(finding.identifier or "")
                db.add(issue)
                new_issues.append(issue)
            else:
                if issue.state == STATE_RESOLVED:
                    self._reopen(issue)
                    reopened_issues.append(issue)
                self._refresh(issue, finding, scan, now)
                if not issue.description:
                    issue.description = descriptions.get(finding.identifier or "")

            # Needed before the findings can point at it.
            db.flush()
            for occurrence in occurrences:
                occurrence.issue_id = issue.id

        resolved_count = self._resolve_disappeared(
            repository, scan, scanned_types, set(by_fingerprint), now
        )

        scan.new_issues_count = len(new_issues)
        scan.resolved_issues_count = resolved_count
        db.commit()

        result = SyncResult(
            new=len(new_issues),
            resolved=resolved_count,
            reopened=len(reopened_issues),
            still_open=len(by_fingerprint) - len(new_issues) - len(reopened_issues),
            new_issues=new_issues,
            reopened_issues=reopened_issues,
        )
        logger.info(
            "Issue sync for scan %s: %d new, %d reopened, %d unchanged, %d resolved",
            scan.id, result.new, result.reopened, result.still_open, result.resolved,
        )
        return result

    def triage(
        self,
        db: Session,
        issue_id: int,
        triage_status: str,
        actor: str,
        justification: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Issue:
        """Record a human decision. Raises `ValueError` on anything invalid, so
        the UI layer surfaces the reason as-is."""
        if triage_status not in VALID_TRIAGE_STATUSES:
            raise ValueError(f"Statut de triage invalide : {triage_status}")

        justification = (justification or "").strip() or None
        if justification and justification not in VEX_JUSTIFICATIONS:
            raise ValueError(f"Justification VEX inconnue : {justification}")
        # VEX requires a justification for "not_affected" — without one the
        # statement carries no information, and an exported VEX document
        # containing it would be invalid.
        if triage_status == "not_affected" and not justification:
            raise ValueError(
                "Une justification est requise pour le statut « non affecté » (exigence VEX)."
            )

        repository = IssueRepository(db)
        issue = repository.find_by_id(issue_id)
        if not issue:
            raise ValueError("Problème introuvable.")

        issue.triage_status = triage_status
        issue.triage_justification = justification
        issue.triage_comment = (comment or "").strip() or None
        issue.triaged_by = actor
        issue.triaged_at = utcnow()
        db.commit()
        logger.info(
            "Issue %s triaged as '%s' by '%s'", issue.id, triage_status, actor or "unknown"
        )
        return issue

    def _create_issue(self, scan: Scan, fingerprint: str, finding: Finding, now: datetime) -> Issue:
        issue = Issue(
            repo_id=scan.repo_id,
            container_id=scan.container_id,
            fingerprint=fingerprint,
            type=finding.type,
            identifier=finding.identifier,
            purl=finding.purl,
            package_name=finding.package_name,
            file_path=finding.file_path,
            state=STATE_OPEN,
            first_seen_at=now,
            last_seen_at=now,
            first_seen_scan_id=scan.id,
            last_seen_scan_id=scan.id,
            times_seen=1,
            triage_status=TRIAGE_UNDER_REVIEW,
        )
        for field in _REFRESHED_FROM_FINDING:
            setattr(issue, field, getattr(finding, field, None))
        issue.is_kev = bool(finding.is_kev)
        return issue

    def _refresh(self, issue: Issue, finding: Finding, scan: Scan, now: datetime) -> None:
        for field in _REFRESHED_FROM_FINDING:
            value = getattr(finding, field, None)
            # Enrichment runs *after* this sync for a brand-new finding, so a
            # null EPSS/KEV on this pass must not erase what a previous scan
            # already established.
            if value is not None:
                setattr(issue, field, value)
        issue.last_seen_at = now
        issue.last_seen_scan_id = scan.id
        issue.times_seen = (issue.times_seen or 0) + 1
        issue.state = STATE_OPEN
        issue.resolved_at = None

    def _reopen(self, issue: Issue) -> None:
        """A resolved issue seen again.

        Only a `fixed` triage is cleared: it has been factually contradicted, so
        leaving it would hide a regression behind a stale decision. A
        `not_affected` judgment is about the code's exposure, not about the
        package's presence, so it survives — and stays visible in the triage
        history for review.
        """
        if issue.triage_status == TRIAGE_FIXED:
            issue.triage_status = TRIAGE_UNDER_REVIEW
            issue.triage_justification = None
            issue.triaged_at = None
            issue.triaged_by = None
            logger.info(
                "Issue %s was marked fixed but reappeared — triage reset to under review", issue.id
            )

    def _resolve_disappeared(
        self,
        repository: IssueRepository,
        scan: Scan,
        scanned_types: Set[str],
        seen_fingerprints: Set[str],
        now: datetime,
    ) -> int:
        if not scanned_types:
            return 0
        candidates = repository.find_open_by_target(
            repo_id=scan.repo_id, container_id=scan.container_id, types=scanned_types
        )
        resolved = 0
        for issue in candidates:
            if issue.fingerprint in seen_fingerprints:
                continue
            issue.state = STATE_RESOLVED
            issue.resolved_at = now
            resolved += 1
        return resolved


def scanned_types_for(
    *, is_container: bool, ai_review_ran: bool, license_policy_ran: bool
) -> Set[str]:
    """Which finding types a scan actually looked for.

    Mirrors the branching in `ScanProcessor.process_scan` (ADR-001 section 5:
    secrets and IaC need source on disk, so they don't apply to images; the AI
    review is opt-in). Expressed here, next to the resolution logic that depends
    on it, so the two cannot drift apart silently.
    """
    types: Set[str] = {"vulnerability"}
    if not is_container:
        types.update({"secret", "iac"})
        if ai_review_ran:
            types.add("ai_review")
    if license_policy_ran:
        types.add("license")
    return types


def summarize_issues(issues: List[Issue]) -> Dict[str, Any]:
    """Severity tally over a set of issues, in the same shape
    `ScanProcessor._summarize_findings` produces for a scan."""
    summary = {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "negligible": 0, "unknown": 0, "total": 0,
    }
    for issue in issues:
        severity = (issue.severity or "unknown").lower()
        summary[severity] = summary.get(severity, 0) + 1
        summary["total"] += 1
    return summary
