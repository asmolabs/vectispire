from zanshin.clock import utcnow
from sqlalchemy import Column, Integer, String, Boolean, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

class Finding(Base):
    """A single, normalized (queryable) result attached to a Scan.

    `Scan.cves`/`Scan.sbom` keep the raw tool output for audit purposes;
    `Finding` rows are the structured projection of that output used by the UI
    and the enrichment step (EPSS/KEV) — see docs/architecture/02.

    A finding is an *observation*, valid for the scan that produced it. State and
    triage belong to `Issue`, which tracks the same problem across scans.
    """
    __tablename__ = "finding"

    id = Column(Integer, primary_key=True, index=True)
    # Indexed: `count_by_scan_ids_and_type` runs on every list and history
    # render, filtering on `scan_id IN (...)`.
    scan_id = Column(Integer, ForeignKey("scan.id", ondelete="CASCADE"), nullable=False, index=True)

    # "vulnerability" (SCA/Grype), "secret" (gitleaks), "iac" (checkov), "license",
    # "eol", "ai_review", and — from the Semgrep step — "sast" and "quality".
    type = Column(String(50), default="vulnerability", nullable=False)

    severity = Column(String(50), nullable=True)
    identifier = Column(String(255), nullable=True)  # e.g. CVE-2024-12345

    # What the tool actually said about *this* occurrence, when the identifier alone does
    # not carry it.
    #
    # Added for Semgrep, where the message is the finding: a rule id, a file and a line
    # tell a reviewer nothing about why the line is wrong. Three earlier features worked
    # around this column's absence — the end-of-life service rebuilds a sentence from
    # columns, the AI review writes its prose into a table of its own, and the review
    # narrative is reassembled at render time — so this is where paying for it stops
    # being avoidable.
    #
    # `Text`, not `String(n)`: a rule message runs to a paragraph and truncating an
    # explanation is worse than storing it.
    description = Column(Text, nullable=True)
    package_name = Column(String(255), nullable=True)
    package_version = Column(String(255), nullable=True)
    purl = Column(String(255), nullable=True)
    # True declared by the project, False pulled in by another package, NULL when
    # the SBOM carried no dependency graph to answer with (see dependency_graph.py).
    is_direct_dependency = Column(Boolean, nullable=True)
    file_path = Column(String(500), nullable=True)
    line = Column(Integer, nullable=True)

    # Which scanner/provider produced this finding (grype, gitleaks, osv, ...).
    source = Column(String(50), default="grype", nullable=False)

    # Populated by the enrichment step (docs/architecture/01).
    epss_score = Column(Float, nullable=True)
    is_kev = Column(Boolean, default=False, nullable=False)

    # What to *do* about it — the part that was missing for the finding to be
    # actionable rather than merely alarming. All of it is present in the
    # scanners' own output (Grype's `vulnerability.fix` / `vulnerability.cvss`,
    # translated identically by the OSV backend) and was simply dropped.
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(255), nullable=True)
    fix_state = Column(String(50), nullable=True)  # fixed, not-fixed, wont-fix, unknown
    fix_versions = Column(String(255), nullable=True)  # comma-separated, as reported
    link = Column(String(500), nullable=True)

    # The cross-scan issue this observation belongs to. State and triage live
    # there, not here: a scan rewrites its findings wholesale, so a status on
    # this row could never outlive one scan (see zanshin/models/issue.py).
    issue_id = Column(Integer, ForeignKey("issue.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at = Column(SafeDateTime, default=utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")
    issue = relationship("Issue", back_populates="findings")
