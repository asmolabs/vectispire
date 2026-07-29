from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

class Finding(Base):
    """A single, normalized (queryable) result attached to a Scan.

    `Scan.cves`/`Scan.sbom` keep the raw tool output for audit purposes;
    `Finding` rows are the structured projection of that output used by the
    UI, VEX triage, and future enrichment (EPSS/KEV) — see ADR-001, section 4.
    """
    __tablename__ = "finding"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(BigInteger, ForeignKey("scan.id"), nullable=False)

    # "vulnerability" (SCA/Grype) today; "secret" / "iac" / "license" are the
    # extension points for the additional scanners described in ADR-001.
    type = Column(String(50), default="vulnerability", nullable=False)

    severity = Column(String(50), nullable=True)
    identifier = Column(String(255), nullable=True)  # e.g. CVE-2024-12345
    package_name = Column(String(255), nullable=True)
    package_version = Column(String(255), nullable=True)
    purl = Column(String(255), nullable=True)
    file_path = Column(String(500), nullable=True)

    # Which scanner/provider produced this finding (grype, gitleaks, osv, ...).
    source = Column(String(50), default="grype", nullable=False)

    # Populated later by the enrichment step (ADR-001, section 6); left null
    # until that phase is implemented.
    epss_score = Column(Float, nullable=True)
    is_kev = Column(Boolean, default=False, nullable=False)

    status = Column(String(50), default="open", nullable=False)  # open, ignored, fixed

    # One-way link to an existing VEX decision (repo, vulnerability, package).
    # `vex_decision` is an existing table with no `finding_id` column of its
    # own — adding one there would require a real migration (no such tool is
    # wired up yet, see ADR-001). Adding the FK here, on this brand-new
    # table, is schema-safe: it only reads `vex_decision.id`, it changes
    # nothing on the vex_decision side.
    vex_decision_id = Column(Integer, ForeignKey("vex_decision.id"), nullable=True)

    created_at = Column(SafeDateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")
    vex_decision = relationship("VexDecision")
