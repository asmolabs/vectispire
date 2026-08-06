import hashlib
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from zanshin.database import Base
from zanshin.clock import utcnow
from zanshin.models.safedatetime import SafeDateTime

# Observed state, set by the scanner pipeline — never by a human.
STATE_OPEN = "open"
STATE_RESOLVED = "resolved"

# Human decision, VEX vocabulary (the same four values `VexDecision` declared
# and the README documents). `under_review` is where everything starts.
TRIAGE_UNDER_REVIEW = "under_review"
TRIAGE_AFFECTED = "affected"
TRIAGE_NOT_AFFECTED = "not_affected"
TRIAGE_FIXED = "fixed"
VALID_TRIAGE_STATUSES = (
    TRIAGE_UNDER_REVIEW,
    TRIAGE_AFFECTED,
    TRIAGE_NOT_AFFECTED,
    TRIAGE_FIXED,
)

# VEX justifications for a `not_affected` statement, per the OpenVEX /
# CSAF vocabulary — kept as the canonical list so a VEX document can be
# produced from these rows later without re-mapping free text.
VEX_JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)


class Issue(Base):
    """One problem on one target, tracked across scans.

    `Finding` is an *observation*: it belongs to a single scan and is rewritten
    from scratch every time one runs. That is why nothing could be acted upon
    before this table existed — a triage decision recorded against a finding
    would be orphaned by the next scan, so the UI never offered one, and
    `Finding.status` stayed "open" for its whole life. `VexDecision` was the
    first attempt at solving this and was never wired up (it is empty in every
    deployment); it is superseded by this table, which covers every finding
    type rather than vulnerabilities only.

    An issue is identified by `fingerprint` — a hash of what makes the problem
    *the same problem* on the next scan (target, type, identifier, package,
    file). Findings link back here, so history stays queryable both ways: what
    did this scan see, and what has this issue done over time.
    """

    __tablename__ = "issue"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_issue_fingerprint"),
        # The two queries the issue screens run constantly: everything
        # outstanding on one target, either kind. Declared here and not only in
        # the migration so `alembic check` can be trusted as a CI gate.
        Index("ix_issue_repo_state", "repo_id", "state"),
        Index("ix_issue_container_state", "container_id", "state"),
    )

    id = Column(Integer, primary_key=True, index=True)

    # Exactly one of these is set, mirroring `Scan`. Not a polymorphic
    # "target_type/target_id" pair: real foreign keys mean the cascade below
    # deletes an entity's issues with it, the way scans already are.
    repo_id = Column(BigInteger, ForeignKey("repository.id"), nullable=True)
    container_id = Column(BigInteger, ForeignKey("container.id"), nullable=True)

    # Stable identity across scans; see `build_fingerprint`.
    fingerprint = Column(String(64), nullable=False, index=True)

    type = Column(String(50), nullable=False)  # vulnerability, secret, iac, license, ai_review
    identifier = Column(String(255), nullable=True)  # CVE-2024-1234, gitleaks rule, checkov check...
    package_name = Column(String(255), nullable=True)
    package_version = Column(String(255), nullable=True)
    purl = Column(String(255), nullable=True)
    # Deliberately *not* part of the fingerprint: a package that moves from direct
    # to transitive is the same problem seen differently, and re-fingerprinting it
    # would drop its history and its triage decision.
    is_direct_dependency = Column(Boolean, nullable=True)
    file_path = Column(String(500), nullable=True)
    # Not part of the fingerprint: a secret that moves down three lines when
    # something is inserted above it is the same secret, and re-fingerprinting on
    # every reformat would reset its triage.
    line = Column(Integer, nullable=True)
    source = Column(String(50), nullable=True)  # grype, osv, gitleaks, checkov, syft, ollama:<model>

    # Latest known assessment data, refreshed on every sighting so lists and
    # sorting never have to reach into the raw scanner output.
    severity = Column(String(50), nullable=True)
    epss_score = Column(Float, nullable=True)
    is_kev = Column(Boolean, default=False, nullable=False)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(255), nullable=True)
    fix_state = Column(String(50), nullable=True)  # fixed, not-fixed, wont-fix, unknown
    fix_versions = Column(String(255), nullable=True)  # comma-separated, as the scanners report them
    link = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)

    # --- Observed state (pipeline-owned) ---
    state = Column(String(20), default=STATE_OPEN, nullable=False)
    first_seen_at = Column(SafeDateTime, default=utcnow, nullable=False)
    last_seen_at = Column(SafeDateTime, default=utcnow, nullable=False)
    resolved_at = Column(SafeDateTime, nullable=True)
    first_seen_scan_id = Column(BigInteger, ForeignKey("scan.id"), nullable=True)
    last_seen_scan_id = Column(BigInteger, ForeignKey("scan.id"), nullable=True)
    # How many scans have seen it — the cheap signal for "is this chronic".
    times_seen = Column(Integer, default=1, nullable=False)

    # --- Triage (human-owned) ---
    triage_status = Column(String(30), default=TRIAGE_UNDER_REVIEW, nullable=False)
    triage_justification = Column(String(64), nullable=True)  # one of VEX_JUSTIFICATIONS
    triage_comment = Column(Text, nullable=True)
    triaged_by = Column(String(255), nullable=True)
    triaged_at = Column(SafeDateTime, nullable=True)
    # When this decision stops being trusted. NULL means "until someone says
    # otherwise", which is what every decision used to mean.
    triage_expires_at = Column(SafeDateTime, nullable=True)

    repository = relationship("ZanshinRepository", back_populates="issues")
    container = relationship("Container", back_populates="issues")
    findings = relationship("Finding", back_populates="issue")
    first_seen_scan = relationship("Scan", foreign_keys=[first_seen_scan_id])
    last_seen_scan = relationship("Scan", foreign_keys=[last_seen_scan_id])

    @property
    def triage_expired(self) -> bool:
        """Whether this decision is past its review date.

        A suppression is a statement about a context — "this code path is not
        reachable", "this package is not shipped in production". Contexts change,
        and nothing brought the decision back for review: a `not_affected` recorded
        in January stayed authoritative in December, in the export handed to a
        customer as much as in the dashboard. This is how VEX suppressions rot.
        """
        if not self.triage_expires_at or self.triage_status == TRIAGE_UNDER_REVIEW:
            return False
        return utcnow() >= self.triage_expires_at

    @property
    def is_actionable(self) -> bool:
        """Still open, and not settled by a human decision — i.e. what a
        dashboard should count as outstanding work."""
        return self.state == STATE_OPEN and self.triage_status in (
            TRIAGE_UNDER_REVIEW,
            TRIAGE_AFFECTED,
        )


def build_fingerprint(
    *,
    repo_id: Optional[int],
    container_id: Optional[int],
    finding_type: str,
    identifier: Optional[str],
    purl: Optional[str],
    package_name: Optional[str],
    file_path: Optional[str],
) -> str:
    """Identity of a problem across scans.

    Deliberately excludes the package *version*: an outdated dependency that
    stays outdated through three version bumps is one issue with a history, not
    three unrelated ones — and a triage decision would otherwise evaporate on
    the next patch release. Everything else that distinguishes two genuinely
    different problems is included: which target, which kind, which
    vulnerability/rule, which package, which file.

    `purl` takes precedence over `package_name` when present because it is the
    stable ecosystem-qualified identity; falling back keeps secrets/IaC/license
    findings (which have no purl) fingerprintable by the same function.
    """
    target = f"repo:{repo_id}" if repo_id is not None else f"container:{container_id}"
    parts = [
        target,
        finding_type or "",
        identifier or "",
        purl or package_name or "",
        file_path or "",
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
