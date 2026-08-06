from zanshin.clock import utcnow
from sqlalchemy import Column, Integer, String, BigInteger, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

class Scan(Base):
    __tablename__ = "scan"

    id = Column(Integer, primary_key=True, index=True)
    branch = Column(String(255), nullable=False)
    sub_path = Column(String(255), default="", nullable=True)
    status = Column(String(255), default="pending", nullable=False)
    sbom = Column(JSON, nullable=True)
    cves = Column(JSON, nullable=True)
    summary = Column(JSON, nullable=True)
    duration_ms = Column(BigInteger, nullable=True)
    findings_count = Column(Integer, default=0, nullable=False)

    # Delta against the previous scan of the same target, computed by
    # `IssueService.sync_from_scan`. Stored rather than derived so a scan list
    # can show "what changed" without opening every issue history.
    new_issues_count = Column(Integer, default=0, nullable=False)
    resolved_issues_count = Column(Integer, default=0, nullable=False)
    # Text, not String(255): the narrow column forced a whole budget-splitting
    # trimmer in the Docker engine just to make a scanner's own words fit. A
    # failure message is exactly the field you don't want truncated.
    error = Column(Text, nullable=True)
    created_at = Column(SafeDateTime, default=utcnow, nullable=False)
    version = Column(String(255), nullable=True)
    project_type = Column(String(255), nullable=True)

    repo_id = Column(BigInteger, ForeignKey("repository.id"), nullable=True)
    repository = relationship("ZanshinRepository", back_populates="scans")

    container_id = Column(BigInteger, ForeignKey("container.id"), nullable=True)
    container = relationship("Container", back_populates="scans")

    # Normalized, queryable results (see ADR-001). `cves`/`sbom` above stay
    # as the raw tool output for audit purposes.
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    # Optional AI code review result (Ollama-backed, see AiReviewService).
    # At most one per scan; absent unless the feature was enabled when this
    # scan ran.
    ai_review = relationship(
        "AiReviewResult", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
