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
    # `none_as_null=True` matters: with SQLAlchemy's default, assigning Python
    # `None` to a JSON column stores the JSON literal `null`, which is *not* SQL
    # NULL — so `sbom IS NOT NULL` stayed true for a scan whose payload had been
    # pruned, and the retention pass re-pruned the same rows forever.
    sbom = Column(JSON(none_as_null=True), nullable=True)
    cves = Column(JSON(none_as_null=True), nullable=True)
    summary = Column(JSON(none_as_null=True), nullable=True)
    # BigInteger here is not a foreign key: it is a duration, and the only column in
    # this schema that legitimately wants the wider type. Every *foreign key* matches
    # the Integer primary key it references — MySQL refuses a BIGINT column
    # referencing an INT one outright, and SQLite/PostgreSQL merely tolerated it.
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

    # --- Ownership of the work (ADR-002) ---
    #
    # `status` says a scan is running; these four say *who* is running it and
    # until when. Without them, "running" meant "some thread, somewhere, maybe":
    # startup recovery had to assume every in-flight scan was orphaned and fail
    # it, which is correct for one process and destroys another agent's work as
    # soon as there are two (ADR-002 §2.3).
    #
    # `claimed_by` holds an `Agent.worker_id` (the agent's uuid as hex), not a
    # foreign key: `Agent.id` is a 16-byte binary GUID, so a join would need a
    # cast that behaves differently on every backend this project supports. The
    # UI resolves the name through `AgentRepository.find_by_worker_id` instead,
    # and a scan keeps its provenance even if the agent row is later deleted —
    # which is the more useful property for an audit trail anyway.
    claimed_by = Column(String(64), nullable=True)
    claimed_at = Column(SafeDateTime, nullable=True)
    # Renewed by the worker as it makes progress. A scan whose lease has lapsed is
    # not killed — nothing here can kill a thread on another machine — it becomes
    # *reclaimable*, and the worker that eventually reports on it is refused.
    lease_expires_at = Column(SafeDateTime, nullable=True)
    # Incremented on every claim, so a scan that is repeatedly picked up and
    # abandoned fails visibly instead of cycling forever.
    attempts = Column(Integer, default=0, nullable=False)

    repo_id = Column(Integer, ForeignKey("repository.id"), nullable=True)
    repository = relationship("ZanshinRepository", back_populates="scans")

    container_id = Column(Integer, ForeignKey("container.id"), nullable=True)
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
