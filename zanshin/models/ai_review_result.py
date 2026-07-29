from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

class AiReviewResult(Base):
    """One row per scan for which the optional AI code review
    (`AiReviewService`, Ollama-backed) actually ran.

    Kept as its own table rather than a `Finding` row: it's a single
    free-form narrative response from the model, not a normalized,
    queryable finding. Adding a `Text` column to the existing `Finding`
    table would need a manual migration (no such tool exists yet — see
    ADR-001), whereas a brand-new table is created safely by
    `Base.metadata.create_all()` at startup, same as `Finding` and
    `AuditLog` were.

    One row per scan (`scan_id` is unique): re-running the review for the
    same scan is not supported in this first version — see ADR-001 for the
    open question of whether/how this should feed into `Finding` later.
    """
    __tablename__ = "ai_review_result"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(BigInteger, ForeignKey("scan.id"), nullable=False, unique=True)

    model = Column(String(255), nullable=False)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=True)
    status = Column(String(50), default="completed", nullable=False)  # completed, failed
    error = Column(String(500), nullable=True)

    created_at = Column(SafeDateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="ai_review", uselist=False)
