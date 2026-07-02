from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

class VexDecision(Base):
    __tablename__ = "vex_decision"

    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(String(255), nullable=False)
    package_name = Column(String(255), nullable=False)
    purl = Column(String(255), nullable=True)
    status = Column(String(255), default="under_review", nullable=False)  # affected, not_affected, fixed, under_review
    justification = Column(String(255), nullable=True)
    response = Column(String(255), nullable=True)
    comment = Column(Text, nullable=True)
    created_at = Column(SafeDateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(SafeDateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    repository_id = Column(BigInteger, ForeignKey("repository.id"), nullable=True)
    repository = relationship("ZanshinRepository", back_populates="vex_decisions")
