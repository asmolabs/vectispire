from datetime import datetime
from sqlalchemy import Column, Integer, String, BigInteger, ForeignKey, JSON
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
    error = Column(String(255), nullable=True)
    created_at = Column(SafeDateTime, default=datetime.utcnow, nullable=False)
    version = Column(String(255), nullable=True)
    project_type = Column(String(255), nullable=True)

    repo_id = Column(BigInteger, ForeignKey("repository.id"), nullable=True)
    repository = relationship("ZanshinRepository", back_populates="scans")

    container_id = Column(BigInteger, ForeignKey("container.id"), nullable=True)
    container = relationship("Container", back_populates="scans")
