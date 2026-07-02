from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

class ZanshinRepository(Base):
    __tablename__ = "repository"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(255), nullable=False)
    branch = Column(String(255), default="main", nullable=False)
    sub_path = Column(String(255), default="", nullable=True)
    name = Column(String(255), nullable=True)
    scan_interval_minutes = Column(Integer, nullable=True)
    scan_cron = Column(String(255), nullable=True)
    last_scheduled_scan_at = Column(SafeDateTime, nullable=True)
    
    ssh_key_id = Column(GUID, ForeignKey("ssh_key.id"), nullable=True)
    ssh_key = relationship("SSHKey")
    
    # Cascade deletes to scans and vex decisions
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan", lazy="joined")
    vex_decisions = relationship("VexDecision", back_populates="repository", cascade="all, delete-orphan")
