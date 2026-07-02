from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from zanshin.database import Base
from zanshin.models.safedatetime import SafeDateTime

class Container(Base):
    __tablename__ = "container"

    id = Column(Integer, primary_key=True, index=True)
    registry = Column(String(255), nullable=True)
    image_name = Column(String(255), nullable=False)
    tag = Column(String(255), default="latest", nullable=False)
    scan_interval_minutes = Column(Integer, nullable=True)
    scan_cron = Column(String(255), nullable=True)
    last_scheduled_scan_at = Column(SafeDateTime, nullable=True)

    scans = relationship("Scan", back_populates="container", cascade="all, delete-orphan", lazy="joined")
