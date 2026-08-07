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
    
    ssh_key_id = Column(GUID, ForeignKey("ssh_key.id", ondelete="SET NULL"), nullable=True)
    ssh_key = relationship("SSHKey")
    
    # Cascade deletes to scans and vex decisions.
    #
    # Deliberately *not* `lazy="joined"`: that made every `find_all()` on
    # repositories eagerly load each repository's entire scan history,
    # `Scan.sbom`/`Scan.cves` blobs included, just to render a list of names.
    # Screens that need scan data now ask `ScanRepository` for column-only
    # summaries (see `ScanSummary`); this relationship exists for the cascade
    # and for the rare case where whole `Scan` entities are genuinely wanted.
    scans = relationship(
        "Scan", back_populates="repository", cascade="all, delete-orphan", passive_deletes=True
    )
    issues = relationship(
        "Issue", back_populates="repository", cascade="all, delete-orphan", passive_deletes=True
    )
