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

    # Not `lazy="joined"` — same reasoning as `ZanshinRepository.scans`:
    # listing containers must not drag every scan's raw SBOM/CVE blob into
    # memory. Lists read `ScanRepository` summaries instead.
    scans = relationship(
        "Scan", back_populates="container", cascade="all, delete-orphan", passive_deletes=True
    )
    issues = relationship(
        "Issue", back_populates="container", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def image_string(self) -> str:
        """The full `registry/image_name:tag` reference, as Docker/Syft expect
        it. The registry is optional (Docker Hub is implicit when absent), so
        it's only prefixed when set.

        Lives on the model rather than being rebuilt at each call site: the
        scan pipeline needs it to pull the image, and the UI needs the same
        string to label scans in the history and the CVE dialog.
        """
        prefix = f"{self.registry}/" if self.registry else ""
        return f"{prefix}{self.image_name}:{self.tag}"
