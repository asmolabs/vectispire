import uuid
from datetime import datetime
from sqlalchemy import Column, String
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

class AuditLog(Base):
    """Maps to `audit_logs`, a table inherited from an earlier implementation
    of this application (present in the database since before the current
    codebase, but with no model/repository wired up to it until now — 0 rows
    regardless of how much the app had been used). Schema kept exactly as-is
    (verified via PRAGMA table_info against the live database) since there's
    no migration tool to alter it — see ADR-001 for that constraint.
    """
    __tablename__ = "audit_logs"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    description = Column(String(255), nullable=False)
    operation_type = Column(String(255), nullable=False)
    resource_id = Column(String(255), nullable=False)
    timestamp = Column(SafeDateTime, default=datetime.utcnow, nullable=False)
    user_id = Column(String(255), nullable=True)
