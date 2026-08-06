import uuid
from zanshin.clock import utcnow
from sqlalchemy import Column, String
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

class ApiKey(Base):
    __tablename__ = "api_key"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)

    # Only the bcrypt hash of the secret is stored; the raw secret is shown
    # to the user once, at creation time, and never persisted or displayed
    # again. `prefix` is a short, non-secret fragment kept for identification
    # in the UI (e.g. "zsk_ab12...") without revealing the full key.
    key_hash = Column(String(255), nullable=False)
    prefix = Column(String(16), nullable=True)

    created_at = Column(SafeDateTime, default=utcnow, nullable=False)
    last_used_at = Column(SafeDateTime, nullable=True)
