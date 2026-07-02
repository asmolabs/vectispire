import uuid
from datetime import datetime
from sqlalchemy import Column, String
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

class ApiKey(Base):
    __tablename__ = "api_key"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    created_at = Column(SafeDateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(SafeDateTime, nullable=True)
