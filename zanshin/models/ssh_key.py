import uuid
from zanshin.clock import utcnow
from sqlalchemy import Column, String, Text
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

class SSHKey(Base):
    __tablename__ = "ssh_key"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    private_key = Column(Text, nullable=False)
    public_key = Column(Text, nullable=True)
    created_at = Column(SafeDateTime, default=utcnow, nullable=False)
