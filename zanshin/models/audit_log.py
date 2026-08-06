import uuid

from sqlalchemy import Column, String

from zanshin.clock import utcnow
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime


class AuditLog(Base):
    """Maps to `audit_logs`, a table inherited from an earlier implementation of this
    application (present in the database since before the current codebase, with no
    model or repository wired up to it — 0 rows regardless of how much the app had
    been used).

    Two additions since the security review:

    - **Where from.** An entry recorded only *who* and *what*. For authentication
      events in particular, the address and the client are what let an operator tell
      "Alice mistyped her password twice" from "someone is walking the account list
      from one host".
    - **Tamper-evidence.** Each entry carries the hash of the previous one, so the
      table is a chain: altering or deleting a past entry breaks every hash after it.
      This does not make the log append-only — anyone with write access can rewrite
      the whole chain — it makes *selective* editing detectable, which is the realistic
      threat when the interesting record is one line among thousands.
    """

    __tablename__ = "audit_logs"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    description = Column(String(255), nullable=False)
    operation_type = Column(String(255), nullable=False)
    resource_id = Column(String(255), nullable=False)
    timestamp = Column(SafeDateTime, default=utcnow, nullable=False)
    user_id = Column(String(255), nullable=True)

    # Request context, when there is one (absent for scheduler-initiated actions).
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)

    # Integrity chain: `entry_hash = H(previous_hash, this entry's fields)`.
    previous_hash = Column(String(64), nullable=True)
    entry_hash = Column(String(64), nullable=True)
