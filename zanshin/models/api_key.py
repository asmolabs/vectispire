import uuid

from sqlalchemy import Column, Integer, String

from zanshin.clock import utcnow
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

# What a key is allowed to do. A key used to grant everything the API exposes, with
# no way to say less — so a pipeline that only needed to read a verdict held a
# credential that could also queue scans.
SCOPE_READ = "read"      # list targets, read issues and scans
SCOPE_SCAN = "scan"      # queue a scan
SCOPE_EXPORT = "export"  # VEX, CSV, SBOM
ALL_SCOPES = (SCOPE_READ, SCOPE_SCAN, SCOPE_EXPORT)
# What an existing key gets when the column is added: everything, because that is
# what it already had. Narrowing silently would break working pipelines.
DEFAULT_SCOPES = ALL_SCOPES


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

    # Comma-separated subset of ALL_SCOPES.
    scopes = Column(String(255), nullable=False, default=",".join(DEFAULT_SCOPES))

    # Optional restriction to a single target. Null on both = every target, which is
    # what a key had before this existed. A key issued for project A's pipeline could
    # read project B's issues, VEX documents and CSV exports.
    target_kind = Column(String(20), nullable=True)  # "repository" | "container"
    target_id = Column(Integer, nullable=True)

    # Optional expiry. A credential that never expires is one nobody ever rotates.
    expires_at = Column(SafeDateTime, nullable=True)

    created_at = Column(SafeDateTime, default=utcnow, nullable=False)
    last_used_at = Column(SafeDateTime, nullable=True)

    @property
    def scope_list(self) -> list:
        return [s for s in (self.scopes or "").split(",") if s]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scope_list

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= utcnow()

    def covers(self, kind: str, target_id) -> bool:
        """Whether this key may act on a given target.

        An unrestricted key covers everything; a restricted one covers exactly its
        own target. `target_id` is compared as an int because it arrives from a URL
        path or a JSON body.
        """
        if self.target_kind is None and self.target_id is None:
            return True
        try:
            return self.target_kind == kind and self.target_id == int(target_id)
        except (TypeError, ValueError):
            return False
