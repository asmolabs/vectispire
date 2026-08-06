from typing import List, Optional
from sqlalchemy.orm import Session
from zanshin.models.audit_log import AuditLog

class AuditLogRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_latest(self) -> Optional[AuditLog]:
        """The most recent entry, whose hash the next one chains onto."""
        return (
            self.db.query(AuditLog)
            .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            .first()
        )

    def find_all_oldest_first(self) -> List[AuditLog]:
        """Every entry, in chain order. Only read by `verify_chain`, which is a
        deliberate check — not something a page render does."""
        return (
            self.db.query(AuditLog)
            .order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
            .all()
        )

    def find_recent(self, limit: int = 200) -> List[AuditLog]:
        return self.db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    def save(self, entry: AuditLog) -> AuditLog:
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry
