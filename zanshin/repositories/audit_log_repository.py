from typing import List
from sqlalchemy.orm import Session
from zanshin.models.audit_log import AuditLog

class AuditLogRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_recent(self, limit: int = 200) -> List[AuditLog]:
        return self.db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    def save(self, entry: AuditLog) -> AuditLog:
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        return entry
