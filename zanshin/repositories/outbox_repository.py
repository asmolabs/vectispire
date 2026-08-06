from typing import List, Optional

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from zanshin.models.outbox_message import (
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_SENT,
    OutboxMessage,
)


class OutboxRepository:
    def __init__(self, db: Session):
        self.db = db

    def add(self, message: OutboxMessage) -> OutboxMessage:
        """Adds without committing.

        Deliberately not `save()`: the whole point of the outbox is that the message
        lands in the *caller's* transaction, alongside the state change it describes.
        A commit here would reintroduce the dual write this table exists to remove.
        """
        self.db.add(message)
        return message

    def find_due(self, now, limit: int = 20) -> List[OutboxMessage]:
        """Pending messages whose backoff has elapsed, oldest first.

        `next_attempt_at IS NULL` covers a message that has never been tried — it is
        due immediately, and treating null as "not yet" would leave every first
        attempt waiting forever.
        """
        return (
            self.db.query(OutboxMessage)
            .filter(
                OutboxMessage.status == STATUS_PENDING,
                or_(
                    OutboxMessage.next_attempt_at.is_(None),
                    OutboxMessage.next_attempt_at <= now,
                ),
            )
            .order_by(OutboxMessage.created_at)
            .limit(limit)
            .all()
        )

    def count_by_status(self) -> dict:
        """`{status: count}` — what the settings screen shows so a stuck queue is
        visible without reading the table."""
        rows = (
            self.db.query(OutboxMessage.status, func.count(OutboxMessage.id))
            .group_by(OutboxMessage.status)
            .all()
        )
        counts = {STATUS_PENDING: 0, STATUS_SENT: 0, STATUS_FAILED: 0}
        for status, count in rows:
            counts[status] = count
        return counts

    def find_failed(self, limit: int = 50) -> List[OutboxMessage]:
        return (
            self.db.query(OutboxMessage)
            .filter(OutboxMessage.status == STATUS_FAILED)
            .order_by(OutboxMessage.created_at.desc())
            .limit(limit)
            .all()
        )

    def find_by_id(self, message_id) -> Optional[OutboxMessage]:
        return self.db.query(OutboxMessage).filter(OutboxMessage.id == message_id).first()

    def delete_sent_before(self, cutoff) -> int:
        """Prune delivered messages. Returns how many were removed."""
        removed = (
            self.db.query(OutboxMessage)
            .filter(OutboxMessage.status == STATUS_SENT, OutboxMessage.sent_at < cutoff)
            .delete(synchronize_session=False)
        )
        self.db.commit()
        return removed
