import logging
from datetime import timedelta
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from zanshin.clock import utcnow
from zanshin.models.processed_message import ProcessedMessage

logger = logging.getLogger(__name__)


class ProcessedMessageRepository:
    def __init__(self, db: Session):
        self.db = db

    def was_processed(self, message_id: str) -> bool:
        if not message_id:
            return False
        return (
            self.db.query(ProcessedMessage)
            .filter(ProcessedMessage.message_id == message_id)
            .first()
            is not None
        )

    def mark(self, message_id: str, message_type: str, agent_id=None) -> ProcessedMessage:
        """Stage the marker **without committing**.

        Deliberately not a `save()`: the whole point is that this row lands in the
        same transaction as the effect it records (see `ProcessedMessage`), so the
        caller commits once, after applying the effect. A `mark()` that committed
        on its own would create the window it exists to close.
        """
        entry = ProcessedMessage(
            message_id=message_id, message_type=message_type, agent_id=agent_id,
            processed_at=utcnow(),
        )
        self.db.add(entry)
        return entry

    def prune(self, older_than_days: int = 7) -> int:
        """Forget markers no sender could still be retrying.

        Kept for a week rather than forever: a message id is only useful while a
        retry is plausible, and this table would otherwise grow with every scan —
        the same reasoning as pruning delivered outbox messages.
        """
        cutoff = utcnow() - timedelta(days=older_than_days)
        # A bulk delete, not a read-then-delete loop: this table grows with every agent
        # report, and there is nothing to inspect on the way past. It became expressible
        # in SQL with migration 0013 — while the column was text, the comparison had to
        # happen in Python, which meant loading the whole table to throw most of it away.
        removed = (
            self.db.query(ProcessedMessage)
            .filter(ProcessedMessage.processed_at < cutoff)
            .delete(synchronize_session=False)
        )
        if removed:
            self.db.commit()
        return removed
