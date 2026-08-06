"""A message to send, written in the same transaction as the thing it describes.

The defect this fixes is small and real. A scan committed its results, and *then*
`NotificationService` posted a webhook. If the process died between the two — a
restart, an OOM kill, a container replaced mid-scan — the notification was lost with
no trace, and the only signal was a channel that stayed quiet on the night something
appeared. If instead the POST failed on a network hiccup, it was logged once and never
retried.

Both are the same problem: a state change in one system (the database) and a message
to another (the webhook), with nothing tying them together. The standard answer is a
row written inside the *same* transaction as the state change, and a relay that sends
it later. That is this table.

Two properties worth stating because they are choices, not consequences:

* **The payload is a snapshot.** What the scan found is serialized at enqueue time, so
  a message sent twenty minutes later says what was true when the scan finished — not
  what the issue rows happen to look like once someone has triaged half of them.
* **The destination is not.** The URL is read from the settings at send time and
  re-validated, so an operator who fixes a typo does not have to re-run a scan to get
  the pending notifications delivered.

Delivery is at-least-once, not exactly-once: the POST can succeed and the transaction
marking it sent can fail. `message_id` travels in the payload so a receiver that cares
can deduplicate — which is the only place that distinction can be resolved.
"""
import uuid

from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.types import JSON

from zanshin.clock import utcnow
from zanshin.database import Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime

STATUS_PENDING = "pending"
STATUS_SENT = "sent"
# Abandoned after `MAX_ATTEMPTS`. Kept rather than deleted: a message nobody will ever
# receive is exactly the thing an operator needs to be able to find.
STATUS_FAILED = "failed"

TYPE_SCAN_DELTA = "scan_delta"


class OutboxMessage(Base):
    __tablename__ = "outbox_message"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    # What kind of message this is. One value today; the column exists because the
    # relay has to be able to route, and adding it later would mean a migration on a
    # table that is being written to on every scan.
    message_type = Column(String(50), nullable=False, default=TYPE_SCAN_DELTA)
    payload = Column(JSON, nullable=False)

    status = Column(String(20), nullable=False, default=STATUS_PENDING, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    # When the relay may next try. Set on every failure, which is what turns "retry"
    # into "retry with backoff" without the relay having to remember anything.
    next_attempt_at = Column(SafeDateTime, nullable=True, index=True)
    last_error = Column(Text, nullable=True)

    created_at = Column(SafeDateTime, default=utcnow, nullable=False)
    sent_at = Column(SafeDateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<OutboxMessage {self.id} {self.message_type} {self.status} "
            f"attempts={self.attempts}>"
        )
