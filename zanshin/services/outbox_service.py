"""The relay that drains the notification outbox.

Split from `NotificationService` on purpose: that one owns *what to say* and *how to
say it* (payload shape, URL validation, the POST); this one owns *when a message gets
another chance*. Keeping them apart is what makes the retry policy testable without a
webhook and the payload testable without a clock.

Retry with exponential backoff, capped, then abandoned. Every part of that sentence is
a decision:

* **Backoff**, because the two realistic failures are a tracker/webhook that is briefly
  unreachable and one that is misconfigured. Retrying the first quickly is right;
  retrying the second every sixty seconds forever turns a mistake into a permanent load.
* **Capped attempts**, because an endpoint that has refused eight times over several
  hours is not going to accept the ninth, and a queue that never drains hides the
  messages that could still be delivered behind ones that never will.
* **Abandoned, not deleted.** A message nobody will ever receive is exactly what an
  operator needs to be able to find, so it stays with its last error and is counted on
  the settings screen.
"""
import logging
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from zanshin.clock import utcnow
from zanshin.models.outbox_message import (
    STATUS_FAILED,
    STATUS_SENT,
    TYPE_SCAN_DELTA,
    OutboxMessage,
)
from zanshin.repositories.outbox_repository import OutboxRepository

logger = logging.getLogger(__name__)

# Eight attempts over a widening window: roughly a minute, then two, four, ... up to
# the cap — about four hours in total, which covers a maintenance window without
# retrying a typo until the end of time.
MAX_ATTEMPTS = 8
BASE_BACKOFF_SECONDS = 60
MAX_BACKOFF_SECONDS = 3600

# How many messages one pass sends. The tick also reaps scans, prunes payloads, expires
# triages and opens tickets; a burst of two hundred webhooks would starve all of them.
MAX_PER_PASS = 20

# Delivered messages are kept briefly so "did it go out?" has an answer for a day or
# two, then pruned — the table is written to on every scan.
SENT_RETENTION_DAYS = 7


def enqueue(
    outbox_repository: OutboxRepository,
    payload: Dict[str, Any],
    message_type: str = TYPE_SCAN_DELTA,
) -> OutboxMessage:
    """Add a message to the caller's open transaction.

    Does not commit, and that is the entire point: the message has to become durable at
    the same instant as the state it describes, or the failure it is meant to prevent
    just moves one line down.

    A `message_id` is stamped into the payload because delivery is at-least-once — the
    POST can succeed and the transaction marking it sent can fail — and a receiver is
    the only place that ambiguity can be resolved.
    """
    message = OutboxMessage(
        id=uuid.uuid4(),
        message_type=message_type,
        payload={**payload},
    )
    message.payload["message_id"] = str(message.id)
    return outbox_repository.add(message)


def relay(
    db: Session,
    *,
    outbox_repository: OutboxRepository,
    notification_service,
    audit_log_service=None,
    limit: int = MAX_PER_PASS,
    now=None,
) -> List[OutboxMessage]:
    """Try every due message once. Returns those delivered.

    Never raises: this runs on the scheduler tick alongside retention, the stalled-scan
    reaper and the ticket sweep, and one unreachable webhook must not stop the rest.
    """
    now = now or utcnow()
    sent: List[OutboxMessage] = []

    for message in outbox_repository.find_due(now, limit=limit):
        message.attempts = (message.attempts or 0) + 1
        try:
            notification_service.deliver(message.payload)
        except Exception as e:
            _record_failure(message, e, now)
            if message.status == STATUS_FAILED:
                logger.error(
                    "Outbox message %s abandoned after %d attempts: %s",
                    message.id, message.attempts, message.last_error,
                )
                if audit_log_service:
                    audit_log_service.record(
                        "NOTIFICATION_ABANDONED",
                        resource_id=str(message.id),
                        description=(
                            f"Notification abandonnée après {message.attempts} tentatives : "
                            f"{message.last_error}"
                        ),
                    )
            else:
                logger.warning(
                    "Outbox message %s failed (attempt %d/%d), retrying at %s: %s",
                    message.id, message.attempts, MAX_ATTEMPTS, message.next_attempt_at, e,
                )
            db.commit()
            continue

        message.status = STATUS_SENT
        message.sent_at = now
        message.next_attempt_at = None
        message.last_error = None
        db.commit()
        sent.append(message)

    if sent:
        logger.info("Outbox: %d message(s) delivered", len(sent))
    return sent


def _record_failure(message: OutboxMessage, error: Exception, now) -> None:
    # Truncated: an HTML error page from a proxy is not worth a kilobyte per attempt in
    # a table written to on every scan.
    message.last_error = f"{type(error).__name__}: {error}"[:500]
    if message.attempts >= MAX_ATTEMPTS:
        message.status = STATUS_FAILED
        message.next_attempt_at = None
        return
    message.next_attempt_at = now + timedelta(seconds=backoff_seconds(message.attempts))


def backoff_seconds(attempts: int) -> int:
    """`60, 120, 240, …` capped at an hour.

    Computed from the attempt count rather than stored, so the policy can be changed
    without a migration and without rows carrying a schedule from an older one.
    """
    if attempts <= 0:
        return BASE_BACKOFF_SECONDS
    return min(BASE_BACKOFF_SECONDS * (2 ** (attempts - 1)), MAX_BACKOFF_SECONDS)


def prune_sent(outbox_repository: OutboxRepository, days: int = SENT_RETENTION_DAYS) -> int:
    return outbox_repository.delete_sent_before(utcnow() - timedelta(days=days))


def counts(outbox_repository: OutboxRepository) -> Dict[str, int]:
    return outbox_repository.count_by_status()
