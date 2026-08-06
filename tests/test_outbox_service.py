"""Tests for the notification outbox.

The defect being fixed has two halves and they need separate tests. One: the message
has to become durable in the *same* transaction as the scan's results, or a crash
between the commit and the POST still loses it — that half is covered in
`test_scan_processor.py`, where the pipeline runs. Two: a delivery that fails has to be
retried, with backoff, and eventually abandoned rather than retried forever — that is
what is here.
"""
from datetime import timedelta

import pytest

from zanshin.clock import utcnow
from zanshin.models.outbox_message import (
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_SENT,
    OutboxMessage,
)
from zanshin.repositories.outbox_repository import OutboxRepository
from zanshin.services.outbox_service import (
    MAX_ATTEMPTS,
    backoff_seconds,
    counts,
    enqueue,
    prune_sent,
    relay,
)


class FakeNotifier:
    """Stands in for `NotificationService.deliver`, which raises on failure so the relay
    can retry — the opposite contract from the rest of that class, and the reason the
    outbox works at all."""

    def __init__(self, failures=0, error=ConnectionError("simulated: webhook down")):
        self.remaining_failures = failures
        self.error = error
        self.delivered = []

    def deliver(self, payload):
        if self.remaining_failures > 0:
            self.remaining_failures -= 1
            raise self.error
        self.delivered.append(payload)


@pytest.fixture()
def repository(db_session):
    return OutboxRepository(db_session)


def _enqueue(db_session, repository, **payload):
    message = enqueue(repository, {"text": "3 nouveaux problèmes", **payload})
    db_session.commit()
    return message


def _relay(db_session, repository, notifier, **kwargs):
    return relay(
        db_session,
        outbox_repository=repository,
        notification_service=notifier,
        **kwargs,
    )


# --- Enqueuing ---

def test_enqueuing_does_not_commit(db_session, repository):
    """The entire point: the message joins the caller's transaction, so it becomes
    durable at the same instant as the state it describes."""
    enqueue(repository, {"text": "quelque chose"})

    db_session.rollback()

    assert db_session.query(OutboxMessage).count() == 0


def test_a_message_starts_pending_and_due_immediately(db_session, repository):
    message = _enqueue(db_session, repository)

    assert message.status == STATUS_PENDING
    assert message.attempts == 0
    # Null, not "now": treating a never-tried message as "not yet due" would leave
    # every first attempt waiting forever.
    assert message.next_attempt_at is None
    assert repository.find_due(utcnow()) == [message]


def test_the_payload_carries_a_message_id(db_session, repository):
    """Delivery is at-least-once — the POST can succeed and the transaction marking it
    sent can fail — so a receiver needs something to deduplicate on."""
    message = _enqueue(db_session, repository)

    assert message.payload["message_id"] == str(message.id)


def test_the_payload_is_a_snapshot(db_session, repository):
    """It says what the scan found, not what the issue rows look like once somebody has
    triaged half of them twenty minutes later."""
    message = _enqueue(db_session, repository, new_count=3)

    assert message.payload["new_count"] == 3


# --- Delivery ---

def test_a_due_message_is_delivered_and_marked_sent(db_session, repository):
    message = _enqueue(db_session, repository)
    notifier = FakeNotifier()

    sent = _relay(db_session, repository, notifier)

    assert [m.id for m in sent] == [message.id]
    assert message.status == STATUS_SENT
    assert message.sent_at is not None
    assert notifier.delivered[0]["text"] == "3 nouveaux problèmes"


def test_a_sent_message_is_not_delivered_twice(db_session, repository):
    _enqueue(db_session, repository)
    notifier = FakeNotifier()

    _relay(db_session, repository, notifier)
    _relay(db_session, repository, notifier)

    assert len(notifier.delivered) == 1


def test_messages_go_out_in_the_order_they_were_enqueued(db_session, repository):
    first = _enqueue(db_session, repository, scan_id=1)
    second = _enqueue(db_session, repository, scan_id=2)
    second.created_at = first.created_at + timedelta(seconds=1)
    db_session.commit()
    notifier = FakeNotifier()

    _relay(db_session, repository, notifier)

    assert [p["scan_id"] for p in notifier.delivered] == [1, 2]


def test_one_pass_is_capped(db_session, repository):
    """The tick also reaps scans, prunes payloads, expires triages and opens tickets; a
    burst of two hundred webhooks would starve all of them."""
    for index in range(5):
        _enqueue(db_session, repository, scan_id=index)
    notifier = FakeNotifier()

    _relay(db_session, repository, notifier, limit=2)

    assert len(notifier.delivered) == 2


# --- Retrying ---

def test_a_failure_leaves_the_message_pending_with_a_retry_date(db_session, repository):
    """A webhook that was briefly unreachable used to lose its message to a single log
    line."""
    message = _enqueue(db_session, repository)
    notifier = FakeNotifier(failures=1)

    assert _relay(db_session, repository, notifier) == []

    assert message.status == STATUS_PENDING
    assert message.attempts == 1
    assert message.next_attempt_at is not None
    assert "ConnectionError" in message.last_error


def test_a_message_in_backoff_is_not_retried_early(db_session, repository):
    message = _enqueue(db_session, repository)
    _relay(db_session, repository, FakeNotifier(failures=1))
    notifier = FakeNotifier()

    _relay(db_session, repository, notifier, now=message.next_attempt_at - timedelta(seconds=1))

    assert notifier.delivered == []


def test_a_message_is_retried_once_its_backoff_has_elapsed(db_session, repository):
    message = _enqueue(db_session, repository)
    _relay(db_session, repository, FakeNotifier(failures=1))
    notifier = FakeNotifier()

    _relay(db_session, repository, notifier, now=message.next_attempt_at)

    assert len(notifier.delivered) == 1
    assert message.status == STATUS_SENT


def test_the_backoff_widens_and_is_capped():
    """Retrying a briefly-unreachable endpoint quickly is right; retrying a misconfigured
    one every sixty seconds forever turns a mistake into a permanent load."""
    delays = [backoff_seconds(n) for n in range(1, 10)]

    assert delays[0] == 60
    assert delays[1] == 120
    assert delays[2] == 240
    assert delays == sorted(delays)
    assert max(delays) == 3600


def test_a_message_is_abandoned_after_the_last_attempt(db_session, repository):
    """An endpoint that has refused eight times over several hours will not accept the
    ninth, and a queue that never drains hides the messages that could still go out."""
    message = _enqueue(db_session, repository)
    notifier = FakeNotifier(failures=MAX_ATTEMPTS)

    now = utcnow()
    for _ in range(MAX_ATTEMPTS):
        _relay(db_session, repository, notifier, now=now)
        now = (message.next_attempt_at or now) + timedelta(seconds=1)

    assert message.status == STATUS_FAILED
    assert message.attempts == MAX_ATTEMPTS
    assert message.next_attempt_at is None


def test_an_abandoned_message_is_kept_rather_than_deleted(db_session, repository):
    """A message nobody will ever receive is exactly what an operator needs to find."""
    message = _enqueue(db_session, repository)
    notifier = FakeNotifier(failures=MAX_ATTEMPTS)
    now = utcnow()
    for _ in range(MAX_ATTEMPTS):
        _relay(db_session, repository, notifier, now=now)
        now = (message.next_attempt_at or now) + timedelta(seconds=1)

    assert repository.find_failed() == [message]
    assert message.last_error


def test_an_abandoned_message_is_audited(db_session, repository, audit_log_repository):
    from zanshin.services.audit_log_service import AuditLogService

    message = _enqueue(db_session, repository)
    notifier = FakeNotifier(failures=MAX_ATTEMPTS)
    now = utcnow()
    for _ in range(MAX_ATTEMPTS):
        _relay(
            db_session, repository, notifier,
            audit_log_service=AuditLogService(audit_log_repository), now=now,
        )
        now = (message.next_attempt_at or now) + timedelta(seconds=1)

    entry = audit_log_repository.find_latest()
    assert entry.operation_type == "NOTIFICATION_ABANDONED"


def test_an_abandoned_message_is_never_retried(db_session, repository):
    message = _enqueue(db_session, repository)
    notifier = FakeNotifier(failures=MAX_ATTEMPTS)
    now = utcnow()
    for _ in range(MAX_ATTEMPTS):
        _relay(db_session, repository, notifier, now=now)
        now = (message.next_attempt_at or now) + timedelta(seconds=1)

    working = FakeNotifier()
    _relay(db_session, repository, working, now=now + timedelta(days=1))

    assert working.delivered == []


def test_one_failing_message_does_not_block_the_others(db_session, repository):
    """Otherwise a single misconfigured destination would hold the whole queue for the
    hours its backoff takes to expire."""
    first = _enqueue(db_session, repository, scan_id=1)
    second = _enqueue(db_session, repository, scan_id=2)
    second.created_at = first.created_at + timedelta(seconds=1)
    db_session.commit()
    notifier = FakeNotifier(failures=1)

    _relay(db_session, repository, notifier)

    assert [p["scan_id"] for p in notifier.delivered] == [2]
    assert first.status == STATUS_PENDING


def test_an_unsafe_url_is_a_failure_like_any_other(db_session, repository):
    """`deliver` validates the destination at send time, so a setting written straight
    into the database becomes a retryable failure rather than an unchecked request."""
    from zanshin.services.url_guard import UnsafeUrlError

    message = _enqueue(db_session, repository)
    notifier = FakeNotifier(failures=1, error=UnsafeUrlError("adresse privée"))

    _relay(db_session, repository, notifier)

    assert message.status == STATUS_PENDING
    assert "UnsafeUrlError" in message.last_error


# --- Housekeeping ---

def test_delivered_messages_are_pruned(db_session, repository):
    message = _enqueue(db_session, repository)
    _relay(db_session, repository, repository and FakeNotifier())
    message.sent_at = utcnow() - timedelta(days=30)
    db_session.commit()

    assert prune_sent(repository, days=7) == 1
    assert db_session.query(OutboxMessage).count() == 0


def test_a_recently_delivered_message_is_kept(db_session, repository):
    """"Did it go out?" needs an answer for a day or two."""
    _enqueue(db_session, repository)
    _relay(db_session, repository, FakeNotifier())

    assert prune_sent(repository, days=7) == 0


def test_a_pending_message_is_never_pruned(db_session, repository):
    _enqueue(db_session, repository)

    assert prune_sent(repository, days=0) == 0
    assert db_session.query(OutboxMessage).count() == 1


def test_the_counts_are_what_the_settings_screen_shows(db_session, repository):
    _enqueue(db_session, repository, scan_id=1)
    sent_one = _enqueue(db_session, repository, scan_id=2)
    _relay(db_session, repository, FakeNotifier(), limit=1)

    tally = counts(repository)

    assert tally[STATUS_SENT] == 1
    assert tally[STATUS_PENDING] == 1
    assert tally[STATUS_FAILED] == 0
    assert sent_one is not None
