"""Tests for cron scheduling.

The defect these close is not a crash: the repository screen collected an expression,
saved it, and the scheduler ignored it — the only trace being a warning in a log no
user reads. A form that accepts a value and does nothing with it is worse than one
that does not offer it.

So the cases below are mostly about the two halves of honouring it: an expression that
cannot be scheduled on is refused *where it is typed*, and one that can actually fires.
"""
from datetime import datetime, timedelta

import pytest

from zanshin.services.cron import (
    InvalidCronExpression,
    is_due,
    next_occurrence,
    validate_expression,
)

MIDNIGHT = datetime(2026, 8, 7, 0, 0)
NIGHTLY_AT_TWO = "0 2 * * *"


# --- Validation ----------------------------------------------------------------

def test_a_valid_expression_is_returned_normalized():
    assert validate_expression("  0 2 * * *  ") == "0 2 * * *"


def test_an_empty_expression_means_no_cron_rather_than_an_error():
    """How an operator goes back to interval scheduling: clear the field."""
    assert validate_expression("") is None
    assert validate_expression("   ") is None
    assert validate_expression(None) is None


@pytest.mark.parametrize("expression", ["tous les soirs", "0 2 * *", "99 * * * *", "* * * *"])
def test_an_unschedulable_expression_is_refused(expression):
    with pytest.raises(InvalidCronExpression):
        validate_expression(expression)


def test_the_refusal_says_what_the_format_is():
    """An operator reading "invalid" learns nothing; the message has to carry an
    example, because that is what they will copy."""
    with pytest.raises(InvalidCronExpression) as refusal:
        validate_expression("tous les soirs")

    message = str(refusal.value)
    assert "0 2 * * *" in message
    assert "tous les soirs" in message


# --- Being due -----------------------------------------------------------------

def test_a_target_never_scheduled_is_due_immediately():
    """Same rule as the interval path: otherwise adding a target with a nightly
    expression would leave it idle until the small hours, and an operator would
    reasonably conclude the schedule is broken."""
    assert is_due(NIGHTLY_AT_TWO, None, MIDNIGHT) is True


def test_it_is_not_due_before_the_next_occurrence():
    last = datetime(2026, 8, 7, 2, 0)

    assert is_due(NIGHTLY_AT_TWO, last, datetime(2026, 8, 7, 23, 0)) is False


def test_it_is_due_once_the_occurrence_has_passed():
    last = datetime(2026, 8, 7, 2, 0)

    assert is_due(NIGHTLY_AT_TWO, last, datetime(2026, 8, 8, 2, 0)) is True
    assert is_due(NIGHTLY_AT_TWO, last, datetime(2026, 8, 8, 2, 5)) is True


def test_a_missed_occurrence_is_caught_rather_than_skipped():
    """Counted from the last run, not from now: a tick that runs late — a restart, a
    slow pass — still catches the occurrence it missed."""
    last = datetime(2026, 8, 1, 2, 0)

    # Five days later, several occurrences missed: still due.
    assert is_due(NIGHTLY_AT_TWO, last, datetime(2026, 8, 6, 12, 0)) is True


def test_an_empty_expression_is_never_due():
    assert is_due("", MIDNIGHT, MIDNIGHT + timedelta(days=1)) is False


def test_an_expression_that_stopped_parsing_stops_that_target_only():
    """A row hand-edited, or a croniter upgrade: scheduling stops for this target
    rather than raising through a tick that has five other jobs to do."""
    assert is_due("not a cron", None, MIDNIGHT) is False


# --- Display -------------------------------------------------------------------

def test_the_next_occurrence_is_computed_for_display():
    """Shown next to the field: a cron expression is easy to get subtly wrong and
    impossible to verify by re-reading."""
    assert next_occurrence(NIGHTLY_AT_TWO, MIDNIGHT) == datetime(2026, 8, 7, 2, 0)


def test_no_occurrence_for_an_unusable_expression():
    assert next_occurrence("not a cron", MIDNIGHT) is None
    assert next_occurrence("", MIDNIGHT) is None
