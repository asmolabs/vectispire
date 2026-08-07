"""Scheduling on a cron expression.

`scan_cron` has existed on `repository` and `container` from the beginning, and the
repository screen has always collected it. Nothing read it: the scheduler used the
interval and logged a warning that no user ever sees. A form that accepts a value and
does nothing with it is worse than one that does not offer it — so either the field had
to go or the expression had to be honoured. It is honoured.

**Why it was worth honouring rather than removing.** An interval cannot say "every night
at two". It drifts: a 24-hour interval fires a few minutes later each day, because the
next run is counted from the last one, so a scan configured to run off-peak eventually
runs in the middle of the working day. For a job that starts containers and pulls whole
registries, when it runs is not a detail.

**Precedence.** A target with a cron expression is scheduled by it, and the interval is
ignored — one target, one schedule, and the one the operator wrote most recently wins by
being the more specific of the two. Clearing the field returns the target to its
interval.
"""
import logging
from datetime import datetime
from typing import Optional

from croniter import croniter

logger = logging.getLogger(__name__)


class InvalidCronExpression(ValueError):
    """The expression is not something croniter can schedule on."""


def validate_expression(expression: Optional[str]) -> Optional[str]:
    """Normalize an expression, or raise with a message an operator can act on.

    Called when a repository is saved, for the same reason the URL is validated there
    (`git_url.validate_repo_url`): the entry point is where a mistake is cheap to fix.
    Finding out that a cron expression was rejected by watching scans *not* happen is
    the expensive way.

    Empty means "no cron", which is a valid state and returns `None` rather than an
    error — that is how an operator goes back to interval scheduling.
    """
    expression = (expression or "").strip()
    if not expression:
        return None
    if not croniter.is_valid(expression):
        raise InvalidCronExpression(
            f"Expression cron invalide : « {expression} ». Format attendu : "
            "minute heure jour mois jour-de-semaine — par exemple « 0 2 * * * » "
            "(toutes les nuits à 2 h) ou « 0 3 * * 1 » (tous les lundis à 3 h)."
        )
    return expression


def is_due(expression: str, last_scheduled_at: Optional[datetime], now: datetime) -> bool:
    """Whether an occurrence has come round since the last scheduled run.

    A target that has never been scanned automatically is due immediately, exactly like
    the interval path: otherwise adding a target with a nightly expression would leave it
    doing nothing until the small hours, and an operator would reasonably conclude that
    the schedule is broken.

    Computed from `last_scheduled_at` rather than from `now`, so a tick that runs late
    (a restart, a slow pass) still catches the occurrence it missed instead of skipping
    to the next one.
    """
    if not expression:
        return False
    if not croniter.is_valid(expression):
        # Checked *before* the "never scheduled" shortcut, and that order matters: an
        # unschedulable expression would otherwise fire once — the one dispatch nobody
        # asked for, from the one target whose configuration is broken. It can only get
        # here by being hand-edited or by a croniter upgrade, since `validate_expression`
        # refuses it at the point it is typed.
        logger.warning("Ignoring unusable cron expression %r", expression)
        return False
    if last_scheduled_at is None:
        return True
    try:
        return croniter(expression, last_scheduled_at).get_next(datetime) <= now
    except Exception:
        logger.warning("Could not schedule on cron expression %r", expression)
        return False


def next_occurrence(expression: str, after: Optional[datetime] = None) -> Optional[datetime]:
    """When the expression fires next, for display.

    Shown next to the field so an operator can confirm that what they typed means what
    they think. A cron expression is exactly the kind of input that is easy to get
    subtly wrong and impossible to verify by re-reading.
    """
    if not expression:
        return None
    try:
        from zanshin.clock import utcnow

        return croniter(expression, after or utcnow()).get_next(datetime)
    except Exception:
        return None
