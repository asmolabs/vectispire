"""The single source of "now" in the application.

`datetime.utcnow()` is deprecated in Python 3.12 and was called from eighteen
places (model defaults, services, the scheduler), which made it eighteen edits
to change anything about how time is handled.

**Why naive UTC and not timezone-aware.** The obvious fix is
`datetime.now(timezone.utc)`, but every timestamp already stored — thousands of
rows, plus everything written by the earlier implementation of this application
— is naive. Mixing the two raises `TypeError: can't compare offset-naive and
offset-aware datetimes` on the first comparison, and the scheduler, the issue
lifecycle and the stalled-scan reaper all compare stored timestamps against
"now". Going timezone-aware therefore requires rewriting every timestamp column
in a data migration; doing it here would be a silent trap instead of a fix.

So this returns naive UTC, exactly as before, and the deprecation goes away. The
migration to aware datetimes becomes a single change to this function plus one
data migration, which is the point of funnelling it through here.
"""
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Current UTC time, naive — see the module docstring for why."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
