from datetime import datetime

from sqlalchemy.types import DateTime, TypeDecorator


class SafeDateTime(TypeDecorator):
    """A timestamp column that tolerates the shapes the pre-Alembic schema left behind.

    **It is a real timestamp now.** It used to be `String`: every date in the schema was
    stored as ISO text, on every backend. That worked — ISO-8601 sorts lexicographically,
    so ordering was right — but it cost more than it looked:

    - no date arithmetic in SQL, so five places loaded a whole table to filter it in
      Python (`fail_stalled_scans`, `reclaim_expired_leases`, the inbox purge…);
    - an index on a timestamp column was an index on text, useful for ordering and
      useless for a range;
    - `WHERE expires_at > now()` was a type error on PostgreSQL, which is how the
      conversion finally got written.

    Migration `0013` rewrites the existing values through the parser below, so nothing
    is lost in translation: the tolerance for legacy formats is exactly what makes the
    conversion safe.

    **What the tolerance still covers.** Values arriving as text (ISO with `T` or a
    space, a trailing `Z`, a UTC offset), as an epoch in seconds or milliseconds, or as
    bytes — the shapes the previous implementation of this application produced. After
    the migration a backend returns real `datetime` objects and none of this runs, but
    it stays because a database restored from an old dump would otherwise fail to read
    rather than fail to parse one column.

    Naive UTC throughout, matching `zanshin.clock.utcnow`: the stored values have always
    been naive, and mixing naive and aware datetimes raises on the first comparison —
    see that module for why going timezone-aware is a separate decision.

    **On sub-second precision.** There used to be a `load_dialect_impl` here declaring
    `DATETIME(fsp=6)` on MySQL, because MySQL truncates to whole seconds unless asked
    otherwise — and the audit trail hashes `timestamp.isoformat()`, so a value written
    with microseconds and read back without them recomputed to a different hash and every
    entry reported itself as tampered with. SQLite and PostgreSQL keep the fraction on
    their own, so with MySQL withdrawn (see `zanshin/database.py`) the override has no
    dialect left to correct. It is recorded here because a future backend that truncates
    would reintroduce exactly that failure, and it does not look like a clock problem.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Accept a datetime, or anything the parser below understands.

        Strings are parsed rather than passed through: a caller handing this column a
        string used to work (it was a string column), and failing on the write path
        would turn a cosmetic inconsistency into an outage.
        """
        if value is None or isinstance(value, datetime):
            return value
        return parse_legacy_timestamp(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, datetime):
            # A backend can hand back an *aware* datetime from a legacy value that
            # carried an offset — SQLite's own DATETIME parser does, before this code
            # ever sees the text. Letting it through would put a mix of naive and aware
            # values in one column, and the first comparison between them raises. This
            # is the trap `zanshin.clock` exists to avoid, so it is closed here too.
            return _to_naive_utc(value) if value.tzinfo is not None else value
        return parse_legacy_timestamp(value)


def parse_legacy_timestamp(value):
    """Best-effort conversion of a stored value into a naive `datetime`.

    Returns the value untouched when it cannot be read, rather than raising: this runs
    while *reading* rows, and one unreadable timestamp should not make a whole screen
    fail. The migration, which cannot be so relaxed, checks the result itself.
    """
    if value is None or isinstance(value, datetime):
        return value

    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except Exception:
            return value

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # `Z` is not understood by `fromisoformat` before Python 3.11, and a space
        # separator is what the previous implementation wrote.
        normalized = text.replace("Z", "+00:00")
        if " " in normalized and "T" not in normalized:
            normalized = normalized.replace(" ", "T", 1)
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            try:
                parsed = datetime.strptime(text.split(".")[0], "%Y-%m-%d %H:%M:%S")
            except Exception:
                return value
        # Anything stored with an offset is converted to UTC and stripped, so the whole
        # schema stays comparable: a mix of naive and aware values raises on the first
        # comparison, which is the trap `zanshin.clock` exists to avoid.
        if parsed.tzinfo is not None:
            parsed = _to_naive_utc(parsed)
        return parsed

    if isinstance(value, (int, float)):
        # Milliseconds, as some Spring Boot configurations wrote them.
        seconds = value / 1000.0 if value > 1e11 else value
        try:
            return datetime.utcfromtimestamp(seconds)
        except Exception:
            return value

    return value


def _to_naive_utc(parsed: datetime) -> datetime:
    from datetime import timezone

    return parsed.astimezone(timezone.utc).replace(tzinfo=None)
