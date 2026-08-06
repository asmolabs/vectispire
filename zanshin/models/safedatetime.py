from sqlalchemy.types import TypeDecorator, String
from datetime import datetime

# Long enough for the widest value this can produce: an ISO-8601 timestamp with
# microseconds and a UTC offset is 32 characters ("2026-08-06T13:34:45.491348-09:30").
# The margin covers a longer offset notation without being a free-for-all.
_ISO_LENGTH = 40


class SafeDateTime(TypeDecorator):
    """A DateTime type decorator that safely parses dates stored as ISO strings,
    timestamps (seconds or milliseconds), or bytes from SQLite databases.

    Stored as text on every backend, not as a native timestamp. That is the point of
    the class — it exists to read the several formats the pre-Alembic schema left
    behind, and `zanshin.clock.utcnow` returns naive UTC for the same reason. Moving
    to native timestamps means rewriting every timestamp column in a data migration,
    which is a decision of its own rather than a side effect of adding a backend.

    The length is declared because MySQL refuses `VARCHAR` without one — a
    `CompileError` on the very first table, and the third portability defect this
    schema had that SQLite could not reveal (SQLite ignores the length entirely, so
    nothing changes for an existing deployment).
    """
    impl = String(_ISO_LENGTH)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                # Remove timezone 'Z' shorthand for compatibility with fromisoformat
                val_str = value.replace("Z", "+00:00")
                # Handle space separator instead of T
                if " " in val_str and "T" not in val_str:
                    val_str = val_str.replace(" ", "T")
                return datetime.fromisoformat(val_str)
            except ValueError:
                # Fallback parser if format differs
                try:
                    return datetime.strptime(value.split(".")[0], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
        if isinstance(value, (int, float)):
            # If timestamp is stored in milliseconds (Spring Boot defaults to millis in some settings)
            if value > 1e11:  # Milliseconds
                return datetime.utcfromtimestamp(value / 1000.0)
            return datetime.utcfromtimestamp(value)
        if isinstance(value, bytes):
            try:
                val_str = value.decode("utf-8").replace("Z", "+00:00")
                if " " in val_str and "T" not in val_str:
                    val_str = val_str.replace(" ", "T")
                return datetime.fromisoformat(val_str)
            except Exception:
                pass
        return value
