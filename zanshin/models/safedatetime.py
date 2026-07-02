from sqlalchemy.types import TypeDecorator, String
from datetime import datetime

class SafeDateTime(TypeDecorator):
    """A DateTime type decorator that safely parses dates stored as ISO strings, 
    timestamps (seconds or milliseconds), or bytes from SQLite databases.
    """
    impl = String
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
