import uuid
from sqlalchemy.types import TypeDecorator, BINARY

class GUID(TypeDecorator):
    """Platform-independent GUID type.
    Uses SQLite's binary/blob type to store 16-byte binary UUIDs.
    """
    impl = BINARY
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                try:
                    return uuid.UUID(value).bytes
                except ValueError:
                    if isinstance(value, bytes) and len(value) == 16:
                        return value
                    raise
            return value.bytes

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            return uuid.UUID(bytes=value)
