"""A UUID column that works on more than one database.

`impl = BINARY` was rendered literally as `BINARY` in DDL, which SQLite accepts
(everything is a blob) and PostgreSQL rejects outright — `type "binary" does not
exist`, on the very first table of the very first migration. So the type was the
thing standing between a configurable database URL and a database that could
actually be configured.

The stored representation stays exactly as it was on SQLite — 16 raw bytes — so no
existing row is touched. PostgreSQL gets its native `uuid` instead, because storing
a UUID as a blob there would give up indexing, `::text` casts and every tool that
knows what a uuid is, for no benefit.
"""
import uuid

from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.types import BINARY, TypeDecorator


class GUID(TypeDecorator):
    """Platform-independent GUID: native `uuid` on PostgreSQL, 16 bytes elsewhere."""

    impl = BINARY
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PostgresUUID(as_uuid=True))
        return dialect.type_descriptor(BINARY(16))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value

        if not isinstance(value, uuid.UUID):
            try:
                value = uuid.UUID(value)
            except (ValueError, AttributeError, TypeError):
                # Already the stored form: 16 raw bytes written by an earlier
                # version, or handed straight back from a query.
                if isinstance(value, bytes) and len(value) == 16:
                    return value if dialect.name != "postgresql" else uuid.UUID(bytes=value)
                raise

        if dialect.name == "postgresql":
            return value
        return value.bytes

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        if isinstance(value, bytes):
            return uuid.UUID(bytes=value)
        # A string can come back from a database whose column was created before
        # this type existed; parsing it is cheaper than failing the whole query.
        return uuid.UUID(str(value))
