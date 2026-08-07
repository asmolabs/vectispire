"""timestamps as real dates

Every timestamp in this schema was stored as ISO text, on every backend, because
`SafeDateTime` existed to read the several formats the pre-Alembic implementation left
behind. It worked — ISO-8601 sorts lexicographically — and it cost more than it looked:

- no date arithmetic in SQL, so five places loaded a whole table to filter it in Python;
- an index on a timestamp was an index on text: fine for ordering, useless for a range;
- `WHERE expires_at > now()` was a type error on PostgreSQL.

**How the conversion is done, and why not in SQL.** `ALTER … USING c::timestamp` would
be one statement per column on PostgreSQL and nothing at all on SQLite, and it would
have to be right about every legacy shape: `T` or space separators, a trailing `Z`, a
UTC offset, an epoch in seconds or in milliseconds. The parser that already knows all of
them is in Python (`parse_legacy_timestamp`), so the values go through it. Same code,
same result, on the three backends — and a value that cannot be read stops the migration
with the row named, rather than being silently rewritten to something plausible.

The trade is speed: this reads and rewrites every timestamp. On the scale this
application runs at (thousands of scans, tens of thousands of findings) it is seconds,
and it happens once.

Revision ID: 0013
Revises: 0012
Create Date: 2026-08-07
"""
import logging
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import zanshin.models.safedatetime

revision: str = '0013'
down_revision: Union[str, None] = '0012'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")

# (table, primary key) -> [(column, nullable)]. Hardcoded rather than read from the
# models: a migration describes the schema *at this revision*, and one that reflected
# the current models would change meaning every time a column is added.
TIMESTAMP_COLUMNS = {
    ("api_key", "id"): [("expires_at", True), ("created_at", False), ("last_used_at", True)],
    ("audit_logs", "id"): [("timestamp", False)],
    ("container", "id"): [("last_scheduled_scan_at", True)],
    ("gate_policy", "id"): [("created_at", False)],
    ("leader_lease", "name"): [("acquired_at", True), ("expires_at", True), ("updated_at", False)],
    ("outbox_message", "id"): [("next_attempt_at", True), ("created_at", False), ("sent_at", True)],
    ("processed_message", "id"): [("processed_at", False)],
    ("ssh_key", "id"): [("created_at", False)],
    ("user", "id"): [("created_at", False), ("updated_at", False)],
    ("agent", "id"): [("last_seen_at", True), ("created_at", False)],
    ("repository", "id"): [("last_scheduled_scan_at", True)],
    ("scan", "id"): [("created_at", False), ("claimed_at", True), ("lease_expires_at", True)],
    ("ai_review_result", "id"): [("created_at", False)],
    ("issue", "id"): [
        ("first_seen_at", False), ("last_seen_at", False), ("resolved_at", True),
        ("triaged_at", True), ("triage_expires_at", True),
    ],
    ("finding", "id"): [("created_at", False)],
}

# How many rows are read at a time. Bounded so a large `finding` table does not have to
# fit in memory, large enough that the migration is not a round trip per row.
BATCH = 500

# Same length the text columns were declared with, for the downgrade.
_ISO_LENGTH = 40


class UnreadableTimestamp(RuntimeError):
    """A stored value that no known format explains. Named with its row, because the
    operator has to look at it — guessing would corrupt an audit trail."""


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    for (table, primary_key), columns in TIMESTAMP_COLUMNS.items():
        if table not in existing:
            continue
        present = {c["name"]: c for c in inspector.get_columns(table)}
        for column, nullable in columns:
            if column not in present:
                continue
            if not _is_text(present[column]["type"]):
                # Already converted — a database created after this revision, or a
                # migration re-run. Nothing to do, and saying so beats failing.
                continue
            _convert(bind, table, primary_key, column, nullable)


def downgrade() -> None:
    """Back to text, in the ISO form the application used to write.

    Not a no-op even though the type is wider: a database restored from a downgrade must
    be readable by the previous code, which parses text.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    for (table, primary_key), columns in TIMESTAMP_COLUMNS.items():
        if table not in existing:
            continue
        present = {c["name"] for c in inspector.get_columns(table)}
        for column, nullable in columns:
            if column in present:
                _revert(bind, table, primary_key, column, nullable)


def _is_text(column_type) -> bool:
    return isinstance(column_type, (sa.String, sa.Text))


def _temp_name(column: str) -> str:
    return f"{column}__dt"


def _indexes_on(inspector, table: str, column: str):
    """Indexes that mention this column, so they can be put back afterwards.

    They have to come off first: batch mode recreates the table from the reflected
    schema, and an index still pointing at the column being replaced makes the rename
    collide with itself. Found by reflection rather than hardcoded — an index added
    later would otherwise break this migration for the deployment that has it.
    """
    return [
        index for index in inspector.get_indexes(table)
        if column in (index.get("column_names") or [])
    ]


def _prepare(bind, table: str, column: str, temp: str, temp_type) -> list:
    """Add the replacement column, and return the indexes to restore afterwards."""
    inspector = sa.inspect(bind)
    indexes = _indexes_on(inspector, table, column)
    if temp in {c["name"] for c in inspector.get_columns(table)}:
        # Left behind by an interrupted run: SQLite does not roll back every DDL
        # statement, so a migration that failed halfway leaves this column in place and
        # the next attempt would collide with it.
        logger.warning("0013: dropping leftover %s.%s from an interrupted run", table, temp)
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_column(temp)
    op.add_column(table, sa.Column(temp, temp_type, nullable=True))
    return indexes


def _swap(table: str, column: str, temp: str, column_type, nullable: bool, indexes) -> None:
    """Replace `column` with `temp`, keeping the name, the nullability and the indexes.

    One operation per batch block, in this order, and that is not stylistic: dropping
    and renaming inside a single block makes the rename collide with the column being
    dropped, and an index still pointing at the old column makes it collide with itself.
    Both were found by the migration failing on exactly the indexed columns.
    """
    for index in indexes:
        op.drop_index(index["name"], table_name=table)
    with op.batch_alter_table(table, schema=None) as batch_op:
        batch_op.drop_column(column)
    with op.batch_alter_table(table, schema=None) as batch_op:
        batch_op.alter_column(temp, new_column_name=column, existing_type=column_type)
    if not nullable:
        # Set after filling, not before: the column has to exist and be populated first,
        # and an empty table would otherwise be the only case that works.
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column(column, existing_type=column_type, nullable=False)
    for index in indexes:
        op.create_index(index["name"], table, [column], unique=index.get("unique", False))


def _convert(bind, table: str, primary_key: str, column: str, nullable: bool) -> None:
    from zanshin.models.safedatetime import parse_legacy_timestamp
    from datetime import datetime

    temp = _temp_name(column)
    logger.info("0013: converting %s.%s to a timestamp", table, column)

    # The models' own type, not a bare `sa.DateTime`: it declares microsecond precision
    # explicitly, which MySQL needs and which the audit chain depends on.
    timestamp_type = zanshin.models.safedatetime.SafeDateTime()
    indexes = _prepare(bind, table, column, temp, timestamp_type)

    source = sa.table(
        table,
        sa.column(primary_key),
        sa.column(column),
        sa.column(temp, zanshin.models.safedatetime.SafeDateTime()),
    )

    converted = 0
    last_key = None
    while True:
        query = sa.select(source.c[primary_key], source.c[column]).order_by(
            source.c[primary_key]
        ).limit(BATCH)
        if last_key is not None:
            query = query.where(source.c[primary_key] > last_key)
        rows = bind.execute(query).fetchall()
        if not rows:
            break

        for key, raw in rows:
            last_key = key
            if raw is None or raw == "":
                continue
            parsed = parse_legacy_timestamp(raw)
            if not isinstance(parsed, datetime):
                raise UnreadableTimestamp(
                    f"{table}.{column} = {raw!r} (ligne {primary_key}={key!r}) n'est pas "
                    "un horodatage lisible. Corrigez ou videz cette valeur, puis "
                    "relancez la migration — la réécrire automatiquement fausserait "
                    "une trace d'audit."
                )
            bind.execute(
                source.update().where(source.c[primary_key] == key).values({temp: parsed})
            )
            converted += 1

        if len(rows) < BATCH:
            break

    _swap(table, column, temp, timestamp_type, nullable, indexes)
    logger.info("0013: %s.%s converted (%d value(s))", table, column, converted)


def _revert(bind, table: str, primary_key: str, column: str, nullable: bool) -> None:
    temp = _temp_name(column)
    text_type = sa.String(length=_ISO_LENGTH)
    indexes = _prepare(bind, table, column, temp, text_type)

    source = sa.table(
        table,
        sa.column(primary_key),
        sa.column(column, zanshin.models.safedatetime.SafeDateTime()),
        sa.column(temp),
    )

    last_key = None
    while True:
        query = sa.select(source.c[primary_key], source.c[column]).order_by(
            source.c[primary_key]
        ).limit(BATCH)
        if last_key is not None:
            query = query.where(source.c[primary_key] > last_key)
        rows = bind.execute(query).fetchall()
        if not rows:
            break
        for key, value in rows:
            last_key = key
            if value is None:
                continue
            bind.execute(
                source.update()
                .where(source.c[primary_key] == key)
                .values({temp: value.isoformat()})
            )
        if len(rows) < BATCH:
            break

    _swap(table, column, temp, text_type, nullable, indexes)
