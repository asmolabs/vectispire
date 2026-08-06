"""align foreign key column types with the primary keys they reference

Every foreign key in this schema was declared `BigInteger` while the primary key it
points at is `Integer`. SQLite does not care (its integers are all the same) and
PostgreSQL tolerates it, so the mismatch survived from the pre-Alembic schema through
six migrations. MySQL refuses it outright — `Referencing column \'container_id\' and
referenced column \'id\' ... are incompatible` — which is how it was finally found.

The correction narrows the foreign keys rather than widening the primary keys. Widening
would have been the more obvious symmetry and is a trap on SQLite: only a column
declared exactly `INTEGER PRIMARY KEY` is an alias for the rowid, so `BIGINT PRIMARY
KEY` would silently stop auto-incrementing. `scan.duration_ms` keeps `BigInteger`: it
is a duration, not a key.

No value is at risk — these hold row ids in the low thousands — so this is a type
declaration catching up with reality, not a data migration.

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import zanshin.models.guid
import zanshin.models.safedatetime

revision: str = '0007'
down_revision: Union[str, None] = '0006'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table, column, nullable) — every foreign key that was too wide.
_FOREIGN_KEYS = [
    ("scan", "repo_id", True),
    ("scan", "container_id", True),
    ("finding", "scan_id", False),
    ("issue", "repo_id", True),
    ("issue", "container_id", True),
    ("issue", "first_seen_scan_id", True),
    ("issue", "last_seen_scan_id", True),
    ("ai_review_result", "scan_id", False),
]


def upgrade() -> None:
    """Alter each column to `Integer`.

    Grouped per table so SQLite rewrites each table once — batch mode recreates the
    whole table for any column change, and doing that per column would rewrite
    `issue` four times.
    """
    inspector = sa.inspect(op.get_bind())

    for table in dict.fromkeys(table for table, _, _ in _FOREIGN_KEYS):
        types = {c["name"]: c["type"] for c in inspector.get_columns(table)}
        # A database created after 0001 was amended already has these as Integer;
        # rewriting the table to change nothing would be four table rewrites of pure
        # cost on SQLite, and a spurious diff to explain later.
        columns = [
            (column, nullable)
            for t, column, nullable in _FOREIGN_KEYS
            if t == table and isinstance(types.get(column), sa.BigInteger)
        ]
        if not columns:
            continue
        with op.batch_alter_table(table, schema=None) as batch_op:
            for column, nullable in columns:
                batch_op.alter_column(
                    column,
                    existing_type=sa.BigInteger(),
                    type_=sa.Integer(),
                    existing_nullable=nullable,
                )


def downgrade() -> None:
    for table in dict.fromkeys(table for table, _, _ in _FOREIGN_KEYS):
        columns = [(c, nullable) for t, c, nullable in _FOREIGN_KEYS if t == table]
        with op.batch_alter_table(table, schema=None) as batch_op:
            for column, nullable in columns:
                batch_op.alter_column(
                    column,
                    existing_type=sa.Integer(),
                    type_=sa.BigInteger(),
                    existing_nullable=nullable,
                )
