"""dependency directness, line numbers and triage review dates

Three columns on `issue`, two on `finding`, all nullable — and nullable is the
point in each case rather than a convenience:

- `is_direct_dependency`: NULL means "no dependency graph said". Defaulting existing
  rows to true or false would state something about every package already recorded
  that nothing established, on the very field meant to decide what to fix first.
  Rows get an answer when their target is next scanned.
- `line`: NULL for everything scanned before it was captured. It is only used to
  place a SARIF annotation, so a missing value degrades to a file-level annotation
  rather than a wrong one.
- `triage_expires_at`: NULL means "until someone says otherwise", which is exactly
  what every existing decision meant. Backfilling a review date would silently
  invalidate suppressions that were made deliberately, and re-open a backlog
  overnight — a policy change disguised as a schema change.

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# The models use custom column types (`GUID`, `SafeDateTime`); autogenerate
# renders them by their fully-qualified name, so these modules must be
# importable from every migration.
import zanshin.models.guid
import zanshin.models.safedatetime

revision: str = '0006'
down_revision: Union[str, None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Column-by-column, for the same reason as 0005: SQLite's DDL is not
    transactional here, so an interrupted run must be resumable rather than stuck
    on "duplicate column"."""
    inspector = sa.inspect(op.get_bind())

    def missing(table: str, column: str) -> bool:
        return column not in {c["name"] for c in inspector.get_columns(table)}

    planned = {
        "issue": [
            ("is_direct_dependency", sa.Column("is_direct_dependency", sa.Boolean(), nullable=True)),
            ("line", sa.Column("line", sa.Integer(), nullable=True)),
            ("triage_expires_at", sa.Column(
                "triage_expires_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True
            )),
        ],
        "finding": [
            ("is_direct_dependency", sa.Column("is_direct_dependency", sa.Boolean(), nullable=True)),
            ("line", sa.Column("line", sa.Integer(), nullable=True)),
        ],
    }

    for table, columns in planned.items():
        to_add = [column for name, column in columns if missing(table, name)]
        if to_add:
            with op.batch_alter_table(table, schema=None) as batch_op:
                for column in to_add:
                    batch_op.add_column(column)


def downgrade() -> None:
    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.drop_column("line")
        batch_op.drop_column("is_direct_dependency")

    with op.batch_alter_table("issue", schema=None) as batch_op:
        batch_op.drop_column("triage_expires_at")
        batch_op.drop_column("line")
        batch_op.drop_column("is_direct_dependency")
