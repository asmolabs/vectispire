"""agents and scan leases

Two changes that only make sense together.

**`agent`** gives the thing that runs a scan an identity. Both kinds of worker are
rows: the web process itself (`builtin`, created at startup, one per host) and any
`python -m zanshin.agent` process (`remote`, authenticated by an API key with the
`agent` scope). Before this, nothing recorded where a scan ran and there was no
way to say "stop running scans on the web instance".

**Lease columns on `scan`** record *who* claimed a scan and *until when*.
`status = 'scanning'` used to be the whole story, which forced startup recovery to
assume every in-flight scan was orphaned and fail it — correct with one process,
and destructive as soon as a second worker exists, because starting the web
instance would fail the scans an agent was running (docs/architecture/04).

Existing rows: `attempts` defaults to 0 and the other three stay null, which reads
as "queued or claimed by nobody". A scan that was running when this migration is
applied therefore looks reclaimable, which is exactly what it is — the process
that was running it did not survive the upgrade either.

Revision ID: 0010
Revises: 0009
Create Date: 2026-08-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import zanshin.models.guid
import zanshin.models.safedatetime

revision: str = '0010'
down_revision: Union[str, None] = '0009'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SCAN_LEASE_COLUMN_NAMES = ("claimed_by", "claimed_at", "lease_expires_at", "attempts")


def _scan_lease_columns():
    """Fresh `Column` objects on every call.

    A module-level tuple would be reused across the two `batch_alter_table`
    blocks below, and a `Column` remembers the table it was attached to — so the
    second use would fail (or need the deprecated `Column.copy()`).
    """
    return [
        sa.Column("claimed_by", sa.String(length=64), nullable=True),
        sa.Column("claimed_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
        sa.Column("lease_expires_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
        # Server default, not just a Python default: the column is NOT NULL and
        # the table already has rows.
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    ]


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())

    if "agent" not in inspector.get_table_names():
        op.create_table(
            "agent",
            sa.Column("id", zanshin.models.guid.GUID(), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.String(length=500), nullable=True),
            sa.Column("kind", sa.String(length=20), nullable=False),
            sa.Column("labels", sa.String(length=255), nullable=True),
            sa.Column("credentials_mode", sa.String(length=20), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("max_concurrent", sa.Integer(), nullable=True),
            sa.Column("api_key_id", zanshin.models.guid.GUID(), nullable=True),
            sa.Column("hostname", sa.String(length=255), nullable=True),
            sa.Column("platform", sa.String(length=255), nullable=True),
            sa.Column("version", sa.String(length=50), nullable=True),
            sa.Column("scanner_engine", sa.String(length=50), nullable=True),
            sa.Column("capabilities", sa.JSON(), nullable=True),
            sa.Column("contract_version", sa.String(length=20), nullable=True),
            sa.Column("last_seen_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
            sa.Column("created_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            # An agent whose key is deleted keeps its history; the row simply
            # stops being able to authenticate.
            sa.ForeignKeyConstraint(["api_key_id"], ["api_key.id"], ondelete="SET NULL"),
            # The name is what an operator refers to an agent by, in the UI and in
            # a launch command; two agents sharing one would make the queue's log
            # unreadable.
            sa.UniqueConstraint("name"),
        )

    existing_scan_columns = {column["name"] for column in inspector.get_columns("scan")}
    with op.batch_alter_table("scan", schema=None) as batch_op:
        for column in _scan_lease_columns():
            if column.name not in existing_scan_columns:
                batch_op.add_column(column)

    # The reclaim query filters on exactly this column and runs on every scheduler
    # tick, expecting to find nothing almost every time.
    existing_indexes = {index["name"] for index in inspector.get_indexes("scan")}
    if "ix_scan_lease_expires_at" not in existing_indexes:
        # Named as SQLAlchemy would name it from `index=True` on the model column, so
        # `alembic check` sees the same schema on both sides.
        op.create_index(
            op.f("ix_scan_lease_expires_at"), "scan", ["lease_expires_at"], unique=False
        )


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_lease_expires_at"), table_name="scan")
    with op.batch_alter_table("scan", schema=None) as batch_op:
        for name in reversed(SCAN_LEASE_COLUMN_NAMES):
            batch_op.drop_column(name)
    op.drop_table("agent")
