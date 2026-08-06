"""stored gate policy and tracker ticket references

Two additions, both nullable-by-design:

- `gate_policy` starts **empty**, and that is the point: an empty table means "use the
  code's own defaults", which is exactly how the gate behaved before the table existed.
  Seeding a row here would impose a policy on a running deployment as a side effect of
  a schema change, and the first thing anyone would notice is a build failing for
  reasons nobody chose.
- `issue.ticket_ref` / `ticket_url` are null for every existing issue, so the first
  sweep treats the current backlog as un-ticketed. That is deliberate rather than
  unavoidable: those issues genuinely have no ticket, and the sweep's own per-run
  ceiling (`MAX_TICKETS_PER_SWEEP`) is what keeps a mature backlog from arriving in the
  tracker all at once.

The unique constraint on `(target_kind, target_id, is_active)` is what makes "one
active policy per scope" a property of the database rather than a hope. It works
because `is_active` is `NULL` for superseded versions and SQL's unique constraints
ignore NULLs — so any number of historical versions coexist while only one row can
hold `True`.

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import zanshin.models.guid
import zanshin.models.safedatetime

revision: str = '0008'
down_revision: Union[str, None] = '0007'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())

    if "gate_policy" not in inspector.get_table_names():
        op.create_table(
            "gate_policy",
            sa.Column("id", sa.Integer(), nullable=False),
            # Not nullable, and the global scope is the sentinel `"*"`/`0`: a NULL
            # scope cannot participate in a unique constraint, because SQL treats
            # NULLs as distinct — which would have allowed two *active global*
            # policies and made the verdict depend on row order.
            sa.Column("target_kind", sa.String(length=20), nullable=False),
            sa.Column("target_id", sa.Integer(), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=True),
            sa.Column("fail_on_severity", sa.String(length=20), nullable=True),
            sa.Column("fail_on_kev", sa.Boolean(), nullable=False),
            sa.Column("fixable_only", sa.Boolean(), nullable=False),
            sa.Column("include_triaged", sa.Boolean(), nullable=False),
            sa.Column("include_ai_review", sa.Boolean(), nullable=False),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("created_by", sa.String(length=255), nullable=True),
            sa.Column("created_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "target_kind", "target_id", "is_active", name="uq_gate_policy_active_scope"
            ),
        )
        with op.batch_alter_table("gate_policy", schema=None) as batch_op:
            batch_op.create_index(batch_op.f("ix_gate_policy_id"), ["id"], unique=False)

    # Column by column, for the reason established in 0005: SQLite's DDL is not
    # transactional here, so an interrupted run has to be resumable.
    existing = {c["name"] for c in inspector.get_columns("issue")}
    to_add = [
        sa.Column("ticket_ref", sa.String(length=64), nullable=True),
        sa.Column("ticket_url", sa.String(length=500), nullable=True),
    ]
    to_add = [column for column in to_add if column.name not in existing]
    if to_add:
        with op.batch_alter_table("issue", schema=None) as batch_op:
            for column in to_add:
                batch_op.add_column(column)


def downgrade() -> None:
    with op.batch_alter_table("issue", schema=None) as batch_op:
        batch_op.drop_column("ticket_url")
        batch_op.drop_column("ticket_ref")

    with op.batch_alter_table("gate_policy", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_gate_policy_id"))
    op.drop_table("gate_policy")
