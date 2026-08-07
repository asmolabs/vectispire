"""leader lease

One row per job that must have exactly one owner across a fleet. Today there is one
such job — the exclusive part of the scheduler tick — and without this table two
instances would each dispatch every due target, i.e. scan everything twice per
interval (ADR-002 §2.2).

A row rather than an engine-specific advisory lock: `pg_advisory_lock` and MySQL's
`GET_LOCK` are named and scoped differently and neither exists on SQLite, so the
single-process deployment would have to special-case itself. A row also survives to be
read afterwards, which is what makes "why did nothing run last night" answerable.

Revision ID: 0012
Revises: 0011
Create Date: 2026-08-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import zanshin.models.safedatetime

revision: str = '0012'
down_revision: Union[str, None] = '0011'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if "leader_lease" in sa.inspect(op.get_bind()).get_table_names():
        return

    op.create_table(
        "leader_lease",
        # The job name is the primary key, and that is the mechanism rather than a
        # convention: two instances starting at the same instant both insert, and the
        # constraint is what makes exactly one of them win.
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("holder", sa.String(length=64), nullable=True),
        sa.Column("acquired_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
        sa.Column("expires_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
        sa.Column("updated_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )


def downgrade() -> None:
    op.drop_table("leader_lease")
