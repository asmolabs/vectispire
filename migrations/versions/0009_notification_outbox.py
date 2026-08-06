"""notification outbox

A webhook used to be posted after the scan's transaction had committed. A crash in
between lost the notification with no trace, and a network failure logged one line and
never retried. Both are the same defect — a state change in one system and a message to
another, with nothing tying them together — and the fix is a row written inside the
same transaction as the state change, plus a relay that sends it later.

The table starts empty and is written to on every scan that finds something notable.
Delivered rows are pruned on the scheduler tick, on the same schedule as the raw
scanner payloads: both grow with every scan and neither is worth keeping for long.

`status` and `next_attempt_at` are indexed because the relay's query filters on exactly
those two, on every tick, and is expected to return nothing almost every time.

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import zanshin.models.guid
import zanshin.models.safedatetime

revision: str = '0009'
down_revision: Union[str, None] = '0008'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if "outbox_message" in sa.inspect(op.get_bind()).get_table_names():
        return

    op.create_table(
        "outbox_message",
        sa.Column("id", zanshin.models.guid.GUID(), nullable=False),
        sa.Column("message_type", sa.String(length=50), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
        sa.Column("sent_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("outbox_message", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_outbox_message_status"), ["status"], unique=False)
        batch_op.create_index(
            batch_op.f("ix_outbox_message_next_attempt_at"), ["next_attempt_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("outbox_message", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_outbox_message_next_attempt_at"))
        batch_op.drop_index(batch_op.f("ix_outbox_message_status"))
    op.drop_table("outbox_message")
