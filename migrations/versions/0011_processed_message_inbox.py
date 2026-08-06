"""processed message inbox

Deduplication of inbound messages, which agents make necessary: an agent that
posts a scan result and loses the response cannot know whether it arrived, so it
retries. The retry does not create duplicate findings (`Issue.fingerprint` already
prevents that) but it does re-run `sync_from_scan`, which increments `times_seen`
— inflating the history of every issue in the report without leaving a visible
duplicate behind.

The row is written in the same transaction as the effect it records, so a crash
cannot leave one without the other.

Revision ID: 0011
Revises: 0010
Create Date: 2026-08-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import zanshin.models.guid
import zanshin.models.safedatetime

revision: str = '0011'
down_revision: Union[str, None] = '0010'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if "processed_message" in sa.inspect(op.get_bind()).get_table_names():
        return

    op.create_table(
        "processed_message",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("message_id", sa.String(length=64), nullable=False),
        sa.Column("message_type", sa.String(length=50), nullable=False),
        sa.Column("agent_id", zanshin.models.guid.GUID(), nullable=True),
        sa.Column("processed_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("processed_message", schema=None) as batch_op:
        # Unique, and that uniqueness is the mechanism rather than a safety net:
        # two retries arriving at once would both pass an application-level
        # "already processed?" check, and only the database can arbitrate.
        batch_op.create_index(
            batch_op.f("ix_processed_message_message_id"), ["message_id"], unique=True
        )


def downgrade() -> None:
    with op.batch_alter_table("processed_message", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_processed_message_message_id"))
    op.drop_table("processed_message")
