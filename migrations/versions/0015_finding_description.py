"""finding description

`Finding` had nowhere to put what a tool actually *said*. It carries an identifier, a
severity, a file and a line, and for a CVE that is enough — `CVE-2024-12345` is a
lookup key, and the prose lives in the advisory. For a Semgrep result it is not: the
rule id and the line tell a reviewer that something is wrong there, never what.

Three features had already worked around the gap rather than close it. The end-of-life
service rebuilds a French sentence out of `package_name` and `package_version`, which
works only because the sentence is a template. The AI review writes its narrative into
a table of its own, `ai_review_result`. The issue layer accepts a `descriptions` map
keyed by identifier, which cannot hold a per-occurrence message at all — ten hits of one
Semgrep rule share one key and would keep an arbitrary one of the ten.

So: one nullable `Text` column. Additive, no backfill, no data migration. `Text` rather
than a bounded string because these messages run to a paragraph, and truncating an
explanation leaves the reader worse off than having none.

Revision ID: 0015
Revises: 0014
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("finding", sa.Column("description", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("finding", "description")
