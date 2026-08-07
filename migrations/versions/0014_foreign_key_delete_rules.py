"""foreign key delete rules

Every foreign key in this schema declared *what* it pointed at and nothing about what
should happen when that thing disappeared. The cascades were ORM-side only, so the
behaviour depended on which layer performed the delete, and it differed per backend:
SQLite ignores foreign keys unless asked, PostgreSQL and MySQL always enforce them. A
delete that silently orphaned rows on a developer's machine therefore raised on a
server — the kind of difference that gets found in production.

Two rules, chosen per column by what the row *means* once its parent is gone:

* **CASCADE** where the row cannot exist without the parent: a scan of a deleted
  target, an issue on a deleted target, a finding of a deleted scan, an AI review of a
  deleted scan.
* **SET NULL** where the row outlives the reference. Three cases, and each was a real
  bug rather than a theoretical one:
  - `issue.first_seen_scan_id` / `last_seen_scan_id`: issues outlive scans by design —
    retention prunes old scans while the issue keeps its history. There is no ORM
    relationship from `Scan` back to these columns, so SQLAlchemy could not have known
    to clear them; deleting a scan on PostgreSQL would simply have failed.
  - `finding.issue_id`: `Issue.findings` had no cascade at all, the hole this migration
    was written to close. SET NULL and not CASCADE because the observation genuinely
    happened; only its attachment to an issue goes away.
  - `repository.ssh_key_id`: deleting a key must not delete the repositories that used
    it. They stay, un-clonable until given another.

Placed after 0013 (`timestamps as real dates`) rather than before, and not by accident:
the SQLite path recreates each table from the *live model definition*, so it has to run
once the models' timestamp types are already what the database holds. Reversed, it would
rewrite the tables with types the next migration changes again.

**Why SQLite is rewritten wholesale.** SQLite cannot alter a constraint; the table has
to be recreated. Alembic's batch mode does that from a table definition, and the
definition used here is the *model's* — which is safe precisely because `alembic check`
is clean before this migration: the only difference between the model and the database
is the delete rules being added. On PostgreSQL and MySQL the constraint is dropped by
its server-chosen name (looked up, not guessed — `finding_scan_id_fkey` there,
`finding_ibfk_1` elsewhere) and recreated.

Revision ID: 0014
Revises: 0013
Create Date: 2026-08-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

import zanshin.models  # noqa: F401 — registers every table on Base.metadata
import zanshin.models.guid
import zanshin.models.safedatetime
from zanshin.database import Base

revision: str = '0014'
down_revision: Union[str, None] = '0013'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table, column, referred table, referred column, rule)
_RULES = [
    ("scan", "repo_id", "repository", "id", "CASCADE"),
    ("scan", "container_id", "container", "id", "CASCADE"),
    ("issue", "repo_id", "repository", "id", "CASCADE"),
    ("issue", "container_id", "container", "id", "CASCADE"),
    ("issue", "first_seen_scan_id", "scan", "id", "SET NULL"),
    ("issue", "last_seen_scan_id", "scan", "id", "SET NULL"),
    ("finding", "scan_id", "scan", "id", "CASCADE"),
    ("finding", "issue_id", "issue", "id", "SET NULL"),
    ("ai_review_result", "scan_id", "scan", "id", "CASCADE"),
    ("repository", "ssh_key_id", "ssh_key", "id", "SET NULL"),
]


def _affected_tables():
    # Ordered, so the recreation happens deterministically and a partial run resumes
    # where it left off rather than in an order that depends on dict iteration.
    seen = []
    for table, *_ in _RULES:
        if table not in seen:
            seen.append(table)
    return seen


def upgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "sqlite":
        _recreate_sqlite_tables()
        return

    inspector = sa.inspect(bind)
    for table, column, referred_table, referred_column, rule in _RULES:
        for existing in inspector.get_foreign_keys(table):
            if column in (existing.get("constrained_columns") or []) and existing.get("name"):
                op.drop_constraint(existing["name"], table, type_="foreignkey")
        op.create_foreign_key(
            f"fk_{table}_{column}",
            table,
            referred_table,
            [column],
            [referred_column],
            ondelete=rule,
        )


def downgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "sqlite":
        # The models carry the rules now, so a copy_from recreation would put them
        # straight back. Downgrading on SQLite would mean hand-writing the previous
        # table definitions, which is a lot of duplication for a state nothing needs to
        # return to — the rules are strictly more correct than their absence.
        return

    for table, column, referred_table, referred_column, _rule in _RULES:
        op.drop_constraint(f"fk_{table}_{column}", table, type_="foreignkey")
        op.create_foreign_key(None, table, referred_table, [column], [referred_column])


def _recreate_sqlite_tables() -> None:
    """Rewrite each affected table from its model definition.

    `recreate="always"` because batch mode otherwise decides for itself whether a
    rewrite is needed, and a constraint change is exactly the case it cannot detect: no
    column is being added or altered, so without this nothing would happen and the
    migration would report success having done nothing.

    The indexes are then recreated explicitly: in SQLite an index is an object of its
    own, and dropping the table takes them with it — batch mode rebuilds the table from
    `copy_from` but not the indexes around it. Found by `alembic check`, which reported
    nine of them missing after the first version of this migration.
    """
    bind = op.get_bind()
    for table in _affected_tables():
        definition = Base.metadata.tables[table]
        with op.batch_alter_table(table, copy_from=definition, recreate="always"):
            pass
        for index in definition.indexes:
            # `checkfirst` so a resumed run does not fail on an index it already made.
            index.create(bind, checkfirst=True)
