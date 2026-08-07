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

**Why SQLite is rewritten wholesale.** SQLite cannot alter a constraint; the table has
to be recreated. Alembic's batch mode does that from a table definition, and the
definition used here is **reflected from the database**, with only the foreign keys this
revision governs substituted in. On PostgreSQL and MySQL the constraint is dropped by
its server-chosen name (looked up, not guessed — `finding_scan_id_fkey` there,
`finding_ibfk_1` elsewhere) and recreated.

That definition used to come from the live models instead, and it was a real bug: see
`_recreate_sqlite_tables`. It also made the position of this revision matter — it had to
sit after 0013 so the models' timestamp types already matched the database. Reflection
removes that coupling entirely; the revision now describes only its own point in
history.

Revision ID: 0014
Revises: 0013
Create Date: 2026-08-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

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
        # Downgrading on SQLite would mean recreating each table with its rules stripped
        # — the mirror image of the upgrade, for a state nothing needs to return to. The
        # rules are strictly more correct than their absence, so the effort buys nothing.
        return

    for table, column, referred_table, referred_column, _rule in _RULES:
        op.drop_constraint(f"fk_{table}_{column}", table, type_="foreignkey")
        op.create_foreign_key(None, table, referred_table, [column], [referred_column])


def _recreate_sqlite_tables() -> None:
    """Rewrite each affected table, keeping its shape and changing only its foreign keys.

    `recreate="always"` because batch mode otherwise decides for itself whether a
    rewrite is needed, and a constraint change is exactly the case it cannot detect: no
    column is being added or altered, so without this nothing would happen and the
    migration would report success having done nothing.

    The indexes are then recreated explicitly: in SQLite an index is an object of its
    own, and dropping the table takes them with it — batch mode rebuilds the table from
    `copy_from` but not the indexes around it. Found by `alembic check`, which reported
    nine of them missing after the first version of this migration.

    **The definition is reflected from the database, not read from the models**, and
    that changed after this migration first shipped. Reading the live models made the
    rewrite describe whatever the application looks like *today* rather than what the
    schema looks like *at this revision*, so the first column added afterwards
    (`finding.description`, revision 0015) broke every fresh SQLite install: batch mode
    emitted `INSERT INTO … SELECT finding.description FROM finding` against a table that
    would not have that column until the next revision. A migration has to describe its
    own point in history; reflection is how it does that, and it makes this one immune to
    every future model change instead of only the ones nobody has made yet.
    """
    bind = op.get_bind()
    for table in _affected_tables():
        definition = _reflect_with_delete_rules(bind, table)
        with op.batch_alter_table(table, copy_from=definition, recreate="always"):
            pass
        for index in definition.indexes:
            # `checkfirst` so a resumed run does not fail on an index it already made.
            index.create(bind, checkfirst=True)


def _reflect_with_delete_rules(bind, table: str) -> sa.Table:
    """The table as it exists, with this revision's `ON DELETE` rules substituted in.

    Reflection alone would recreate the table identically, rules included — which is to
    say it would do nothing. So the columns are copied as reflected and the foreign keys
    this revision governs are replaced with ones carrying their rule.
    """
    reflected = sa.Table(table, sa.MetaData(), autoload_with=bind)
    rules = {
        column: (referred_table, referred_column, rule)
        for governed_table, column, referred_table, referred_column, rule in _RULES
        if governed_table == table
    }

    columns = []
    for column in reflected.columns:
        copied = column._copy()
        # `_copy()` carries the reflected foreign keys along; drop them so the governed
        # ones can be re-declared with their rule and the others reflected untouched.
        copied.foreign_keys = set()
        for original in column.foreign_keys:
            if column.name in rules:
                referred_table, referred_column, rule = rules[column.name]
                copied.append_foreign_key(
                    sa.ForeignKey(f"{referred_table}.{referred_column}", ondelete=rule)
                )
            else:
                copied.append_foreign_key(sa.ForeignKey(original.target_fullname))
        columns.append(copied)

    # Unique constraints travel separately from the columns, and losing one is silent:
    # the table rebuilds fine and only stops rejecting duplicates. `uq_issue_fingerprint`
    # is what makes an issue's identity across scans a *single* row.
    uniques = [
        sa.UniqueConstraint(
            *[column.name for column in constraint.columns], name=constraint.name
        )
        for constraint in reflected.constraints
        if isinstance(constraint, sa.UniqueConstraint)
    ]

    definition = sa.Table(table, sa.MetaData(), *columns, *uniques)
    for index in reflected.indexes:
        sa.Index(
            index.name,
            *[definition.columns[column.name] for column in index.columns],
            unique=index.unique,
        )
    return definition
