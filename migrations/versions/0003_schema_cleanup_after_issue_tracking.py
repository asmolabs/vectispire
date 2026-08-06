"""schema cleanup after issue tracking

Four changes, all of them things that were previously impossible (no migration
tool) or pointless (superseded by `issue`):

1. `scan.error` becomes `Text`. The 255-character limit is what forced a
   budget-splitting trimmer in the Docker engine — ~35 lines whose only job was
   to make a scanner's own explanation fit. That code goes away with this column
   change.
2. `finding.status` and `finding.vex_decision_id` are dropped, and with them the
   `vex_decision` table. All three were superseded by `issue`: state and triage
   live there. `finding.status` was written once as "open" and never read;
   `vex_decision` was never written to at all.
3. `finding.scan_id` gets an index. `count_by_scan_ids_and_type` filters on it
   on every list and history render, and it was a table scan.
4. `user.username` gets its unique index. The model declared `unique=True`, but
   the legacy table (created by an earlier implementation) never had it, so
   uniqueness rested on a read-then-write in `UserService` — two concurrent
   creations of the same login both succeeded. The migration fails loudly if
   duplicates already exist, which is the correct outcome: they need a human
   decision, not a silent pick.

Revision ID: 0003
Revises: 0002
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

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Note: the foreign key columns created here were originally `BigInteger` against
    # `Integer` primary keys, which MySQL refuses. Amended so a fresh database can be
    # built on any backend; databases created by the original are corrected by 0007.
    _guard_against_duplicate_usernames()

    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.alter_column(
            "error",
            existing_type=sa.String(length=255),
            type_=sa.Text(),
            existing_nullable=True,
        )

    # MySQL refuses to drop a column that a foreign key still needs, so the
    # constraint goes first. Its name is whatever the server chose when the baseline
    # created it (`finding_ibfk_2` on MySQL, `finding_vex_decision_id_fkey` on
    # PostgreSQL, nothing at all on SQLite), so it is looked up rather than guessed.
    _drop_foreign_keys_on("finding", "vex_decision_id")

    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.drop_column("vex_decision_id")
        batch_op.drop_column("status")
        batch_op.create_index(batch_op.f("ix_finding_scan_id"), ["scan_id"], unique=False)

    op.drop_table("vex_decision")

    # Replaces the non-unique legacy index of the same name, if present. Checked by
    # inspection rather than with `if_exists=True`: MySQL has no
    # `DROP INDEX IF EXISTS` and fails on the syntax itself.
    with op.batch_alter_table("user", schema=None) as batch_op:
        if _has_index("user", "ix_user_username"):
            batch_op.drop_index("ix_user_username")
        batch_op.create_index("ix_user_username", ["username"], unique=True)


def _has_index(table: str, index_name: str) -> bool:
    return any(
        index["name"] == index_name
        for index in sa.inspect(op.get_bind()).get_indexes(table)
    )


def _drop_foreign_keys_on(table: str, column: str) -> None:
    """Drop any foreign key constraint that covers `column`.

    SQLite has no `ALTER TABLE ... DROP CONSTRAINT` and does not need one — batch mode
    rewrites the table without the column, constraint included — so it is skipped
    there. Unnamed constraints are skipped too: there is nothing to address them by,
    and the backends that require this step always name them.
    """
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    for constraint in sa.inspect(bind).get_foreign_keys(table):
        if column in (constraint.get("constrained_columns") or []) and constraint.get("name"):
            op.drop_constraint(constraint["name"], table, type_="foreignkey")


def _guard_against_duplicate_usernames() -> None:
    """Refuse to continue if the data contradicts the constraint being added.

    Creating the unique index would fail anyway; failing here means the error
    names the actual problem instead of surfacing as a bare IntegrityError.
    """
    # Built from SQLAlchemy constructs rather than raw SQL so the identifier is
    # quoted per dialect: `user` is a reserved word in PostgreSQL, where an
    # unquoted `FROM user` resolves to the current_user function and the query
    # fails with "column username does not exist".
    user_table = sa.table("user", sa.column("username"))
    count = sa.func.count().label("n")
    duplicates = (
        op.get_bind()
        .execute(
            sa.select(user_table.c.username, count)
            .group_by(user_table.c.username)
            .having(count > 1)
        )
        .mappings()
        .all()
    )
    if duplicates:
        names = ", ".join(f"{row['username']!r} ({row['n']}×)" for row in duplicates)
        raise RuntimeError(
            "Impossible d'ajouter l'unicité sur `user.username` : doublons présents "
            f"({names}). Renommez ou supprimez les comptes en doublon, puis relancez la migration."
        )


def downgrade() -> None:
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_index("ix_user_username")
        batch_op.create_index("ix_user_username", ["username"], unique=False)

    op.create_table(
        "vex_decision",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=255), nullable=False),
        sa.Column("package_name", sa.String(length=255), nullable=False),
        sa.Column("purl", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=255), nullable=False),
        sa.Column("justification", sa.String(length=255), nullable=True),
        sa.Column("response", sa.String(length=255), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
        sa.Column("updated_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
        sa.Column("repository_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["repository_id"], ["repository.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("vex_decision", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_vex_decision_id"), ["id"], unique=False)

    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_finding_scan_id"))
        batch_op.add_column(
            sa.Column("status", sa.String(length=50), nullable=False, server_default="open")
        )
        batch_op.add_column(sa.Column("vex_decision_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_finding_vex_decision_id", "vex_decision", ["vex_decision_id"], ["id"]
        )

    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.alter_column(
            "error",
            existing_type=sa.Text(),
            type_=sa.String(length=255),
            existing_nullable=True,
        )
