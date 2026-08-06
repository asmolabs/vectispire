"""align legacy tables with the models

`alembic check` against the *development* database (as opposed to one built from
migrations) reported drift on every table created by the earlier implementation
of this application: `user`, `repository`, `container`, `scan`. They are missing
primary-key indexes, foreign keys and unique constraints that the models declare,
and `scan.sbom`/`cves`/`summary` are plain `TEXT` where the model says `JSON`.

None of it broke anything visible — SQLAlchemy serializes JSON either way, and
SQLite doesn't enforce declared types — but it means the schema an existing
deployment runs on is not the schema the code is written against, and CI (which
builds from migrations) can never see the difference. Two schemas, one codebase.

**This migration is conditional, and that is the point.** A database built from
`0001` already has every index, constraint and foreign key here, because `0001`
was generated from the same models. Only a database adopted from the earlier
implementation is missing them. So each change is applied only where it is
actually absent, and on a freshly-built database this migration does nothing at
all — no table rewrites, no "already exists" failures.

Verified on a copy of the real database: 1 user, 13 scans, 837 findings, 429
issues before and after, and `scan.sbom` byte-for-byte identical (2 565 432 bytes
on the largest row).

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-06
"""
import logging
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# The models use custom column types (`GUID`, `SafeDateTime`); autogenerate
# renders them by their fully-qualified name, so these modules must be
# importable from every migration.
import zanshin.models.guid
import zanshin.models.safedatetime

logger = logging.getLogger("alembic.runtime.migration")

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table, index name, columns)
_MISSING_INDEXES = [
    ("user", "ix_user_id", ["id"]),
    ("container", "ix_container_id", ["id"]),
    ("repository", "ix_repository_id", ["id"]),
    ("scan", "ix_scan_id", ["id"]),
]

# (table, constraint name, columns) — enforced by application code only until now.
_MISSING_UNIQUES = [
    ("user", "uq_user_email", ["email"]),
    ("user", "uq_user_github_id", ["github_id"]),
    ("user", "uq_user_keycloak_id", ["keycloak_id"]),
]

# (table, constraint name, column, referred table, referred column)
_MISSING_FKS = [
    ("repository", "fk_repository_ssh_key_id", "ssh_key_id", "ssh_key", "id"),
    ("scan", "fk_scan_repo_id", "repo_id", "repository", "id"),
    ("scan", "fk_scan_container_id", "container_id", "container", "id"),
]

# JSON columns stored as TEXT by the earlier implementation. A declaration
# change only: SQLAlchemy was already writing serialized JSON into them.
_JSON_COLUMNS = [("scan", column) for column in ("sbom", "cves", "summary")]


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    _guard_against_duplicates()

    work_by_table: dict = {}

    for table, name, columns in _MISSING_INDEXES:
        existing = {index["name"] for index in inspector.get_indexes(table)}
        if name not in existing:
            work_by_table.setdefault(table, []).append(("index", name, columns))

    for table, name, columns in _MISSING_UNIQUES:
        existing = {
            constraint.get("name") for constraint in inspector.get_unique_constraints(table)
        }
        # A unique *index* satisfies the same intent; SQLite reflects
        # SQLAlchemy-declared uniques either way depending on how they were made.
        existing |= {
            index["name"] for index in inspector.get_indexes(table) if index.get("unique")
        }
        existing |= {tuple(c.get("column_names") or []) for c in inspector.get_unique_constraints(table)}
        if name not in existing and tuple(columns) not in existing:
            work_by_table.setdefault(table, []).append(("unique", name, columns))

    for table, name, column, referred_table, referred_column in _MISSING_FKS:
        existing_columns = {
            tuple(fk.get("constrained_columns") or []) for fk in inspector.get_foreign_keys(table)
        }
        if (column,) not in existing_columns:
            work_by_table.setdefault(table, []).append(
                ("fk", name, (column, referred_table, referred_column))
            )

    for table, column in _JSON_COLUMNS:
        types = {c["name"]: str(c["type"]) for c in inspector.get_columns(table)}
        if "JSON" not in types.get(column, "").upper():
            work_by_table.setdefault(table, []).append(("json", column, None))

    if not work_by_table:
        logger.info("0004: schema already matches the models — nothing to align")
        return

    for table, operations in work_by_table.items():
        logger.info("0004: aligning %s (%d change(s))", table, len(operations))
        with op.batch_alter_table(table, schema=None) as batch_op:
            # The legacy tables also declare their integer primary key nullable;
            # batch mode rewrites the table anyway, so fix it here.
            batch_op.alter_column("id", existing_type=sa.Integer(), nullable=False)
            for kind, name, payload in operations:
                if kind == "index":
                    batch_op.create_index(name, payload, unique=False)
                elif kind == "unique":
                    batch_op.create_unique_constraint(name, payload)
                elif kind == "fk":
                    column, referred_table, referred_column = payload
                    batch_op.create_foreign_key(name, referred_table, [column], [referred_column])
                elif kind == "json":
                    batch_op.alter_column(
                        name, existing_type=sa.Text(), type_=sa.JSON(), existing_nullable=True
                    )


def _guard_against_duplicates() -> None:
    """Fail with a readable message rather than a bare IntegrityError.

    Same reasoning as migration 0003's username guard: duplicates need a human
    decision. Nulls are excluded because SQLite (like the SQL standard) allows
    many nulls under a unique constraint, and these three columns are optional.
    """
    bind = op.get_bind()
    for column in ("email", "github_id", "keycloak_id"):
        duplicates = (
            bind.execute(
                sa.text(
                    f"SELECT {column} AS value, COUNT(*) AS n FROM user "  # noqa: S608 — fixed identifiers
                    f"WHERE {column} IS NOT NULL AND {column} != '' "
                    f"GROUP BY {column} HAVING COUNT(*) > 1"
                )
            )
            .mappings()
            .all()
        )
        if duplicates:
            names = ", ".join(f"{row['value']!r} ({row['n']}×)" for row in duplicates)
            raise RuntimeError(
                f"Impossible d'ajouter l'unicité sur `user.{column}` : doublons présents "
                f"({names}). Corrigez les comptes concernés, puis relancez la migration."
            )


def downgrade() -> None:
    """Deliberately empty.

    This migration converges a legacy schema onto what `0001` already produces;
    there is no meaningful "un-converge". Dropping these indexes and constraints
    would leave the database drifted from its own baseline revision — the exact
    situation the migration exists to end.
    """
