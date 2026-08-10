"""Alembic environment.

Takes both the target metadata and the database URL from the application
itself, so `alembic` on the command line and Zanshin at startup can never
operate on different databases or compare against a stale schema.
"""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from zanshin.database import DATABASE_URL, Base
from zanshin.models.guid import GUID
from zanshin.models.safedatetime import SafeDateTime
import zanshin.models  # noqa: F401 — registers every model on Base.metadata

config = context.config
config.set_main_option("sqlalchemy.url", DATABASE_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# SQLite stores `GUID` as NUMERIC and hands `SafeDateTime` back as TIMESTAMP, so
# reflection never returns these as themselves and autogenerate reports a type
# change on every single run. Suppressing the comparison for these two types (and
# only these two) is what makes `alembic check` a usable CI gate: without it, the
# check fails permanently and stops meaning anything.
#
# Still true for `SafeDateTime` now that it is a real timestamp rather than text:
# what reflection returns is `TIMESTAMP` on SQLite and `TIMESTAMP WITHOUT TIME ZONE`
# on PostgreSQL, neither of which compares equal to the decorator.
# `tests/test_timestamp_migration_backends.py` checks the conversion
# produces what the models declare, which is the guarantee this exclusion gives up.
_UNRELIABLY_REFLECTED_TYPES = (GUID, SafeDateTime)

# Tables créées par les migrations mais dont aucun modèle SQLAlchemy ne parle, parce
# qu'elles appartiennent au plan de contrôle TypeScript (voir
# docs/migration-nestjs-angular.md). Sans cette exclusion, `alembic check` proposerait
# de les supprimer à chaque exécution — elles sont dans la base et absentes de
# `Base.metadata`.
#
# Déclarer des modèles Python inutilisés pour faire taire la vérification serait pire :
# du code mort qui prétend décrire quelque chose que Python n'écrit jamais, et qui
# dériverait en silence de ce que les entités TypeORM décrivent réellement. C'est
# `backend/src/persistence/schema-parity.integration-spec.ts` qui vérifie ces tables-là,
# contre le schéma que produisent ces mêmes migrations.
_OWNED_BY_TYPESCRIPT = frozenset({"session", "login_attempt"})


def _include_object(obj, name, type_, reflected, compare_to):
    if type_ == "table" and name in _OWNED_BY_TYPESCRIPT:
        return False
    # Un index porté par l'une de ces tables suit sa table.
    if type_ == "index" and getattr(obj, "table", None) is not None:
        return obj.table.name not in _OWNED_BY_TYPESCRIPT
    return True


def _compare_type(context, inspected_column, metadata_column, inspected_type, metadata_type):
    if isinstance(metadata_type, _UNRELIABLY_REFLECTED_TYPES):
        return False
    # `None` defers to Alembic's own comparison for every other type.
    return None


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=_compare_type,
        include_object=_include_object,
        dialect_opts={"paramstyle": "named"},
        # SQLite cannot ALTER most things in place; batch mode rewrites the
        # table instead, which is what makes column changes possible at all
        # here (the limitation recorded in docs/architecture/02).
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=_compare_type,
            include_object=_include_object,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
