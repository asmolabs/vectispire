"""Schema management at startup.

Replaces `Base.metadata.create_all`, which could only ever *add* tables — the
limitation docs/architecture/02 records, and the reason every earlier feature had to invent
a new table rather than add a column to an existing one.

Three situations have to be handled, because this application is deployed by
copying the source tree and running it, not by an operator who runs migrations
by hand:

1. **Fresh database** — no tables at all: replay every migration.
2. **Database predating Alembic** — tables exist, no `alembic_version`: stamp
   the baseline revision (its schema is by definition what's already there),
   then apply anything newer. Replaying `0001` here would fail on
   "table already exists".
3. **Already managed** — apply whatever is missing.

Case 2 is what makes the introduction of Alembic invisible to the existing
deployment. It keys off the `user` table: `alembic_version` absent *and* real
tables present means "adopt", not "build".
"""
import fcntl
import logging
import os
import stat
import tempfile
from contextlib import contextmanager

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from zanshin.database import DATABASE_URL, describe_database, engine, is_sqlite, sqlite_file_path

logger = logging.getLogger(__name__)

BASELINE_REVISION = "0001"

# Serialises `upgrade_to_head` across processes.
#
# This runs at import time, and Reflex imports the app module in more than one
# process (and more than once per process). Two upgrades starting together on SQLite
# is not a hypothetical: Alembic treats SQLite DDL as non-transactional, so one
# process applied half of a migration while the other failed on "duplicate column",
# and the version stamp stayed behind — leaving a database that was neither at the
# old revision nor the new one, and that refused every subsequent attempt.
# Placed next to the database rather than in the source tree: the thing being
# serialised is access to *that database*, so two deployments sharing a checkout but
# holding separate databases must not block each other — and a read-only source tree
# must not stop the application from starting.
def _default_lock_path() -> str:
    database_file = sqlite_file_path()
    if database_file:
        return database_file + ".migration.lock"
    # A server database has no local file to sit beside. The lock still serialises
    # the processes on *this* host, which is what the concurrent-import problem
    # actually was; see the caveat in `upgrade_to_head`.
    return os.path.join(tempfile.gettempdir(), "zanshin.migration.lock")


MIGRATION_LOCK_PATH = os.getenv("ZANSHIN_MIGRATION_LOCK") or _default_lock_path()


@contextmanager
def _migration_lock():
    """Hold an exclusive file lock for the duration of the upgrade.

    A file lock rather than a database lock: the thing being serialised is the
    migration *runner*, and at the moment it starts there may be no schema to lock
    against. Blocking (not `LOCK_NB`): the second process should wait and then find
    nothing to do, not fail to start.
    """
    with open(MIGRATION_LOCK_PATH, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALEMBIC_INI_PATH = os.path.join(_PROJECT_ROOT, "alembic.ini")


def _alembic_config() -> Config:
    config = Config(ALEMBIC_INI_PATH)
    config.set_main_option("script_location", os.path.join(_PROJECT_ROOT, "migrations"))
    # The migrations read the URL from `zanshin.database` themselves; setting it
    # here too keeps `alembic` on the command line and this code in agreement
    # even if one of them is invoked from another working directory.
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    return config


def upgrade_to_head() -> None:
    """Bring the database to the latest revision. Raises on failure: starting
    the application against a schema it can't read would fail later anyway, in
    a much more confusing way.

    Can be turned off with `ZANSHIN_AUTO_MIGRATE=false`, for a deployment that runs
    `alembic upgrade head` as its own step. That is the right thing to do with a
    server database on several application hosts: the file lock below serialises the
    processes of one host, and nothing coordinates two hosts starting at once.
    Skipping does not mean ignoring — the schema is still checked, and a database
    behind the code stops the application here rather than at the first query.
    """
    logger.info("Database: %s", describe_database())
    if not auto_migrate_enabled():
        _verify_at_head()
        return
    with _migration_lock():
        _upgrade_to_head_locked()


def auto_migrate_enabled() -> bool:
    return (os.getenv("ZANSHIN_AUTO_MIGRATE") or "true").strip().lower() not in (
        "false", "0", "no", "off"
    )


def _verify_at_head() -> None:
    """Refuse to start against a schema older than the code expects."""
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(_alembic_config())
    head = script.get_current_head()
    with engine.connect() as connection:
        current = MigrationContext.configure(connection).get_current_revision()

    if current == head:
        logger.info("Automatic migration disabled; schema is at head (%s)", head)
        return
    raise RuntimeError(
        f"ZANSHIN_AUTO_MIGRATE est désactivé et le schéma est en révision "
        f"{current or '(aucune)'} alors que le code attend {head}. "
        "Exécutez « alembic upgrade head » avant de démarrer l'application."
    )


def _upgrade_to_head_locked() -> None:
    config = _alembic_config()
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    if "alembic_version" not in tables and "user" in tables:
        logger.info(
            "Existing database with no migration history — stamping baseline revision %s",
            BASELINE_REVISION,
        )
        command.stamp(config, BASELINE_REVISION)

    command.upgrade(config, "head")
    logger.info("Database schema is up to date")
    restrict_database_permissions()


def restrict_database_permissions(path=None) -> None:
    """Make the database file readable by its owner only.

    Only applies to SQLite. It holds bcrypt password hashes and encrypted SSH
    private keys, and SQLite
    creates it with the process umask — 0644 in practice, i.e. readable by every
    local account. Applied at startup rather than documented as a deployment step,
    because a permission that depends on someone remembering it is not a
    permission. Never raises: a read-only or exotic filesystem must not stop the
    application from starting.
    """
    # Takes the path as an argument so it can be called on a database other than the
    # configured one — which is also what makes it testable without reaching into
    # another module's globals.
    path = path or sqlite_file_path()
    if not path:
        # A server database's permissions are the server's business, not a file mode.
        return
    try:
        current = stat.S_IMODE(os.stat(path).st_mode)
        if current & (stat.S_IRWXG | stat.S_IRWXO):
            os.chmod(path, 0o600)
            logger.info("Tightened permissions on %s (%o -> 600)", path, current)
    except OSError as e:
        logger.warning("Could not tighten permissions on %s: %s", path, e)
