"""Schema management at startup.

Replaces `Base.metadata.create_all`, which could only ever *add* tables — the
limitation ADR-001 recorded, and the reason every earlier feature had to invent
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
import logging
import os
import stat

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from zanshin.database import DATABASE_URL, engine

logger = logging.getLogger(__name__)

BASELINE_REVISION = "0001"

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
    a much more confusing way."""
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


def restrict_database_permissions() -> None:
    """Make the database file readable by its owner only.

    It holds bcrypt password hashes and encrypted SSH private keys, and SQLite
    creates it with the process umask — 0644 in practice, i.e. readable by every
    local account. Applied at startup rather than documented as a deployment step,
    because a permission that depends on someone remembering it is not a
    permission. Never raises: a read-only or exotic filesystem must not stop the
    application from starting.
    """
    if not DATABASE_URL.startswith("sqlite:///"):
        return
    path = DATABASE_URL[len("sqlite:///"):]
    try:
        current = stat.S_IMODE(os.stat(path).st_mode)
        if current & (stat.S_IRWXG | stat.S_IRWXO):
            os.chmod(path, 0o600)
            logger.info("Tightened permissions on %s (%o -> 600)", path, current)
    except OSError as e:
        logger.warning("Could not tighten permissions on %s: %s", path, e)
