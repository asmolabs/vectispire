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
