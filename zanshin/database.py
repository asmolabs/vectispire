"""Database configuration.

Where the data lives is a deployment decision, and it was only half a decision
before: `ZANSHIN_DATABASE_URL` existed, but the engine was built with
`connect_args={"check_same_thread": False}` unconditionally — a SQLite-only
argument — so any other dialect failed at import with a `TypeError` from the
driver. The variable looked like a supported knob and was one only for SQLite
files.

Two knobs now, in order of precedence:

1. `ZANSHIN_DATABASE_URL` — a full SQLAlchemy URL. Use it for anything that is not
   a local file (`postgresql+psycopg://user:pass@host/zanshin`).
2. `ZANSHIN_DB_PATH` — a path to a SQLite file. The common case deserves the
   simpler knob: keeping the data outside the source tree should not require
   knowing SQLAlchemy's URL syntax, and a bare path is also what is easy to get
   right in a systemd unit or a compose file.

Default: `zanshin/database.sqlite`, next to this module, which is what every
existing deployment already uses.

Engine options are chosen per dialect rather than shared, because the two cases
want opposite things: SQLite needs its cross-thread check disabled (the scan pool
and Reflex's event loop touch the same connection pool) and a busy timeout so a
concurrent writer waits instead of failing; a server database needs connection
pooling and `pool_pre_ping`, which are meaningless for a file.
"""
import logging
import os

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError, NoSuchModuleError
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "database.sqlite"))


class DatabaseConfigurationError(RuntimeError):
    """The configured database cannot be used, with a reason worth reading.

    Raised at import rather than at first query: a URL typo or a missing driver
    should stop the application immediately, not surface later as a failed request
    with a stack trace from inside SQLAlchemy.
    """


def resolve_database_url() -> str:
    """The configured URL, from either knob or the default."""
    explicit_url = (os.getenv("ZANSHIN_DATABASE_URL") or "").strip()
    if explicit_url:
        return explicit_url

    path = (os.getenv("ZANSHIN_DB_PATH") or "").strip()
    if path:
        # Absolute, because a relative path would resolve against the working
        # directory — which differs between `reflex run`, `alembic` on the command
        # line and a systemd unit, i.e. three different databases from one setting.
        return f"sqlite:///{os.path.abspath(os.path.expanduser(path))}"

    return f"sqlite:///{DEFAULT_DB_PATH}"


DATABASE_URL = resolve_database_url()


def is_sqlite(url=None) -> bool:
    """Default `None`, not `DATABASE_URL`: a default argument is evaluated once at
    import, so a caller that reassigns the module's URL — a test, or code that
    reconfigures before the engine is built — would be silently ignored."""
    url = url if url is not None else DATABASE_URL
    try:
        return make_url(url).get_backend_name() == "sqlite"
    except Exception:
        return url.startswith("sqlite")


def sqlite_file_path(url=None):
    """The file behind a SQLite URL, or `None` for anything else.

    One place to answer this, because three callers need it for reasons that have
    nothing to do with SQLAlchemy: tightening the file's permissions, placing the
    migration lock next to it, and reporting what is actually in use at startup.
    """
    url = url if url is not None else DATABASE_URL
    if not is_sqlite(url):
        return None
    database = make_url(url).database
    # `sqlite://` with no path is the in-memory database — there is no file.
    return os.path.abspath(database) if database else None


# Kept for the callers that predate `sqlite_file_path` and for the common case
# where the answer is simply "the default file".
DB_PATH = sqlite_file_path() or DEFAULT_DB_PATH


def _engine_options(url: str) -> dict:
    if is_sqlite(url):
        return {
            "connect_args": {
                # The scan pool's worker threads and Reflex's event loop both reach
                # the same pool; SQLite's own guard would reject that.
                "check_same_thread": False,
                # Wait for a concurrent writer instead of raising "database is
                # locked" straight away. Zanshin writes from several threads (scan
                # workers, the scheduler, requests), so contention is normal rather
                # than exceptional.
                "timeout": float(os.getenv("ZANSHIN_DB_TIMEOUT_SECONDS", "30")),
            },
        }
    return {
        # A pooled connection can have been closed by the server, a proxy or a
        # firewall while it sat idle; without this the next request gets the stale
        # one and fails for reasons that have nothing to do with itself.
        "pool_pre_ping": True,
        "pool_size": int(os.getenv("ZANSHIN_DB_POOL_SIZE", "5")),
        "max_overflow": int(os.getenv("ZANSHIN_DB_MAX_OVERFLOW", "10")),
        "pool_recycle": int(os.getenv("ZANSHIN_DB_POOL_RECYCLE_SECONDS", "1800")),
    }


def create_configured_engine(url=None):
    """Build the engine, turning every way this fails into a readable error."""
    url = url if url is not None else DATABASE_URL
    try:
        return create_engine(url, **_engine_options(url))
    except NoSuchModuleError as e:
        raise DatabaseConfigurationError(
            f"Dialecte de base de données inconnu dans ZANSHIN_DATABASE_URL : {e}. "
            "Exemples valides : sqlite:////chemin/zanshin.sqlite, "
            "postgresql+psycopg://utilisateur:motdepasse@hôte/zanshin"
        ) from e
    except ModuleNotFoundError as e:
        raise DatabaseConfigurationError(
            f"Le pilote de base de données requis n'est pas installé ({e.name}). "
            "Pour PostgreSQL : uv sync --extra postgres"
        ) from e
    except ArgumentError as e:
        raise DatabaseConfigurationError(
            f"URL de base de données invalide : {e}"
        ) from e


engine = create_configured_engine()


def enable_sqlite_foreign_keys(target_engine) -> None:
    """Make SQLite enforce the foreign keys it declares.

    SQLite parses `REFERENCES` clauses and then ignores them unless asked, per
    connection. PostgreSQL and MySQL always enforce them, so without this the same
    schema had two behaviours: a delete that silently orphaned rows on the development
    machine raised on a server — the sort of difference that is found in production.

    Now that every foreign key carries an `ondelete` rule (migration 0013), enforcing
    them here makes the three backends agree. Registered per engine rather than
    globally so a test engine gets the same treatment.
    """
    if not is_sqlite(str(target_engine.url)):
        return

    @event.listens_for(target_engine, "connect")
    def _set_pragma(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


enable_sqlite_foreign_keys(engine)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def describe_database() -> str:
    """What is actually in use, safe to log — credentials removed.

    Worth a line at startup: the failure this prevents is an operator who set the
    variable in the wrong place and spent an afternoon looking at an empty
    dashboard backed by a second, unnoticed database.
    """
    url = make_url(DATABASE_URL)
    return sqlite_file_path() or url.render_as_string(hide_password=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
