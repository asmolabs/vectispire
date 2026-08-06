"""Pointing the application at another database, from inside a test.

`zanshin.database` builds its engine at import time, and the modules that use it do
`from zanshin.database import engine, SessionLocal` — by value. So changing an
environment variable after import changes nothing, and every module that already
grabbed a name has to be given the new one.

Rebinding module attributes is not how one would design this from scratch. The
alternative is worse: threading an engine through `zanshin.schema`,
`zanshin.bootstrap`, `zanshin.api.deps` and the scheduler purely so tests can
substitute one, which would put test seams in production signatures. Confined to
this helper, with the affected modules listed explicitly, it stays legible.
"""
import contextlib
import importlib
import os
import tempfile


# Modules that hold a reference to something from `zanshin.database`, and the names
# they hold. Listed rather than discovered: a name that gets added later should show
# up as a failing test, not be silently patched by a clever scan.
_REBOUND = {
    "zanshin.schema": ("engine", "DATABASE_URL"),
    "zanshin.api.deps": ("SessionLocal",),
    "zanshin.bootstrap": ("SessionLocal",),
    "zanshin.services.scheduler": ("SessionLocal",),
}


class ConfiguredDatabase:
    def __init__(self, url, engine, session_factory, base):
        self.url = url
        self.engine = engine
        self.SessionLocal = session_factory
        self.Base = base


@contextlib.contextmanager
def configured_database(url: str):
    """Run the block with the whole application pointed at `url`.

    Everything is restored on the way out, including the environment, so an
    interrupted test cannot leave the next one writing to a container that is gone.
    """
    import zanshin.database as database

    previous_env = os.environ.get("ZANSHIN_DATABASE_URL")
    os.environ["ZANSHIN_DATABASE_URL"] = url

    engine = database.create_configured_engine(url)
    session_factory = database.sessionmaker(
        autocommit=False, autoflush=False, bind=engine
    )

    saved_database = {
        name: getattr(database, name) for name in ("DATABASE_URL", "engine", "SessionLocal")
    }
    database.DATABASE_URL = url
    database.engine = engine
    database.SessionLocal = session_factory

    saved_modules = {}
    for module_name, attributes in _REBOUND.items():
        module = importlib.import_module(module_name)
        saved_modules[module_name] = {name: getattr(module, name) for name in attributes}
        for name in attributes:
            setattr(module, name, {"engine": engine, "SessionLocal": session_factory,
                                   "DATABASE_URL": url}[name])

    # The lock defaults to a path beside the configured SQLite file; a server URL has
    # none, and a test must not contend with a running application's lock either.
    import zanshin.schema as schema

    saved_lock = schema.MIGRATION_LOCK_PATH
    schema.MIGRATION_LOCK_PATH = os.path.join(
        tempfile.gettempdir(), "zanshin-test.migration.lock"
    )

    try:
        yield ConfiguredDatabase(url, engine, session_factory, database.Base)
    finally:
        schema.MIGRATION_LOCK_PATH = saved_lock
        for module_name, attributes in saved_modules.items():
            module = importlib.import_module(module_name)
            for name, value in attributes.items():
                setattr(module, name, value)
        for name, value in saved_database.items():
            setattr(database, name, value)
        engine.dispose()
        if previous_env is None:
            os.environ.pop("ZANSHIN_DATABASE_URL", None)
        else:
            os.environ["ZANSHIN_DATABASE_URL"] = previous_env
