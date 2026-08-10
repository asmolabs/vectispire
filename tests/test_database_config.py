"""Tests for how the database is configured.

The bug these exist to prevent is not a crash: it is a setting that looks like it
worked. `ZANSHIN_DATABASE_URL` was documented as the way to point Zanshin at
another database, and the engine passed SQLite-only connect arguments regardless of
dialect — so the variable was real for one dialect and a trap for the rest. In the
same spirit, `ZANSHIN_DB_PATH` is tested here because a *relative* path silently
resolves against the working directory, which differs between `reflex run`,
`alembic` on the command line and a systemd unit: one setting, three databases.
"""
import os

import pytest

from zanshin.database import (
    DEFAULT_DB_PATH,
    SUPPORTED_BACKENDS,
    DatabaseConfigurationError,
    assert_backend_supported,
    create_configured_engine,
    describe_database,
    is_sqlite,
    resolve_database_url,
    sqlite_file_path,
    _engine_options,
)


@pytest.fixture(autouse=True)
def _no_inherited_configuration(monkeypatch):
    monkeypatch.delenv("ZANSHIN_DATABASE_URL", raising=False)
    monkeypatch.delenv("ZANSHIN_DB_PATH", raising=False)


# --- Which database is chosen ---

def test_the_default_is_the_file_in_the_source_tree():
    assert resolve_database_url() == f"sqlite:///{DEFAULT_DB_PATH}"


def test_a_path_is_enough_for_the_common_case(monkeypatch, tmp_path):
    """Keeping the data outside the source tree should not require knowing
    SQLAlchemy's URL syntax."""
    monkeypatch.setenv("ZANSHIN_DB_PATH", str(tmp_path / "zanshin.sqlite"))

    assert resolve_database_url() == f"sqlite:///{tmp_path / 'zanshin.sqlite'}"


def test_a_relative_path_is_made_absolute(monkeypatch):
    """Otherwise it resolves against the working directory, which is not the same
    for `reflex run`, `alembic` and a service unit — three databases from one
    setting, and the symptom is an empty dashboard rather than an error."""
    monkeypatch.setenv("ZANSHIN_DB_PATH", "data/zanshin.sqlite")

    url = resolve_database_url()

    assert url.startswith("sqlite:////") or url.startswith(f"sqlite:///{os.sep}")
    assert os.path.isabs(url[len("sqlite:///"):])


def test_a_home_relative_path_is_expanded(monkeypatch):
    monkeypatch.setenv("ZANSHIN_DB_PATH", "~/zanshin.sqlite")

    assert os.path.expanduser("~") in resolve_database_url()


def test_a_full_url_wins_over_a_path(monkeypatch):
    """Both set is a misconfiguration, and the more specific setting is the one the
    operator reached for deliberately."""
    monkeypatch.setenv("ZANSHIN_DB_PATH", "/tmp/ignored.sqlite")
    monkeypatch.setenv("ZANSHIN_DATABASE_URL", "postgresql+psycopg://u:p@db/zanshin")

    assert resolve_database_url() == "postgresql+psycopg://u:p@db/zanshin"


def test_an_empty_variable_is_not_a_setting(monkeypatch):
    """`ZANSHIN_DATABASE_URL=` in a compose file means "unset", not "connect to
    nothing"."""
    monkeypatch.setenv("ZANSHIN_DATABASE_URL", "   ")

    assert resolve_database_url() == f"sqlite:///{DEFAULT_DB_PATH}"


# --- Dialect awareness ---

def test_the_dialect_is_recognised():
    assert is_sqlite("sqlite:////var/lib/zanshin.sqlite") is True
    assert is_sqlite("postgresql+psycopg://u:p@db/zanshin") is False


def test_the_sqlite_file_is_extracted():
    assert sqlite_file_path("sqlite:////var/lib/zanshin.sqlite") == "/var/lib/zanshin.sqlite"


def test_a_server_database_has_no_file():
    """Asked by three callers for reasons that have nothing to do with SQLAlchemy:
    tightening file permissions, placing the migration lock, and reporting what is
    in use."""
    assert sqlite_file_path("postgresql+psycopg://u:p@db/zanshin") is None


def test_the_in_memory_database_has_no_file():
    assert sqlite_file_path("sqlite://") is None


def test_sqlite_gets_its_cross_thread_check_disabled_and_a_busy_timeout():
    options = _engine_options("sqlite:////var/lib/zanshin.sqlite")

    assert options["connect_args"]["check_same_thread"] is False
    # Scan workers, the scheduler and requests all write; waiting for a lock beats
    # failing on one.
    assert options["connect_args"]["timeout"] > 0
    assert "pool_size" not in options


def test_a_server_database_gets_pooling_and_not_sqlite_arguments():
    """The defect this encodes: `check_same_thread` was passed to every dialect, so
    a PostgreSQL URL failed inside the driver — the documented knob was a trap."""
    options = _engine_options("postgresql+psycopg://u:p@db/zanshin")

    assert "connect_args" not in options
    assert options["pool_pre_ping"] is True
    assert options["pool_size"] >= 1


def test_the_pool_is_tunable(monkeypatch):
    monkeypatch.setenv("ZANSHIN_DB_POOL_SIZE", "20")

    assert _engine_options("postgresql+psycopg://u:p@db/zanshin")["pool_size"] == 20


# --- Failing usefully ---

def test_an_unknown_dialect_names_the_problem():
    """At import, not at the first query: a URL typo should stop the application,
    not surface later as a failed request with a stack trace from SQLAlchemy."""
    with pytest.raises(DatabaseConfigurationError, match="Dialecte"):
        create_configured_engine("nosuchdialect://u:p@db/zanshin")


def test_an_unparseable_url_names_the_problem():
    with pytest.raises(DatabaseConfigurationError):
        create_configured_engine("this is not a url")


# --- Which backends are supported ---

@pytest.mark.parametrize("url", [
    "sqlite:////tmp/zanshin.sqlite",
    "postgresql+psycopg://u:p@db/zanshin",
])
def test_the_supported_backends_are_accepted(url):
    assert_backend_supported(url)


@pytest.mark.parametrize("url", [
    "mysql+pymysql://u:p@db/zanshin",
    "mariadb+pymysql://u:p@db/zanshin",
])
def test_a_withdrawn_backend_is_refused_and_says_so(url):
    """MySQL is refused rather than left to work by accident.

    This is the whole point of removing it explicitly: SQLAlchemy would connect happily
    and most of Zanshin would function, so an operator who kept a MySQL URL would meet
    the removal months later, as an audit log declaring itself tampered with. The message
    has to name what happened and what to do instead — an "unsupported dialect" would
    send the reader hunting for a typo.
    """
    with pytest.raises(DatabaseConfigurationError) as failure:
        assert_backend_supported(url)

    message = str(failure.value)
    assert "PostgreSQL" in message, "the message must say what to migrate to"
    assert "audit" in message.lower() or "falsifié" in message, (
        "the message must say why, or it reads as an arbitrary removal"
    )


def test_the_refusal_also_guards_the_engine_factory():
    """Every engine goes through one door, including the ones tests and tooling build."""
    with pytest.raises(DatabaseConfigurationError):
        create_configured_engine("mysql+pymysql://u:p@db/zanshin")


def test_an_unparseable_url_is_left_to_the_url_parser():
    """`assert_backend_supported` must not claim a typo is an unsupported dialect."""
    assert_backend_supported("this is not a url")


def test_the_supported_list_is_the_two_backends_the_suite_covers():
    """A guard on the list itself: adding a backend here without tests would make this
    module's other assertions vacuous."""
    assert SUPPORTED_BACKENDS == ("sqlite", "postgresql")


def test_the_password_is_not_logged(monkeypatch):
    """`describe_database` exists to be logged at startup — the failure it prevents
    is an operator pointing the variable at the wrong place and spending an
    afternoon on an empty dashboard — so it must not put credentials in the log."""
    import zanshin.database as database

    monkeypatch.setattr(database, "DATABASE_URL", "postgresql+psycopg://user:s3cret@db/zanshin")

    described = database.describe_database()

    assert "s3cret" not in described
    assert "db/zanshin" in described


def test_a_sqlite_deployment_is_described_by_its_file(monkeypatch):
    import zanshin.database as database

    monkeypatch.setattr(database, "DATABASE_URL", "sqlite:////var/lib/zanshin.sqlite")

    assert database.describe_database() == "/var/lib/zanshin.sqlite"


# --- Startup migration ---

@pytest.mark.parametrize("value,expected", [
    (None, True), ("true", True), ("1", True), ("", True),
    ("false", False), ("0", False), ("no", False), ("off", False), ("FALSE", False),
])
def test_automatic_migration_can_be_turned_off(monkeypatch, value, expected):
    """A server database on several application hosts should migrate as its own
    deployment step: the file lock serialises the processes of one host, and nothing
    coordinates two hosts starting at once."""
    from zanshin.schema import auto_migrate_enabled

    if value is None:
        monkeypatch.delenv("ZANSHIN_AUTO_MIGRATE", raising=False)
    else:
        monkeypatch.setenv("ZANSHIN_AUTO_MIGRATE", value)

    assert auto_migrate_enabled() is expected


def test_the_migration_lock_sits_next_to_the_database(monkeypatch):
    """Not in the source tree: two deployments sharing a checkout but holding
    separate databases must not block each other, and a read-only checkout must not
    stop the application from starting.

    Asserted through the function rather than the module constant, so the test does
    not depend on which database the test run itself was configured with.
    """
    import zanshin.database as database
    import zanshin.schema as schema

    monkeypatch.setattr(database, "DATABASE_URL", "sqlite:////var/lib/zanshin.sqlite")

    assert schema._default_lock_path() == "/var/lib/zanshin.sqlite.migration.lock"


def test_a_server_database_gets_a_lock_outside_the_source_tree(monkeypatch):
    """There is no file to sit beside. The lock still serialises this host's
    processes, which is what the concurrent-import problem actually was — two hosts
    starting at once needs `ZANSHIN_AUTO_MIGRATE=false` and a deployment step."""
    import zanshin.database as database
    import zanshin.schema as schema

    monkeypatch.setattr(database, "DATABASE_URL", "postgresql+psycopg://u:p@db/zanshin")

    path = schema._default_lock_path()

    assert path.endswith("zanshin.migration.lock")
    assert os.path.isabs(path)


def test_skipping_migration_still_refuses_an_outdated_schema(monkeypatch, tmp_path):
    """Skipping is not ignoring. Starting against a schema the code cannot read
    would fail later anyway, in a much more confusing place."""
    import zanshin.schema as schema

    monkeypatch.setenv("ZANSHIN_AUTO_MIGRATE", "false")

    class _EmptyContext:
        @staticmethod
        def get_current_revision():
            return None

    monkeypatch.setattr(
        "alembic.runtime.migration.MigrationContext.configure",
        staticmethod(lambda *a, **k: _EmptyContext()),
    )

    with pytest.raises(RuntimeError, match="alembic upgrade head"):
        schema.upgrade_to_head()
