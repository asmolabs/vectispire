"""A brand-new database, built by running every migration in order.

The rest of the suite creates its schema straight from the models, which is fast and
right for testing behaviour — and completely blind to the migration chain. So the one
thing every real installation does first was the one thing nothing exercised.

It failed. Revision `0014` rebuilds the SQLite tables from `Base.metadata`, i.e. from
whatever the models look like *now* rather than at that point in history. The first
column added afterwards (`finding.description`, revision `0015`) made it emit
`INSERT INTO … SELECT finding.description FROM finding` against a table that would not
have that column until the next revision, and a fresh install died there. Found by
running a real scan against a fresh database, which is a very roundabout way of finding
out that `alembic upgrade head` does not work.

`alembic check` did not catch it either, and could not: it compares an *already migrated*
database against the models. Reaching head is precisely what it assumes.
"""
import os
import sqlite3

import pytest


def _alembic(command, database_path, repository_root):
    import subprocess
    import sys

    return subprocess.run(
        [sys.executable, "-m", "alembic", *command.split()],
        cwd=repository_root,
        env={
            **os.environ,
            "ZANSHIN_DATABASE_URL": f"sqlite:///{database_path}",
            "ENCRYPTION_KEY": "fresh-install-test-key-32-bytes!",
        },
        capture_output=True,
        timeout=300,
    )


REPOSITORY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def fresh_database(tmp_path):
    """An empty file, migrated to head by `alembic upgrade head`.

    Run in a subprocess rather than in-process: `zanshin.database` resolves its URL at
    import time, so pointing this session at a temporary file would mean reloading the
    module — and every model already registered against the old `Base` would be lost,
    which is a good way to make this test pass for the wrong reason.
    """
    database_path = tmp_path / "fresh.sqlite"
    completed = _alembic("upgrade head", str(database_path), REPOSITORY_ROOT)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")[-3000:]

    return str(database_path)


def _columns(path, table):
    with sqlite3.connect(path) as connection:
        return [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]


def _foreign_keys(path, table):
    with sqlite3.connect(path) as connection:
        return {(row[2], row[3], row[6]) for row in connection.execute(
            f"PRAGMA foreign_key_list({table})"
        )}


def test_an_empty_database_reaches_head(fresh_database):
    """The whole point. Every table below comes from a different revision, so their
    presence together says the chain ran end to end."""
    with sqlite3.connect(fresh_database) as connection:
        tables = {
            row[0] for row in connection.execute(
                "select name from sqlite_master where type='table'"
            )
        }

    assert {"repository", "scan", "finding", "issue", "agent", "leader_lease"} <= tables


def test_the_schema_matches_the_models_afterwards(fresh_database):
    """`alembic check`, on a database built by the migrations rather than by the models.

    Same command CI already runs, pointed at a database that started empty — which is the
    difference that matters, since the usual run compares against a database somebody
    migrated incrementally over months and which can therefore be right by accident.

    Run through the project's own `env.py` rather than by calling `compare_metadata`
    directly: that file configures the custom-type comparison, without which every GUID
    column reports as drift."""
    completed = _alembic("check", fresh_database, REPOSITORY_ROOT)

    output = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    assert completed.returncode == 0, f"dérive après migration depuis zéro :\n{output[-3000:]}"


def test_a_column_added_after_0014_survives_its_table_rebuild(fresh_database):
    """The specific failure: revision 0014 recreates these tables, and it must describe
    them as they are at *that* revision, not as the models describe them today."""
    assert "description" in _columns(fresh_database, "finding")


def test_the_delete_rules_of_0014_are_actually_applied(fresh_database):
    """And the fix must not have quietly turned that migration into a no-op: rebuilding
    the tables identically would leave no trace and pass every other check here."""
    assert ("scan", "scan_id", "CASCADE") in _foreign_keys(fresh_database, "finding")
    assert ("issue", "issue_id", "SET NULL") in _foreign_keys(fresh_database, "finding")
    assert ("ssh_key", "ssh_key_id", "SET NULL") in _foreign_keys(fresh_database, "repository")


def test_the_unique_constraints_survive_the_rebuild(fresh_database):
    """Losing one is silent — the table rebuilds fine and merely stops rejecting
    duplicates. `issue.fingerprint` being unique is what makes one problem one row
    across every scan of a target."""
    row = (
        "insert into issue (fingerprint, type, state, times_seen, first_seen_at, "
        "last_seen_at, is_kev, triage_status) "
        "values ('f', 'sast', 'open', 1, '2026-08-07 00:00:00', '2026-08-07 00:00:00', 0, "
        "'under_review')"
    )
    with sqlite3.connect(fresh_database) as connection:
        connection.execute(row)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(row)


def test_the_migration_chain_has_a_single_head():
    """Two heads mean two people numbered a revision at the same time, and `upgrade head`
    then refuses to run at all."""
    from alembic.script import ScriptDirectory

    from zanshin.schema import _alembic_config

    assert len(ScriptDirectory.from_config(_alembic_config()).get_heads()) == 1
