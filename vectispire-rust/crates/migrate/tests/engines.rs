//! The runner on real servers, without the Java oracle: what a start accepts and what it refuses.
//!
//! Needs Docker only. The checksums and the schema it is compared with are the ones the real Flyway
//! produced, committed under `reference/migrate/` by `tests/oracle.rs`; this suite is what keeps them
//! true on every run, and `oracle.rs` is what keeps them true to Flyway.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Server, execute, history, schema};
use vectispire_migrate::{Engine, Error, File, MigrationSet, Options};
use vectispire_testkit::read;

fn checksums_of(engine: Engine, set: &MigrationSet) -> String {
    set.resolve(engine).unwrap().iter().map(|m| format!("{}\t{}\n", m.script, m.checksum)).collect()
}

/// Every checksum Flyway recorded for the develop files is the one this crate computes, offline.
#[test]
fn the_checksums_are_the_ones_flyway_recorded() {
    for engine in Engine::ALL {
        let expected = read(&format!("migrate/checksums-{}-develop.txt", engine.vendor()));
        assert_eq!(checksums_of(engine, &MigrationSet::embedded()), expected, "{engine:?}");
    }
}

fn small_set(extra: &[(&str, &str, &str)]) -> MigrationSet {
    // A tiny layout the rules accept: V1–V39 are required in every vendor directory, so each is a
    // one-line table; the interesting versions come after.
    let mut files = Vec::new();
    for version in 1..=39 {
        for vendor in ["mysql", "postgresql"] {
            files.push(File {
                directory: vendor.to_owned(),
                name: format!("V{version}__t{version}.sql"),
                bytes: format!("create table t{version} (id int);\n").into_bytes(),
            });
        }
    }
    files.push(File {
        directory: "common".to_owned(),
        name: "V9000__placeholder_probe.sql".to_owned(),
        bytes: b"create table probe (id ${id}, at ${ts});\n".to_vec(),
    });
    for (directory, name, sql) in extra {
        files.push(File {
            directory: (*directory).to_owned(),
            name: (*name).to_owned(),
            bytes: sql.as_bytes().to_vec(),
        });
    }
    MigrationSet::of(files)
}

async fn started(engine: Engine, set: MigrationSet) -> (Server, vectispire_migrate::Database, Options) {
    let server = Server::start(engine);
    let database = server.database().await;
    let options = Options { set, ..Options::default() };
    vectispire_migrate::run(&database, &options).await.unwrap();
    (server, database, options)
}

fn modified(set: &MigrationSet, name: &str, sql: &str) -> MigrationSet {
    MigrationSet::of(
        set.files()
            .iter()
            .map(|f| if f.name == name { File { bytes: sql.as_bytes().to_vec(), ..f.clone() } } else { f.clone() })
            .collect(),
    )
}

fn without(set: &MigrationSet, name: &str) -> MigrationSet {
    MigrationSet::of(set.files().iter().filter(|f| f.name != name).cloned().collect())
}

async fn refused(database: &vectispire_migrate::Database, options: &Options) -> String {
    match vectispire_migrate::run(database, options).await {
        Err(error) => error.to_string(),
        Ok(report) => panic!("started, applying {:?}", report.applied),
    }
}

async fn tampered_file_is_refused(engine: Engine) {
    let set = small_set(&[]);
    let (_server, database, _) = started(engine, set.clone()).await;
    let changed = modified(&set, "V9000__placeholder_probe.sql", "create table probe (id ${id});\n");
    let message = refused(&database, &Options { set: changed, ..Options::default() }).await;
    assert!(message.contains("Migration checksum mismatch for migration version 9000"), "{message}");
    assert!(message.contains("Either revert the changes to the migration, or run repair"), "{message}");
}

async fn missing_applied_version_is_refused(engine: Engine) {
    let set = small_set(&[("common", "V9001__later.sql", "create table later (id ${id});\n")]);
    let (_server, database, _) = started(engine, set.clone()).await;
    // V9001 applied but its file is gone, while a newer one exists: missing, not future.
    let set = small_set(&[("common", "V9002__newer.sql", "create table newer (id ${id});\n")]);
    let message = refused(&database, &Options { set, ..Options::default() }).await;
    assert!(message.contains("Detected applied migration not resolved locally: 9001."), "{message}");
}

async fn newer_build_is_accepted(engine: Engine) {
    let set = small_set(&[("common", "V9001__later.sql", "create table later (id ${id});\n")]);
    let (_server, database, _) = started(engine, set.clone()).await;
    // The database is ahead of these files: a rollback to an older build, accepted as Flyway's
    // `*:future` accepts it.
    let older = without(&set, "V9001__later.sql");
    let report = vectispire_migrate::run(&database, &Options { set: older, ..Options::default() }).await.unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(report.future, ["9001"]);
}

async fn out_of_order_is_refused(engine: Engine) {
    let base = small_set(&[("common", "V9002__second.sql", "create table second (id ${id});\n")]);
    let (_server, database, _) = started(engine, base.clone()).await;
    let with_gap = small_set(&[
        ("common", "V9001__never_applied.sql", "create table gap (id ${id});\n"),
        ("common", "V9002__second.sql", "create table second (id ${id});\n"),
    ]);
    let message = refused(&database, &Options { set: with_gap, ..Options::default() }).await;
    assert!(message.contains("Detected resolved migration not applied to database: 9001."), "{message}");
    assert!(message.contains("-outOfOrder=true"), "{message}");
}

async fn failed_row_is_refused(engine: Engine) {
    let set = small_set(&[]);
    let (_server, database, options) = started(engine, set).await;
    execute(&database, "UPDATE flyway_schema_history SET success = false WHERE version = '9000'").await;
    let message = refused(&database, &options).await;
    assert!(message.contains("Detected failed migration to version 9000 (placeholder probe)."), "{message}");
    assert!(message.contains("run repair to fix the schema history"), "{message}");
}

async fn description_mismatch_is_refused(engine: Engine) {
    let set = small_set(&[]);
    let (_server, database, options) = started(engine, set).await;
    execute(&database, "UPDATE flyway_schema_history SET description = 'something else' WHERE version = '9000'").await;
    let message = refused(&database, &options).await;
    assert!(message.contains("Migration description mismatch for migration version 9000"), "{message}");
}

async fn objects_without_a_history_are_refused(engine: Engine) {
    let server = Server::start(engine);
    let database = server.database().await;
    execute(&database, "create table somebody_elses (id int)").await;
    let message = refused(&database, &Options { set: small_set(&[]), ..Options::default() }).await;
    assert!(message.contains("Found non-empty schema(s)"), "{message}");
    assert!(message.contains("but no schema history table"), "{message}");
}

/// A migration that fails: on PostgreSQL nothing is left and no row is written; on MySQL its DDL
/// committed as it ran, a row with `success = 0` is written, and the next start refuses.
async fn failing_migration(engine: Engine) {
    let set = small_set(&[("common", "V9001__breaks.sql", "create table fine (id ${id});\nthis is not sql;\n")]);
    let server = Server::start(engine);
    let database = server.database().await;
    let options = Options { set, ..Options::default() };
    let message = refused(&database, &options).await;
    assert!(message.contains("Migration of schema"), "{message}");
    assert!(message.contains("9001 - breaks"), "{message}");

    let rows = history(&database).await;
    match engine {
        Engine::PostgreSql => {
            assert!(message.contains("Changes successfully rolled back."), "{message}");
            assert!(rows.iter().all(|row| row.ends_with("\ttrue")), "{rows:?}");
            assert!(rows.iter().all(|row| !row.contains("9001")), "{rows:?}");
            // Nothing half-made: the table the first statement created is gone.
            assert!(!schema(&database).await.contains("|fine|"));
        }
        Engine::MySql => {
            assert!(message.contains("Please restore backups and roll back database and code!"), "{message}");
            assert!(rows.last().unwrap().contains("\t9001\t") && rows.last().unwrap().ends_with("\tfalse"), "{rows:?}");
            // DDL committed as it ran, and the next start says so instead of going on.
            assert!(schema(&database).await.contains("|fine|"));
        }
    }
    let again = refused(&database, &options).await;
    match engine {
        // PostgreSQL left no trace: the same migration is tried again and fails the same way.
        Engine::PostgreSql => assert!(again.contains("9001 - breaks"), "{again}"),
        Engine::MySql => assert!(again.contains("Detected failed migration to version 9001"), "{again}"),
    }
}

/// Two runners start together on an empty database: one applies every migration, the other waits for
/// the lock and finds nothing to do, and no version is applied twice.
async fn two_runners_together(engine: Engine) {
    let server = Server::start(engine);
    let database = server.database().await;
    let options = Options { set: small_set(&[]), ..Options::default() };
    let (first, second) =
        tokio::join!(vectispire_migrate::run(&database, &options), vectispire_migrate::run(&database, &options));
    let (first, second) = (first.unwrap(), second.unwrap());
    let mut applied: Vec<String> = first.applied.iter().chain(&second.applied).cloned().collect();
    let total = applied.len();
    applied.sort();
    applied.dedup();
    assert_eq!(applied.len(), total, "a version was applied twice: {first:?} {second:?}");
    assert_eq!(total, 40, "{first:?} {second:?}");
    let rows = history(&database).await;
    assert_eq!(rows.len(), 40);
    assert!(rows.iter().all(|row| row.ends_with("\ttrue")));
}

macro_rules! on_both_engines {
    ($($name:ident => $body:ident),* $(,)?) => {$(
        mod $name {
            use super::*;
            #[tokio::test(flavor = "multi_thread")]
            async fn mysql() { $body(Engine::MySql).await; }
            #[tokio::test(flavor = "multi_thread")]
            async fn postgres() { $body(Engine::PostgreSql).await; }
        }
    )*};
}

on_both_engines! {
    a_tampered_file_is_refused => tampered_file_is_refused,
    an_applied_version_without_its_file_is_refused => missing_applied_version_is_refused,
    a_database_ahead_of_the_files_is_accepted => newer_build_is_accepted,
    an_unapplied_older_file_is_refused => out_of_order_is_refused,
    a_failed_row_is_refused => failed_row_is_refused,
    a_renamed_migration_is_refused => description_mismatch_is_refused,
    objects_without_a_history_are_refused_ => objects_without_a_history_are_refused,
    a_failing_migration => failing_migration,
    two_runners_together => two_runners_together,
}

#[tokio::test]
async fn a_configured_type_stops_the_start_before_the_database_is_touched() {
    let mut placeholders = std::collections::BTreeMap::new();
    placeholders.insert("ts".to_owned(), "datetime".to_owned());
    let options = Options { placeholders, ..Options::default() };
    // No server: the refusal comes before any connection, so a pool that cannot connect is never asked.
    let pool = sqlx::mysql::MySqlPoolOptions::new().connect_lazy("mysql://nobody@127.0.0.1:1/none").unwrap();
    let error = vectispire_migrate::run(&vectispire_migrate::Database::MySql(pool), &options).await.unwrap_err();
    assert!(matches!(error, Error::PlaceholderOverride { .. }), "{error}");
}
