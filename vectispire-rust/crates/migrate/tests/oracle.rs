//! The runner against the real Flyway, both ways, on both engines.
//!
//! **This is the proof the crate exists for**: that an installation the Java control plane migrated
//! continues under Rust, and that one Rust migrated is accepted by Java. Each test runs the real Flyway
//! 12.4 with the Java configuration (`oracle/oracle.sh`), so it needs a JDK 25 and Gradle besides
//! Docker; it is the `oracle` feature's suite, run by `oracle/check-oracle.sh`:
//!
//! ```sh
//! cargo test -p vectispire-migrate --features oracle --test oracle
//! ```
//!
//! It also writes the reference files the default suite is held to (`reference/migrate/`): the
//! checksums Flyway recorded and the schema Flyway produced, with `VECTISPIRE_REFERENCE_WRITE=1`;
//! otherwise it requires them to be exactly what is committed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Server, history, migrations_at, schema};
use vectispire_migrate::{Engine, MigrationSet, Options};
use vectispire_testkit::expect;

/// The 0.11.1 line, whose V91 the embedded (develop) set does not have yet.
const LINE_0111: &str = "b8bd7e8d0";

fn reference_name(engine: Engine, what: &str, line: &str) -> String {
    format!("migrate/{what}-{}-{line}.txt", engine.vendor())
}

/// The checksums as the `checksum` column holds them, one `script<TAB>checksum` per line.
fn checksums(history: &[String]) -> String {
    history
        .iter()
        .map(|row| {
            let columns: Vec<&str> = row.split('\t').collect();
            format!("{}\t{}\n", columns[4], columns[5])
        })
        .collect()
}

async fn java_migrates_then_rust_continues(
    engine: Engine,
    set: MigrationSet,
    root: Option<&std::path::Path>,
    line: &str,
) {
    if !common::runs_on(engine) {
        return;
    }
    let server = Server::start(engine);
    let database = server.database().await;
    server.oracle("migrate", root, None).unwrap();
    let java_history = history(&database).await;
    let java_schema = schema(&database).await;
    expect(&reference_name(engine, "checksums", line), &checksums(&java_history));
    expect(&reference_name(engine, "schema", line), &java_schema);

    let options = Options { set, ..Options::default() };
    // Every checksum Flyway stored is the one the runner computes from the same file.
    let resolved = options.set.resolve(engine).unwrap();
    for row in &java_history {
        let columns: Vec<&str> = row.split('\t').collect();
        let file = resolved.iter().find(|m| m.script == columns[4]).unwrap_or_else(|| panic!("{}", columns[4]));
        assert_eq!(file.checksum.to_string(), columns[5], "{} on {engine:?}", columns[4]);
        assert_eq!(file.description, columns[2], "{} on {engine:?}", columns[4]);
    }

    let validation = vectispire_migrate::validate(&database, &options).await.unwrap();
    assert!(validation.is_valid(), "{}", validation.message());
    assert!(validation.pending.is_empty());
    let report = vectispire_migrate::run(&database, &options).await.unwrap();
    assert!(report.applied.is_empty(), "Rust re-applied {:?}", report.applied);
    assert_eq!(history(&database).await, java_history);
}

async fn rust_migrates_then_java_accepts(
    engine: Engine,
    set: MigrationSet,
    root: Option<&std::path::Path>,
    line: &str,
) {
    if !common::runs_on(engine) {
        return;
    }
    let server = Server::start(engine);
    let database = server.database().await;
    let options = Options { set, ..Options::default() };
    let report = vectispire_migrate::run(&database, &options).await.unwrap();
    assert!(!report.applied.is_empty());

    let output = server.oracle("check", root, None).unwrap_or_else(|refused| panic!("Java refused: {refused}"));
    assert!(output.contains("valid, nothing to apply"), "{output}");
    // The schema is the one Flyway itself produces from the same files…
    assert_eq!(schema(&database).await, vectispire_testkit::read(&reference_name(engine, "schema", line)));
    // …and the history holds the checksums Flyway records.
    assert_eq!(
        checksums(&history(&database).await),
        vectispire_testkit::read(&reference_name(engine, "checksums", line))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_java_then_rust() {
    java_migrates_then_rust_continues(Engine::MySql, MigrationSet::embedded(), None, "develop").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_java_then_rust() {
    java_migrates_then_rust_continues(Engine::PostgreSql, MigrationSet::embedded(), None, "develop").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_java_then_rust_on_0111() {
    let files = migrations_at(LINE_0111);
    let set = MigrationSet::from_dir(files.path()).unwrap();
    java_migrates_then_rust_continues(Engine::MySql, set, Some(files.path()), "0.11.1").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_java_then_rust_on_0111() {
    let files = migrations_at(LINE_0111);
    let set = MigrationSet::from_dir(files.path()).unwrap();
    java_migrates_then_rust_continues(Engine::PostgreSql, set, Some(files.path()), "0.11.1").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_rust_then_java() {
    rust_migrates_then_java_accepts(Engine::MySql, MigrationSet::embedded(), None, "develop").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_rust_then_java() {
    rust_migrates_then_java_accepts(Engine::PostgreSql, MigrationSet::embedded(), None, "develop").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_rust_then_java_on_0111() {
    let files = migrations_at(LINE_0111);
    let set = MigrationSet::from_dir(files.path()).unwrap();
    rust_migrates_then_java_accepts(Engine::MySql, set, Some(files.path()), "0.11.1").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_rust_then_java_on_0111() {
    let files = migrations_at(LINE_0111);
    let set = MigrationSet::from_dir(files.path()).unwrap();
    rust_migrates_then_java_accepts(Engine::PostgreSql, set, Some(files.path()), "0.11.1").await;
}

/// An installation Java migrated to V89, upgraded by a Rust build, then started again by Java.
async fn java_to_v89_rust_the_rest_java_again(engine: Engine) {
    if !common::runs_on(engine) {
        return;
    }
    let server = Server::start(engine);
    let database = server.database().await;
    server.oracle("migrate", None, Some("89")).unwrap();
    let before = history(&database).await;
    assert!(before.last().unwrap().split('\t').nth(1) == Some("89"), "{before:?}");

    let report = vectispire_migrate::run(&database, &Options::default()).await.unwrap();
    let above_89: Vec<String> = MigrationSet::embedded()
        .resolve(engine)
        .unwrap()
        .iter()
        .filter(|m| m.version > vectispire_migrate::Version::parse("89").unwrap())
        .map(|m| m.version.to_string())
        .collect();
    assert!(!above_89.is_empty());
    assert_eq!(report.applied, above_89);
    let output = server.oracle("check", None, None).unwrap_or_else(|refused| panic!("Java refused: {refused}"));
    assert!(output.contains("valid, nothing to apply"), "{output}");
    assert_eq!(schema(&database).await, vectispire_testkit::read(&reference_name(engine, "schema", "develop")));
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_java_to_v89_then_rust_then_java() {
    java_to_v89_rust_the_rest_java_again(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_java_to_v89_then_rust_then_java() {
    java_to_v89_rust_the_rest_java_again(Engine::PostgreSql).await;
}

/// A Java and a Rust instance starting together on an empty database: each takes Flyway's lock in
/// turn, every migration is applied once, and the schema is the one either alone produces.
async fn java_and_rust_start_together(engine: Engine) {
    if !common::runs_on(engine) {
        return;
    }
    let server = Server::start(engine);
    let database = server.database().await;
    let java = {
        let jdbc = (server.jdbc_url(), engine, server.user(), server.password());
        let script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("oracle/oracle.sh");
        std::thread::spawn(move || {
            std::process::Command::new(script)
                .args(["migrate", &jdbc.0, &jdbc.2, &jdbc.3, jdbc.1.vendor(), "-"])
                .output()
                .unwrap()
        })
    };
    let rust = vectispire_migrate::run(&database, &Options::default()).await;
    let java = java.join().unwrap();
    assert!(java.status.success(), "Java: {}", String::from_utf8_lossy(&java.stderr));
    let rust = rust.unwrap_or_else(|error| panic!("Rust: {error}"));

    let rows = history(&database).await;
    let versions: Vec<&str> = rows.iter().filter_map(|row| row.split('\t').nth(1)).collect();
    let mut unique = versions.clone();
    unique.dedup();
    assert_eq!(versions, unique, "a version applied twice: {rows:#?}");
    assert!(rows.iter().all(|row| row.ends_with("\ttrue")), "{rows:#?}");
    assert_eq!(checksums(&rows), vectispire_testkit::read(&reference_name(engine, "checksums", "develop")));
    assert_eq!(schema(&database).await, vectispire_testkit::read(&reference_name(engine, "schema", "develop")));
    eprintln!("{engine:?}: Rust applied {} migration(s), Java the rest", rust.applied.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn mysql_java_and_rust_together() {
    java_and_rust_start_together(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_java_and_rust_together() {
    java_and_rust_start_together(Engine::PostgreSql).await;
}
