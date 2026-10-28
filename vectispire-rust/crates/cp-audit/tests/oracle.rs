//! The audit log against the real Java one, both ways, on both engines.
//!
//! **This is the proof the crate exists for**: an installation's audit log is a chain the Java control plane
//! started, and the switch to Rust must neither break it nor make it unverifiable to Java during the transition.
//! Each test runs the application's own `AuditLogService` (`oracle/oracle.sh`), so it needs a JDK 25 and
//! Gradle besides Docker; it is the `oracle` feature's suite, run by `oracle/check-oracle.sh`:
//!
//! ```sh
//! cargo test -p vectispire-cp-audit --features oracle --test oracle
//! ```

#![cfg(feature = "oracle")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use support::{Migrated, Oracle, plain_log};
use vectispire_cp_audit::{AuditLog, AuditLogQuery, AuditOperation, Record, StoredEntry, SystemClock};
use vectispire_cp_db::Engine;

/// The shapes the Java oracle writes, from this side: an address or none, a blank user agent, a description
/// past 255 characters, an absent resource.
fn rust_entry(label: &str, index: usize) -> Record {
    let operations = [
        AuditOperation::LoginSuccess,
        AuditOperation::SettingUpdated,
        AuditOperation::IssueTriaged,
        AuditOperation::UserCreated,
        AuditOperation::ApiKeyCreated,
    ];
    Record {
        operation: operations[index % operations.len()],
        resource_id: (!index.is_multiple_of(5)).then(|| format!("resource-{index}")),
        description: Some(if index % 7 == 3 {
            format!("{label} {index} {}", "é".repeat(300))
        } else {
            format!("{label} {index} — Rust wrote this, \"quoted\" \\ and\nbroken")
        }),
        user_id: Some(format!("rust-{label}")),
        ip_address: (!index.is_multiple_of(3)).then(|| format!("203.0.113.{}", index % 250)),
        user_agent: Some(if index.is_multiple_of(4) { "   ".to_owned() } else { format!("cp-audit/{index}") }),
        signal: None,
    }
}

async fn rust_appends(log: &AuditLog, label: &str, count: usize) {
    for index in 0..count {
        log.append(rust_entry(label, index)).await.unwrap();
    }
}

async fn entries(log: &AuditLog) -> Vec<StoredEntry> {
    // The whole log, oldest first, through the query side's export count and the verification's own read.
    let mut all = log.recent(100_000).await.unwrap();
    all.reverse();
    all
}

/// One unbroken chain: every entry onto the one before it, a single root. The head lock is what makes this
/// hold under concurrent writers; without it two writers that read the same head fork the log.
fn assert_linear(all: &[StoredEntry]) {
    assert!(!all.is_empty());
    assert_eq!(all[0].previous_hash, None, "one root");
    for pair in all.windows(2) {
        assert_eq!(pair[1].previous_hash, pair[0].entry_hash, "{} chains onto {}", pair[1].id, pair[0].id);
    }
}

fn assert_java_intact(server: &Migrated) {
    assert_eq!(server.oracle(&["verify"]).unwrap(), "intact\t0\n", "Java's verification of the log");
}

async fn assert_rust_intact(log: &AuditLog) {
    let verification = log.verify().await.unwrap();
    assert_eq!(verification.broken, None, "Rust's verification of the log");
    assert_eq!(verification.unverifiable, 0);
}

async fn java_starts_and_rust_continues(engine: Engine) {
    let server = Migrated::start(engine).await;
    server.oracle(&["append", "24", "java-first", "3"]).unwrap();
    let db = server.connect().await;
    let log = plain_log(&db);
    assert_rust_intact(&log).await;
    rust_appends(&log, "rust-after", 24).await;
    assert_java_intact(&server);
    assert_rust_intact(&log).await;
    let all = entries(&log).await;
    assert_eq!(all.len(), 48);
    assert_linear(&all);
    assert!(all[24].user_id.as_deref() == Some("rust-rust-after"), "Rust's first entry chains onto Java's last");
}

async fn rust_starts_and_java_continues(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let log = plain_log(&db);
    rust_appends(&log, "rust-first", 24).await;
    assert_java_intact(&server);
    server.oracle(&["append", "24", "java-after", "3"]).unwrap();
    assert_rust_intact(&log).await;
    assert_java_intact(&server);
    let all = entries(&log).await;
    assert_eq!(all.len(), 48);
    assert_linear(&all);
}

/// Turn and turn about, as a rolling switch-over would have it: Java, Rust, Java, Rust — each run chaining onto the
/// other's last entry, and each verifying the whole log after every turn.
async fn java_and_rust_take_turns(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let log = plain_log(&db);
    for turn in 0..3 {
        server.oracle(&["append", "5", &format!("java-turn-{turn}"), "1"]).unwrap();
        assert_rust_intact(&log).await;
        rust_appends(&log, &format!("turn-{turn}"), 5).await;
        assert_java_intact(&server);
    }
    let all = entries(&log).await;
    assert_eq!(all.len(), 30);
    assert_linear(&all);
    for (index, entry) in all.iter().enumerate() {
        let java = (index / 5).is_multiple_of(2);
        assert_eq!(entry.user_id.as_deref().unwrap().starts_with("java-"), java, "entry {index} written by its turn");
    }
}

/// A Java and a Rust writer at once, each several threads deep: the one-row lock serialises them across
/// processes and languages, so the log stays one chain that both verify.
async fn java_and_rust_write_at_once(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let log = plain_log(&db);
    log.append(rust_entry("seed", 1)).await.unwrap();
    let server = Arc::new(server);
    let java = {
        let server = Arc::clone(&server);
        std::thread::spawn(move || server.oracle(&["append", "80", "java-together", "4"]))
    };
    let mut writers = Vec::new();
    for writer in 0..4 {
        let log = log.clone();
        writers.push(tokio::spawn(async move {
            for index in 0..20 {
                log.append(rust_entry(&format!("together-{writer}"), index)).await.unwrap();
            }
        }));
    }
    for writer in writers {
        writer.await.unwrap();
    }
    java.join().unwrap().unwrap();
    let all = entries(&log).await;
    assert_eq!(all.len(), 161);
    assert_linear(&all);
    let languages = all.iter().filter(|entry| entry.user_id.as_deref() == Some("java-java-together")).count();
    assert_eq!(languages, 80, "every Java entry is in the one chain");
    assert_rust_intact(&log).await;
    assert_java_intact(&server);
}

/// The evidence bundle's `02_immutable_audit_log.jsonl`: the same rows, the same bytes, whichever wrote them.
async fn the_bundle_lines_are_java_s_bytes(engine: Engine) {
    let server = Migrated::start(engine).await;
    server.oracle(&["append", "12", "java-bundle", "1"]).unwrap();
    let db = server.connect().await;
    let log = plain_log(&db);
    rust_appends(&log, "rust-bundle", 12).await;
    let query = AuditLogQuery::new(log.clone(), Arc::new(SystemClock), Vec::new());
    let rust = query.as_json_lines().await.unwrap();
    let java = server.oracle(&["export"]).unwrap();
    assert_eq!(rust.entries, 24);
    assert_eq!(rust.text, java, "the bundle's lines");
}

/// A field changed behind the log's back is found by both, in the same words.
async fn both_find_a_tampered_field_and_say_where(engine: Engine) {
    let server = Migrated::start(engine).await;
    server.oracle(&["append", "6", "java-tamper", "1"]).unwrap();
    let db = server.connect().await;
    let log = plain_log(&db);
    rust_appends(&log, "rust-tamper", 6).await;
    let all = entries(&log).await;
    let victim = &all[8];
    server.sql_as_admin(&format!(
        "update t_audit_log set description = 'quietly edited' where id = '{}'",
        victim.id.as_hyphenated()
    ));
    let expected = format!("Entry {}: its own content no longer matches its hash.", victim.id.as_hyphenated());
    assert_eq!(log.verify().await.unwrap().broken.as_deref(), Some(expected.as_str()));
    assert_eq!(server.oracle(&["verify"]).unwrap(), format!("{expected}\t0\n"));
}

/// A Java control plane whose JVM is not on UTC still dates its entries in UTC — Hibernate writes an `Instant`
/// as a UTC timestamp on both engines — so Rust reads the instants Java hashed, and the chain continues.
async fn a_java_writer_outside_utc_dates_its_entries_alike(engine: Engine) {
    let server = Migrated::start(engine).await;
    server.oracle_in_zone("Europe/Brussels", &["append", "10", "java-brussels", "1"]).unwrap();
    server.oracle_in_zone("America/Los_Angeles", &["append", "10", "java-la", "1"]).unwrap();
    let db = server.connect().await;
    let log = plain_log(&db);
    assert_rust_intact(&log).await;
    rust_appends(&log, "rust-after-zones", 10).await;
    assert_java_intact(&server);
    assert_eq!(server.oracle_in_zone("Asia/Tokyo", &["verify"]).unwrap(), "intact\t0\n");
    assert_linear(&entries(&log).await);
}

macro_rules! on_both_engines {
    ($($name:ident),* $(,)?) => {
        mod mysql {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { super::$name(super::Engine::MySql).await; })*
        }
        mod postgres {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { super::$name(super::Engine::PostgreSql).await; })*
        }
    };
}

on_both_engines!(
    java_starts_and_rust_continues,
    rust_starts_and_java_continues,
    java_and_rust_take_turns,
    java_and_rust_write_at_once,
    the_bundle_lines_are_java_s_bytes,
    both_find_a_tampered_field_and_say_where,
    a_java_writer_outside_utc_dates_its_entries_alike,
);
