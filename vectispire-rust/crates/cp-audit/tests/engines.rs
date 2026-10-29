//! The audit log on real servers, both engines, without Java: concurrency, tampering with every column, the
//! listeners and their fallback, the mirror, the clock, the read side.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use support::{FixedClock, MemoryMirror, Migrated, plain_log};
use time::{Duration, OffsetDateTime};
use vectispire_cp_audit::{
    AuditChainBroken, AuditError, AuditLog, AuditLogQuery, AuditOperation, ChainBrokenListener, Listener,
    ListenerError, NoMirror, QueryError, Record, StoredEntry, SystemClock,
};
use vectispire_cp_db::{Db, Engine, Tx};

fn record(index: usize) -> Record {
    Record {
        operation: AuditOperation::SettingUpdated,
        resource_id: Some(format!("setting-{index}")),
        description: Some(format!("entry {index}")),
        user_id: Some("ciso".into()),
        ip_address: Some("203.0.113.7".into()),
        user_agent: Some("tests".into()),
        signal: None,
    }
}

async fn chain(log: &AuditLog) -> Vec<StoredEntry> {
    let mut all = log.recent(100_000).await.unwrap();
    all.reverse();
    all
}

fn assert_linear(all: &[StoredEntry]) {
    assert_eq!(all[0].previous_hash, None);
    for pair in all.windows(2) {
        assert_eq!(pair[1].previous_hash, pair[0].entry_hash, "{} chains onto {}", pair[1].id, pair[0].id);
    }
}

/// Two instances — two pools, two logs, each with eight tasks — write at once: one chain, intact.
async fn concurrent_writers_keep_one_chain(engine: Engine) {
    let server = Migrated::start(engine).await;
    let first = plain_log(&server.connect().await);
    let second = plain_log(&server.connect().await);
    let mut writers = Vec::new();
    for task in 0..16 {
        let log = if task % 2 == 0 { first.clone() } else { second.clone() };
        writers.push(tokio::spawn(async move {
            for index in 0..15 {
                log.append(record(task * 100 + index)).await.unwrap();
            }
        }));
    }
    for writer in writers {
        writer.await.unwrap();
    }
    let all = chain(&first).await;
    assert_eq!(all.len(), 240);
    assert_linear(&all);
    let timestamps: Vec<_> = all.iter().map(|entry| entry.timestamp).collect();
    assert!(timestamps.windows(2).all(|pair| pair[0] < pair[1]), "instants strictly increase along the chain");
    let verification = first.verify().await.unwrap();
    assert_eq!((verification.broken, verification.unverifiable), (None, 0));
}

/// Every column the hash covers, changed behind the log's back, is found — and the first entry that no longer
/// verifies is named. The two hash columns too: a rewritten hash no longer matches, a rewritten predecessor
/// points at nothing.
async fn tampering_with_any_column_is_found(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let log = plain_log(&db);
    for index in 0..4 {
        log.append(record(index)).await.unwrap();
    }
    let victim = chain(&log).await[1].clone();
    let id = victim.id.as_hyphenated().to_string();
    let edits = [
        ("description", "'edited'"),
        ("operation_type", "'LOGIN_SUCCESS'"),
        ("resource_id", "'elsewhere'"),
        ("user_id", "'someone-else'"),
        ("ip_address", "'198.51.100.1'"),
        ("user_agent", "'other'"),
        ("entry_hash", "'0000000000000000000000000000000000000000000000000000000000000000'"),
    ];
    for (column, value) in edits {
        let original = server.sql_as_admin(&format!("select {column} from t_audit_log where id = '{id}'"));
        server.sql_as_admin(&format!("update t_audit_log set {column} = {value} where id = '{id}'"));
        let broken = log.verify().await.unwrap().broken.unwrap_or_default();
        assert!(broken.contains(&id) || column == "entry_hash", "{column}: {broken}");
        if column == "entry_hash" {
            // The rewritten hash no longer matches the entry, which is reported first.
            assert_eq!(broken, format!("Entry {id}: its own content no longer matches its hash."), "{column}");
        }
        assert!(!log.recent_entries_match_their_hashes().await.unwrap(), "{column}: the window check sees it too");
        server.sql_as_admin(&format!("update t_audit_log set {column} = '{}' where id = '{id}'", original.trim()));
        assert_eq!(log.verify().await.unwrap().broken, None, "{column} restored");
    }

    // The instant: a millisecond later is another entry.
    let moved = match engine {
        Engine::MySql => format!("update t_audit_log set timestamp = timestamp + interval 1 second where id = '{id}'"),
        Engine::PostgreSql => {
            format!("update t_audit_log set timestamp = timestamp + interval '1 second' where id = '{id}'")
        }
    };
    server.sql_as_admin(&moved);
    assert!(log.verify().await.unwrap().broken.is_some_and(|broken| broken.contains(&id)), "timestamp");
    let restore = match engine {
        Engine::MySql => format!("update t_audit_log set timestamp = timestamp - interval 1 second where id = '{id}'"),
        Engine::PostgreSql => {
            format!("update t_audit_log set timestamp = timestamp - interval '1 second' where id = '{id}'")
        }
    };
    server.sql_as_admin(&restore);
    assert_eq!(log.verify().await.unwrap().broken, None, "timestamp restored");

    // The predecessor rewritten: it points at nothing the log holds.
    let third = chain(&log).await[2].clone();
    server.sql_as_admin(&format!(
        "update t_audit_log set previous_hash = '{}' where id = '{}'",
        "a".repeat(64),
        third.id.as_hyphenated()
    ));
    let broken = log.verify().await.unwrap().broken.unwrap();
    assert!(broken.contains(&third.id.as_hyphenated().to_string()), "previous_hash: {broken}");
}

/// Deleting an entry somebody descends from breaks the chain; deleting the tip does not — and the mirror is what
/// sees that one.
async fn a_deletion_is_found_by_the_chain_or_by_the_mirror(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let mirror = Arc::new(MemoryMirror::default());
    let log = AuditLog::new(db.clone(), mirror.clone(), Arc::new(SystemClock), Vec::new());
    for index in 0..4 {
        log.append(record(index)).await.unwrap();
    }
    assert_eq!(mirror.lines.lock().unwrap().len(), 4, "one mirror line per entry");
    let all = chain(&log).await;
    let line = mirror.lines.lock().unwrap()[0].clone();
    assert_eq!(line.id, all[0].id.as_hyphenated().to_string());
    assert_eq!(line.timestamp, vectispire_cp_audit::chain::canonical(all[0].timestamp), "the hash's own instant");
    assert_eq!(Some(line.entry_hash), all[0].entry_hash);

    server.sql_as_admin(&format!("delete from t_audit_log where id = '{}'", all[3].id.as_hyphenated()));
    assert_eq!(log.verify().await.unwrap().broken, None, "the tip's deletion is invisible to the chain");
    let comparison = log.verify_against_mirror().await.unwrap();
    assert_eq!((comparison.missing_from_table, comparison.missing_from_mirror), (1, 0), "but not to the mirror");
    // And the report does not call it intact because the chain holds: the mirror's word counts.
    let heard = Arc::new(Heard::default());
    let query = AuditLogQuery::new(log.clone(), Arc::new(SystemClock), vec![heard.clone()]);
    let integrity = query.verify().await.unwrap();
    assert_eq!((integrity.intact, integrity.broken.as_deref(), integrity.missing_from_table), (false, None, 1));
    assert_eq!(
        heard.events.lock().unwrap().last().map(|event| (event.broken_at.clone(), event.missing_from_table)),
        Some((None, 1))
    );

    server.sql_as_admin(&format!("delete from t_audit_log where id = '{}'", all[1].id.as_hyphenated()));
    let broken = log.verify().await.unwrap().broken.unwrap();
    assert!(broken.contains("has vanished from the log"), "{broken}");

    let integrity = query.verify().await.unwrap();
    assert!(!integrity.intact);
    assert_eq!((integrity.total, integrity.missing_from_table, integrity.mirrored), (2, 2, true));
    assert_eq!(heard.events.lock().unwrap().len(), 2, "the SIEM hears every broken verification");
    query.verify().await.unwrap();
    assert_eq!(heard.events.lock().unwrap().len(), 3, "every time, not once");
}

#[derive(Default)]
struct Heard {
    events: std::sync::Mutex<Vec<AuditChainBroken>>,
}

impl ChainBrokenListener for Heard {
    fn chain_broken<'a>(&'a self, event: &'a AuditChainBroken) -> BoxFuture<'a, ()> {
        self.events.lock().unwrap().push(event.clone());
        async {}.boxed()
    }
}

/// A mirror that refuses a line costs the line, not the entry: the table has it, and the comparison says so.
async fn a_refused_mirror_line_costs_only_the_line(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let mirror = Arc::new(MemoryMirror::default());
    let log = AuditLog::new(db.clone(), mirror.clone(), Arc::new(SystemClock), Vec::new());
    log.append(record(1)).await.unwrap();
    mirror.refuse.store(true, Ordering::SeqCst);
    log.append(record(2)).await.unwrap();
    assert_eq!(chain(&log).await.len(), 2);
    let comparison = log.verify_against_mirror().await.unwrap();
    assert_eq!((comparison.missing_from_table, comparison.missing_from_mirror), (0, 1));
}

/// What goes into the columns: Java's cuts and Java's absences.
async fn the_columns_hold_what_java_would_store(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let log = plain_log(&db);
    log.append(Record {
        operation: AuditOperation::IssueTriaged,
        resource_id: None,
        description: Some(format!("{}🛡", "é".repeat(254))),
        user_id: Some("u".repeat(300)),
        ip_address: Some(" \t ".into()),
        user_agent: Some(format!("{}x", "a".repeat(255))),
        signal: None,
    })
    .await
    .unwrap();
    log.append(Record { ip_address: Some("9".repeat(70)), ..record(2) }).await.unwrap();
    let all = chain(&log).await;
    assert_eq!(all[0].resource_id, "null", "String.valueOf of an absent resource");
    assert_eq!(all[0].description, "é".repeat(254), "the pair that would straddle 255 is dropped whole");
    assert_eq!(all[0].user_id.as_deref().map(str::len), Some(255));
    assert_eq!(all[0].ip_address, None, "a blank address is none");
    assert_eq!(all[0].user_agent.as_deref(), Some("a".repeat(255).as_str()));
    assert_eq!(all[1].ip_address.as_deref(), Some("9".repeat(64).as_str()), "the address column is 64 wide");
    assert_eq!(log.verify().await.unwrap().broken, None);
}

/// `record` never fails and `append` says why: no description (the column is `not null`), and no chain lock.
async fn record_swallows_and_append_reports(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let log = plain_log(&db);
    log.record(Record { description: None, ..record(1) }).await;
    assert!(matches!(log.append(Record { description: None, ..record(1) }).await, Err(AuditError::DescriptionMissing)));
    server.sql_as_admin("delete from t_audit_chain_head");
    log.record(record(2)).await;
    assert!(matches!(log.append(record(3)).await, Err(AuditError::ChainHeadMissing)), "never written unlocked");
    assert!(chain(&log).await.is_empty(), "nothing was written by any of them");
}

/// Same instant, five entries: strictly increasing milliseconds. A clock behind the head: a millisecond after it.
async fn instants_strictly_increase_whatever_the_clock_says(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let fixed = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
    let clock = FixedClock::at(fixed);
    let log = AuditLog::new(db.clone(), Arc::new(NoMirror), clock.clone(), Vec::new());
    for index in 0..5 {
        log.append(record(index)).await.unwrap();
    }
    let all = chain(&log).await;
    let offsets: Vec<i64> = all.iter().map(|entry| (entry.timestamp - fixed).whole_milliseconds() as i64).collect();
    assert_eq!(offsets, vec![0, 1, 2, 3, 4]);

    // Another instance, whose clock runs an hour behind: its entry is dated after the head it chains onto.
    let behind = AuditLog::new(db.clone(), Arc::new(NoMirror), FixedClock::at(fixed - Duration::hours(1)), Vec::new());
    behind.append(record(9)).await.unwrap();
    let all = chain(&log).await;
    assert_eq!(all[5].timestamp, all[4].timestamp + Duration::milliseconds(1));
    assert_eq!(log.verify().await.unwrap().broken, None);
}

/// A listener that writes in the entry's transaction, and can be told to fail.
struct Writer {
    fail: bool,
    in_transaction: AtomicUsize,
    after_commit: AtomicUsize,
}

impl Listener for Writer {
    fn recorded_in_transaction<'a>(
        &'a self,
        entry: &'a Record,
        _at: OffsetDateTime,
        tx: &'a mut Tx,
    ) -> BoxFuture<'a, Result<(), ListenerError>> {
        async move {
            self.in_transaction.fetch_add(1, Ordering::SeqCst);
            let key = format!("listener.{}", entry.description.clone().unwrap_or_default());
            match tx {
                Tx::MySql(t) => {
                    sqlx::query("insert into t_setting (`key`, value) values (?, 'x')")
                        .bind(&key)
                        .execute(&mut **t)
                        .await?;
                }
                Tx::PostgreSql(t) => {
                    sqlx::query("insert into t_setting (key, value) values ($1, 'x')")
                        .bind(&key)
                        .execute(&mut **t)
                        .await?;
                }
            }
            if self.fail { Err("the listener refused".into()) } else { Ok(()) }
        }
        .boxed()
    }

    fn recorded<'a>(&'a self, _entry: &'a Record, _at: OffsetDateTime) -> BoxFuture<'a, Result<(), ListenerError>> {
        self.after_commit.fetch_add(1, Ordering::SeqCst);
        async { Err::<(), ListenerError>("an after-commit failure is logged".into()) }.boxed()
    }

    fn name(&self) -> &str {
        "Writer"
    }
}

async fn settings_rows(db: &Db) -> i64 {
    use sqlx::Row as _;
    match db {
        Db::MySql(pool) => sqlx::query("select count(*) from t_setting where `key` like 'listener.%'")
            .fetch_one(pool)
            .await
            .unwrap()
            .get(0),
        Db::PostgreSql(pool) => sqlx::query("select count(*) from t_setting where key like 'listener.%'")
            .fetch_one(pool)
            .await
            .unwrap()
            .get(0),
    }
}

/// In the entry's transaction when it works, the entry alone and the listener after the commit when it fails —
/// never both, and never the entry lost to the listener.
async fn a_listener_writes_with_the_entry_or_hears_after_it(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let working =
        Arc::new(Writer { fail: false, in_transaction: AtomicUsize::new(0), after_commit: AtomicUsize::new(0) });
    let log = AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(SystemClock), vec![working.clone()]);
    log.append(record(1)).await.unwrap();
    assert_eq!((working.in_transaction.load(Ordering::SeqCst), working.after_commit.load(Ordering::SeqCst)), (1, 0));
    assert_eq!(settings_rows(&db).await, 1, "the listener's write committed with the entry");

    let failing =
        Arc::new(Writer { fail: true, in_transaction: AtomicUsize::new(0), after_commit: AtomicUsize::new(0) });
    let log = AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(SystemClock), vec![failing.clone()]);
    log.append(record(2)).await.unwrap();
    assert_eq!((failing.in_transaction.load(Ordering::SeqCst), failing.after_commit.load(Ordering::SeqCst)), (1, 1));
    assert_eq!(settings_rows(&db).await, 1, "its write rolled back with the first attempt");
    let all = chain(&log).await;
    assert_eq!(all.len(), 2, "the entry was written once, alone");
    assert_eq!(log.verify().await.unwrap().broken, None);
}

/// The screen's page: filters, the search's bound, clamping, Spring Data's page offsets; the digests' count; the
/// resources an operation named, past a batch and, on MySQL, as the column's collation compares.
async fn the_read_side_answers_as_java_s_does(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let clock = FixedClock::at(OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap());
    let log = AuditLog::new(db.clone(), Arc::new(NoMirror), clock.clone(), Vec::new());
    for index in 0..12 {
        log.append(Record {
            operation: if index % 3 == 0 { AuditOperation::LoginSuccess } else { AuditOperation::SettingUpdated },
            user_id: Some(if index % 2 == 0 { "alice".into() } else { "bob".into() }),
            description: Some(format!("Entry {index} about Sast_Enabled")),
            ..record(index)
        })
        .await
        .unwrap();
    }
    let query = AuditLogQuery::new(log.clone(), clock.clone(), Vec::new());
    let page = query.page(None, None, None, 5, 0).await.unwrap();
    assert_eq!((page.total, page.items.len(), page.limit, page.offset), (12, 5, 5, 0));
    assert_eq!(page.items[0].description, "Entry 11 about Sast_Enabled", "newest first");
    let page = query.page(None, None, None, 5, 7).await.unwrap();
    assert_eq!(page.offset, 7, "the offset as asked");
    assert_eq!(page.items[0].description, "Entry 6 about Sast_Enabled", "the page that holds it: from 5");
    assert_eq!(query.page(None, None, None, 0, -3).await.unwrap().limit, 1, "clamped to one");
    assert_eq!(query.page(None, None, None, 5000, 0).await.unwrap().limit, 200, "clamped to two hundred");
    assert_eq!(query.page(Some("LOGIN_SUCCESS"), None, None, 50, 0).await.unwrap().total, 4);
    assert_eq!(query.page(Some("  "), Some("bob"), None, 50, 0).await.unwrap().total, 6, "a blank filter is none");
    assert_eq!(query.page(None, None, Some("  SAST_ENABLED "), 50, 0).await.unwrap().total, 12, "case-insensitive");
    assert_eq!(query.page(None, None, Some("setting-1"), 50, 0).await.unwrap().total, 3, "the resource too");
    let refused = query.page(None, None, Some(&"x".repeat(501)), 50, 0).await;
    assert!(
        matches!(refused, Err(QueryError::InvalidInput(message)) if message == "search is longer than 500 characters.")
    );

    assert_eq!(query.operation_types().await.unwrap(), vec!["LOGIN_SUCCESS", "SETTING_UPDATED"]);
    let since = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap() + Duration::milliseconds(6);
    assert_eq!(query.count_since("SETTING_UPDATED", since).await.unwrap(), 4, "entries 7, 8, 10 and 11");

    let mut asked: Vec<String> = (0..2_500).map(|index| format!("unrelated-{index}")).collect();
    asked.push("setting-4".into());
    asked.push("setting-4".into());
    asked.push("SETTING-5".into());
    let named = query.resources_named("SETTING_UPDATED", &asked).await.unwrap();
    match engine {
        Engine::MySql => assert_eq!(
            named.into_iter().collect::<Vec<_>>(),
            vec!["setting-4", "setting-5"],
            "MySQL's collation compares without case, as Hibernate's `in` does there"
        ),
        Engine::PostgreSql => assert_eq!(named.into_iter().collect::<Vec<_>>(), vec!["setting-4"]),
    }
    let integrity = query.verify().await.unwrap();
    assert!(integrity.intact && !integrity.mirrored && integrity.verified == 12);
}

/// The switchover operation: an edited row gets its hash recomputed and the chain verifies again — which is
/// exactly why nothing but an operator runs it.
async fn the_rebuild_relinks_the_whole_chain(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let log = plain_log(&db);
    for index in 0..3 {
        log.append(record(index)).await.unwrap();
    }
    let middle = chain(&log).await[1].id.as_hyphenated().to_string();
    server.sql_as_admin(&format!("update t_audit_log set description = 'rewritten' where id = '{middle}'"));
    assert!(log.verify().await.unwrap().broken.is_some());
    assert_eq!(log.rebuild().await.unwrap(), 3);
    assert_eq!(log.verify().await.unwrap().broken, None);
    assert_linear(&chain(&log).await);
}

macro_rules! on_both_engines {
    ($($name:ident),* $(,)?) => {
        mod mysql {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { if vectispire_cp_db::testing::runs_on(super::Engine::MySql) { super::$name(super::Engine::MySql).await; } })*
        }
        mod postgres {
            $(#[tokio::test(flavor = "multi_thread")]
            async fn $name() { if vectispire_cp_db::testing::runs_on(super::Engine::PostgreSql) { super::$name(super::Engine::PostgreSql).await; } })*
        }
    };
}

on_both_engines!(
    concurrent_writers_keep_one_chain,
    tampering_with_any_column_is_found,
    a_deletion_is_found_by_the_chain_or_by_the_mirror,
    a_refused_mirror_line_costs_only_the_line,
    the_columns_hold_what_java_would_store,
    record_swallows_and_append_reports,
    instants_strictly_increase_whatever_the_clock_says,
    a_listener_writes_with_the_entry_or_hears_after_it,
    the_read_side_answers_as_java_s_does,
    the_rebuild_relinks_the_whole_chain,
);
