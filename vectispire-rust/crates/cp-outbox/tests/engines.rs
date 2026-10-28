//! `t_outbox_message` on real servers, both engines — `OutboxDatabaseTest` and `OutboxClaimIntegrationTest`, and the
//! rows themselves dumped against the ones Java's `enqueue` saves (`reference/outbox/relay.json`).
//!
//! What only a real engine settles: that a message rolled back with its caller never existed; that a never-tried
//! message is due (a `null` check in SQL, the kind of condition that reads correct and is not); that the claim, a
//! conditional update with no row lock, holds under contention — MySQL's repeatable read in particular; and that the
//! bytes a row holds are the bytes Java's row holds. One server per engine, the table emptied between the cases.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod fakes;
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fakes::{Answer, Answers, Fixed, Log, java_instant, parse_instant};
use serde_json::{Value, json};
use support::Migrated;
use time::OffsetDateTime;
use time::macros::datetime;
use uuid::Uuid;
use vectispire_cp_db::{Db, Engine, Mode};
use vectispire_cp_maintenance::{MaintenanceTask, SystemClock};
use vectispire_cp_outbox::{JavaRegistry, NotificationRelayTask, Outbox, PENDING, Registry, database_store, retry};

const AT: OffsetDateTime = datetime!(2026-10-17 09:30:00.123456 UTC);

fn reference() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/outbox/relay.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn outbox(db: &Db, registry: Registry, at: OffsetDateTime) -> Outbox {
    Outbox::on_database(db.clone(), registry, Arc::new(Fixed(at)))
}

fn none() -> Answers {
    Arc::new(BTreeMap::new())
}

fn log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}

async fn enqueue(outbox: &Outbox, db: &Db, payload: &Value, message_type: &str, team: Option<i64>) -> Uuid {
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    let id = outbox.enqueue(&mut tx, payload, message_type, team).await.unwrap();
    tx.commit().await.unwrap();
    id
}

/// Every column of one row, as text: the payload and the error in hex, so no client escaping stands between the row
/// and the comparison; the instants in Java's `Instant.toString()` at the microsecond.
fn dump(server: &Migrated, id: Uuid) -> String {
    let statement = match server.engine {
        Engine::MySql => format!(
            "select concat_ws('|', id, message_type, lower(hex(payload)), coalesce(team_id, 'null'), status, attempts, \
             coalesce(date_format(next_attempt_at, '%Y-%m-%dT%H:%i:%s.%fZ'), 'null'), \
             coalesce(lower(hex(last_error)), 'null'), date_format(created_at, '%Y-%m-%dT%H:%i:%s.%fZ'), \
             coalesce(date_format(sent_at, '%Y-%m-%dT%H:%i:%s.%fZ'), 'null')) from t_outbox_message where id = '{id}'"
        ),
        Engine::PostgreSql => {
            let instant =
                |column: &str| format!("to_char({column} at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')");
            format!(
                "select concat_ws('|', id, message_type, encode(convert_to(payload, 'UTF8'), 'hex'), \
                 coalesce(team_id::text, 'null'), status, attempts, coalesce({}, 'null'), \
                 coalesce(encode(convert_to(last_error, 'UTF8'), 'hex'), 'null'), {}, coalesce({}, 'null')) \
                 from t_outbox_message where id = '{id}'",
                instant("next_attempt_at"),
                instant("created_at"),
                instant("sent_at")
            )
        }
    };
    server.sql_as_admin(&statement).trim().to_owned()
}

fn hex(text: &str) -> String {
    text.bytes().map(|byte| format!("{byte:02x}")).collect()
}

fn empty(server: &Migrated) {
    server.sql_as_admin("delete from t_outbox_message");
}

async fn counts(outbox: &Outbox) -> BTreeMap<String, i64> {
    outbox.counts().await.unwrap()
}

// ── OutboxDatabaseTest ──

async fn a_rolled_back_message_never_existed(server: &Migrated, db: &Db) {
    let outbox = outbox(db, Registry::default(), AT);
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    let id = outbox.enqueue(&mut tx, &json!({"scan_id": 1}), "scan_delta", None).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(dump(server, id), "", "{}: the message went with the scan that failed", server.engine);
    assert!(counts(&outbox).await.is_empty());
}

/// The rows Java's `enqueue` saves, written by Rust: every column the same, the payload byte for byte once Java's
/// random id — `{message_id}` in the file — is the one this enqueue drew.
async fn the_rows_are_java_s(server: &Migrated, db: &Db) {
    let reference = reference();
    for row in reference["enqueued"].as_array().unwrap() {
        let created = parse_instant(row["created_at"].as_str().unwrap());
        let outbox = outbox(db, Registry::default(), created);
        let input: Value = serde_json::from_str(row["input"].as_str().unwrap()).unwrap();
        let id = enqueue(&outbox, db, &input, row["message_type"].as_str().unwrap(), row["team_id"].as_i64()).await;
        let payload = row["payload"].as_str().unwrap().replace("{message_id}", &id.to_string());
        let expected = [
            id.to_string(),
            row["message_type"].as_str().unwrap().to_owned(),
            hex(&payload),
            row["team_id"].as_i64().map_or("null".to_owned(), |team| team.to_string()),
            row["status"].as_str().unwrap().to_owned(),
            row["attempts"].to_string(),
            "null".to_owned(),
            "null".to_owned(),
            row["created_at"].as_str().unwrap().to_owned(),
            "null".to_owned(),
        ]
        .join("|");
        assert_eq!(dump(server, id), expected, "{}: the row of {}", server.engine, row["input"]);
    }
    empty(server);
}

async fn a_claim_is_exclusive_and_lapses(server: &Migrated, db: &Db) {
    let outbox = outbox(db, Registry::default(), AT);
    let id = enqueue(&outbox, db, &json!({"scan_id": 7}), "scan_delta", None).await;
    let store = database_store(db.clone());
    let now = AT + time::Duration::seconds(1);
    let until = now + retry::CLAIM_WINDOW;
    assert_eq!(store.find_due(PENDING, now, 20).await.unwrap().len(), 1, "never tried is due now");
    assert_eq!(store.claim(id, PENDING, now, until).await.unwrap(), 1, "the first instance takes it");
    assert_eq!(store.claim(id, PENDING, now, until).await.unwrap(), 0, "the second finds it taken");
    assert!(store.find_due(PENDING, now, 20).await.unwrap().is_empty());
    // An instance that dies mid-delivery does not hold the message for ever.
    let later = until + time::Duration::seconds(1);
    assert_eq!(store.find_due(PENDING, later, 20).await.unwrap().len(), 1);
    assert_eq!(store.claim(id, PENDING, later, later + time::Duration::seconds(300)).await.unwrap(), 1);

    // A scheduled retry is not due before its time.
    store
        .record_attempt(id, 1, Some("connection refused"), PENDING, Some(now + time::Duration::seconds(600)))
        .await
        .unwrap();
    assert!(store.find_due(PENDING, now, 20).await.unwrap().is_empty());
    assert_eq!(store.find_due(PENDING, now + time::Duration::seconds(601), 20).await.unwrap().len(), 1);
    empty(server);
}

async fn due_rows_come_oldest_first_and_at_most_the_limit(server: &Migrated, db: &Db) {
    let mut ids = Vec::new();
    for second in [3, 1, 2] {
        let outbox = outbox(db, Registry::default(), AT + time::Duration::seconds(second));
        ids.push((second, enqueue(&outbox, db, &json!({"n": second}), "scan_delta", None).await));
    }
    ids.sort();
    let store = database_store(db.clone());
    let due = store.find_due(PENDING, AT + time::Duration::seconds(10), 2).await.unwrap();
    assert_eq!(due.iter().map(|row| row.id).collect::<Vec<_>>(), vec![ids[0].1, ids[1].1], "{}", server.engine);
    assert_eq!(due[0].payload, format!(r#"{{"n":1,"message_id":"{}"}}"#, ids[0].1));
    empty(server);
}

async fn only_delivered_messages_past_their_retention_are_pruned(server: &Migrated, db: &Db) {
    let outbox = outbox(db, Registry::default(), AT);
    let pending = enqueue(&outbox, db, &json!({"scan_id": 1}), "scan_delta", None).await;
    let old = enqueue(&outbox, db, &json!({"scan_id": 2}), "scan_delta", None).await;
    let recent = enqueue(&outbox, db, &json!({"scan_id": 3}), "scan_delta", None).await;
    let store = database_store(db.clone());
    store.mark_sent(old, 1, "sent", AT - retry::SENT_RETENTION - time::Duration::seconds(60)).await.unwrap();
    store.mark_sent(recent, 1, "sent", AT - retry::SENT_RETENTION + time::Duration::seconds(60)).await.unwrap();
    assert_eq!(counts(&outbox).await, BTreeMap::from([("pending".to_owned(), 1), ("sent".to_owned(), 2)]));
    assert_eq!(outbox.prune_sent().await.unwrap(), 1, "{}", server.engine);
    assert_ne!(dump(server, pending), "");
    assert_ne!(dump(server, recent), "");
    assert_eq!(dump(server, old), "");
    empty(server);
}

/// The relay over the database: each row settled as Java settles it, and read back from the table.
async fn the_relay_settles_each_row(server: &Migrated, db: &Db) {
    let enqueuer = outbox(db, Registry::default(), AT);
    let sent = enqueue(&enqueuer, db, &json!({"scan_id": 1}), "scan_delta", Some(4)).await;
    let failing = enqueue(&enqueuer, db, &json!({"event": "x"}), "siem_event", None).await;
    let gone = enqueue(&enqueuer, db, &json!({"event": "y"}), "siem_event", None).await;
    let unknown = enqueue(&enqueuer, db, &json!({"alert": 1}), "token_alert", None).await;
    let answers: Answers = Arc::new(BTreeMap::from([
        (failing, Answer::Fails("OutboundFailureException".into(), Some("connection refused".into()))),
        (gone, Answer::Gone("the SIEM export was switched off".into())),
    ]));
    let log = log();
    let at = AT + time::Duration::seconds(5);
    let relay = Outbox::on_database(
        db.clone(),
        Registry::new(
            fakes::handlers(&["siem_event"], &answers, &log),
            fakes::channels(&["scan_delta"], &answers, &log),
        ),
        Arc::new(Fixed(at)),
    );
    let result = relay.relay(20).await.unwrap();
    assert_eq!((result.sent, result.failed, result.abandoned), (1, 2, 1), "{}", server.engine);
    let created = java_instant(AT);
    let row = |id: Uuid| dump(server, id).split('|').map(str::to_owned).collect::<Vec<_>>();
    let sent_row = row(sent);
    assert_eq!(&sent_row[3..], ["4", "sent", "1", "null", "null", &created, &java_instant(at)]);
    let retry_at = java_instant(at + time::Duration::seconds(60));
    assert_eq!(
        &row(failing)[4..],
        ["pending", "1", &retry_at, &hex("OutboundFailureException: connection refused"), &created, "null"]
    );
    assert_eq!(&row(gone)[4..], ["failed", "1", "null", &hex("the SIEM export was switched off"), &created, "null"]);
    // The danger the guard exists for, on a real row: a type this relay does not know is retried, then abandoned.
    assert_eq!(
        &row(unknown)[4..],
        [
            "pending",
            "1",
            &retry_at,
            &hex("IllegalStateException: No channel handles outbox type token_alert"),
            &created,
            "null"
        ]
    );
    empty(server);
}

/// The relay task with this binary's registry — none of Java's types yet — over rows Java's relay would deliver:
/// nothing is claimed, nothing is counted, every column stays as it was.
async fn a_held_relay_leaves_java_s_rows_alone(server: &Migrated, db: &Db) {
    let enqueuer = outbox(db, Registry::default(), AT);
    let java = JavaRegistry::compiled_in().unwrap();
    let mut ids = Vec::new();
    for message_type in java.handlers.iter().chain(java.channels.iter()) {
        ids.push(enqueue(&enqueuer, db, &json!({"from": "java"}), message_type, None).await);
    }
    let before: Vec<String> = ids.iter().map(|id| dump(server, *id)).collect();
    let task = NotificationRelayTask::new(
        Arc::new(Outbox::on_database(db.clone(), Registry::default(), Arc::new(SystemClock))),
        &java,
    );
    assert!(task.is_held());
    for _ in 0..3 {
        task.run().await.unwrap();
    }
    let after: Vec<String> = ids.iter().map(|id| dump(server, *id)).collect();
    assert_eq!(before, after, "{}: a held relay touches no row", server.engine);
    empty(server);
}

// ── OutboxClaimIntegrationTest ──

/// Java's case: eight instances each read the due set first, so every one holds all twenty ids before any claim —
/// the worst case, and the realistic one.
async fn each_due_message_is_claimed_by_exactly_one_instance(server: &Migrated) {
    let db = server.connect().await;
    let created = AT;
    for i in 0..20 {
        let outbox = outbox(&db, Registry::default(), created + time::Duration::milliseconds(i));
        enqueue(&outbox, &db, &json!({}), "scan_delta", None).await;
    }
    let at = created + time::Duration::seconds(1);
    let until = at + retry::CLAIM_WINDOW;
    let mut passes = Vec::new();
    for _ in 0..8 {
        let store = database_store(server.connect().await);
        passes.push(tokio::spawn(async move {
            let mut mine = Vec::new();
            for due in store.find_due(PENDING, at, 20).await.unwrap() {
                if store.claim(due.id, PENDING, at, until).await.unwrap() == 1 {
                    mine.push(due.id);
                }
            }
            mine
        }));
    }
    let mut claimed = Vec::new();
    for pass in passes {
        claimed.extend(pass.await.unwrap());
    }
    let unique: BTreeSet<Uuid> = claimed.iter().copied().collect();
    assert_eq!(unique.len(), claimed.len(), "{}: a message claimed twice is a message delivered twice", server.engine);
    assert_eq!(claimed.len(), 20, "{}: and every due message is claimed by someone", server.engine);
    empty(server);
}

/// Two whole relays on two pools, racing over the same rows: each message delivered once, none lost, none abandoned.
async fn two_relays_racing_deliver_each_message_once(server: &Migrated) {
    let db = server.connect().await;
    let enqueuer = Outbox::on_database(db.clone(), Registry::default(), Arc::new(SystemClock));
    let mut ids = BTreeSet::new();
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    for n in 0..60 {
        ids.insert(enqueuer.enqueue(&mut tx, &json!({"n": n}), "race", None).await.unwrap());
    }
    tx.commit().await.unwrap();

    let delivered: Log = log();
    let mut relays = Vec::new();
    for _ in 0..2 {
        let pool = server.connect().await;
        let relay = Outbox::on_database(
            pool,
            Registry::new(fakes::handlers(&["race"], &none(), &delivered), Vec::new()),
            Arc::new(SystemClock),
        );
        relays.push(tokio::spawn(async move {
            let mut sent = 0;
            for _ in 0..10 {
                let result = relay.relay(retry::MAX_PER_PASS).await.unwrap();
                assert_eq!((result.failed, result.abandoned), (0, 0));
                sent += result.sent;
            }
            sent
        }));
    }
    let mut sent = 0;
    for relay in relays {
        sent += relay.await.unwrap();
    }
    let delivered: Vec<Uuid> =
        delivered.lock().unwrap().iter().map(|call| Uuid::parse_str(call["id"].as_str().unwrap()).unwrap()).collect();
    let unique: BTreeSet<Uuid> = delivered.iter().copied().collect();
    assert_eq!(delivered.len(), unique.len(), "{}: no message delivered twice", server.engine);
    assert_eq!(unique, ids, "{}: and none lost", server.engine);
    assert_eq!(sent, 60);
    assert_eq!(counts(&enqueuer).await, BTreeMap::from([("sent".to_owned(), 60)]), "{}: none abandoned", server.engine);
    empty(server);
}

async fn on(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    a_rolled_back_message_never_existed(&server, &db).await;
    the_rows_are_java_s(&server, &db).await;
    a_claim_is_exclusive_and_lapses(&server, &db).await;
    due_rows_come_oldest_first_and_at_most_the_limit(&server, &db).await;
    only_delivered_messages_past_their_retention_are_pruned(&server, &db).await;
    the_relay_settles_each_row(&server, &db).await;
    a_held_relay_leaves_java_s_rows_alone(&server, &db).await;
    each_due_message_is_claimed_by_exactly_one_instance(&server).await;
    two_relays_racing_deliver_each_message_once(&server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_outbox_on_mysql() {
    on(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_outbox_on_postgresql() {
    on(Engine::PostgreSql).await;
}
