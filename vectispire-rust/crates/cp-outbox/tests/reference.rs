//! The outbox held to `reference/outbox/relay.json`, which `OutboxReferenceSetTest` writes by running Java's
//! `OutboxService` over a mocked repository: the policy's constants and backoff table, the errors as `last_error` keeps
//! them, the rows `enqueue` saves, and — scenario by scenario — every repository call the relay made, what each
//! destination was handed, and the pass's result. The Rust relay runs the same scenarios over a recording store and
//! must make the same calls, in the same order, with the same arguments.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod fakes;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fakes::{Answer, Fixed, Recording, java_instant, parse_instant};
use serde_json::Value;
use uuid::Uuid;
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_outbox::{
    DueMessage, JavaRegistry, NewMessage, NotificationRelayTask, Outbox, Registry, SentMessagesTask, retry,
};

fn reference() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/outbox/relay.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn now(reference: &Value) -> time::OffsetDateTime {
    // The instant every scenario runs at is the `at` of its first call.
    parse_instant(reference["scenarios"][0]["calls"][0]["args"][1].as_str().unwrap())
}

#[test]
fn the_policy_is_java_s() {
    let reference = reference();
    let constants = &reference["constants"];
    assert_eq!(constants["maxAttempts"], retry::MAX_ATTEMPTS);
    assert_eq!(constants["baseBackoffSeconds"], retry::BASE_BACKOFF.whole_seconds());
    assert_eq!(constants["maxBackoffSeconds"], retry::MAX_BACKOFF.whole_seconds());
    assert_eq!(constants["maxPerPass"], retry::MAX_PER_PASS);
    assert_eq!(constants["claimWindowSeconds"], retry::CLAIM_WINDOW.whole_seconds());
    assert_eq!(constants["sentRetentionSeconds"], retry::SENT_RETENTION.whole_seconds());
    assert_eq!(constants["scanDeltaType"], vectispire_cp_outbox::TYPE_SCAN_DELTA);

    let at = now(&reference);
    for row in reference["backoff"].as_array().unwrap() {
        let attempts = i32::try_from(row["attempts"].as_i64().unwrap()).unwrap();
        assert_eq!(retry::backoff(attempts).whole_seconds(), row["backoffSeconds"].as_i64().unwrap(), "{attempts}");
        assert_eq!(retry::is_abandoned(attempts), row["abandoned"].as_bool().unwrap(), "{attempts}");
        assert_eq!(
            retry::next_attempt_at(attempts, at).map(java_instant),
            row["nextAttemptAt"].as_str().map(str::to_owned),
            "{attempts}"
        );
    }
}

#[test]
fn errors_are_kept_as_java_keeps_them() {
    for row in reference()["recordableErrors"].as_array().unwrap() {
        let recorded = retry::recordable_error(row["kind"].as_str().unwrap(), row["message"].as_str());
        assert_eq!(recorded, row["recorded"].as_str().unwrap(), "{}", row["kind"]);
    }
}

#[test]
fn the_rows_enqueue_writes_are_java_s() {
    let reference = reference();
    let rows = reference["enqueued"].as_array().unwrap();
    assert!(rows.len() >= 12, "the reference set read something");
    let id = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    for row in rows {
        assert_eq!(row["returnsTheRowsId"], true, "Java returns the id it stamped");
        assert_eq!(row["payloadNamesTheId"], true);
        let input: Value = serde_json::from_str(row["input"].as_str().unwrap()).unwrap();
        let message = NewMessage::pending(
            id,
            row["message_type"].as_str().unwrap(),
            row["team_id"].as_i64(),
            &input,
            parse_instant(row["created_at"].as_str().unwrap()),
        )
        .unwrap();
        let input = row["input"].as_str().unwrap();
        // Java's id is random: the file holds it as `{message_id}`.
        let payload = message.payload.replace(&id.to_string(), "{message_id}");
        assert_eq!(payload, row["payload"].as_str().unwrap(), "the stamped payload of {input}");
        assert_eq!(message.message_type, row["message_type"].as_str().unwrap());
        assert_eq!(message.team_id, row["team_id"].as_i64());
        assert_eq!(message.status, row["status"].as_str().unwrap());
        assert_eq!(i64::from(message.attempts), row["attempts"].as_i64().unwrap());
        assert_eq!(message.next_attempt_at.map(java_instant), row["next_attempt_at"].as_str().map(str::to_owned));
        assert_eq!(message.last_error.as_deref(), row["last_error"].as_str());
        assert_eq!(java_instant(message.created_at), row["created_at"].as_str().unwrap());
        assert_eq!(message.sent_at.map(java_instant), row["sent_at"].as_str().map(str::to_owned));
    }
}

fn strings(value: &Value) -> Vec<&str> {
    value.as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect()
}

#[tokio::test]
async fn the_relay_makes_java_s_calls_scenario_by_scenario() {
    let reference = reference();
    let at = now(&reference);
    let mut ran = 0;
    for scenario in reference["scenarios"].as_array().unwrap() {
        let Some(due) = scenario["due"].as_array() else { continue };
        let name = scenario["name"].as_str().unwrap();
        let mut answers = BTreeMap::new();
        let mut store = Recording::default();
        let mut rows = Vec::new();
        for row in due {
            let id = Uuid::parse_str(row["id"].as_str().unwrap()).unwrap();
            rows.push(DueMessage {
                id,
                message_type: row["message_type"].as_str().unwrap().to_owned(),
                team_id: row["team_id"].as_i64(),
                payload: row["payload"].as_str().unwrap().to_owned(),
                attempts: i32::try_from(row["attempts"].as_i64().unwrap()).unwrap(),
            });
            if !row["claimable"].as_bool().unwrap() {
                store.taken.insert(id);
            }
            let answer = match row["outcome"].as_str().unwrap() {
                "gone" => Answer::Gone(row["reason"].as_str().unwrap().to_owned()),
                "fails" => {
                    Answer::Fails(row["kind"].as_str().unwrap().to_owned(), row["message"].as_str().map(str::to_owned))
                }
                _ => Answer::Delivered,
            };
            answers.insert(id, answer);
        }
        *store.due.lock().unwrap() = rows;
        let store = Arc::new(store);
        let (answers, log) = (Arc::new(answers), Arc::new(Mutex::new(Vec::new())));
        let registry = Registry::new(
            fakes::handlers(&strings(&scenario["handlers"]), &answers, &log),
            fakes::channels(&strings(&scenario["channels"]), &answers, &log),
        );
        let outbox = Outbox::new(store.clone(), registry, Arc::new(Fixed(at)));
        let result = outbox.relay(retry::MAX_PER_PASS).await.unwrap();

        assert_eq!(Value::Array(store.calls()), scenario["calls"], "{name}: the repository calls");
        assert_eq!(Value::Array(log.lock().unwrap().clone()), scenario["delivered"], "{name}: what was delivered");
        let expected = &scenario["result"];
        assert_eq!(
            (result.sent, result.failed, result.abandoned),
            (
                u32::try_from(expected["sent"].as_u64().unwrap()).unwrap(),
                u32::try_from(expected["failed"].as_u64().unwrap()).unwrap(),
                u32::try_from(expected["abandoned"].as_u64().unwrap()).unwrap()
            ),
            "{name}: the result"
        );
        ran += 1;
    }
    assert!(ran >= 25, "every scenario ran: {ran}");
}

fn named<'a>(reference: &'a Value, name: &str) -> &'a Value {
    reference["scenarios"].as_array().unwrap().iter().find(|s| s["name"] == name).unwrap()
}

/// A registry with every type Java relays, each delivering nothing: the relay task is open.
fn as_java(java: &JavaRegistry) -> Registry {
    let (answers, log) = (Arc::new(BTreeMap::new()), Arc::new(Mutex::new(Vec::new())));
    let handlers: Vec<&str> = java.handlers.iter().map(String::as_str).collect();
    let channels: Vec<&str> = java.channels.iter().map(String::as_str).collect();
    Registry::new(fakes::handlers(&handlers, &answers, &log), fakes::channels(&channels, &answers, &log))
}

#[tokio::test]
async fn the_tasks_ask_what_java_s_ask() {
    let reference = reference();
    let at = now(&reference);
    let java = JavaRegistry::compiled_in().unwrap();

    let store = Arc::new(Recording::default());
    let outbox = Arc::new(Outbox::new(store.clone(), as_java(&java), Arc::new(Fixed(at))));
    let relay = NotificationRelayTask::new(outbox, &java);
    assert!(!relay.is_held(), "{}", relay.coverage());
    relay.run().await.unwrap();
    assert_eq!(Value::Array(store.calls()), named(&reference, "the relay task")["calls"]);

    let purge = named(&reference, "the purge task");
    let store = Arc::new(Recording { pruned: 3, ..Recording::default() });
    let outbox = Arc::new(Outbox::new(store.clone(), Registry::default(), Arc::new(Fixed(at))));
    assert_eq!(outbox.prune_sent().await.unwrap(), purge["pruned"].as_u64().unwrap());
    SentMessagesTask::new(outbox).run().await.unwrap();
    assert_eq!(Value::Array(store.calls()), purge["calls"]);
}

#[tokio::test]
async fn the_counts_are_java_s() {
    let reference = reference();
    let rows = vec![("sent".to_owned(), 4), ("failed".to_owned(), 1), ("pending".to_owned(), 12)];
    let store = Arc::new(Recording { counts: rows, ..Recording::default() });
    let outbox = Outbox::new(store, Registry::default(), Arc::new(Fixed(now(&reference))));
    let counts = serde_json::to_value(outbox.counts().await.unwrap()).unwrap();
    assert_eq!(counts, named(&reference, "the counts")["counts"]);
}

#[test]
fn the_compiled_in_registry_is_the_reference_set_s() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/outbox/registry.json");
    let file: JavaRegistry = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let compiled = JavaRegistry::compiled_in().unwrap();
    assert_eq!(compiled, file);
    // Java's eleven: what the started application relays on the day the guard was written. A type added on the Java
    // side regenerates the file, and the guard holds the relay back until the port follows.
    assert_eq!(compiled.handlers.len() + compiled.channels.len(), 11, "{compiled:?}");
    assert!(compiled.channels.contains(vectispire_cp_outbox::TYPE_SCAN_DELTA));
}
