//! `OutboxServiceTest`'s cases that `tests/reference.rs` does not already run against Java's own calls, and the relay
//! guard: the task is held back while the registry differs from Java's, and a held task touches nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod fakes;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use fakes::{Answer, Answers, Fixed, Log, Recording};
use serde_json::{Value, json};
use time::macros::datetime;
use uuid::Uuid;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence};
use vectispire_cp_outbox::{
    DueMessage, JavaRegistry, NewMessage, NotificationRelayTask, Outbox, PayloadError, Registry, SentMessagesTask,
    retry, stamped,
};

const AT: time::OffsetDateTime = datetime!(2026-08-18 14:00:00 UTC);

fn due(id: u128, message_type: &str, attempts: i32) -> DueMessage {
    let id = Uuid::from_u128(id);
    DueMessage {
        id,
        message_type: message_type.to_owned(),
        team_id: None,
        payload: format!(r#"{{"scan_id":7,"message_id":"{id}"}}"#),
        attempts,
    }
}

fn outbox(store: Arc<Recording>, handlers: &[&str], channels: &[&str], answers: Answers, log: &Log) -> Outbox {
    Outbox::new(
        store,
        Registry::new(fakes::handlers(handlers, &answers, log), fakes::channels(channels, &answers, log)),
        Arc::new(Fixed(AT)),
    )
}

fn store_with(rows: Vec<DueMessage>) -> Arc<Recording> {
    let store = Recording::default();
    *store.due.lock().unwrap() = rows;
    Arc::new(store)
}

fn log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}

#[test]
fn the_payload_carries_a_message_identifier_because_delivery_is_at_least_once() {
    let id = Uuid::from_u128(0xf);
    let message = NewMessage::pending(id, "scan_delta", None, &json!({"scan_id": 7}), AT).unwrap();
    assert!(message.payload.contains(&format!(r#""message_id":"{id}""#)));
    assert_eq!(message.status, "pending");
    assert_eq!(message.next_attempt_at, None, "never tried is due now");
}

#[test]
fn a_payload_that_is_not_an_object_is_refused_not_wrapped() {
    for payload in [json!(null), json!(true), json!(3), json!("text"), json!([1])] {
        assert!(
            matches!(stamped(&payload, Uuid::nil()), Err(PayloadError::NotAnObject(_))),
            "{payload} has nowhere to carry its id"
        );
    }
}

#[tokio::test]
async fn a_panicking_destination_fails_its_message_and_the_pass_goes_on() {
    let store = store_with(vec![due(1, "siem_event", 0), due(2, "siem_event", 0)]);
    let answers: Answers = Arc::new(BTreeMap::from([(Uuid::from_u128(1), Answer::Panics("the SIEM driver broke"))]));
    let outbox = outbox(store.clone(), &["siem_event"], &[], answers, &log());
    let result = outbox.relay(20).await.unwrap();
    assert_eq!((result.sent, result.failed, result.abandoned), (1, 1, 0));
    let calls = store.calls();
    assert_eq!(calls[2]["method"], "recordAttempt");
    assert_eq!(calls[2]["args"][2], "panic: the SIEM driver broke", "the panic's text is the reason");
    assert_eq!(calls[4]["method"], "markSent", "the second message is still delivered");
}

#[tokio::test]
async fn a_literal_panic_s_text_is_the_reason_too() {
    let store = store_with(vec![due(1, "siem_event", 0)]);
    let answers: Answers = Arc::new(BTreeMap::from([(Uuid::from_u128(1), Answer::PanicsLiterally)]));
    outbox(store.clone(), &["siem_event"], &[], answers, &log()).relay(20).await.unwrap();
    assert_eq!(store.calls()[2]["args"][2], "panic: a literal panic");
}

#[tokio::test]
async fn a_failure_of_the_store_ends_the_pass_as_java_s_exception_does() {
    let mut store = Recording { failing: Some("markSent"), ..Recording::default() };
    *store.due.get_mut().unwrap() = vec![due(1, "scan_delta", 0), due(2, "scan_delta", 0)];
    let store = Arc::new(store);
    let outbox = outbox(store.clone(), &[], &["scan_delta"], Arc::new(BTreeMap::new()), &log());
    assert!(outbox.relay(20).await.is_err());
    assert_eq!(store.calls().len(), 3, "nothing after the failed write: findDue, claim, markSent");
}

#[tokio::test]
async fn a_handler_takes_its_type_before_a_channel_of_the_same_type() {
    let log = log();
    let store = store_with(vec![due(1, "shared", 0)]);
    let outbox = outbox(store, &["shared"], &["shared"], Arc::new(BTreeMap::new()), &log);
    outbox.relay(20).await.unwrap();
    let delivered = log.lock().unwrap().clone();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0]["to"], "handler shared");
}

#[tokio::test]
async fn the_first_of_two_destinations_of_one_type_delivers() {
    let first: Log = log();
    let second: Log = log();
    let none: Answers = Arc::new(BTreeMap::new());
    let mut channels = fakes::channels(&["scan_delta"], &none, &first);
    channels.extend(fakes::channels(&["scan_delta"], &none, &second));
    let outbox = Outbox::new(
        store_with(vec![due(1, "scan_delta", 0)]),
        Registry::new(Vec::new(), channels),
        Arc::new(Fixed(AT)),
    );
    outbox.relay(20).await.unwrap();
    assert_eq!((first.lock().unwrap().len(), second.lock().unwrap().len()), (1, 0));
}

#[tokio::test]
async fn the_clock_is_read_at_the_microsecond() {
    let store = store_with(Vec::new());
    let outbox =
        Outbox::new(store.clone(), Registry::default(), Arc::new(Fixed(datetime!(2026-08-18 14:00:00.123456789 UTC))));
    outbox.relay(20).await.unwrap();
    assert_eq!(store.calls()[0]["args"][1], "2026-08-18T14:00:00.123456Z", "as CoreConfiguration.clock() ticks");
}

// ── the guard ──

fn java() -> JavaRegistry {
    JavaRegistry::compiled_in().unwrap()
}

fn types(set: &BTreeSet<String>) -> Vec<&str> {
    set.iter().map(String::as_str).collect()
}

fn registry_with(handlers: &[&str], channels: &[&str]) -> Registry {
    let none: Answers = Arc::new(BTreeMap::new());
    Registry::new(fakes::handlers(handlers, &none, &log()), fakes::channels(channels, &none, &log()))
}

async fn relay_task(registry: Registry) -> (NotificationRelayTask, Arc<Recording>) {
    let store = store_with(vec![due(1, "token_alert", 0)]);
    let outbox = Arc::new(Outbox::new(store.clone(), registry, Arc::new(Fixed(AT))));
    (NotificationRelayTask::new(outbox, &java()), store)
}

#[tokio::test]
async fn the_relay_is_held_while_this_binary_relays_none_of_java_s_types() {
    let (task, store) = relay_task(Registry::default()).await;
    assert!(task.is_held());
    let coverage = task.coverage();
    assert_eq!(coverage.missing_handlers, types(&java().handlers));
    assert_eq!(coverage.missing_channels, types(&java().channels));
    task.run().await.unwrap();
    task.run().await.unwrap();
    assert_eq!(store.calls(), Vec::<Value>::new(), "a held relay reads nothing and claims nothing");
}

#[tokio::test]
async fn the_relay_runs_once_the_registry_is_java_s() {
    let java = java();
    let (task, store) = relay_task(registry_with(&types(&java.handlers), &types(&java.channels))).await;
    assert!(!task.is_held(), "{}", task.coverage());
    task.run().await.unwrap();
    let methods: Vec<Value> = store.calls().iter().map(|call| call["method"].clone()).collect();
    assert_eq!(methods, vec![json!("findDue"), json!("claim"), json!("markSent")]);
}

#[tokio::test]
async fn one_type_missing_holds_the_relay() {
    let java = java();
    let mut handlers = types(&java.handlers);
    let missing = handlers.remove(0).to_owned();
    let (task, store) = relay_task(registry_with(&handlers, &types(&java.channels))).await;
    assert!(task.is_held());
    assert_eq!(task.coverage().missing_handlers, vec![missing]);
    assert!(task.coverage().missing_channels.is_empty() && task.coverage().extra_handlers.is_empty());
    task.run().await.unwrap();
    assert!(store.calls().is_empty());
}

#[tokio::test]
async fn one_channel_missing_holds_the_relay() {
    let java = java();
    let mut channels = types(&java.channels);
    let missing = channels.pop().unwrap().to_owned();
    let (task, _) = relay_task(registry_with(&types(&java.handlers), &channels)).await;
    assert_eq!(task.coverage().missing_channels, vec![missing]);
    assert!(task.is_held());
}

#[tokio::test]
async fn a_handler_java_does_not_relay_holds_the_relay_too() {
    let java = java();
    let mut handlers = types(&java.handlers);
    handlers.push("carrier_pigeon");
    let (task, _) = relay_task(registry_with(&handlers, &types(&java.channels))).await;
    assert!(task.is_held(), "Java would abandon its rows after a switch back");
    assert_eq!(task.coverage().extra_handlers, vec!["carrier_pigeon".to_owned()]);
}

#[tokio::test]
async fn a_channel_java_does_not_relay_holds_the_relay_too() {
    let java = java();
    let mut channels = types(&java.channels);
    channels.push("scan_delta_fax");
    let (task, _) = relay_task(registry_with(&types(&java.handlers), &channels)).await;
    assert!(task.is_held());
    assert_eq!(task.coverage().extra_channels, vec!["scan_delta_fax".to_owned()]);
}

#[tokio::test]
async fn a_channel_registered_as_a_handler_holds_the_relay() {
    // The same names in the wrong contract: a channel's row would reach a handler that reads another shape.
    let java = java();
    let mut handlers = types(&java.handlers);
    let mut channels = types(&java.channels);
    let moved = channels.remove(0);
    handlers.push(moved);
    let (task, _) = relay_task(registry_with(&handlers, &channels)).await;
    assert!(task.is_held());
    assert_eq!(task.coverage().missing_channels, vec![moved.to_owned()]);
    assert_eq!(task.coverage().extra_handlers, vec![moved.to_owned()]);
}

#[tokio::test]
async fn the_tasks_fill_the_outbox_s_two_slots() {
    let outbox = Arc::new(Outbox::new(store_with(Vec::new()), Registry::default(), Arc::new(Fixed(AT))));
    assert_eq!(NotificationRelayTask::new(outbox.clone(), &java()).sequence(), Sequence::NotificationRelay);
    assert_eq!(SentMessagesTask::new(outbox).sequence(), Sequence::SentMessages);
    assert_eq!(retry::MAX_PER_PASS, 20);
}
