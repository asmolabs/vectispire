//! A store that records every call as `reference/outbox/relay.json` writes Java's repository calls, and destinations
//! that record what they are handed and answer as told — what `OutboxServiceTest` and `OutboxReferenceSetTest` mock.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_maintenance::Clock;
use vectispire_cp_outbox::{
    Delivery, DeliveryError, DueMessage, NotificationChannel, OutboxHandler, OutboxStore, StoreFuture,
};

/// Java's `Instant.toString()`: the fraction in groups of three digits, none when it is zero.
pub fn java_instant(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    );
    let nanos = at.nanosecond();
    let fraction = if nanos == 0 {
        String::new()
    } else if nanos.is_multiple_of(1_000_000) {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    };
    format!("{base}{fraction}Z")
}

pub fn parse_instant(text: &str) -> OffsetDateTime {
    OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).unwrap()
}

#[derive(Debug)]
pub struct Fixed(pub OffsetDateTime);

impl Clock for Fixed {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// The repository as a mock: due rows handed over, claims answered per id, every call written down.
#[derive(Default)]
pub struct Recording {
    pub due: Mutex<Vec<DueMessage>>,
    /// Ids whose claim another instance won.
    pub taken: BTreeSet<Uuid>,
    pub pruned: u64,
    pub counts: Vec<(String, i64)>,
    pub calls: Mutex<Vec<Value>>,
    /// A call that fails, by method name.
    pub failing: Option<&'static str>,
}

impl Recording {
    fn record(&self, method: &str, args: Vec<Value>) -> Result<(), vectispire_cp_outbox::StoreError> {
        self.calls.lock().unwrap().push(json!({ "method": method, "args": args }));
        if self.failing == Some(method) {
            return Err(format!("{method} failed").into());
        }
        Ok(())
    }

    pub fn calls(&self) -> Vec<Value> {
        self.calls.lock().unwrap().clone()
    }
}

fn instant(at: Option<OffsetDateTime>) -> Value {
    at.map_or(Value::Null, |at| Value::String(java_instant(at)))
}

impl OutboxStore for Recording {
    fn find_due(&self, status: &'static str, at: OffsetDateTime, limit: u32) -> StoreFuture<'_, Vec<DueMessage>> {
        Box::pin(async move {
            self.record("findDue", vec![json!(status), instant(Some(at)), json!(limit)])?;
            Ok(self.due.lock().unwrap().clone())
        })
    }

    fn claim(&self, id: Uuid, status: &'static str, at: OffsetDateTime, until: OffsetDateTime) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            self.record("claim", vec![json!(id.to_string()), json!(status), instant(Some(at)), instant(Some(until))])?;
            Ok(u64::from(!self.taken.contains(&id)))
        })
    }

    fn record_attempt<'a>(
        &'a self,
        id: Uuid,
        attempts: i32,
        last_error: Option<&'a str>,
        status: &'static str,
        next_attempt_at: Option<OffsetDateTime>,
    ) -> StoreFuture<'a, u64> {
        Box::pin(async move {
            self.record(
                "recordAttempt",
                vec![
                    json!(id.to_string()),
                    json!(attempts),
                    json!(last_error),
                    json!(status),
                    instant(next_attempt_at),
                ],
            )?;
            Ok(1)
        })
    }

    fn mark_sent(
        &self,
        id: Uuid,
        attempts: i32,
        status: &'static str,
        sent_at: OffsetDateTime,
    ) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            self.record(
                "markSent",
                vec![json!(id.to_string()), json!(attempts), json!(status), instant(Some(sent_at))],
            )?;
            Ok(1)
        })
    }

    fn delete_sent_before(&self, status: &'static str, cutoff: OffsetDateTime) -> StoreFuture<'_, u64> {
        Box::pin(async move {
            self.record("deleteSentBefore", vec![json!(status), instant(Some(cutoff))])?;
            Ok(self.pruned)
        })
    }

    fn count_by_status(&self) -> StoreFuture<'_, Vec<(String, i64)>> {
        Box::pin(async move {
            self.record("countByStatus", Vec::new())?;
            Ok(self.counts.clone())
        })
    }
}

/// What a destination answers, by message id; an id it was not told about is delivered.
#[derive(Debug, Clone)]
pub enum Answer {
    Delivered,
    Gone(String),
    Fails(String, Option<String>),
    /// `panic!("{text}")`: a `String` payload.
    Panics(&'static str),
    /// A literal `panic!`: a `&'static str` payload.
    PanicsLiterally,
}

pub type Answers = Arc<BTreeMap<Uuid, Answer>>;
pub type Log = Arc<Mutex<Vec<Value>>>;

fn answer(answers: &Answers, id: Uuid) -> Result<(), DeliveryError> {
    match answers.get(&id).cloned().unwrap_or(Answer::Delivered) {
        Answer::Delivered => Ok(()),
        Answer::Gone(reason) => Err(DeliveryError::Gone(reason)),
        Answer::Fails(kind, message) => Err(DeliveryError::Failed { kind, message }),
        Answer::Panics(text) => panic!("{text}"),
        Answer::PanicsLiterally => panic!("a literal panic"),
    }
}

pub struct Handler {
    pub kind: String,
    pub answers: Answers,
    pub log: Log,
}

impl OutboxHandler for Handler {
    fn message_type(&self) -> &str {
        &self.kind
    }

    fn deliver<'a>(&'a self, message_id: Uuid, payload: &'a str) -> Delivery<'a> {
        Box::pin(async move {
            self.log.lock().unwrap().push(json!({
                "to": format!("handler {}", self.kind), "id": message_id.to_string(), "payload": payload
            }));
            answer(&self.answers, message_id)
        })
    }
}

/// A channel reads the message id from the payload, as Java's channel reads `NotificationPayload.messageId()`.
pub struct Channel {
    pub kind: String,
    pub answers: Answers,
    pub log: Log,
}

impl NotificationChannel for Channel {
    fn message_type(&self) -> &str {
        &self.kind
    }

    fn is_configured(&self) -> bool {
        true
    }

    fn deliver<'a>(&'a self, payload: &'a str, team_id: Option<i64>) -> Delivery<'a> {
        Box::pin(async move {
            let id: Value = serde_json::from_str(payload)
                .map_err(|error| DeliveryError::failed("JsonParseException", error.to_string()))?;
            let id = id["message_id"].as_str().unwrap_or_default().to_owned();
            self.log.lock().unwrap().push(json!({
                "to": format!("channel {}", self.kind), "id": id, "team": team_id
            }));
            answer(&self.answers, Uuid::parse_str(&id).unwrap_or_default())
        })
    }
}

pub fn handlers(types: &[&str], answers: &Answers, log: &Log) -> Vec<Arc<dyn OutboxHandler>> {
    types
        .iter()
        .map(|kind| {
            Arc::new(Handler { kind: (*kind).to_owned(), answers: answers.clone(), log: log.clone() })
                as Arc<dyn OutboxHandler>
        })
        .collect()
}

pub fn channels(types: &[&str], answers: &Answers, log: &Log) -> Vec<Arc<dyn NotificationChannel>> {
    types
        .iter()
        .map(|kind| {
            Arc::new(Channel { kind: (*kind).to_owned(), answers: answers.clone(), log: log.clone() })
                as Arc<dyn NotificationChannel>
        })
        .collect()
}
