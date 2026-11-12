//! Queues the security events a SOC receives, so that each is sent only if what caused it committed — `SiemEvents`.
//!
//! **The outbox, not a call.** An event is an outbox row written in the transaction it describes, sent by
//! the relay after the commit with the relay's claim, backoff and abandonment, and never on the path of the action it
//! reports. **At least once**: a collector can accept an event and the write recording the delivery can fail; the
//! event then leaves again, carrying the outbox message id as CEF `externalId`, which is what a SOC deduplicates on.
//!
//! **Ways in.**
//!
//! - [`Listener::recorded_in_transaction`] — the hook. Every audit entry passes here inside its own transaction, so
//!   the event commits with it ([`Listener::recorded`] is the audit log's fallback when the two could not); the entries
//!   that signal an event — by their operation, or because their writer named one — become one. Actor, address,
//!   target and action come from the entry, so the event says what the audit log says.
//! - [`SiemEvents::enqueue`] (in the caller's transaction, `MANDATORY` as a type) and [`SiemEvents::publish`] (in one
//!   of its own, never failing) — for the events with no audit entry behind them: a KEV reclassification, a gate
//!   refusal. Java's `SecurityEventRaised` and `SecurityEventRaisedApart` are Spring events delivered to these two; the
//!   modules that raise them (issues, gate, the threat feed) are handed this queue as `cp-outbox`'s
//!   [`SecurityEvents`] port, which these two implement.
//! - [`ChainBrokenListener`] — the audit log's own alarm, heard rather than called, so that the audit log, which this
//!   listens to, does not call it back.
//!
//! Nothing is queued when the export is off, has no endpoint, or the event is below the configured minimum: the table
//! is written on every scan already, and a queue nobody will send is a queue an operator has to learn to ignore.

use std::sync::Arc;

use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use vectispire_cp_audit::{AuditChainBroken, ChainBrokenListener, Clock, Listener, ListenerError, Record};
use vectispire_cp_db::{Db, Mode, Tx};
use vectispire_cp_outbox::{Outbox, RaiseError, SecurityEvents};
use vectispire_domain::instant::Instant;
use vectispire_domain::java;
use vectispire_domain::siem::{CefEvent, SecurityEventType, severity_filter, signalled_by};

use crate::persistence;

/// The outbox `message_type`. Stored on every row: it must not move.
pub const TYPE: &str = "siem_event";

/// Enough for any audit description, bounded so that one oversized value cannot bloat every row. UTF-16 units.
pub const MAX_MESSAGE_LENGTH: usize = 1_024;

/// What the outbox row holds: the event, not its rendering — `SiemEvents.QueuedEvent`. The CEF line is rendered at
/// delivery, so the product version and the message id it carries are the ones in force when it leaves.
///
/// **The members are Java's, in Java's order**, because either control plane reads what the other queued:
/// `eventType` (the constant's name), `timestamp` (epoch milliseconds, CEF's `rt`), `message` (`null` written, not
/// omitted), `extensions` (in their order) and `cefSeverity` — the event's own, which is not always the type's; absent
/// in a row queued before it was stored, which then leaves at its type's severity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueuedEvent {
    #[serde(default)]
    pub event_type: Option<String>,
    /// A primitive `long` in Java: absent or `null` reads as zero.
    #[serde(default, deserialize_with = "nullable_long")]
    pub timestamp: i64,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub extensions: Option<Map<String, Value>>,
    #[serde(default)]
    pub cef_severity: Option<i32>,
}

fn nullable_long<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    Ok(Option::<i64>::deserialize(deserializer)?.unwrap_or(0))
}

/// Why a queued row cannot become an event — each the exception Java's delivery throws, which the relay retries and
/// then abandons.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    /// `IllegalStateException`: the row is not a `QueuedEvent`, or names a type this version does not know (a row a
    /// newer version wrote, during an upgrade).
    #[error("{0}")]
    State(String),
    /// `IllegalArgumentException`: the event refuses itself — an extension key that is not one, a severity off the
    /// scale.
    #[error("{0}")]
    Argument(String),
}

impl Unreadable {
    pub fn kind(&self) -> &'static str {
        match self {
            Unreadable::State(_) => "IllegalStateException",
            Unreadable::Argument(_) => "IllegalArgumentException",
        }
    }
}

impl QueuedEvent {
    /// `QueuedEvent.of`.
    pub fn of(event: &CefEvent) -> QueuedEvent {
        let extensions =
            event.extensions().iter().map(|(key, value)| (key.clone(), Value::String(value.clone()))).collect();
        QueuedEvent {
            event_type: Some(event.event_type().wire_name().to_owned()),
            // `toEpochMilli` throws past some 292 million years; a clock does not get there.
            timestamp: event.timestamp().to_epoch_milli().unwrap_or(i64::MAX),
            message: event.message().map(str::to_owned),
            extensions: Some(extensions),
            cef_severity: Some(i32::from(event.cef_severity())),
        }
    }

    /// The stored text, read as Java's mapper reads it: unknown members (the `message_id` the outbox stamps) ignored.
    ///
    /// **Not Jackson's coercions.** A member of another type — an extension value that is a number, a timestamp that
    /// is a string — is refused here where Jackson would coerce it. Neither control plane writes one.
    pub fn read(payload: &str) -> Result<QueuedEvent, Unreadable> {
        serde_json::from_str(payload)
            .map_err(|error| Unreadable::State(format!("A queued SIEM event could not be read: {error}")))
    }

    /// `toEvent`: the event, carrying the message id as `externalId` — in place if the row already names one, last
    /// otherwise, as `LinkedHashMap.put` does.
    pub fn to_event(&self, message_id: &str) -> Result<CefEvent, Unreadable> {
        let known = self.event_type.as_deref().and_then(SecurityEventType::from_wire_name).ok_or_else(|| {
            Unreadable::State(format!("SIEM event {message_id} names an event type this version does not know"))
        })?;
        let mut extensions: Vec<(String, String)> = Vec::new();
        for (key, value) in self.extensions.iter().flatten() {
            let Value::String(text) = value else {
                return Err(Unreadable::State(format!(
                    "A queued SIEM event could not be read: the extension {key} is not text"
                )));
            };
            extensions.push((key.clone(), text.clone()));
        }
        match extensions.iter_mut().find(|(key, _)| key == "externalId") {
            Some((_, existing)) => message_id.clone_into(existing),
            None => extensions.push(("externalId".to_owned(), message_id.to_owned())),
        }
        let pairs: Vec<(&str, &str)> = extensions.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
        let severity = self.cef_severity.unwrap_or_else(|| i32::from(known.cef_severity()));
        CefEvent::new(known, of_epoch_milli(self.timestamp), self.message.as_deref(), &pairs, severity)
            .map_err(|refused| Unreadable::Argument(refused.0))
    }
}

/// `Instant.ofEpochMilli`: floor division, so a negative millisecond is in the second before.
pub fn of_epoch_milli(milliseconds: i64) -> Instant {
    let nano = u32::try_from(milliseconds.rem_euclid(1_000)).unwrap_or(0).saturating_mul(1_000_000);
    Instant { epoch_second: milliseconds.div_euclid(1_000), nano }
}

/// An instant of the control plane's clock as the domain holds one.
pub fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

/// Why an event was not queued.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("the SIEM configuration could not be read: {0}")]
    Config(#[from] persistence::DbError),
    #[error(transparent)]
    Outbox(#[from] vectispire_cp_outbox::EnqueueError),
    #[error("the transaction could not be opened or committed: {0}")]
    Transaction(String),
}

/// The event queue.
pub struct SiemEvents {
    db: Db,
    outbox: Arc<Outbox>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SiemEvents {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SiemEvents").finish_non_exhaustive()
    }
}

impl SiemEvents {
    pub fn new(db: Db, outbox: Arc<Outbox>, clock: Arc<dyn Clock>) -> SiemEvents {
        SiemEvents { db, outbox, clock }
    }

    /// Adds an event to the transaction **the caller already opened** — Java's `MANDATORY`, as a type: a caller with
    /// no transaction would commit the event independently of what it describes. Its failure is the caller's to roll
    /// back with.
    pub async fn enqueue(&self, tx: &mut Tx, event: &CefEvent) -> Result<(), QueueError> {
        queue(&self.outbox, tx, event).await
    }

    /// Queues an event in a transaction of its own, for a caller whose state has already committed or that has none.
    /// **Never fails**: the export must not fail the action it reports on; a failure is logged at error.
    ///
    /// Call it outside any open write transaction: inside one, the event would report a state that may still roll
    /// back, on a second connection held while the first keeps its locks (decision 0033).
    pub async fn publish(&self, event: &CefEvent) {
        if let Err(failed) = self.publish_apart(event).await {
            tracing::error!("SIEM event {} could not be queued: {failed}", event.event_type().wire_name());
        }
    }

    async fn publish_apart(&self, event: &CefEvent) -> Result<(), QueueError> {
        let mut tx =
            self.db.begin(Mode::ReadWrite).await.map_err(|error| QueueError::Transaction(error.to_string()))?;
        match queue(&self.outbox, &mut tx, event).await {
            Ok(()) => tx.commit().await.map_err(|error| QueueError::Transaction(error.to_string())),
            Err(failed) => {
                let _ = tx.rollback().await;
                Err(failed)
            }
        }
    }
}

/// The one rule of what is queued.
async fn queue(outbox: &Outbox, tx: &mut Tx, event: &CefEvent) -> Result<(), QueueError> {
    if matches!(event.event_type(), SecurityEventType::PingTest | SecurityEventType::SiemExportStopped) {
        // The connection test is sent synchronously by the route; queued, it would reach the collector a minute later
        // and prove nothing about the moment the button was pressed. The stop notice is sent synchronously by the save,
        // to the collector being left; queued, it would be read against a configuration that no longer names it.
        return Ok(());
    }
    let Some(config) = persistence::find_in(tx).await? else { return Ok(()) };
    let exporting = config.enabled && config.endpoint.as_deref().is_some_and(|endpoint| !java::is_blank(endpoint));
    if !exporting || !severity_filter::admits(event, Some(&config.min_severity)) {
        return Ok(());
    }
    outbox.enqueue(tx, &QueuedEvent::of(event), TYPE, None).await?;
    Ok(())
}

/// The event an audit entry signals — by its writer's choice, or by its operation — or `None`.
pub fn signalled_by_entry(entry: &Record, at: OffsetDateTime) -> Option<CefEvent> {
    let signalled = match entry.signal {
        Some(signal) => match SecurityEventType::from_wire_name(signal.0) {
            Some(named) => Some(named),
            None => {
                // `Signal` is a name here where Java's is the enum itself; a name the catalogue does not hold is a
                // writer's mistake, said loudly rather than dropped in silence.
                tracing::error!(
                    "The audit entry {} names the security event {}, which the SIEM catalogue does not hold; it is \
                     read by its operation instead",
                    entry.operation,
                    signal.0
                );
                signalled_by(entry.operation.wire_name())
            }
        },
        None => signalled_by(entry.operation.wire_name()),
    }?;
    let message = entry.description.as_deref().map(bounded);
    CefEvent::builder(signalled, instant(at))
        .message(message.as_deref())
        .user(entry.user_id.as_deref())
        .source_ip(entry.ip_address.as_deref())
        .action(entry.operation.wire_name())
        .target(entry.resource_id.as_deref())
        .user_agent(entry.user_agent.as_deref())
        .build()
        .ok()
}

/// `message.substring(0, 1024)` — in UTF-16 units, as Java cuts. A cut through a surrogate pair leaves Java a lone
/// high surrogate, which the database driver stores as `?`: so does this.
pub fn bounded(message: &str) -> String {
    if java::utf16_len(message) <= MAX_MESSAGE_LENGTH {
        return message.to_owned();
    }
    let mut kept = String::with_capacity(MAX_MESSAGE_LENGTH);
    let mut units = 0usize;
    for c in message.chars() {
        let width = c.len_utf16();
        if units.saturating_add(width) > MAX_MESSAGE_LENGTH {
            if units < MAX_MESSAGE_LENGTH {
                // Room for one unit, and the character needs two: Java keeps its high surrogate.
                kept.push('?');
            }
            break;
        }
        kept.push(c);
        units = units.saturating_add(width);
    }
    kept
}

impl Listener for SiemEvents {
    /// The event and its entry commit together, so an event exists exactly when its entry does (decision 0033).
    /// Entries that signal nothing cost no query.
    fn recorded_in_transaction<'a>(
        &'a self,
        entry: &'a Record,
        at: OffsetDateTime,
        tx: &'a mut Tx,
    ) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async move {
            if let Some(event) = signalled_by_entry(entry, at) {
                queue(&self.outbox, tx, &event).await.map_err(|failed| Box::new(failed) as ListenerError)?;
            }
            Ok(())
        })
    }

    /// The same event, after the entry committed apart from it — the audit log's fallback.
    fn recorded<'a>(&'a self, entry: &'a Record, at: OffsetDateTime) -> BoxFuture<'a, Result<(), ListenerError>> {
        Box::pin(async move {
            if let Some(event) = signalled_by_entry(entry, at) {
                self.publish(&event).await;
            }
            Ok(())
        })
    }

    fn name(&self) -> &str {
        "SiemEvents"
    }
}

impl ChainBrokenListener for SiemEvents {
    /// Heard synchronously, in the verifying request, outside any transaction: [`SiemEvents::publish`] gives it one of
    /// its own and swallows a failure, so the verification answers whatever the export does.
    fn chain_broken<'a>(&'a self, broken: &'a AuditChainBroken) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let event = CefEvent::builder(SecurityEventType::AuditChainBroken, instant(self.clock.now()))
                .message(broken.describe().as_str())
                .action("AUDIT_VERIFIED")
                .target(broken.broken_at.as_deref())
                .build();
            match event {
                Ok(event) => self.publish(&event).await,
                Err(refused) => tracing::error!("The audit chain's alarm could not be built: {refused}"),
            }
        })
    }
}

impl SecurityEvents for SiemEvents {
    fn raise<'a>(&'a self, tx: &'a mut Tx, event: &'a CefEvent) -> BoxFuture<'a, Result<(), RaiseError>> {
        Box::pin(async move { self.enqueue(tx, event).await.map_err(|failed| Box::new(failed) as RaiseError) })
    }

    fn raise_apart<'a>(&'a self, event: &'a CefEvent) -> BoxFuture<'a, ()> {
        Box::pin(self.publish(event))
    }
}
