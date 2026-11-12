//! The control plane's outbox — the Rust of `core.outbox` (plan, Phase 2 task 2.2). A **shared** module, as Java
//! declares it on `VectispireApplication`; it uses `maintenance` and nothing else.
//!
//! - [`Outbox::enqueue`] adds a message to the transaction **the caller already opened** — a `&mut Tx`, Java's
//!   `MANDATORY` as a type — so the message becomes durable at the instant the state it describes does, or not at all
//!   (decision 0033). The message id is stamped into the payload, because delivery is at least once.
//! - [`Outbox::relay`] tries each due message once: claimed by a conditional update on `next_attempt_at` (no row lock),
//!   delivered by its type's handler or channel, settled on its own — sent, retried on the backoff, or abandoned with
//!   its reason. A type nobody handles is a failure like any other, retried then abandoned, never skipped.
//! - [`SecurityEvents`] is the port a module raises a SIEM event through — Java's `SecurityEventRaised` and
//!   `SecurityEventRaisedApart` — implemented by the SIEM module and handed in by the binary, so that `issues`, `gate`
//!   and the threat feed raise events without depending on the export.
//! - [`Outbox::prune_sent`] and [`Outbox::counts`] are the purge and the screen's figures.
//! - [`NotificationRelayTask`] and [`SentMessagesTask`] are the module's slots in the maintenance turns. **The relay task
//!   is held back while this binary's handlers differ from Java's** (README.md, "The relay is held back").

#![forbid(unsafe_code)]

mod delivery;
mod internal;
mod payload;
mod persistence;
pub mod retry;
mod security_events;

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use futures_util::FutureExt;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_maintenance::{Clock, MaintenanceTask};

pub use delivery::{
    Coverage, Delivery, DeliveryError, JAVA_REGISTRY, JavaRegistry, NotificationChannel, OutboxHandler, Registry,
};
pub use internal::{NotificationRelayTask, SentMessagesTask};
pub use payload::{PayloadError, stamped};
pub use persistence::{DueMessage, FAILED, NewMessage, OutboxStore, PENDING, SENT, StoreError, StoreFuture};
pub use security_events::{NotExported, RaiseError, SecurityEvents};

use delivery::Route;

/// Every message the scan notifications write: the generic webhook's type.
pub const TYPE_SCAN_DELTA: &str = "scan_delta";

/// What one pass did: delivered, to be retried, out of attempts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayResult {
    pub sent: u32,
    pub failed: u32,
    pub abandoned: u32,
}

impl NewMessage {
    /// The row for `payload` under `id`: pending, never tried — a null next attempt is "due now", not "not yet".
    pub fn pending<T: Serialize + ?Sized>(
        id: Uuid,
        message_type: &str,
        team_id: Option<i64>,
        payload: &T,
        created_at: OffsetDateTime,
    ) -> Result<NewMessage, PayloadError> {
        Ok(NewMessage {
            id,
            message_type: message_type.to_owned(),
            team_id,
            payload: stamped(payload, id)?,
            status: PENDING,
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            created_at,
            sent_at: None,
        })
    }
}

/// Why a message was not queued. The caller's transaction is then to be rolled back with the state it describes.
#[derive(Debug, thiserror::Error)]
pub enum EnqueueError {
    #[error(transparent)]
    Payload(#[from] PayloadError),
    #[error("the outbox message was not written: {0}")]
    Database(StoreError),
}

/// The compiled-in Java registry did not read — a build whose reference file is broken, refused at start.
#[derive(Debug, thiserror::Error)]
#[error("reference/outbox/registry.json does not read: {0}")]
pub struct UnreadableRegistry(#[from] serde_json::Error);

/// The module's two maintenance tasks, the relay held to the Java registry compiled into this binary.
pub fn tasks(outbox: Arc<Outbox>) -> Result<Vec<Arc<dyn MaintenanceTask>>, UnreadableRegistry> {
    let java = JavaRegistry::compiled_in()?;
    Ok(vec![
        Arc::new(NotificationRelayTask::new(outbox.clone(), &java)) as Arc<dyn MaintenanceTask>,
        Arc::new(SentMessagesTask::new(outbox)),
    ])
}

/// The store on `t_outbox_message`: the relay's statements, each committed on its own.
pub fn database_store(db: Db) -> Arc<dyn OutboxStore> {
    Arc::new(persistence::Rows(db))
}

/// The outbox: the queue and its relay.
pub struct Outbox {
    store: Arc<dyn OutboxStore>,
    registry: Registry,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Outbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbox").field("registry", &self.registry).finish_non_exhaustive()
    }
}

impl Outbox {
    /// Over any store: the database's ([`Outbox::on_database`]), or a recording one in tests.
    pub fn new(store: Arc<dyn OutboxStore>, registry: Registry, clock: Arc<dyn Clock>) -> Outbox {
        Outbox { store, registry, clock }
    }

    pub fn on_database(db: Db, registry: Registry, clock: Arc<dyn Clock>) -> Outbox {
        Outbox::new(database_store(db), registry, clock)
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The clock's instant at the microsecond, as `CoreConfiguration.clock()` ticks: what the columns keep, so the
    /// claim's `at` and the row's value compare as Java's do.
    fn now(&self) -> OffsetDateTime {
        let now = self.clock.now();
        now.replace_microsecond(now.microsecond()).unwrap_or(now)
    }

    /// Adds a message to the caller's transaction and returns the id stamped into its payload.
    ///
    /// **No transaction of its own, and that is the whole point**: a message committed on its own would announce
    /// issues a rollback then removed — the window the outbox exists to close. One message per destination (`team_id`
    /// is whose channel this copy is for, `None` for the global one): a single row for several would let one broken
    /// destination hold back the others, or mark them all delivered on the first success.
    pub async fn enqueue<T: Serialize + ?Sized>(
        &self,
        tx: &mut Tx,
        payload: &T,
        message_type: &str,
        team_id: Option<i64>,
    ) -> Result<Uuid, EnqueueError> {
        let message = NewMessage::pending(Uuid::new_v4(), message_type, team_id, payload, self.now())?;
        persistence::insert(tx, &message).await.map_err(|error| EnqueueError::Database(Box::new(error)))?;
        Ok(message.id)
    }

    /// Tries each due message once, at most `limit`, and says what happened.
    ///
    /// **A delivery's failure never ends the pass**: an unreachable webhook must not stop the rest. A failure of the
    /// store does, as in Java, where the repository's exception leaves `relay` and the turn logs it: the claimed rows
    /// not yet settled fall due again when their claim lapses.
    pub async fn relay(&self, limit: u32) -> Result<RelayResult, StoreError> {
        let at = self.now();
        let due = self.store.find_due(PENDING, at, limit).await?;
        let mut result = RelayResult::default();
        for message in due {
            // **Claimed before it is sent.** Every instance runs this pass and reads the same due rows; without the
            // claim each of them delivered each message.
            if self.store.claim(message.id, PENDING, at, at.saturating_add(retry::CLAIM_WINDOW)).await? == 0 {
                continue;
            }
            // Wrapping, as Java's `int` does: a corrupted counter at its maximum is not a reason to stop the pass.
            let attempts = message.attempts.wrapping_add(1);
            match self.deliver(&message).await {
                Ok(()) => {
                    self.store.mark_sent(message.id, attempts, SENT, at).await?;
                    result.sent = result.sent.saturating_add(1);
                }
                Err(DeliveryError::Gone(reason)) => {
                    // Abandoned at once: twelve attempts would fill the log with an error nobody can act on.
                    self.store.record_attempt(message.id, attempts, Some(&reason), FAILED, None).await?;
                    tracing::error!("Outbox message {} abandoned: {reason}", message.id);
                    result.abandoned = result.abandoned.saturating_add(1);
                }
                Err(DeliveryError::Failed { kind, message: text }) => {
                    if self.settle_failure(&message, attempts, at, &kind, text.as_deref()).await? {
                        result.abandoned = result.abandoned.saturating_add(1);
                    } else {
                        result.failed = result.failed.saturating_add(1);
                    }
                }
            }
        }
        if result.sent > 0 {
            tracing::info!("Outbox: {} message(s) delivered.", result.sent);
        }
        Ok(result)
    }

    /// Records a failed attempt; whether the message is now abandoned for good.
    async fn settle_failure(
        &self,
        message: &DueMessage,
        attempts: i32,
        at: OffsetDateTime,
        kind: &str,
        text: Option<&str>,
    ) -> Result<bool, StoreError> {
        let abandoned = retry::is_abandoned(attempts);
        let next = retry::next_attempt_at(attempts, at);
        let reason = retry::recordable_error(kind, text);
        let status = if abandoned { FAILED } else { PENDING };
        self.store.record_attempt(message.id, attempts, Some(&reason), status, next).await?;
        if abandoned {
            tracing::error!("Outbox message {} abandoned after {attempts} attempts: {reason}", message.id);
        } else {
            tracing::warn!(
                "Outbox message {} failed (attempt {attempts}/{}), retrying at {}.",
                message.id,
                retry::MAX_ATTEMPTS,
                next.map_or_else(|| "never".to_owned(), |next| next.to_string())
            );
        }
        Ok(abandoned)
    }

    /// Hands a row to whoever delivers its type. A type nobody delivers is an error with Java's sentence — retried,
    /// then abandoned with it as its reason — never a silent skip: a skipped row would sit in the table for ever,
    /// counted as neither sent nor failed.
    ///
    /// A destination that panics fails its message like an exception does in Java, rather than ending the pass with
    /// the message claimed and unsettled: it would come back every five minutes, its attempts never counted.
    async fn deliver(&self, message: &DueMessage) -> Result<(), DeliveryError> {
        let delivery = match self.registry.route(&message.message_type) {
            Some(Route::Handler(handler)) => handler.deliver(message.id, &message.payload),
            Some(Route::Channel(channel)) => channel.deliver(&message.payload, message.team_id),
            None => {
                return Err(DeliveryError::failed(
                    "IllegalStateException",
                    format!("No channel handles outbox type {}", message.message_type),
                ));
            }
        };
        AssertUnwindSafe(delivery).catch_unwind().await.unwrap_or_else(|panic| {
            let text = panic
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
                .or_else(|| panic.downcast_ref::<String>().cloned());
            Err(DeliveryError::Failed { kind: "panic".to_owned(), message: text })
        })
    }

    /// Deletes the messages delivered more than [`retry::SENT_RETENTION`] ago. The table is written on every scan.
    pub async fn prune_sent(&self) -> Result<u64, StoreError> {
        self.store.delete_sent_before(SENT, self.now().saturating_sub(retry::SENT_RETENTION)).await
    }

    /// The count per status — abandonments included, which the screen has to show.
    pub async fn counts(&self) -> Result<BTreeMap<String, i64>, StoreError> {
        Ok(self.store.count_by_status().await?.into_iter().collect())
    }
}
