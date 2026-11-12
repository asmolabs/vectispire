//! The relay's side of `t_outbox_message` — Java's `OutboxMessageRepository`, as a port.
//!
//! **A port, so the relay can be run over a recording store.** That is how `OutboxServiceTest` runs Java's relay (a
//! mocked repository), and how `reference/outbox/relay.json` was written: the calls Java's relay makes, in order,
//! with their arguments. The Rust relay over a recording store must make the same ones (`tests/reference.rs`); over
//! the database the same calls are the checked statements of this layer ([`super::Rows`]). Declared here, below the
//! service, as `cp-access` declares its stores: the layer that implements a port is the one that may define it.
//!
//! Every method is **one statement, committed on its own**: Java's repository methods are `@Transactional` and the
//! relay calls them outside any transaction of its own, so a claim is visible to the other instances before the
//! delivery, and each message is settled in its own transaction — the twelfth failing does not undo the eleven
//! recorded before it.

use std::future::Future;
use std::pin::Pin;

use time::OffsetDateTime;
use uuid::Uuid;

/// A failure of the store, kept opaque: the relay names no driver.
pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

/// A store call under way.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// `status`, as stored. Java passes them as arguments and so does the port: they are the data contract.
pub const PENDING: &str = "pending";
pub const SENT: &str = "sent";
pub const FAILED: &str = "failed";

/// A row the due query hands over: what the relay needs to deliver and settle it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueMessage {
    pub id: Uuid,
    pub message_type: String,
    pub team_id: Option<i64>,
    pub payload: String,
    pub attempts: i32,
}

/// `OutboxMessageRepository`, method for method.
pub trait OutboxStore: Send + Sync {
    /// `findDue`: rows of `status` whose next attempt is unset or not after `at`, oldest first (`created_at`, then
    /// `id`), at most `limit`. **An unset next attempt is a first attempt**, due now: read as "not yet", the whole
    /// queue would sit for ever about to go out.
    fn find_due(&self, status: &'static str, at: OffsetDateTime, limit: u32) -> StoreFuture<'_, Vec<DueMessage>>;

    /// `claim`: pushes the row's next attempt to `until` **on the condition the due query read** — still `status`,
    /// still due at `at`. Of two instances that read the same row, the second update finds it pushed ahead and changes
    /// nothing: 1 is "this caller holds it", 0 "someone else does". No row lock: the conditional update is the
    /// mechanism (`tests/engines.rs` races two relays on it).
    fn claim(&self, id: Uuid, status: &'static str, at: OffsetDateTime, until: OffsetDateTime) -> StoreFuture<'_, u64>;

    /// `recordAttempt`: the attempt count, the error, the status and the next attempt (`None` clears it).
    fn record_attempt<'a>(
        &'a self,
        id: Uuid,
        attempts: i32,
        last_error: Option<&'a str>,
        status: &'static str,
        next_attempt_at: Option<OffsetDateTime>,
    ) -> StoreFuture<'a, u64>;

    /// `markSent`: the attempt count, the status and the instant; the next attempt and the error cleared.
    fn mark_sent(&self, id: Uuid, attempts: i32, status: &'static str, sent_at: OffsetDateTime)
    -> StoreFuture<'_, u64>;

    /// `deleteSentBefore`: rows of `status` with a `sent_at` before `cutoff`.
    fn delete_sent_before(&self, status: &'static str, cutoff: OffsetDateTime) -> StoreFuture<'_, u64>;

    /// `countByStatus`: `(status, count)` per status present.
    fn count_by_status(&self) -> StoreFuture<'_, Vec<(String, i64)>>;
}

/// A row as `enqueue` writes it — every column of `t_outbox_message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMessage {
    pub id: Uuid,
    pub message_type: String,
    pub team_id: Option<i64>,
    pub payload: String,
    pub status: &'static str,
    pub attempts: i32,
    pub next_attempt_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
    pub sent_at: Option<OffsetDateTime>,
}
