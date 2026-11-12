//! Writing and verifying the audit log — `AuditLogService`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use vectispire_cp_db::{Db, LOCK_BACKOFF, LockConflict, Mode, Tx, retry_on_lock_conflict};

use crate::chain::{self, Verification};
use crate::listener::{Listener, ListenerError};
use crate::mirror::{Mirror, MirrorComparison, MirrorEntry};
use crate::persistence::{self, DbError};
use crate::record::{Clock, Record, StoredEntry};
use crate::text::{ADDRESS_COLUMN, TEXT_COLUMN, blank_to_none, truncate, truncate_optional};

/// How many recent entries [`AuditLog::recent_entries_match_their_hashes`] checks: enough that tampering with
/// something an operator did today is caught, small enough to cost one indexed read.
const RECENT_INTEGRITY_WINDOW: i64 = 500;

/// Why an entry, or a verification, could not be done.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error(transparent)]
    Database(#[from] DbError),
    #[error("t_audit_chain_head has lost its row: audit entries are not written without the chain's lock")]
    ChainHeadMissing,
    /// `t_audit_log.description` is `not null`: Java sends the row and the database refuses it; here the
    /// refusal is said before the statement, with the same outcome — no entry, and the failure reported.
    #[error("an audit entry has no description, which t_audit_log.description requires")]
    DescriptionMissing,
    #[error("an audit listener refused the entry: {0}")]
    Listener(ListenerError),
    #[error("the audit mirror could not be read: {0}")]
    Mirror(String),
}

impl LockConflict for AuditError {
    fn is_lock_conflict(&self) -> bool {
        matches!(self, AuditError::Database(database) if database.is_lock_conflict())
    }
}

/// The audit log.
///
/// **[`AuditLog::record`] never fails.** A failure to write the log must not fail the action it describes:
/// the opposite would give a full table the power to stop an administrator signing in. [`AuditLog::append`]
/// returns the failure, for a caller that retries — the outbox's handlers, which would otherwise mark an entry
/// delivered that was lost.
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    mirror: Arc<dyn Mirror>,
    clock: Arc<dyn Clock>,
    listeners: Vec<Arc<dyn Listener>>,
    /// The last millisecond handed out, so that instants strictly increase on this instance. Two entries of
    /// one millisecond would otherwise be ordered by a random id: built in one order and read back in another,
    /// and the verification would fail on an intact log. Advancing rather than waiting — the log needs an
    /// order, not an exact clock — and per instance, which is a known limit: two instances legitimately fork,
    /// and the verification breaks the tie on the identifier.
    last_issued: AtomicI64,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditLog")
            .field("engine", &self.inner.db.engine())
            .field("mirror", &self.inner.mirror)
            .field("listeners", &self.inner.listeners.iter().map(|listener| listener.name()).collect::<Vec<_>>())
            .finish()
    }
}

impl AuditLog {
    pub fn new(db: Db, mirror: Arc<dyn Mirror>, clock: Arc<dyn Clock>, listeners: Vec<Arc<dyn Listener>>) -> AuditLog {
        AuditLog { inner: Arc::new(Inner { db, mirror, clock, listeners, last_issued: AtomicI64::new(i64::MIN) }) }
    }

    /// The pool, for the query side of the module.
    pub(crate) fn db(&self) -> &Db {
        &self.inner.db
    }

    /// Appends an entry, **in its own transaction**: the audited action's may still roll back, and the attempt is
    /// exactly what an auditor wants to see. Never fails — a failure is logged at error level, because a log that
    /// stops recording in silence is worse than one that stops loudly.
    pub async fn record(&self, entry: Record) {
        if let Err(failed) = self.write_with_its_effects(&entry).await {
            tracing::error!(operation = %entry.operation, "Audit entry could not be written: {failed}");
        }
    }

    /// Appends an entry, and returns the failure when it cannot be written.
    pub async fn append(&self, entry: Record) -> Result<(), AuditError> {
        self.write_with_its_effects(&entry).await
    }

    /// The entry and what its listeners write, in one transaction — or, if that fails, the entry alone.
    ///
    /// Once apart, whatever failed: after a rollback nothing tells a listener's failure from the entry's own, and
    /// it need not. The entry is written again without the listeners, and if that fails too the failure was the
    /// entry's.
    async fn write_with_its_effects(&self, entry: &Record) -> Result<(), AuditError> {
        if self.inner.listeners.is_empty() {
            return self.write_retrying_on_locks(entry, false).await;
        }
        match self.write_retrying_on_locks(entry, true).await {
            Ok(()) => Ok(()),
            Err(together) => {
                tracing::warn!(
                    operation = %entry.operation,
                    "Audit entry {} and its listeners' writes could not commit together; writing the entry alone: {together}",
                    entry.operation
                );
                self.write_retrying_on_locks(entry, false).await
            }
        }
    }

    /// The entry's transaction, tried again when a lock refused it — and only then. A refused lock is not a
    /// refused entry: two writers meet at the chain's head, and the engine picks a deadlock's loser or lets a
    /// wait time out; each is gone a moment later. Any other failure is the entry's own.
    async fn write_retrying_on_locks(&self, entry: &Record, with_listeners: bool) -> Result<(), AuditError> {
        retry_on_lock_conflict(&LOCK_BACKOFF, || self.write(entry, with_listeners)).await
    }

    async fn write(&self, entry: &Record, with_listeners: bool) -> Result<(), AuditError> {
        let mut tx = self.inner.db.begin(Mode::ReadWrite).await.map_err(DbError::from)?;
        match self.write_in(&mut tx, entry, with_listeners).await {
            Ok((stored, at)) => {
                tx.commit().await.map_err(DbError::from)?;
                if !with_listeners {
                    self.after_commit(&stored, at).await;
                }
                Ok(())
            }
            Err(failed) => {
                // A rollback that fails leaves the connection to the pool, which discards it; the entry's own
                // failure is the one worth reporting.
                let _ = tx.rollback().await;
                Err(failed)
            }
        }
    }

    async fn write_in(
        &self,
        tx: &mut Tx,
        entry: &Record,
        with_listeners: bool,
    ) -> Result<(Record, OffsetDateTime), AuditError> {
        if !persistence::lock_chain(tx).await? {
            return Err(AuditError::ChainHeadMissing);
        }
        let head = persistence::head(tx).await?.map(StoredEntry::from_row);

        // Set here rather than left to a column default: the hash covers the timestamp, and a value applied by
        // the database after the computation would make every entry fail its own verification.
        let timestamp = after(head.as_ref(), self.monotonic_now());
        let mut row = StoredEntry {
            id: Uuid::new_v4(),
            description: entry
                .description
                .as_deref()
                .map(|text| truncate(text, TEXT_COLUMN).to_owned())
                .unwrap_or_default(),
            operation_type: entry.operation.wire_name().to_owned(),
            // `String.valueOf`: an absent resource is the four letters "null" in the column.
            resource_id: truncate(entry.resource_id.as_deref().unwrap_or("null"), TEXT_COLUMN).to_owned(),
            timestamp,
            user_id: truncate_optional(entry.user_id.as_deref(), TEXT_COLUMN),
            ip_address: truncate_optional(blank_to_none(entry.ip_address.as_deref()), ADDRESS_COLUMN),
            user_agent: truncate_optional(blank_to_none(entry.user_agent.as_deref()), TEXT_COLUMN),
            previous_hash: head.and_then(|head| head.entry_hash),
            entry_hash: None,
        };
        if entry.description.is_none() {
            return Err(AuditError::DescriptionMissing);
        }
        row.entry_hash = Some(chain::entry_hash(&row.chain_entry()));
        persistence::insert(tx, &row.to_row()).await?;

        let stored = Record {
            operation: entry.operation,
            // The caller's, not the column's.
            resource_id: entry.resource_id.clone(),
            description: Some(row.description.clone()),
            user_id: row.user_id.clone(),
            ip_address: row.ip_address.clone(),
            user_agent: row.user_agent.clone(),
            signal: entry.signal,
        };

        // **Before the mirror.** A listener that fails aborts this transaction and the entry is written again on
        // its own: had the mirror line gone first, it would hold an attempt the table never kept.
        if with_listeners {
            for listener in &self.inner.listeners {
                listener.recorded_in_transaction(&stored, row.timestamp, tx).await.map_err(AuditError::Listener)?;
            }
        }

        // **Mirrored before the commit, deliberately.** A rollback after the line leaves the mirror holding an
        // entry the table never kept — noise the comparison reports as unrecorded. Writing after the commit would
        // leave the opposite, an entry missing from the mirror, which is the case the mirror exists for.
        if !self.inner.mirror.append(&mirrored(&row)) {
            tracing::error!("Audit entry {} is in the table but not in the mirror", row.id);
        }
        Ok((stored, row.timestamp))
    }

    /// The fallback: tells the listeners once the entry's transaction has committed. What they receive is the
    /// entry as stored, so an event forwarded to a SOC says what the audit log says.
    async fn after_commit(&self, stored: &Record, at: OffsetDateTime) {
        for listener in &self.inner.listeners {
            if let Err(failed) = listener.recorded(stored, at).await {
                tracing::error!("Audit listener {} failed on {}: {failed}", listener.name(), stored.operation);
            }
        }
    }

    /// The next instant, strictly after the last one this instance handed out.
    fn monotonic_now(&self) -> OffsetDateTime {
        let now = self.inner.clock.now();
        let candidate = i64::try_from(now.unix_timestamp_nanos().div_euclid(1_000_000)).unwrap_or(i64::MAX);
        let next = |previous: i64| if candidate > previous { candidate } else { previous.saturating_add(1) };
        // The closure always answers, so the update cannot fail; `previous` is what it replaced.
        let previous = self
            .inner
            .last_issued
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |previous| Some(next(previous)))
            .unwrap_or_else(|unchanged| unchanged);
        i128::from(next(previous))
            .checked_mul(1_000_000)
            .and_then(|nanos| OffsetDateTime::from_unix_timestamp_nanos(nanos).ok())
            .unwrap_or(now)
    }

    /// The newest entries, for the screen.
    pub async fn recent(&self, limit: i64) -> Result<Vec<StoredEntry>, AuditError> {
        Ok(persistence::recent(&self.inner.db, limit).await?.into_iter().map(StoredEntry::from_row).collect())
    }

    /// The integrity of the most recent entries, without reading the table: each rehashed from its own fields.
    ///
    /// That detects a *modified* row, the realistic threat. It does not check that predecessors still exist — an
    /// entry at the window's edge legitimately points outside it. So `false` is a real finding ("a recent entry
    /// no longer matches its own hash"), and `true` means "nothing recent was altered", not "the log is whole".
    pub async fn recent_entries_match_their_hashes(&self) -> Result<bool, AuditError> {
        for row in
            persistence::recent(&self.inner.db, RECENT_INTEGRITY_WINDOW).await?.into_iter().map(StoredEntry::from_row)
        {
            let Some(stored) = row.entry_hash.as_deref().filter(|hash| !crate::text::is_blank(hash)) else {
                // Predates the chaining: counting it would be an alarm about a row nobody claimed was covered.
                continue;
            };
            if stored != chain::entry_hash(&row.chain_entry()) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The whole chain, verified — `None` in [`Verification::broken`] when it is intact. Reads the whole table:
    /// a deliberate verification, not something done on every page render.
    pub async fn verify(&self) -> Result<Verification, AuditError> {
        let rows: Vec<StoredEntry> =
            persistence::all_in_chain_order(&self.inner.db).await?.into_iter().map(StoredEntry::from_row).collect();
        Ok(chain::verify(&rows.iter().map(StoredEntry::verifiable).collect::<Vec<_>>()))
    }

    /// Whether a second copy exists at all — the question, without the comparison.
    pub fn mirror_configured(&self) -> bool {
        self.inner.mirror.configured()
    }

    /// Compares the two copies, by entry hash, as a multiset: an entry twice in the mirror and once in the table
    /// is a difference of one — a duplicate line is how a retried write shows, and it must not hide a deletion.
    pub async fn verify_against_mirror(&self) -> Result<MirrorComparison, AuditError> {
        if !self.inner.mirror.configured() {
            return Ok(MirrorComparison { configured: false, missing_from_table: 0, missing_from_mirror: 0 });
        }
        let mut in_mirror: HashMap<String, usize> = HashMap::new();
        for hash in self.inner.mirror.entry_hashes().map_err(AuditError::Mirror)? {
            let held = in_mirror.entry(hash).or_default();
            *held = held.saturating_add(1);
        }
        let mut missing_from_mirror: usize = 0;
        for row in persistence::all_in_chain_order(&self.inner.db).await?.into_iter().map(StoredEntry::from_row) {
            let Some(hash) = row.entry_hash.filter(|hash| !crate::text::is_blank(hash)) else { continue };
            match in_mirror.get_mut(&hash) {
                Some(remaining) if *remaining > 0 => *remaining = remaining.saturating_sub(1),
                _ => missing_from_mirror = usize::saturating_add(missing_from_mirror, 1),
            }
        }
        Ok(MirrorComparison { configured: true, missing_from_table: in_mirror.values().sum(), missing_from_mirror })
    }

    /// Recomputes the whole chain. **An operations command, run with somebody watching**, wired to no route and
    /// no startup: rewriting an integrity log is what that log exists to make detectable.
    pub async fn rebuild(&self) -> Result<usize, AuditError> {
        let rows: Vec<StoredEntry> =
            persistence::all_in_chain_order(&self.inner.db).await?.into_iter().map(StoredEntry::from_row).collect();
        let rebuilt = chain::rebuild(&rows.iter().map(StoredEntry::verifiable).collect::<Vec<_>>());
        let mut tx = self.inner.db.begin(Mode::ReadWrite).await.map_err(DbError::from)?;
        for (row, entry) in rows.iter().zip(&rebuilt) {
            persistence::update_hashes(
                &mut tx,
                row.id,
                entry.entry.previous_hash.as_deref(),
                entry.entry_hash.as_deref().unwrap_or_default(),
            )
            .await?;
        }
        tx.commit().await.map_err(DbError::from)?;
        Ok(rebuilt.len())
    }
}

/// Later than the head, whichever instance wrote it: the lock orders the writers but not their clocks, and an
/// instance a millisecond behind another would date its entry before the head it chains onto.
fn after(head: Option<&StoredEntry>, candidate: OffsetDateTime) -> OffsetDateTime {
    match head {
        Some(head) if candidate <= head.timestamp => {
            head.timestamp.checked_add(Duration::milliseconds(1)).unwrap_or(head.timestamp)
        }
        _ => candidate,
    }
}

fn mirrored(row: &StoredEntry) -> MirrorEntry {
    MirrorEntry {
        id: row.id.as_hyphenated().to_string(),
        timestamp: chain::canonical(row.timestamp),
        operation: row.operation_type.clone(),
        resource_id: Some(row.resource_id.clone()),
        user_id: row.user_id.clone(),
        ip_address: row.ip_address.clone(),
        user_agent: row.user_agent.clone(),
        description: Some(row.description.clone()),
        previous_hash: row.previous_hash.clone(),
        entry_hash: row.entry_hash.clone().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored_at(nanos: i128) -> StoredEntry {
        StoredEntry {
            id: Uuid::nil(),
            description: String::new(),
            operation_type: String::new(),
            resource_id: String::new(),
            timestamp: OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap(),
            user_id: None,
            ip_address: None,
            user_agent: None,
            previous_hash: None,
            entry_hash: None,
        }
    }

    #[derive(Debug)]
    struct Frozen(std::sync::Mutex<OffsetDateTime>);

    impl Clock for Frozen {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap()
        }
    }

    /// Strictly increasing on this instance whatever the clock does — standing still, or stepping back — so two
    /// entries of one millisecond are never ordered by a random id.
    #[tokio::test]
    async fn instants_handed_out_strictly_increase() {
        let at = OffsetDateTime::from_unix_timestamp(1_792_224_000).unwrap();
        let clock = Arc::new(Frozen(std::sync::Mutex::new(at)));
        // Never connected: the pool is lazy, and this test asks only for instants.
        let pool = sqlx::mysql::MySqlPoolOptions::new().connect_lazy("mysql://nobody@127.0.0.1:9/none").unwrap();
        let log = AuditLog::new(Db::MySql(pool), Arc::new(crate::NoMirror), clock.clone(), Vec::new());
        let millisecond = Duration::milliseconds(1);
        assert_eq!(log.monotonic_now(), at);
        assert_eq!(log.monotonic_now(), at + millisecond, "the clock stood still");
        *clock.0.lock().unwrap() = at - Duration::seconds(5);
        assert_eq!(log.monotonic_now(), at + millisecond * 2, "the clock stepped back");
        *clock.0.lock().unwrap() = at + Duration::seconds(1);
        assert_eq!(log.monotonic_now(), at + Duration::seconds(1), "a later clock is taken as it is");
    }

    #[test]
    fn an_entry_is_dated_after_the_head_it_chains_onto() {
        let head = stored_at(2_000_000_000_000_000);
        let behind = OffsetDateTime::from_unix_timestamp_nanos(1_999_000_000_000_000).unwrap();
        assert_eq!(after(Some(&head), behind), head.timestamp + Duration::milliseconds(1));
        assert_eq!(
            after(Some(&head), head.timestamp),
            head.timestamp + Duration::milliseconds(1),
            "equal is not after"
        );
        let ahead = head.timestamp + Duration::seconds(1);
        assert_eq!(after(Some(&head), ahead), ahead);
        assert_eq!(after(None, behind), behind);
    }
}
