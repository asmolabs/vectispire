//! Taking, holding and losing the lease that makes a job single-owner — `LeaderElection`, on `t_leader_lease`.
//!
//! **One primitive: a conditional `UPDATE` whose affected row count names the winner.** Weaker than `SELECT … FOR
//! UPDATE SKIP LOCKED`, and enough here because what it protects is periodic and nearly idempotent: two instances
//! briefly believing themselves leader run a duplicate tick, not a corrupted row, and the next tick settles it.
//!
//! **What "leader" covers**: the scheduling tick, which has an effect *per period* — two instances ticking together
//! would scan every due target once per instance. Not what is per instance by nature: every instance goes on claiming
//! work for its own built-in worker, or a fleet would sit idle behind whichever instance holds the lease. The other
//! maintenance turns run on every instance (`cp-maintenance`); this lease is the scheduler's own.
//!
//! **Deliberately not one transaction**: the read is followed by a conditional update whose `where` carries what was
//! read, so the arbitration is in the statement rather than in an isolation level — and a losing insert must not poison
//! a transaction that then refuses to commit the "we did not get it" answer.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::Db;
use vectispire_cp_targets::Clock;

use crate::persistence::{self, StoreError};

/// The scheduler's lease — one row per exclusive job.
pub const JOB_SCHEDULER: &str = "scheduler";

/// `LeaderProperties.lease`'s default: comfortably longer than the minute's tick that renews it, so a slow tick does
/// not hand the work over, and short enough that a dead leader is replaced in a few minutes.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(180);

/// The election, for this process.
pub struct LeaderElection {
    db: Db,
    lease: Duration,
    clock: Arc<dyn Clock>,
    instance: String,
}

impl std::fmt::Debug for LeaderElection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LeaderElection")
            .field("lease", &self.lease)
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

/// `INSTANCE_ID`: this process, for the life of this process — **not the host name**, since two instances on one host
/// is a deployment somebody will try, and not persisted: a restarted instance has forgotten what it was doing, and is
/// rightly a new holder. Thirty-two hexadecimal digits, as Java's UUID without its hyphens.
pub fn instance_id() -> String {
    Uuid::new_v4().simple().to_string()
}

impl LeaderElection {
    /// `lease` at least a second: `vectispire.leader.lease` read as a bare number of milliseconds would be a lease that
    /// lapses before its first renewal (the configuration refuses it at start, as `@DurationMin` does).
    pub fn new(db: Db, lease: Duration, clock: Arc<dyn Clock>) -> LeaderElection {
        LeaderElection { db, lease, clock, instance: instance_id() }
    }

    /// This process's holder name.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// `acquire()`: the scheduler's lease for this process, at the clock's instant.
    pub async fn acquire_scheduler(&self) -> Result<bool, StoreError> {
        let at = self.clock.now();
        self.acquire(JOB_SCHEDULER, &self.instance, at).await
    }

    /// `acquire`: takes or renews the lease, and says whether `holder` holds it. Three cases in one, because the caller
    /// does not care which — nobody ever held it, somebody let it expire, or it is ours and renewed. **Renewal is what
    /// makes the leader stable**: one that had to win again every tick would move the work around the fleet.
    ///
    /// `at` is the instant the caller judges its work by: a lease taken at one instant while targets are judged at
    /// another is two clocks in one tick, one deciding who writes and the other what.
    pub async fn acquire(&self, name: &str, holder: &str, at: OffsetDateTime) -> Result<bool, StoreError> {
        // A lease past what an instant holds is a configuration nobody writes; it saturates rather than wraps.
        let lease = time::Duration::try_from(self.lease).unwrap_or(time::Duration::MAX);
        let expires_at = at.checked_add(lease).unwrap_or(at);
        let existing = {
            let mut tx = persistence::read(&self.db).await?;
            let found = persistence::lease(&mut tx, name).await;
            tx.commit().await?;
            found?
        };
        let Some(lease) = existing else {
            return Ok(self.create(name, holder, at, expires_at).await);
        };
        let mine = lease.holder.as_deref() == Some(holder);
        let expired = lease.expires_at.is_none_or(|expiry| expiry <= at);
        if !mine && !expired {
            return Ok(false);
        }
        let mut tx = persistence::write(&self.db).await?;
        let updated = if mine {
            persistence::renew_leadership(&mut tx, name, holder, expires_at, at).await
        } else {
            match (&lease.holder, lease.expires_at) {
                // Conditioned on the holder **and** the expiry just read: an instance that took the lease in between
                // changed both, and this matches nothing — we lose rather than steal a lease somebody holds.
                (Some(previous), Some(expiry)) => {
                    persistence::take_over_from(&mut tx, name, holder, expires_at, at, previous, expiry).await
                }
                // A released lease is taken by its own statement: a bare parameter compared with `null` cannot be typed
                // by PostgreSQL, and the single statement failed there after every clean shutdown.
                _ => persistence::take_over_released(&mut tx, name, holder, expires_at, at).await,
            }
        };
        let updated = match updated {
            Ok(rows) => {
                tx.commit().await?;
                rows
            }
            Err(failure) => {
                let _ = tx.rollback().await;
                return Err(failure);
            }
        };
        if updated > 0 && !mine {
            tracing::info!(holder, lease = name, "This instance took the lease.");
        }
        Ok(updated > 0)
    }

    /// First acquisition, a bare insert: two instances started together both try it, and **the primary key
    /// arbitrates** — the loser's refusal is its answer, and it tries again at the next tick.
    async fn create(&self, name: &str, holder: &str, at: OffsetDateTime, expires_at: OffsetDateTime) -> bool {
        let Ok(mut tx) = persistence::write(&self.db).await else { return false };
        match persistence::insert_lease(&mut tx, name, holder, at, expires_at).await {
            Ok(_) => {
                let taken = tx.commit().await.is_ok();
                if taken {
                    tracing::info!(holder, lease = name, "This instance took the lease.");
                }
                taken
            }
            Err(_) => {
                let _ = tx.rollback().await;
                false
            }
        }
    }

    /// `release`: the lease handed back, so a successor takes it at once instead of waiting for expiry. Best effort by
    /// nature — a killed process releases nothing, which is why expiry exists and nothing depends on this.
    pub async fn release(&self, name: &str, holder: &str) -> Result<bool, StoreError> {
        let at = self.clock.now();
        let mut tx = persistence::write(&self.db).await?;
        match persistence::release_leadership(&mut tx, name, holder, at).await {
            Ok(rows) => {
                tx.commit().await?;
                Ok(rows > 0)
            }
            Err(failure) => {
                let _ = tx.rollback().await;
                Err(failure)
            }
        }
    }

    /// The scheduler's lease released by this process — at shutdown.
    pub async fn release_scheduler(&self) -> Result<bool, StoreError> {
        self.release(JOB_SCHEDULER, &self.instance).await
    }

    /// `currentHolder`: who holds the lease at `at`, `None` when it is free or stale — "why is nothing happening" is a
    /// question this answers.
    pub async fn current_holder(&self, name: &str, at: OffsetDateTime) -> Result<Option<String>, StoreError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::lease(&mut tx, name).await;
        tx.commit().await?;
        Ok(found?.and_then(|lease| match (lease.holder, lease.expires_at) {
            (Some(holder), Some(expiry)) if expiry > at => Some(holder),
            _ => None,
        }))
    }

    /// `isLeader`: whether `holder` holds the lease at `at`, without taking it.
    pub async fn is_leader(&self, name: &str, holder: &str, at: OffsetDateTime) -> Result<bool, StoreError> {
        Ok(self.current_holder(name, at).await?.as_deref() == Some(holder))
    }
}
