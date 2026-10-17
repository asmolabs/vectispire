//! The jobs that run once per database, whatever the number of instances starting — Java's `OneShotJobs`.
//!
//! **A read of "has it run?" cannot decide this.** The repair of withheld claims read its own audit entry: two
//! instances starting together both found none, both ran, and both wrote one. The decision is the primary key's:
//! [`OneShotJobs::claim`] inserts the job's name, and of two instances only one insert succeeds — the other waits for
//! the first transaction to end and then fails.
//!
//! **And a failed insert does not say why it failed.** The loser's refusal is a unique violation on both engines, but
//! a lock that timed out or a connection that dropped fails the same statement, and the first Java version read every
//! failure as "taken elsewhere" — a claim that failed for any reason would have been reported as somebody else's while
//! nobody ran the job. So the failure is returned, and only the row answers: [`OneShotJobs::has_run`], read after the
//! rollback, is what tells a lost claim from a failed one.

use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Tx};

use crate::persistence::{self, DbError};

/// Where a claim's instant comes from (`java.time.Clock`).
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> OffsetDateTime;
}

/// The system's clock, in UTC.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A claim or a read that failed. After a failed claim the caller rolls back and asks [`OneShotJobs::has_run`].
#[derive(Debug, thiserror::Error)]
pub enum OneShotError {
    #[error(transparent)]
    Database(#[from] DbError),
}

/// The one-shot jobs of this database.
#[derive(Debug, Clone)]
pub struct OneShotJobs {
    db: Db,
    clock: Arc<dyn Clock>,
}

impl OneShotJobs {
    pub fn new(db: Db, clock: Arc<dyn Clock>) -> OneShotJobs {
        OneShotJobs { db, clock }
    }

    /// Takes the job for this caller, or fails.
    ///
    /// **First, in the transaction that does the job's work** — Java's `MANDATORY`, which the `&mut Tx` makes a
    /// matter of types: the row and the work commit together, so a job that fails half-way is not recorded as run,
    /// and an instance that crashes before its commit leaves the job to the next start. A failure leaves the
    /// transaction unusable — on PostgreSQL it accepts no further statement — so the caller rolls it back and then
    /// asks [`OneShotJobs::has_run`]: yes means another instance holds it, no means the claim failed and the next
    /// start retries.
    ///
    /// `name` is at most 64 characters, the column's width; a longer one fails at the database, as in Java.
    pub async fn claim(&self, tx: &mut Tx, name: &str) -> Result<(), OneShotError> {
        persistence::claim(tx, name, self.clock.now()).await?;
        Ok(())
    }

    /// Whether a committed row holds the job — read on a connection of its own, after the rollback of a claim that
    /// failed and never inside that transaction: there PostgreSQL would refuse the read, and MySQL would answer for a
    /// snapshot that may predate the winner's commit.
    pub async fn has_run(&self, name: &str) -> Result<bool, OneShotError> {
        Ok(persistence::exists(&self.db, name).await?)
    }
}
