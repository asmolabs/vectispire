//! Transactions, with the two shapes the Java side uses: the caller's, and one of its own.

use std::future::Future;
use std::time::Duration;

use sqlx::{MySql, Postgres, Transaction};

use crate::db::Db;
use crate::engine::Engine;

/// Whether the transaction may write.
///
/// `ReadOnly` is the 137 `@Transactional(readOnly = true)` of the Java side, said to the server
/// (`START TRANSACTION READ ONLY`, `BEGIN READ ONLY`) rather than only to Hibernate's flush mode, so a
/// write slipped into a read is refused by the engine instead of committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    ReadWrite,
    ReadOnly,
}

/// One open transaction on one connection.
#[derive(Debug)]
pub enum Tx {
    MySql(Transaction<'static, MySql>),
    PostgreSql(Transaction<'static, Postgres>),
}

impl Tx {
    pub fn engine(&self) -> Engine {
        match self {
            Tx::MySql(_) => Engine::MySql,
            Tx::PostgreSql(_) => Engine::PostgreSql,
        }
    }

    pub async fn commit(self) -> Result<(), sqlx::Error> {
        match self {
            Tx::MySql(tx) => tx.commit().await,
            Tx::PostgreSql(tx) => tx.commit().await,
        }
    }

    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        match self {
            Tx::MySql(tx) => tx.rollback().await,
            Tx::PostgreSql(tx) => tx.rollback().await,
        }
    }
}

impl Db {
    /// Begins a transaction on a connection of its own.
    ///
    /// **This is also `REQUIRES_NEW`.** A transaction is a value here, not a thread-local the
    /// container joins, so "a new one, whatever the caller holds" is simply a second call: it takes a
    /// second connection, and commits or rolls back without regard to the first — which is what the
    /// audit log needs, an entry that survives the action it describes failing (`AuditLogService`).
    /// Joining the caller's transaction is passing its `&mut Tx` down; there is no third behaviour.
    pub async fn begin(&self, mode: Mode) -> Result<Tx, sqlx::Error> {
        Ok(match (self, mode) {
            (Db::MySql(pool), Mode::ReadWrite) => Tx::MySql(pool.begin().await?),
            (Db::MySql(pool), Mode::ReadOnly) => Tx::MySql(pool.begin_with("START TRANSACTION READ ONLY").await?),
            (Db::PostgreSql(pool), Mode::ReadWrite) => Tx::PostgreSql(pool.begin().await?),
            (Db::PostgreSql(pool), Mode::ReadOnly) => Tx::PostgreSql(pool.begin_with("BEGIN READ ONLY").await?),
        })
    }
}

/// Whether a failure is a lock the engine gave up on — a deadlock it broke, a lock wait it timed out,
/// a serialization it could not keep — rather than anything the statement itself got wrong.
///
/// The codes are the ones Spring translates to `PessimisticLockingFailureException`
/// (`sql-error-codes.xml`), the exception the Java side retries on:
///
/// | engine | code | Spring's name |
/// |---|---|---|
/// | MySQL | 1205 lock wait timeout, 3572 `NOWAIT` refused | `cannotAcquireLockCodes` |
/// | MySQL | 1213 deadlock | `deadlockLoserCodes` |
/// | PostgreSQL | `55P03` lock not available | `cannotAcquireLockCodes` |
/// | PostgreSQL | `40P01` deadlock | `deadlockLoserCodes` |
/// | PostgreSQL | `40001` serialization failure | `cannotSerializeTransactionCodes` |
pub fn is_lock_conflict(error: &sqlx::Error) -> bool {
    let sqlx::Error::Database(database) = error else {
        return false;
    };
    if let Some(mysql) = database.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>() {
        return matches!(mysql.number(), 1205 | 1213 | 3572);
    }
    if let Some(postgres) = database.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
        return matches!(postgres.code(), "55P03" | "40P01" | "40001");
    }
    false
}

/// The waits between attempts, `AuditLogService.LOCK_BACKOFF`: five retries, doubling from 50 ms — about
/// 1.5 s in all before the conflict is the caller's.
pub const LOCK_BACKOFF: [Duration; 5] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
];

/// An error a retried unit of work may end in: the retry needs to see the database error under it.
pub trait LockConflict {
    fn is_lock_conflict(&self) -> bool;
}

impl LockConflict for sqlx::Error {
    fn is_lock_conflict(&self) -> bool {
        is_lock_conflict(self)
    }
}

/// Runs `attempt` again after each wait of `backoff` while it fails on a lock conflict.
///
/// **The whole unit is retried, not the statement.** The engine rolled the transaction back when it
/// chose this one as the deadlock's loser, so a statement retried inside it would run in a transaction
/// that no longer exists; `attempt` begins and commits its own. Every other failure is returned at
/// once — retrying a constraint violation only repeats it.
pub async fn retry_on_lock_conflict<T, E, F, Fut>(backoff: &[Duration], mut attempt: F) -> Result<T, E>
where
    E: LockConflict,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut waits = backoff.iter();
    loop {
        match attempt().await {
            Err(error) if error.is_lock_conflict() => match waits.next() {
                Some(wait) => tokio::time::sleep(*wait).await,
                None => return Err(error),
            },
            outcome => return outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Debug, PartialEq)]
    enum Failure {
        Locked,
        Broken,
    }

    impl LockConflict for Failure {
        fn is_lock_conflict(&self) -> bool {
            *self == Failure::Locked
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_conflict_is_retried_until_it_clears() {
        let calls = Cell::new(0);
        let outcome = retry_on_lock_conflict(&LOCK_BACKOFF, || {
            calls.set(calls.get() + 1);
            let call = calls.get();
            async move { if call < 3 { Err(Failure::Locked) } else { Ok(call) } }
        })
        .await;
        assert_eq!(outcome, Ok(3));
    }

    #[tokio::test(start_paused = true)]
    async fn a_conflict_that_outlasts_the_backoff_is_the_callers() {
        let calls = Cell::new(0);
        let outcome: Result<(), Failure> = retry_on_lock_conflict(&LOCK_BACKOFF, || {
            calls.set(calls.get() + 1);
            async { Err(Failure::Locked) }
        })
        .await;
        assert_eq!(outcome, Err(Failure::Locked));
        assert_eq!(calls.get(), 1 + LOCK_BACKOFF.len(), "one attempt, then one per wait");
    }

    #[tokio::test(start_paused = true)]
    async fn any_other_failure_is_returned_at_once() {
        let calls = Cell::new(0);
        let outcome: Result<(), Failure> = retry_on_lock_conflict(&LOCK_BACKOFF, || {
            calls.set(calls.get() + 1);
            async { Err(Failure::Broken) }
        })
        .await;
        assert_eq!((outcome, calls.get()), (Err(Failure::Broken), 1));
    }
}
