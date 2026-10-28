//! `t_outbox_message` (V1, `team_id` since V7, `idx_outbox_due` since V18): the insert `enqueue` makes in the
//! caller's transaction, and [`Rows`], the relay's store on the database.
//!
//! **Targeted updates, never a row read and written back**, as Java's repository: the relay settles a message from
//! outside anything that loaded it, and a write of the whole row would rewrite a payload it never meant to touch.
//!
//! **Checked statements, `sqlx::query!`, one module per engine**, each described by a migrated server of its engine
//! while compiling and kept in this crate's `.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh check cp-outbox`) — the
//! arrangement and its reasons are `cp-audit`'s persistence's, and `cp-db`'s README's. The id is `char(36)` and the
//! instants `datetime(6)` / `timestamp with time zone`, bound and read through `cp-db`'s `TextUuid` and `UtcInstant`.

#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;
mod store;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::{Db, Tx};

pub use store::{DueMessage, FAILED, NewMessage, OutboxStore, PENDING, SENT, StoreError, StoreFuture};

/// A database failure, kept in this layer: the service sees a [`StoreError`].
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    /// The engine's statements were compiled out — only the one-engine build of the cache script lacks some, and
    /// only that build constructs it.
    #[cfg_attr(all(feature = "mysql-queries", feature = "postgres-queries"), allow(dead_code))]
    #[error("this build holds no statements for {0}")]
    EngineNotCompiled(&'static str),
}

/// Dispatches one statement to the engine's module; an engine compiled out answers
/// [`DbError::EngineNotCompiled`], and with both on — every build but the cache script's — that arm does not exist.
macro_rules! on {
    ($target:expr, $enum:ident, |$handle:ident| $mysql:expr, $postgres:expr) => {
        match $target {
            #[cfg(feature = "mysql-queries")]
            $enum::MySql($handle) => $mysql,
            #[cfg(not(feature = "mysql-queries"))]
            $enum::MySql(_) => Err(DbError::EngineNotCompiled("MySQL")),
            #[cfg(feature = "postgres-queries")]
            $enum::PostgreSql($handle) => $postgres,
            #[cfg(not(feature = "postgres-queries"))]
            $enum::PostgreSql(_) => Err(DbError::EngineNotCompiled("PostgreSQL")),
        }
    };
}

/// `messages.save(message)` in `enqueue`: every column written, the nulls included, as Hibernate's insert does.
pub async fn insert(tx: &mut Tx, message: &NewMessage) -> Result<(), DbError> {
    on!(tx, Tx, |t| mysql::insert(t, message).await, postgres::insert(t, message).await)
}

/// The relay's store on the database: each call one statement on the pool, committed on its own.
#[derive(Debug, Clone)]
pub struct Rows(pub Db);

fn boxed<'a, T: Send + 'a>(
    future: impl std::future::Future<Output = Result<T, DbError>> + Send + 'a,
) -> StoreFuture<'a, T> {
    Box::pin(async move { future.await.map_err(|error| Box::new(error) as StoreError) })
}

impl OutboxStore for Rows {
    fn find_due(&self, status: &'static str, at: OffsetDateTime, limit: u32) -> StoreFuture<'_, Vec<DueMessage>> {
        boxed(async move {
            on!(
                &self.0,
                Db,
                |pool| mysql::find_due(pool, status, at, limit).await,
                postgres::find_due(pool, status, at, limit).await
            )
        })
    }

    fn claim(&self, id: Uuid, status: &'static str, at: OffsetDateTime, until: OffsetDateTime) -> StoreFuture<'_, u64> {
        boxed(async move {
            on!(
                &self.0,
                Db,
                |pool| mysql::claim(pool, id, status, at, until).await,
                postgres::claim(pool, id, status, at, until).await
            )
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
        boxed(async move {
            on!(
                &self.0,
                Db,
                |pool| mysql::record_attempt(pool, id, attempts, last_error, status, next_attempt_at).await,
                postgres::record_attempt(pool, id, attempts, last_error, status, next_attempt_at).await
            )
        })
    }

    fn mark_sent(
        &self,
        id: Uuid,
        attempts: i32,
        status: &'static str,
        sent_at: OffsetDateTime,
    ) -> StoreFuture<'_, u64> {
        boxed(async move {
            on!(
                &self.0,
                Db,
                |pool| mysql::mark_sent(pool, id, attempts, status, sent_at).await,
                postgres::mark_sent(pool, id, attempts, status, sent_at).await
            )
        })
    }

    fn delete_sent_before(&self, status: &'static str, cutoff: OffsetDateTime) -> StoreFuture<'_, u64> {
        boxed(async move {
            on!(
                &self.0,
                Db,
                |pool| mysql::delete_sent_before(pool, status, cutoff).await,
                postgres::delete_sent_before(pool, status, cutoff).await
            )
        })
    }

    fn count_by_status(&self) -> StoreFuture<'_, Vec<(String, i64)>> {
        boxed(async move {
            on!(&self.0, Db, |pool| mysql::count_by_status(pool).await, postgres::count_by_status(pool).await)
        })
    }
}
