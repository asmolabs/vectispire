//! `t_issue_ticket` (`IssueTicketEntity`, `IssueTicketRepository`) and `t_webhook_delivery` (`WebhookDeliveryEntity`,
//! `WebhookDeliveryRepository`).
//!
//! **Checked statements, `sqlx::query!`, one module per engine**, kept in this crate's `.sqlx/`
//! (`crates/cp-db/scripts/sqlx-prepare.sh check cp-tickets`). Every statement is fixed. The purge deletes a batch's
//! links one issue at a time rather than with an `in (…)` whose length follows the input: MySQL has no array parameter,
//! and a batch is at most a thousand short statements in the deleting transaction.
//!
//! The instants are `datetime(6)` on MySQL — bound and read as `UtcInstant` — and `timestamp with time zone` on
//! PostgreSQL.

#[cfg(feature = "mysql-queries")]
mod mysql;
#[cfg(feature = "postgres-queries")]
mod postgres;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, Tx};

/// A link, column by column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRow {
    pub id: i64,
    pub issue_id: i64,
    pub provider: String,
    pub ticket_key: String,
    pub ticket_url: String,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// A database failure, kept in this layer: a service names this type and never the driver's.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error("this build holds no statements for {0}")]
    EngineNotCompiled(&'static str),
}

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

/// `findByIssueIdOrderByCreatedAtDescIdDesc`.
pub async fn tickets_of(db: &Db, issue_id: i64) -> Result<Vec<TicketRow>, DbError> {
    let mut tx = db.begin(Mode::ReadOnly).await?;
    let rows = on!(&mut tx, Tx, |t| mysql::tickets_of(t, issue_id).await, postgres::tickets_of(t, issue_id).await)?;
    tx.commit().await?;
    Ok(rows)
}

/// `save` of a new link: its id.
pub async fn insert(db: &Db, row: &TicketRow) -> Result<i64, DbError> {
    let mut tx = db.begin(Mode::ReadWrite).await?;
    let id = on!(&mut tx, Tx, |t| mysql::insert(t, row).await, postgres::insert(t, row).await)?;
    tx.commit().await?;
    Ok(id)
}

/// `deleteByIssueIdIn`, in the deleting transaction.
pub async fn delete_of_issues(tx: &mut Tx, issue_ids: &[i64]) -> Result<u64, DbError> {
    let mut deleted = 0u64;
    for &issue_id in issue_ids {
        deleted = deleted.saturating_add(on!(
            &mut *tx,
            Tx,
            |t| mysql::delete_of_issue(t, issue_id).await,
            postgres::delete_of_issue(t, issue_id).await
        )?);
    }
    Ok(deleted)
}

/// `deleteBefore`, on its own transaction.
pub async fn delete_deliveries_before(db: &Db, cutoff: OffsetDateTime) -> Result<u64, DbError> {
    let mut tx = db.begin(Mode::ReadWrite).await?;
    let deleted = on!(
        &mut tx,
        Tx,
        |t| mysql::delete_deliveries_before(t, cutoff).await,
        postgres::delete_deliveries_before(t, cutoff).await
    )?;
    tx.commit().await?;
    Ok(deleted)
}

/// `saveAndFlush` of a new delivery: the duplicate key refused by the engine, as `persist` of a fresh entity is.
pub async fn insert_delivery(
    db: &Db,
    body_hash: &str,
    provider: &str,
    received_at: OffsetDateTime,
) -> Result<(), DbError> {
    let mut tx = db.begin(Mode::ReadWrite).await?;
    on!(
        &mut tx,
        Tx,
        |t| mysql::insert_delivery(t, body_hash, provider, received_at).await,
        postgres::insert_delivery(t, body_hash, provider, received_at).await
    )?;
    tx.commit().await?;
    Ok(())
}

/// `existsById`.
pub async fn delivery_exists(db: &Db, body_hash: &str) -> Result<bool, DbError> {
    let mut tx = db.begin(Mode::ReadOnly).await?;
    let exists = on!(
        &mut tx,
        Tx,
        |t| mysql::delivery_exists(t, body_hash).await,
        postgres::delivery_exists(t, body_hash).await
    )?;
    tx.commit().await?;
    Ok(exists)
}
