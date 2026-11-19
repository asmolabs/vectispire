//! The statements on MySQL, checked against a migrated server while compiling (`super`'s note).

use sqlx::MySqlConnection;
use time::OffsetDateTime;
use vectispire_cp_db::types::UtcInstant;

use super::{DbError, TicketRow};

pub async fn tickets_of(conn: &mut MySqlConnection, issue_id: i64) -> Result<Vec<TicketRow>, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ select id, issue_id, provider, ticket_key, ticket_url, status, \
         created_at as `created_at: UtcInstant`, updated_at as `updated_at: UtcInstant` \
         from t_issue_ticket where issue_id = ? order by created_at desc, id desc",
        issue_id
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(|row| TicketRow {
        id: row.id,
        issue_id: row.issue_id,
        provider: row.provider,
        ticket_key: row.ticket_key,
        ticket_url: row.ticket_url,
        status: row.status,
        created_at: row.created_at.0,
        updated_at: row.updated_at.0,
    })
    .collect())
}

pub async fn insert(conn: &mut MySqlConnection, row: &TicketRow) -> Result<i64, DbError> {
    let done = sqlx::query!(
        "/* mysql */ insert into t_issue_ticket \
         (issue_id, provider, ticket_key, ticket_url, status, created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?)",
        row.issue_id,
        row.provider,
        row.ticket_key,
        row.ticket_url,
        row.status,
        UtcInstant(row.created_at),
        UtcInstant(row.updated_at)
    )
    .execute(conn)
    .await?;
    Ok(i64::try_from(done.last_insert_id()).unwrap_or(i64::MAX))
}

pub async fn delete_of_issue(conn: &mut MySqlConnection, issue_id: i64) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* mysql */ delete from t_issue_ticket where issue_id = ?", issue_id)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn delete_deliveries_before(conn: &mut MySqlConnection, cutoff: OffsetDateTime) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* mysql */ delete from t_webhook_delivery where received_at < ?", UtcInstant(cutoff))
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn insert_delivery(
    conn: &mut MySqlConnection,
    body_hash: &str,
    provider: &str,
    received_at: OffsetDateTime,
) -> Result<(), DbError> {
    sqlx::query!(
        "/* mysql */ insert into t_webhook_delivery (body_hash, provider, received_at) values (?, ?, ?)",
        body_hash,
        provider,
        UtcInstant(received_at)
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delivery_exists(conn: &mut MySqlConnection, body_hash: &str) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!("/* mysql */ select count(*) from t_webhook_delivery where body_hash = ?", body_hash)
        .fetch_one(conn)
        .await?
        > 0)
}
