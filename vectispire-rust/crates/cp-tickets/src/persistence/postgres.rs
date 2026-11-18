//! The statements on PostgreSQL, checked against a migrated server while compiling (`super`'s note). The instants
//! are `timestamp with time zone`, bound and read as `OffsetDateTime`.

use sqlx::PgConnection;
use time::OffsetDateTime;

use super::{DbError, TicketRow};

pub async fn tickets_of(conn: &mut PgConnection, issue_id: i64) -> Result<Vec<TicketRow>, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ select id, issue_id, provider, ticket_key, ticket_url, status, created_at, updated_at \
         from t_issue_ticket where issue_id = $1 order by created_at desc, id desc",
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
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
    .collect())
}

pub async fn insert(conn: &mut PgConnection, row: &TicketRow) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        "/* postgres */ insert into t_issue_ticket \
         (issue_id, provider, ticket_key, ticket_url, status, created_at, updated_at) \
         values ($1, $2, $3, $4, $5, $6, $7) returning id",
        row.issue_id,
        row.provider,
        row.ticket_key,
        row.ticket_url,
        row.status,
        row.created_at,
        row.updated_at
    )
    .fetch_one(conn)
    .await?)
}

pub async fn delete_of_issue(conn: &mut PgConnection, issue_id: i64) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* postgres */ delete from t_issue_ticket where issue_id = $1", issue_id)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn delete_deliveries_before(conn: &mut PgConnection, cutoff: OffsetDateTime) -> Result<u64, DbError> {
    Ok(sqlx::query!("/* postgres */ delete from t_webhook_delivery where received_at < $1", cutoff)
        .execute(conn)
        .await?
        .rows_affected())
}

pub async fn insert_delivery(
    conn: &mut PgConnection,
    body_hash: &str,
    provider: &str,
    received_at: OffsetDateTime,
) -> Result<(), DbError> {
    sqlx::query!(
        "/* postgres */ insert into t_webhook_delivery (body_hash, provider, received_at) values ($1, $2, $3)",
        body_hash,
        provider,
        received_at
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn delivery_exists(conn: &mut PgConnection, body_hash: &str) -> Result<bool, DbError> {
    Ok(sqlx::query_scalar!(
        "/* postgres */ select count(*) as \"count!\" from t_webhook_delivery where body_hash = $1",
        body_hash
    )
    .fetch_one(conn)
    .await?
        > 0)
}
