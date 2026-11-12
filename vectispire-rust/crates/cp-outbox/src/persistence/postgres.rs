//! `t_outbox_message`'s statements on PostgreSQL, checked against a migrated server while compiling (`super`'s note).
//! PostgreSQL describes its parameters, so a bind of the wrong type does not build; `cp-db`'s two custom types are
//! bound `as _`, the macro's override for a type it cannot name, and checked by the engine suite.

use sqlx::PgConnection;
use sqlx::postgres::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::types::{TextUuid, UtcInstant};

use super::DbError;
use super::{DueMessage, NewMessage};

pub async fn insert(conn: &mut PgConnection, message: &NewMessage) -> Result<(), DbError> {
    sqlx::query!(
        "/* postgres */ insert into t_outbox_message (id, message_type, payload, team_id, status, attempts, \
         next_attempt_at, last_error, created_at, sent_at) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        TextUuid(message.id) as _,
        message.message_type,
        message.payload,
        message.team_id,
        message.status,
        message.attempts,
        message.next_attempt_at.map(UtcInstant) as _,
        message.last_error,
        UtcInstant(message.created_at) as _,
        message.sent_at.map(UtcInstant) as _,
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn find_due(pool: &PgPool, status: &str, at: OffsetDateTime, limit: u32) -> Result<Vec<DueMessage>, DbError> {
    let rows = sqlx::query!(
        r#"/* postgres */ select id as "id: TextUuid", message_type, team_id, payload, attempts from t_outbox_message
         where status = $1 and (next_attempt_at is null or next_attempt_at <= $2)
         order by created_at asc, id asc limit $3"#,
        status,
        UtcInstant(at) as _,
        i64::from(limit),
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| DueMessage {
            id: row.id.0,
            message_type: row.message_type,
            team_id: row.team_id,
            payload: row.payload,
            attempts: row.attempts,
        })
        .collect())
}

pub async fn claim(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    at: OffsetDateTime,
    until: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_outbox_message set next_attempt_at = $1 \
         where id = $2 and status = $3 and (next_attempt_at is null or next_attempt_at <= $4)",
        UtcInstant(until) as _,
        TextUuid(id) as _,
        status,
        UtcInstant(at) as _,
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn record_attempt(
    pool: &PgPool,
    id: Uuid,
    attempts: i32,
    last_error: Option<&str>,
    status: &str,
    next_attempt_at: Option<OffsetDateTime>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_outbox_message set attempts = $1, last_error = $2, status = $3, next_attempt_at = $4 \
         where id = $5",
        attempts,
        last_error,
        status,
        next_attempt_at.map(UtcInstant) as _,
        TextUuid(id) as _,
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn mark_sent(
    pool: &PgPool,
    id: Uuid,
    attempts: i32,
    status: &str,
    sent_at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_outbox_message set attempts = $1, status = $2, sent_at = $3, next_attempt_at = null, \
         last_error = null where id = $4",
        attempts,
        status,
        UtcInstant(sent_at) as _,
        TextUuid(id) as _,
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn delete_sent_before(pool: &PgPool, status: &str, cutoff: OffsetDateTime) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ delete from t_outbox_message where status = $1 and sent_at is not null and sent_at < $2",
        status,
        UtcInstant(cutoff) as _,
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn count_by_status(pool: &PgPool) -> Result<Vec<(String, i64)>, DbError> {
    let rows =
        sqlx::query!(r#"/* postgres */ select status, count(id) as "count!" from t_outbox_message group by status"#)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|row| (row.status, row.count)).collect())
}
