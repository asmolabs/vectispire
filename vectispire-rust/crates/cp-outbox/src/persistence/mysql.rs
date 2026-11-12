//! `t_outbox_message`'s statements on MySQL, checked against a migrated server while compiling (`super`'s note).
//! MySQL describes no parameter type, so the binds are checked at run time by the engine suite, on this engine.

use sqlx::MySqlConnection;
use sqlx::mysql::MySqlPool;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::types::{TextUuid, UtcInstant};

use super::DbError;
use super::{DueMessage, NewMessage};

pub async fn insert(conn: &mut MySqlConnection, message: &NewMessage) -> Result<(), DbError> {
    sqlx::query!(
        "/* mysql */ insert into t_outbox_message (id, message_type, payload, team_id, status, attempts, \
         next_attempt_at, last_error, created_at, sent_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        TextUuid(message.id),
        message.message_type,
        message.payload,
        message.team_id,
        message.status,
        message.attempts,
        message.next_attempt_at.map(UtcInstant),
        message.last_error,
        UtcInstant(message.created_at),
        message.sent_at.map(UtcInstant),
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn find_due(
    pool: &MySqlPool,
    status: &str,
    at: OffsetDateTime,
    limit: u32,
) -> Result<Vec<DueMessage>, DbError> {
    let rows = sqlx::query!(
        "/* mysql */ select id as `id: TextUuid`, message_type, team_id, payload, attempts from t_outbox_message \
         where status = ? and (next_attempt_at is null or next_attempt_at <= ?) \
         order by created_at asc, id asc limit ?",
        status,
        UtcInstant(at),
        limit,
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
    pool: &MySqlPool,
    id: Uuid,
    status: &str,
    at: OffsetDateTime,
    until: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_outbox_message set next_attempt_at = ? \
         where id = ? and status = ? and (next_attempt_at is null or next_attempt_at <= ?)",
        UtcInstant(until),
        TextUuid(id),
        status,
        UtcInstant(at),
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn record_attempt(
    pool: &MySqlPool,
    id: Uuid,
    attempts: i32,
    last_error: Option<&str>,
    status: &str,
    next_attempt_at: Option<OffsetDateTime>,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_outbox_message set attempts = ?, last_error = ?, status = ?, next_attempt_at = ? \
         where id = ?",
        attempts,
        last_error,
        status,
        next_attempt_at.map(UtcInstant),
        TextUuid(id),
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn mark_sent(
    pool: &MySqlPool,
    id: Uuid,
    attempts: i32,
    status: &str,
    sent_at: OffsetDateTime,
) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_outbox_message set attempts = ?, status = ?, sent_at = ?, next_attempt_at = null, \
         last_error = null where id = ?",
        attempts,
        status,
        UtcInstant(sent_at),
        TextUuid(id),
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn delete_sent_before(pool: &MySqlPool, status: &str, cutoff: OffsetDateTime) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ delete from t_outbox_message where status = ? and sent_at is not null and sent_at < ?",
        status,
        UtcInstant(cutoff),
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn count_by_status(pool: &MySqlPool) -> Result<Vec<(String, i64)>, DbError> {
    let rows =
        sqlx::query!("/* mysql */ select status, count(id) as `count: i64` from t_outbox_message group by status")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|row| (row.status, row.count)).collect())
}
