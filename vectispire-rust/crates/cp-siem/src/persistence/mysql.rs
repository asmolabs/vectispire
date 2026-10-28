//! `t_siem_config`'s statements on MySQL, checked against a migrated server while compiling (`super`'s note).

use sqlx::{Executor, MySql};
use vectispire_cp_db::types::UtcInstant;

use super::{ConfigRow, DbError, SINGLETON_ID};

/// On a pool or in a transaction: the export's readers do both.
pub async fn find<'c>(executor: impl Executor<'c, Database = MySql>) -> Result<Option<ConfigRow>, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ select id, enabled as `enabled: bool`, protocol, endpoint, auth_header, tls_ca_pem, min_severity, \
         created_at as `created_at: UtcInstant`, updated_at as `updated_at: UtcInstant` \
         from t_siem_config where id = ?",
        SINGLETON_ID
    )
    .fetch_optional(executor)
    .await?
    .map(|row| ConfigRow {
        id: row.id,
        enabled: row.enabled,
        protocol: row.protocol,
        endpoint: row.endpoint,
        auth_header: row.auth_header,
        tls_ca_pem: row.tls_ca_pem,
        min_severity: row.min_severity,
        created_at: row.created_at.0,
        updated_at: row.updated_at.0,
    }))
}

pub async fn insert(conn: &mut sqlx::MySqlConnection, row: &ConfigRow) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ insert into t_siem_config \
         (id, enabled, protocol, endpoint, auth_header, tls_ca_pem, min_severity, created_at, updated_at) \
         values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        row.id,
        row.enabled,
        row.protocol,
        row.endpoint,
        row.auth_header,
        row.tls_ca_pem,
        row.min_severity,
        UtcInstant(row.created_at),
        UtcInstant(row.updated_at),
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn update(conn: &mut sqlx::MySqlConnection, row: &ConfigRow) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* mysql */ update t_siem_config set enabled = ?, protocol = ?, endpoint = ?, auth_header = ?, \
         tls_ca_pem = ?, min_severity = ?, updated_at = ? where id = ?",
        row.enabled,
        row.protocol,
        row.endpoint,
        row.auth_header,
        row.tls_ca_pem,
        row.min_severity,
        UtcInstant(row.updated_at),
        row.id,
    )
    .execute(conn)
    .await?
    .rows_affected())
}
