//! `t_siem_config`'s statements on PostgreSQL, checked against a migrated server while compiling (`super`'s note).
//! The two instants are `timestamp without time zone`: bound and read as `UtcInstant`, the override telling the macro
//! so (`as _`, `: UtcInstant`).

use sqlx::{Executor, Postgres};
use vectispire_cp_db::types::UtcInstant;

use super::{ConfigRow, DbError, SINGLETON_ID};

/// On a pool or in a transaction: the export's readers do both.
pub async fn find<'c>(executor: impl Executor<'c, Database = Postgres>) -> Result<Option<ConfigRow>, DbError> {
    Ok(sqlx::query!(
        r#"/* postgres */ select id, enabled, protocol, endpoint, auth_header, tls_ca_pem, min_severity,
           created_at as "created_at: UtcInstant", updated_at as "updated_at: UtcInstant"
           from t_siem_config where id = $1"#,
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

pub async fn insert(conn: &mut sqlx::PgConnection, row: &ConfigRow) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ insert into t_siem_config \
         (id, enabled, protocol, endpoint, auth_header, tls_ca_pem, min_severity, created_at, updated_at) \
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        row.id,
        row.enabled,
        row.protocol,
        row.endpoint,
        row.auth_header,
        row.tls_ca_pem,
        row.min_severity,
        UtcInstant(row.created_at) as _,
        UtcInstant(row.updated_at) as _,
    )
    .execute(conn)
    .await?
    .rows_affected())
}

pub async fn update(conn: &mut sqlx::PgConnection, row: &ConfigRow) -> Result<u64, DbError> {
    Ok(sqlx::query!(
        "/* postgres */ update t_siem_config set enabled = $1, protocol = $2, endpoint = $3, auth_header = $4, \
         tls_ca_pem = $5, min_severity = $6, updated_at = $7 where id = $8",
        row.enabled,
        row.protocol,
        row.endpoint,
        row.auth_header,
        row.tls_ca_pem,
        row.min_severity,
        UtcInstant(row.updated_at) as _,
        row.id,
    )
    .execute(conn)
    .await?
    .rows_affected())
}
