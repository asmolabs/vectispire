//! `t_login_attempt` — `LoginAttemptRepository`. The id is `char(36)`, a UUID's text as Hibernate writes it.

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Db, Tx};

use super::AttemptRow;
use crate::persistence::model::StoreError;

/// `save(attempt)`, inside the reservation's transaction.
pub(super) async fn insert(tx: &mut Tx, id: Uuid, key: &str, at: OffsetDateTime) -> Result<(), StoreError> {
    let id = id.as_hyphenated().to_string();
    let at = to_microseconds(at);
    match tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(tx) => {
            sqlx::query!(
                "/* mysql */ insert into t_login_attempt (id, counter_key, occurred_at) values (?, ?, ?)",
                id,
                key,
                at
            )
            .execute(&mut **tx)
            .await?;
        }
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(tx) => {
            sqlx::query!(
                "/* postgres */ insert into t_login_attempt (id, counter_key, occurred_at) values ($1, $2, $3)",
                id,
                key,
                at
            )
            .execute(&mut **tx)
            .await?;
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    }
    Ok(())
}

/// A row as stored.
struct Stored {
    id: String,
    occurred_at: OffsetDateTime,
}

/// `findByCounterKeyAndOccurredAtAfter`.
pub(super) async fn find_after(db: &Db, key: &str, after: OffsetDateTime) -> Result<Vec<AttemptRow>, StoreError> {
    let after = to_microseconds(after);
    // MySQL's `datetime(6)` would be read as a zone-less `PrimitiveDateTime`; Hibernate stores UTC there.
    let stored = match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_as!(
                Stored,
                r#"/* mysql */ select id, occurred_at as "occurred_at: _" from t_login_attempt
                where counter_key = ? and occurred_at > ?"#,
                key,
                after
            )
            .fetch_all(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query_as!(
            Stored,
            "/* postgres */ select id, occurred_at from t_login_attempt where counter_key = $1 and occurred_at > $2",
            key,
            after
        )
        .fetch_all(pool)
        .await?,
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    };
    stored
        .into_iter()
        .map(|row| {
            let id = Uuid::try_parse(&row.id).map_err(|error| StoreError(Box::new(error)))?;
            Ok(AttemptRow { id, occurred_at: row.occurred_at })
        })
        .collect()
}

/// `deleteByCounterKey`.
pub(super) async fn delete_by_key(db: &Db, key: &str) -> Result<u64, StoreError> {
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_login_attempt where counter_key = ?", key)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => sqlx::query!("/* postgres */ delete from t_login_attempt where counter_key = $1", key)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `deleteByIdIn`: one statement, as Java's JPQL `in :ids` is — `deleteAllById` read each row and deleted it one
/// statement at a time, while concurrent attempts are exactly when this runs.
///
/// **On MySQL the statement is built here and not checked**: one placeholder per id, as the administrator count's
/// `in (…)` (the module's note). The ids are bound, never written into the text. PostgreSQL's `= any($1)` is checked.
pub(super) async fn delete_ids(db: &Db, ids: &[Uuid]) -> Result<u64, StoreError> {
    if ids.is_empty() {
        return Ok(0);
    }
    let ids: Vec<String> = ids.iter().map(|id| id.as_hyphenated().to_string()).collect();
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            let marks = vec!["?"; ids.len()].join(", ");
            let text = format!("/* mysql */ delete from t_login_attempt where id in ({marks})");
            let mut query = sqlx::query(sqlx::AssertSqlSafe(text));
            for id in &ids {
                query = query.bind(id);
            }
            query.execute(pool).await?.rows_affected()
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            // `id` is `character(36)`: compared as text, which the 36 characters of a UUID fill exactly.
            sqlx::query!("/* postgres */ delete from t_login_attempt where id = any($1::text[])", &ids)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}

/// `deleteBefore`: what has left the window — the hourly purge.
pub(super) async fn delete_before(db: &Db, cutoff: OffsetDateTime) -> Result<u64, StoreError> {
    let cutoff = to_microseconds(cutoff);
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => sqlx::query!("/* mysql */ delete from t_login_attempt where occurred_at < ?", cutoff)
            .execute(pool)
            .await?
            .rows_affected(),
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query!("/* postgres */ delete from t_login_attempt where occurred_at < $1", cutoff)
                .execute(pool)
                .await?
                .rows_affected()
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(super::not_built()),
    })
}
