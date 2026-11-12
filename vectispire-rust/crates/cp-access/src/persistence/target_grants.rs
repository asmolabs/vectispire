//! What names a target in `access`' tables — `UserTargetRepository.deleteByTarget` / `countByTarget`, the same on
//! `TeamTargetRepository`, and `ApiKeyRepository.findRestrictedTo` / `revokeByIds` — for `TargetGrants`.
//!
//! **Run in the caller's transaction**: the revocation belongs to the deletion that causes it (Java's
//! `Propagation.MANDATORY`). Committed on its own, a deletion that then rolled back would leave its target standing
//! and its grants gone. Checked statements, cached in `crates/cp-access/.sqlx/`.

use uuid::Uuid;
use vectispire_cp_db::Tx;

use super::StoreError;

/// An integration key restricted to a target — `TargetGrants.RevokedKey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestrictedKey {
    pub id: Uuid,
    pub name: String,
}

macro_rules! on_tx {
    ($tx:expr, |$t:ident| $mysql:expr, $postgres:expr) => {
        match $tx {
            #[cfg(feature = "mysql-queries")]
            Tx::MySql($t) => Ok($mysql),
            #[cfg(feature = "postgres-queries")]
            Tx::PostgreSql($t) => Ok($postgres),
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => Err(StoreError::EngineNotBuilt),
        }
    };
}

/// Deletes the account and team grants naming the target; answers how many went.
pub(crate) async fn delete_grants(tx: &mut Tx, kind: &str, id: i64) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_grants(t, kind, id).await?, postgres::delete_grants(t, kind, id).await?)
}

/// The integration keys restricted to the target — an agent's key has no owner and is not one of them.
pub(crate) async fn keys_restricted_to(tx: &mut Tx, kind: &str, id: i64) -> Result<Vec<RestrictedKey>, StoreError> {
    on_tx!(tx, |t| mysql::keys_restricted_to(t, kind, id).await?, postgres::keys_restricted_to(t, kind, id).await?)
}

/// Deletes one key, by the id read just before — so the entries name exactly the rows that went.
pub(crate) async fn delete_key(tx: &mut Tx, id: Uuid) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_key(t, id).await?, postgres::delete_key(t, id).await?)
}

/// `(accounts, teams)` granted the target.
pub(crate) async fn count_grantees(tx: &mut Tx, kind: &str, id: i64) -> Result<(i64, i64), StoreError> {
    on_tx!(tx, |t| mysql::count_grantees(t, kind, id).await?, postgres::count_grantees(t, kind, id).await?)
}

#[cfg(feature = "mysql-queries")]
mod mysql {
    use sqlx::MySqlConnection;
    use uuid::Uuid;
    use vectispire_cp_db::types::TextUuid;

    use super::RestrictedKey;

    pub(super) async fn delete_grants(conn: &mut MySqlConnection, kind: &str, id: i64) -> sqlx::Result<u64> {
        let users =
            sqlx::query!("/* mysql */ delete from t_user_target where target_kind = ? and target_id = ?", kind, id)
                .execute(&mut *conn)
                .await?
                .rows_affected();
        let teams =
            sqlx::query!("/* mysql */ delete from t_team_target where target_kind = ? and target_id = ?", kind, id)
                .execute(&mut *conn)
                .await?
                .rows_affected();
        Ok(users.saturating_add(teams))
    }

    pub(super) async fn keys_restricted_to(
        conn: &mut MySqlConnection,
        kind: &str,
        id: i64,
    ) -> sqlx::Result<Vec<RestrictedKey>> {
        let rows = sqlx::query!(
            r#"/* mysql */ select id as "id: TextUuid", name from t_api_key
               where target_kind = ? and target_id = ? and owner_user_id is not null"#,
            kind,
            id
        )
        .fetch_all(conn)
        .await?;
        Ok(rows.into_iter().map(|row| RestrictedKey { id: row.id.0, name: row.name }).collect())
    }

    pub(super) async fn delete_key(conn: &mut MySqlConnection, id: Uuid) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_api_key where id = ?", TextUuid(id))
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn count_grantees(conn: &mut MySqlConnection, kind: &str, id: i64) -> sqlx::Result<(i64, i64)> {
        let accounts = sqlx::query_scalar!(
            r#"/* mysql */ select count(*) as "count!: i64" from t_user_target where target_kind = ? and target_id = ?"#,
            kind,
            id
        )
        .fetch_one(&mut *conn)
        .await?;
        let teams = sqlx::query_scalar!(
            r#"/* mysql */ select count(*) as "count!: i64" from t_team_target where target_kind = ? and target_id = ?"#,
            kind,
            id
        )
        .fetch_one(conn)
        .await?;
        Ok((accounts, teams))
    }
}

#[cfg(feature = "postgres-queries")]
mod postgres {
    use sqlx::PgConnection;
    use uuid::Uuid;
    use vectispire_cp_db::types::TextUuid;

    use super::RestrictedKey;

    pub(super) async fn delete_grants(conn: &mut PgConnection, kind: &str, id: i64) -> sqlx::Result<u64> {
        let users = sqlx::query!(
            "/* postgres */ delete from t_user_target where target_kind = $1 and target_id = $2",
            kind,
            id
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();
        let teams = sqlx::query!(
            "/* postgres */ delete from t_team_target where target_kind = $1 and target_id = $2",
            kind,
            id
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();
        Ok(users.saturating_add(teams))
    }

    pub(super) async fn keys_restricted_to(
        conn: &mut PgConnection,
        kind: &str,
        id: i64,
    ) -> sqlx::Result<Vec<RestrictedKey>> {
        let rows = sqlx::query!(
            r#"/* postgres */ select id as "id: TextUuid", name from t_api_key
               where target_kind = $1 and target_id = $2 and owner_user_id is not null"#,
            kind,
            id
        )
        .fetch_all(conn)
        .await?;
        Ok(rows.into_iter().map(|row| RestrictedKey { id: row.id.0, name: row.name }).collect())
    }

    pub(super) async fn delete_key(conn: &mut PgConnection, id: Uuid) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* postgres */ delete from t_api_key where id = $1", TextUuid(id) as _)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn count_grantees(conn: &mut PgConnection, kind: &str, id: i64) -> sqlx::Result<(i64, i64)> {
        let accounts = sqlx::query_scalar!(
            r#"/* postgres */ select count(*) as "count!: i64" from t_user_target where target_kind = $1 and target_id = $2"#,
            kind,
            id
        )
        .fetch_one(&mut *conn)
        .await?;
        let teams = sqlx::query_scalar!(
            r#"/* postgres */ select count(*) as "count!: i64" from t_team_target where target_kind = $1 and target_id = $2"#,
            kind,
            id
        )
        .fetch_one(conn)
        .await?;
        Ok((accounts, teams))
    }
}
