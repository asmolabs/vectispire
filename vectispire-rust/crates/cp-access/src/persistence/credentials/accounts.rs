//! The columns of `t_user` a credential needs: who the account is, and whether it may still act.
//!
//! The accounts task (1.1) owns `t_user`; this is the read `AuthService.activeUserOf` and
//! `ApiKeyAuthService.integrationFor` make, kept to those columns.

use vectispire_cp_db::Db;

use super::StoreError;

/// An account as a credential sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountRow {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub is_active: bool,
    pub must_change_password: bool,
}

/// `users.findById(id)`.
pub(crate) async fn find(db: &Db, id: i64) -> Result<Option<AccountRow>, StoreError> {
    // The flags are `bit(1)` on MySQL, which the macro would read as an integer: named as the field's `bool`.
    Ok(match db {
        #[cfg(feature = "mysql-queries")]
        Db::MySql(pool) => {
            sqlx::query_as!(
                AccountRow,
                r#"/* mysql */ select id, username, role, is_active as "is_active: _",
                must_change_password as "must_change_password: _" from t_user where id = ?"#,
                id
            )
            .fetch_optional(pool)
            .await?
        }
        #[cfg(feature = "postgres-queries")]
        Db::PostgreSql(pool) => {
            sqlx::query_as!(
                AccountRow,
                "/* postgres */ select id, username, role, is_active, must_change_password from t_user where id = $1",
                id
            )
            .fetch_optional(pool)
            .await?
        }
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::not_built()),
    })
}
