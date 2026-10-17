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

type Tuple = (i64, String, String, bool, bool);

/// `users.findById(id)`.
pub(crate) async fn find(db: &Db, id: i64) -> Result<Option<AccountRow>, StoreError> {
    let row: Option<Tuple> =
        match db {
            Db::MySql(pool) => {
                sqlx::query_as(
                    "/* mysql */ select id, username, role, is_active, must_change_password from t_user where id = ?",
                )
                .bind(id)
                .fetch_optional(pool)
                .await?
            }
            Db::PostgreSql(pool) => sqlx::query_as(
                "/* postgres */ select id, username, role, is_active, must_change_password from t_user where id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?,
        };
    Ok(row.map(|(id, username, role, is_active, must_change_password)| AccountRow {
        id,
        username,
        role,
        is_active,
        must_change_password,
    }))
}
