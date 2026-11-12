//! `UserRepository.countActiveAdministratorsExcluding(roles, -1)`: the active accounts holding one of these roles.
//!
//! The Java query excludes an id, and every caller passes `-1`, which no account holds; the exclusion is not
//! ported, since nothing asks for it.
//!
//! **One checked statement per role, summed**, rather than `role in (…)` built at run time: the list is derived
//! from the flags (`roles::approver_roles`), so its length is not fixed text, and a checked statement must be. The
//! sum is the same count — a row holds one role, and the names are distinct under any collation — and each
//! comparison is still the engine's: on MySQL, `role = 'ADMIN'` matches a stored `admin`, as the Java `in` does
//! (`tests/authz_on_both_engines.rs` pins both engines).

use vectispire_cp_db::Db;

use super::StoreError;

/// How many active accounts hold one of `roles`.
pub(crate) async fn count_active_holding(db: &Db, roles: &[&str]) -> Result<i64, StoreError> {
    let mut total = 0_i64;
    for role in roles {
        let holding = match db {
            #[cfg(feature = "mysql-queries")]
            Db::MySql(pool) => {
                sqlx::query_scalar!("/* mysql */ select count(*) from t_user where is_active = true and role = ?", role)
                    .fetch_one(pool)
                    .await?
            }
            #[cfg(feature = "postgres-queries")]
            Db::PostgreSql(pool) => {
                sqlx::query_scalar!(
                    r#"/* postgres */ select count(*) as "count!" from t_user where is_active = true and role = $1"#,
                    role
                )
                .fetch_one(pool)
                .await?
            }
            #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
            _ => return Err(StoreError::EngineNotBuilt),
        };
        total = total.saturating_add(holding);
    }
    Ok(total)
}
