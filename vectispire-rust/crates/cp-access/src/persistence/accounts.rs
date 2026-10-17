//! `UserRepository.countActiveAdministratorsExcluding(roles, -1)`: the active accounts holding one of these roles.
//!
//! The Java query excludes an id, and every caller passes `-1`, which no account holds; the exclusion is not
//! ported, since nothing asks for it.

use sea_query::{Alias, Expr, ExprTrait, MysqlQueryBuilder, PostgresQueryBuilder, Query};
use sea_query_sqlx::SqlxBinder;
use sqlx::AssertSqlSafe;
use vectispire_cp_db::Db;

use super::StoreError;

/// How many active accounts hold one of `roles`. `roles` empty answers 0 without asking: `role in ()`.
pub(crate) async fn count_active_holding(db: &Db, roles: &[&str]) -> Result<i64, StoreError> {
    if roles.is_empty() {
        return Ok(0);
    }
    let mut statement = Query::select();
    statement
        .expr(Expr::cust("count(*)"))
        .from(Alias::new("t_user"))
        .and_where(Expr::col(Alias::new("is_active")).eq(true))
        .and_where(Expr::col(Alias::new("role")).is_in(roles.iter().map(|role| (*role).to_owned())));
    // Sound: sea-query's rendering of the identifiers above; the roles and the flag are bound.
    match db {
        Db::MySql(pool) => {
            let (sql, values) = statement.build_sqlx(MysqlQueryBuilder);
            Ok(sqlx::query_scalar_with(AssertSqlSafe(sql), values).fetch_one(pool).await?)
        }
        Db::PostgreSql(pool) => {
            let (sql, values) = statement.build_sqlx(PostgresQueryBuilder);
            Ok(sqlx::query_scalar_with(AssertSqlSafe(sql), values).fetch_one(pool).await?)
        }
    }
}
