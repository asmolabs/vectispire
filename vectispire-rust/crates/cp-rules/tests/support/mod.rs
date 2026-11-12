//! Test harness for `vectispire-cp-rules`: a migrated database on each engine (`vectispire_cp_db::testing`'s, in a
//! throwaway container or on the shared server CI names), and database utilities.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use vectispire_cp_db::Db;

#[allow(unused_imports)] // not every suite of the crate reaches a database
pub use vectispire_cp_db::testing::TestDatabase as Migrated;

pub async fn clean(db: &Db) {
    match db {
        Db::MySql(pool) => {
            sqlx::query("delete from t_semgrep_rule_set").execute(pool).await.unwrap();
        }
        Db::PostgreSql(pool) => {
            sqlx::query("delete from t_semgrep_rule_set").execute(pool).await.unwrap();
        }
    }
}
