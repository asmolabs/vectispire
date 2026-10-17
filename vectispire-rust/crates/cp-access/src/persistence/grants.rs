//! The grants: `t_user_target`, `t_team_member`, `t_team_target` — `UserTargetRepository.findByUserId`,
//! `TeamMemberRepository.findByUserId` and `TeamTargetRepository.findByTeamIdIn`.
//!
//! Read inside the caller's read-only transaction, so the three answers come from one snapshot. **Each statement is
//! spelled per engine and fixed** except the team list, built by sea-query with bound values in batches; the
//! live suite (`tests/engines.rs`) runs every one of them on both engines against the schema the migrations built.

use sea_query::{Alias, Expr, ExprTrait, MysqlQueryBuilder, PostgresQueryBuilder, Query};
use sea_query_sqlx::SqlxBinder;
use sqlx::{AssertSqlSafe, Row};
use vectispire_cp_db::{Db, Mode, Tx};

use super::StoreError;

/// A grant as `t_user_target` and `t_team_target` hold it: a kind (`TeamRules.KIND_*`) and an identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub kind: String,
    pub id: i64,
}

/// Every grant the account holds — directly, then through each of its teams — read in **one read-only
/// transaction**, as `@Transactional(readOnly = true)` gave the Java side: the three answers come from one
/// snapshot.
pub(crate) async fn of_account(db: &Db, user_id: i64) -> Result<Vec<Grant>, StoreError> {
    let mut tx = db.begin(Mode::ReadOnly).await?;
    let mut grants = of_user(&mut tx, user_id).await?;
    let teams = teams_of(&mut tx, user_id).await?;
    // **The guard, not an optimisation**: `in ()` is a syntax error on some engines and matches every row on
    // others, and "matches everything" here means an account in no team sees the entire backlog.
    if !teams.is_empty() {
        grants.extend(of_teams(&mut tx, &teams).await?);
    }
    tx.commit().await?;
    Ok(grants)
}

/// How many team ids one statement binds: far under every engine's limit, as the Java side's batches are.
const TEAM_BATCH: usize = 1_000;

/// The grants made to the account directly.
async fn of_user(tx: &mut Tx, user_id: i64) -> Result<Vec<Grant>, sqlx::Error> {
    let rows = match tx {
        Tx::MySql(tx) => sqlx::query("select target_kind, target_id from t_user_target where user_id = ?")
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .map(|row| Ok(Grant { kind: row.try_get(0)?, id: row.try_get(1)? }))
            .collect::<Result<Vec<_>, sqlx::Error>>()?,
        Tx::PostgreSql(tx) => sqlx::query("select target_kind, target_id from t_user_target where user_id = $1")
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .map(|row| Ok(Grant { kind: row.try_get(0)?, id: row.try_get(1)? }))
            .collect::<Result<Vec<_>, sqlx::Error>>()?,
    };
    Ok(rows)
}

/// The teams the account is a member of.
async fn teams_of(tx: &mut Tx, user_id: i64) -> Result<Vec<i64>, sqlx::Error> {
    match tx {
        Tx::MySql(tx) => {
            sqlx::query_scalar("select team_id from t_team_member where user_id = ?")
                .bind(user_id)
                .fetch_all(&mut **tx)
                .await
        }
        Tx::PostgreSql(tx) => {
            sqlx::query_scalar("select team_id from t_team_member where user_id = $1")
                .bind(user_id)
                .fetch_all(&mut **tx)
                .await
        }
    }
}

/// The grants made to these teams. **Never called with no team** — the caller's guard: `team_id in ()` is a syntax
/// error on some engines and every row on others.
async fn of_teams(tx: &mut Tx, teams: &[i64]) -> Result<Vec<Grant>, sqlx::Error> {
    let mut grants = Vec::new();
    for batch in teams.chunks(TEAM_BATCH) {
        let mut statement = Query::select();
        statement
            .columns([Alias::new("target_kind"), Alias::new("target_id")])
            .from(Alias::new("t_team_target"))
            .and_where(Expr::col(Alias::new("team_id")).is_in(batch.iter().copied()));
        // Sound: the text is sea-query's rendering of the identifiers above; the team ids are bound.
        let rows = match tx {
            Tx::MySql(tx) => {
                let (sql, values) = statement.build_sqlx(MysqlQueryBuilder);
                sqlx::query_with(AssertSqlSafe(sql), values)
                    .fetch_all(&mut **tx)
                    .await?
                    .into_iter()
                    .map(|row| Ok(Grant { kind: row.try_get(0)?, id: row.try_get(1)? }))
                    .collect::<Result<Vec<_>, sqlx::Error>>()?
            }
            Tx::PostgreSql(tx) => {
                let (sql, values) = statement.build_sqlx(PostgresQueryBuilder);
                sqlx::query_with(AssertSqlSafe(sql), values)
                    .fetch_all(&mut **tx)
                    .await?
                    .into_iter()
                    .map(|row| Ok(Grant { kind: row.try_get(0)?, id: row.try_get(1)? }))
                    .collect::<Result<Vec<_>, sqlx::Error>>()?
            }
        };
        grants.extend(rows);
    }
    Ok(grants)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **What the empty-team guard stands on, pinned.** The guard in [`of_account`] keeps `team_id in ()` from being
    /// sent at all; were it removed, sea-query renders an empty list as a condition no row meets on both engines —
    /// not the syntax error, nor the "every row" some drivers read it as. Removing the guard is therefore not
    /// observable through the database (the mutation campaign records it as surviving), and this test is what says
    /// why it is safe: an empty grant list from teams stays empty.
    #[test]
    fn an_empty_team_list_is_a_condition_no_row_meets() {
        let mut statement = Query::select();
        statement
            .column(Alias::new("target_id"))
            .from(Alias::new("t_team_target"))
            .and_where(Expr::col(Alias::new("team_id")).is_in(Vec::<i64>::new()));
        // Rendered with the values written in: bound, it is `? = ?` over 1 and 2.
        for sql in [statement.to_string(MysqlQueryBuilder), statement.to_string(PostgresQueryBuilder)] {
            assert!(sql.ends_with("WHERE 1 = 2"), "{sql}");
        }
    }
}
