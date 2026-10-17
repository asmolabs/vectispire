//! The grants: `t_user_target`, `t_team_member`, `t_team_target` — `UserTargetRepository.findByUserId`,
//! `TeamMemberRepository.findByUserId` and `TeamTargetRepository.findByTeamIdIn`.
//!
//! **Checked statements** (`sqlx::query_as!`), described against both engines' migrated schema at compile time and
//! cached in `crates/cp-access/.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh`). Every one is fixed text, so none
//! needs a query builder:
//!
//! - the Java side reads the account's teams, then the teams' grants with `team_id in :teamIds`, behind a guard
//!   for the empty list — `in ()` is a syntax error on some engines and every row on others, and "every row" here
//!   would hand an account in no team the whole backlog. **One join replaces both statements and the guard**: an
//!   account in no team joins no row, so the hazard the guard stood against has no statement left to occur in.
//!   The two answers are the same set, which `tests/authz_on_both_engines.rs` holds to the Java matrix.

use vectispire_cp_db::{Db, Mode, Tx};

use super::StoreError;

/// A grant as `t_user_target` and `t_team_target` hold it: a kind (`TeamRules.KIND_*`) and an identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub kind: String,
    pub id: i64,
}

/// Every grant the account holds — directly, then through its teams — read in **one read-only transaction**, as
/// `@Transactional(readOnly = true)` gave the Java side: both answers come from one snapshot, so a grant moved from
/// the account to its team between the two reads is neither lost nor doubled.
pub(crate) async fn of_account(db: &Db, user_id: i64) -> Result<Vec<Grant>, StoreError> {
    let mut tx = db.begin(Mode::ReadOnly).await?;
    let grants = match &mut tx {
        #[cfg(feature = "mysql-queries")]
        Tx::MySql(tx) => mysql::of_account(tx, user_id).await?,
        #[cfg(feature = "postgres-queries")]
        Tx::PostgreSql(tx) => postgres::of_account(tx, user_id).await?,
        #[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
        _ => return Err(StoreError::EngineNotBuilt),
    };
    tx.commit().await?;
    Ok(grants)
}

#[cfg(feature = "mysql-queries")]
mod mysql {
    use sqlx::{MySql, Transaction};

    use super::Grant;

    pub(super) async fn of_account(tx: &mut Transaction<'static, MySql>, user_id: i64) -> sqlx::Result<Vec<Grant>> {
        let mut grants = sqlx::query_as!(
            Grant,
            "/* mysql */ select target_kind as kind, target_id as id from t_user_target where user_id = ?",
            user_id
        )
        .fetch_all(&mut **tx)
        .await?;
        grants.extend(
            sqlx::query_as!(
                Grant,
                "/* mysql */ select t.target_kind as kind, t.target_id as id from t_team_target t \
                 join t_team_member m on m.team_id = t.team_id where m.user_id = ?",
                user_id
            )
            .fetch_all(&mut **tx)
            .await?,
        );
        Ok(grants)
    }
}

#[cfg(feature = "postgres-queries")]
mod postgres {
    use sqlx::{Postgres, Transaction};

    use super::Grant;

    pub(super) async fn of_account(tx: &mut Transaction<'static, Postgres>, user_id: i64) -> sqlx::Result<Vec<Grant>> {
        let mut grants = sqlx::query_as!(
            Grant,
            "/* postgres */ select target_kind as kind, target_id as id from t_user_target where user_id = $1",
            user_id
        )
        .fetch_all(&mut **tx)
        .await?;
        grants.extend(
            sqlx::query_as!(
                Grant,
                "/* postgres */ select t.target_kind as kind, t.target_id as id from t_team_target t \
                 join t_team_member m on m.team_id = t.team_id where m.user_id = $1",
                user_id
            )
            .fetch_all(&mut **tx)
            .await?,
        );
        Ok(grants)
    }
}
