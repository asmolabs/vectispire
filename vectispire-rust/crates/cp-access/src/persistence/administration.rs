//! What the administration services read and write — `TeamRepository`, `TeamMemberRepository`,
//! `TeamTargetRepository`, `TeamWebhookRepository`, `UserTargetRepository`, and the few reads of `UserRepository` and
//! `ApiKeyRepository` the team, grant and key screens make.
//!
//! **Every statement runs in the caller's transaction** (`&mut Tx`), so that a service decides what commits together:
//! a replacement's delete and its inserts, a team's deletion and the rows that name it. Checked statements, one per
//! engine and tagged with it, cached in `crates/cp-access/.sqlx/` (`crates/cp-db/scripts/sqlx-prepare.sh`).
//!
//! **Ordered where Java's answer is not.** `findByTeamId`, `findByUserId` and `findAll` carry no `order by`: the order
//! is the engine's — MySQL's clustered primary key, PostgreSQL's heap. These read in the primary key's order, which
//! is what the MySQL recordings show, and a fixed order the PostgreSQL ones can be compared against.

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, Tx};

use super::StoreError;
use super::grants::Grant;

/// A row of `t_team` — `TeamEntity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamRow {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
}

/// What the administration needs of an account it names — never the row, whose secrets stay in `accounts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountBrief {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub is_active: bool,
}

/// `team_id` and how many rows it has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Count {
    pub team_id: i64,
    pub count: i64,
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

/// A read-write transaction: what a gesture writes commits together or not at all.
pub(crate) async fn write(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadWrite).await?)
}

/// A read-only transaction: the reads of one answer from one snapshot.
pub(crate) async fn read(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadOnly).await?)
}

pub(crate) async fn commit(tx: Tx) -> Result<(), StoreError> {
    Ok(tx.commit().await?)
}

// ── teams ────────────────────────────────────────────────────────────────────────────────────────────────────────

pub(crate) async fn teams(tx: &mut Tx) -> Result<Vec<TeamRow>, StoreError> {
    on_tx!(tx, |t| mysql::teams(t).await?, postgres::teams(t).await?)
}

pub(crate) async fn team(tx: &mut Tx, id: i64) -> Result<Option<TeamRow>, StoreError> {
    on_tx!(tx, |t| mysql::team(t, id).await?, postgres::team(t, id).await?)
}

/// `findByNameIgnoreCase`, as Spring Data derives it: `upper(name) = upper(?)`, compared by the engine — on MySQL
/// under the column's collation, which also folds accents.
pub(crate) async fn team_named(tx: &mut Tx, name: &str) -> Result<Option<TeamRow>, StoreError> {
    on_tx!(tx, |t| mysql::team_named(t, name).await?, postgres::team_named(t, name).await?)
}

pub(crate) async fn insert_team(
    tx: &mut Tx,
    name: &str,
    description: Option<&str>,
    created_at: OffsetDateTime,
) -> Result<i64, StoreError> {
    on_tx!(
        tx,
        |t| mysql::insert_team(t, name, description, created_at).await?,
        postgres::insert_team(t, name, description, created_at).await?
    )
}

pub(crate) async fn update_team(tx: &mut Tx, id: i64, name: &str, description: Option<&str>) -> Result<(), StoreError> {
    on_tx!(
        tx,
        |t| mysql::update_team(t, id, name, description).await?,
        postgres::update_team(t, id, name, description).await?
    )
}

pub(crate) async fn delete_team(tx: &mut Tx, id: i64) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_team(t, id).await?, postgres::delete_team(t, id).await?)
}

/// Every team's member count, in one statement: a count per team is where a list quietly becomes N+1.
pub(crate) async fn member_counts(tx: &mut Tx) -> Result<Vec<Count>, StoreError> {
    on_tx!(tx, |t| mysql::member_counts(t).await?, postgres::member_counts(t).await?)
}

pub(crate) async fn target_counts(tx: &mut Tx) -> Result<Vec<Count>, StoreError> {
    on_tx!(tx, |t| mysql::target_counts(t).await?, postgres::target_counts(t).await?)
}

pub(crate) async fn members_of(tx: &mut Tx, team_id: i64) -> Result<Vec<i64>, StoreError> {
    on_tx!(tx, |t| mysql::members_of(t, team_id).await?, postgres::members_of(t, team_id).await?)
}

pub(crate) async fn delete_members(tx: &mut Tx, team_id: i64) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_members(t, team_id).await?, postgres::delete_members(t, team_id).await?)
}

/// `TeamMemberEntity(team, user, origin)`.
pub(crate) async fn insert_member(tx: &mut Tx, team_id: i64, user_id: i64, origin: &str) -> Result<(), StoreError> {
    on_tx!(
        tx,
        |t| mysql::insert_member(t, team_id, user_id, origin).await?,
        postgres::insert_member(t, team_id, user_id, origin).await?
    )
}

pub(crate) async fn team_targets(tx: &mut Tx, team_id: i64) -> Result<Vec<Grant>, StoreError> {
    on_tx!(tx, |t| mysql::team_targets(t, team_id).await?, postgres::team_targets(t, team_id).await?)
}

pub(crate) async fn delete_team_targets(tx: &mut Tx, team_id: i64) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_team_targets(t, team_id).await?, postgres::delete_team_targets(t, team_id).await?)
}

/// `targets.save(new TeamTargetEntity(…))` — a merge, since the entity's id is assigned: a pair already written is
/// left as it is rather than refused, so the same target sent twice is one row.
pub(crate) async fn insert_team_target(tx: &mut Tx, team_id: i64, kind: &str, id: i64) -> Result<(), StoreError> {
    on_tx!(
        tx,
        |t| mysql::insert_team_target(t, team_id, kind, id).await?,
        postgres::insert_team_target(t, team_id, kind, id).await?
    )
}

/// The teams with a channel of their own, by identifier.
pub(crate) async fn teams_with_webhook(tx: &mut Tx) -> Result<Vec<i64>, StoreError> {
    on_tx!(tx, |t| mysql::teams_with_webhook(t).await?, postgres::teams_with_webhook(t).await?)
}

pub(crate) async fn webhook_url(tx: &mut Tx, team_id: i64) -> Result<Option<String>, StoreError> {
    on_tx!(tx, |t| mysql::webhook_url(t, team_id).await?, postgres::webhook_url(t, team_id).await?)
}

pub(crate) async fn delete_webhook(tx: &mut Tx, team_id: i64) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_webhook(t, team_id).await?, postgres::delete_webhook(t, team_id).await?)
}

pub(crate) async fn insert_webhook(tx: &mut Tx, team_id: i64, url: &str) -> Result<(), StoreError> {
    on_tx!(tx, |t| mysql::insert_webhook(t, team_id, url).await?, postgres::insert_webhook(t, team_id, url).await?)
}

/// `TeamTargetRepository.findByTarget`: the teams granted one target directly, by identifier.
pub(crate) async fn teams_granted(tx: &mut Tx, kind: &str, id: i64) -> Result<Vec<i64>, StoreError> {
    on_tx!(tx, |t| mysql::teams_granted(t, kind, id).await?, postgres::teams_granted(t, kind, id).await?)
}

// ── accounts ─────────────────────────────────────────────────────────────────────────────────────────────────────

pub(crate) async fn account(tx: &mut Tx, id: i64) -> Result<Option<AccountBrief>, StoreError> {
    on_tx!(tx, |t| mysql::account(t, id).await?, postgres::account(t, id).await?)
}

/// Every account's id and username — `users.findAll()`, read for the names the key list prints.
pub(crate) async fn usernames(tx: &mut Tx) -> Result<Vec<(i64, String)>, StoreError> {
    on_tx!(tx, |t| mysql::usernames(t).await?, postgres::usernames(t).await?)
}

pub(crate) async fn user_targets(tx: &mut Tx, user_id: i64) -> Result<Vec<Grant>, StoreError> {
    on_tx!(tx, |t| mysql::user_targets(t, user_id).await?, postgres::user_targets(t, user_id).await?)
}

pub(crate) async fn delete_user_targets(tx: &mut Tx, user_id: i64) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_user_targets(t, user_id).await?, postgres::delete_user_targets(t, user_id).await?)
}

pub(crate) async fn insert_user_target(tx: &mut Tx, user_id: i64, kind: &str, id: i64) -> Result<(), StoreError> {
    on_tx!(
        tx,
        |t| mysql::insert_user_target(t, user_id, kind, id).await?,
        postgres::insert_user_target(t, user_id, kind, id).await?
    )
}

#[cfg(feature = "mysql-queries")]
mod mysql {
    use sqlx::MySqlConnection;
    use time::OffsetDateTime;
    use vectispire_cp_db::types::UtcInstant;

    use super::{AccountBrief, Count, Grant, TeamRow};

    pub(super) async fn teams(conn: &mut MySqlConnection) -> sqlx::Result<Vec<TeamRow>> {
        sqlx::query_as!(
            TeamRow,
            r#"/* mysql */ select id, name, description, created_at as "created_at: _" from t_team order by id"#
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn team(conn: &mut MySqlConnection, id: i64) -> sqlx::Result<Option<TeamRow>> {
        sqlx::query_as!(
            TeamRow,
            r#"/* mysql */ select id, name, description, created_at as "created_at: _" from t_team where id = ?"#,
            id
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn team_named(conn: &mut MySqlConnection, name: &str) -> sqlx::Result<Option<TeamRow>> {
        sqlx::query_as!(
            TeamRow,
            r#"/* mysql */ select id, name, description, created_at as "created_at: _" from t_team
               where upper(name) = upper(?) order by id"#,
            name
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn insert_team(
        conn: &mut MySqlConnection,
        name: &str,
        description: Option<&str>,
        created_at: OffsetDateTime,
    ) -> sqlx::Result<i64> {
        let done = sqlx::query!(
            "/* mysql */ insert into t_team (name, description, created_at) values (?, ?, ?)",
            name,
            description,
            UtcInstant(created_at)
        )
        .execute(conn)
        .await?;
        i64::try_from(done.last_insert_id()).map_err(|error| sqlx::Error::Decode(Box::new(error)))
    }

    pub(super) async fn update_team(
        conn: &mut MySqlConnection,
        id: i64,
        name: &str,
        description: Option<&str>,
    ) -> sqlx::Result<()> {
        sqlx::query!("/* mysql */ update t_team set name = ?, description = ? where id = ?", name, description, id)
            .execute(conn)
            .await
            .map(drop)
    }

    pub(super) async fn delete_team(conn: &mut MySqlConnection, id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_team where id = ?", id).execute(conn).await?.rows_affected())
    }

    pub(super) async fn member_counts(conn: &mut MySqlConnection) -> sqlx::Result<Vec<Count>> {
        sqlx::query_as!(
            Count,
            r#"/* mysql */ select team_id, count(*) as "count!: i64" from t_team_member group by team_id"#
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn target_counts(conn: &mut MySqlConnection) -> sqlx::Result<Vec<Count>> {
        sqlx::query_as!(
            Count,
            r#"/* mysql */ select team_id, count(*) as "count!: i64" from t_team_target group by team_id"#
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn members_of(conn: &mut MySqlConnection, team_id: i64) -> sqlx::Result<Vec<i64>> {
        sqlx::query_scalar!("/* mysql */ select user_id from t_team_member where team_id = ? order by user_id", team_id)
            .fetch_all(conn)
            .await
    }

    pub(super) async fn delete_members(conn: &mut MySqlConnection, team_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_team_member where team_id = ?", team_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn insert_member(
        conn: &mut MySqlConnection,
        team_id: i64,
        user_id: i64,
        origin: &str,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "/* mysql */ insert into t_team_member (team_id, user_id, origin) values (?, ?, ?)",
            team_id,
            user_id,
            origin
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn team_targets(conn: &mut MySqlConnection, team_id: i64) -> sqlx::Result<Vec<Grant>> {
        sqlx::query_as!(
            Grant,
            "/* mysql */ select target_kind as kind, target_id as id from t_team_target where team_id = ? \
             order by target_kind, target_id",
            team_id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn delete_team_targets(conn: &mut MySqlConnection, team_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_team_target where team_id = ?", team_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn insert_team_target(
        conn: &mut MySqlConnection,
        team_id: i64,
        kind: &str,
        id: i64,
    ) -> sqlx::Result<()> {
        // Not `insert ignore`, which would swallow a foreign key's refusal too: only the duplicate is a no-op.
        sqlx::query!(
            "/* mysql */ insert into t_team_target (team_id, target_kind, target_id) values (?, ?, ?) \
             on duplicate key update target_id = target_id",
            team_id,
            kind,
            id
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn teams_with_webhook(conn: &mut MySqlConnection) -> sqlx::Result<Vec<i64>> {
        sqlx::query_scalar!("/* mysql */ select team_id from t_team_webhook order by team_id").fetch_all(conn).await
    }

    pub(super) async fn webhook_url(conn: &mut MySqlConnection, team_id: i64) -> sqlx::Result<Option<String>> {
        sqlx::query_scalar!("/* mysql */ select url from t_team_webhook where team_id = ?", team_id)
            .fetch_optional(conn)
            .await
    }

    pub(super) async fn delete_webhook(conn: &mut MySqlConnection, team_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_team_webhook where team_id = ?", team_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn insert_webhook(conn: &mut MySqlConnection, team_id: i64, url: &str) -> sqlx::Result<()> {
        sqlx::query!("/* mysql */ insert into t_team_webhook (team_id, url) values (?, ?)", team_id, url)
            .execute(conn)
            .await
            .map(drop)
    }

    pub(super) async fn teams_granted(conn: &mut MySqlConnection, kind: &str, id: i64) -> sqlx::Result<Vec<i64>> {
        sqlx::query_scalar!(
            "/* mysql */ select team_id from t_team_target where target_kind = ? and target_id = ? order by team_id",
            kind,
            id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn account(conn: &mut MySqlConnection, id: i64) -> sqlx::Result<Option<AccountBrief>> {
        sqlx::query_as!(
            AccountBrief,
            r#"/* mysql */ select id, username, role, is_active as "is_active: bool" from t_user where id = ?"#,
            id
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn usernames(conn: &mut MySqlConnection) -> sqlx::Result<Vec<(i64, String)>> {
        let rows = sqlx::query!("/* mysql */ select id, username from t_user order by id").fetch_all(conn).await?;
        Ok(rows.into_iter().map(|row| (row.id, row.username)).collect())
    }

    pub(super) async fn user_targets(conn: &mut MySqlConnection, user_id: i64) -> sqlx::Result<Vec<Grant>> {
        sqlx::query_as!(
            Grant,
            "/* mysql */ select target_kind as kind, target_id as id from t_user_target where user_id = ? \
             order by target_kind, target_id",
            user_id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn delete_user_targets(conn: &mut MySqlConnection, user_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_user_target where user_id = ?", user_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn insert_user_target(
        conn: &mut MySqlConnection,
        user_id: i64,
        kind: &str,
        id: i64,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "/* mysql */ insert into t_user_target (user_id, target_kind, target_id) values (?, ?, ?)",
            user_id,
            kind,
            id
        )
        .execute(conn)
        .await
        .map(drop)
    }
}

#[cfg(feature = "postgres-queries")]
mod postgres {
    use sqlx::PgConnection;
    use time::OffsetDateTime;

    use super::{AccountBrief, Count, Grant, TeamRow};

    pub(super) async fn teams(conn: &mut PgConnection) -> sqlx::Result<Vec<TeamRow>> {
        sqlx::query_as!(TeamRow, "/* postgres */ select id, name, description, created_at from t_team order by id")
            .fetch_all(conn)
            .await
    }

    pub(super) async fn team(conn: &mut PgConnection, id: i64) -> sqlx::Result<Option<TeamRow>> {
        sqlx::query_as!(
            TeamRow,
            "/* postgres */ select id, name, description, created_at from t_team where id = $1",
            id
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn team_named(conn: &mut PgConnection, name: &str) -> sqlx::Result<Option<TeamRow>> {
        sqlx::query_as!(
            TeamRow,
            "/* postgres */ select id, name, description, created_at from t_team where upper(name) = upper($1) \
             order by id",
            name
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn insert_team(
        conn: &mut PgConnection,
        name: &str,
        description: Option<&str>,
        created_at: OffsetDateTime,
    ) -> sqlx::Result<i64> {
        sqlx::query_scalar!(
            "/* postgres */ insert into t_team (name, description, created_at) values ($1, $2, $3) returning id",
            name,
            description,
            created_at
        )
        .fetch_one(conn)
        .await
    }

    pub(super) async fn update_team(
        conn: &mut PgConnection,
        id: i64,
        name: &str,
        description: Option<&str>,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "/* postgres */ update t_team set name = $1, description = $2 where id = $3",
            name,
            description,
            id
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn delete_team(conn: &mut PgConnection, id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* postgres */ delete from t_team where id = $1", id).execute(conn).await?.rows_affected())
    }

    pub(super) async fn member_counts(conn: &mut PgConnection) -> sqlx::Result<Vec<Count>> {
        sqlx::query_as!(
            Count,
            r#"/* postgres */ select team_id, count(*) as "count!: i64" from t_team_member group by team_id"#
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn target_counts(conn: &mut PgConnection) -> sqlx::Result<Vec<Count>> {
        sqlx::query_as!(
            Count,
            r#"/* postgres */ select team_id, count(*) as "count!: i64" from t_team_target group by team_id"#
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn members_of(conn: &mut PgConnection, team_id: i64) -> sqlx::Result<Vec<i64>> {
        sqlx::query_scalar!(
            "/* postgres */ select user_id from t_team_member where team_id = $1 order by user_id",
            team_id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn delete_members(conn: &mut PgConnection, team_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* postgres */ delete from t_team_member where team_id = $1", team_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn insert_member(
        conn: &mut PgConnection,
        team_id: i64,
        user_id: i64,
        origin: &str,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "/* postgres */ insert into t_team_member (team_id, user_id, origin) values ($1, $2, $3)",
            team_id,
            user_id,
            origin
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn team_targets(conn: &mut PgConnection, team_id: i64) -> sqlx::Result<Vec<Grant>> {
        sqlx::query_as!(
            Grant,
            "/* postgres */ select target_kind as kind, target_id as id from t_team_target where team_id = $1 \
             order by target_kind, target_id",
            team_id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn delete_team_targets(conn: &mut PgConnection, team_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* postgres */ delete from t_team_target where team_id = $1", team_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn insert_team_target(
        conn: &mut PgConnection,
        team_id: i64,
        kind: &str,
        id: i64,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "/* postgres */ insert into t_team_target (team_id, target_kind, target_id) values ($1, $2, $3) \
             on conflict (team_id, target_kind, target_id) do nothing",
            team_id,
            kind,
            id
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn teams_with_webhook(conn: &mut PgConnection) -> sqlx::Result<Vec<i64>> {
        sqlx::query_scalar!("/* postgres */ select team_id from t_team_webhook order by team_id").fetch_all(conn).await
    }

    pub(super) async fn webhook_url(conn: &mut PgConnection, team_id: i64) -> sqlx::Result<Option<String>> {
        sqlx::query_scalar!("/* postgres */ select url from t_team_webhook where team_id = $1", team_id)
            .fetch_optional(conn)
            .await
    }

    pub(super) async fn delete_webhook(conn: &mut PgConnection, team_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* postgres */ delete from t_team_webhook where team_id = $1", team_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn insert_webhook(conn: &mut PgConnection, team_id: i64, url: &str) -> sqlx::Result<()> {
        sqlx::query!("/* postgres */ insert into t_team_webhook (team_id, url) values ($1, $2)", team_id, url)
            .execute(conn)
            .await
            .map(drop)
    }

    pub(super) async fn teams_granted(conn: &mut PgConnection, kind: &str, id: i64) -> sqlx::Result<Vec<i64>> {
        sqlx::query_scalar!(
            "/* postgres */ select team_id from t_team_target where target_kind = $1 and target_id = $2 \
             order by team_id",
            kind,
            id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn account(conn: &mut PgConnection, id: i64) -> sqlx::Result<Option<AccountBrief>> {
        sqlx::query_as!(
            AccountBrief,
            "/* postgres */ select id, username, role, is_active from t_user where id = $1",
            id
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn usernames(conn: &mut PgConnection) -> sqlx::Result<Vec<(i64, String)>> {
        let rows = sqlx::query!("/* postgres */ select id, username from t_user order by id").fetch_all(conn).await?;
        Ok(rows.into_iter().map(|row| (row.id, row.username)).collect())
    }

    pub(super) async fn user_targets(conn: &mut PgConnection, user_id: i64) -> sqlx::Result<Vec<Grant>> {
        sqlx::query_as!(
            Grant,
            "/* postgres */ select target_kind as kind, target_id as id from t_user_target where user_id = $1 \
             order by target_kind, target_id",
            user_id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn delete_user_targets(conn: &mut PgConnection, user_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* postgres */ delete from t_user_target where user_id = $1", user_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn insert_user_target(
        conn: &mut PgConnection,
        user_id: i64,
        kind: &str,
        id: i64,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "/* postgres */ insert into t_user_target (user_id, target_kind, target_id) values ($1, $2, $3)",
            user_id,
            kind,
            id
        )
        .execute(conn)
        .await
        .map(drop)
    }
}
