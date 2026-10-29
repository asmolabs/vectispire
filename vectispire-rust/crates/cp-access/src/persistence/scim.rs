//! What SCIM provisioning reads and writes beyond the administration's statements — `UserRepository`'s reads and the
//! columns a directory sets, `SessionRepository.deleteByUserId` inside the account's transaction, and
//! `TeamMemberRepository`'s memberships with their usernames, the directory's own upsert and the removal of one.
//!
//! **Every statement runs in the caller's transaction** (`&mut Tx`), as `administration`'s do: the service decides what
//! commits together — an account's row and the sessions its change closes, an account's deletion and its sessions.
//! Teams are read and written through `administration` (`team`, `team_named`, `insert_team`, `update_team`,
//! `delete_members`, …); only what SCIM adds is here. Checked statements, one per engine and tagged with it, cached in
//! `crates/cp-access/.sqlx/`.
//!
//! **An account write sets the directory's columns only** (`display_name`, `email`, `keycloak_id`, `is_active`,
//! `role`, `updated_at`), where Java saves the whole entity read at the start of the request: a second factor enrolled
//! or a password changed in between was written back as it was read.

use time::OffsetDateTime;
use vectispire_cp_db::Tx;

use super::StoreError;

/// The columns of `t_user` an account's view carries — `UserView`, without any secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRow {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub github_id: Option<String>,
    pub keycloak_id: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub must_change_password: bool,
    pub mfa_enabled: bool,
}

/// An account the directory creates: a password nobody knows, no obligation to change it, no second factor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAccountRow {
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub keycloak_id: Option<String>,
    pub is_active: bool,
    pub role: String,
    pub password: String,
    pub at: OffsetDateTime,
}

/// `TeamMembership`: a member of a team and its username, absent when the account is gone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub team_id: i64,
    pub user_id: i64,
    pub username: Option<String>,
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

// ── accounts ─────────────────────────────────────────────────────────────────────────────────────────────────────

/// `findById`, for a read.
pub(crate) async fn account(tx: &mut Tx, id: i64) -> Result<Option<AccountRow>, StoreError> {
    on_tx!(tx, |t| mysql::account(t, id).await?, postgres::account(t, id).await?)
}

/// `findById`, for a write: the row is locked until the transaction ends, so two replacements of one account cannot
/// both find it unbound and bind it to two subjects — the second waits, then reads the first's binding and is refused.
pub(crate) async fn account_to_change(tx: &mut Tx, id: i64) -> Result<Option<AccountRow>, StoreError> {
    on_tx!(tx, |t| mysql::account_to_change(t, id).await?, postgres::account_to_change(t, id).await?)
}

/// `findByUsername`, compared by the engine — on MySQL under the column's collation.
pub(crate) async fn account_named(tx: &mut Tx, username: &str) -> Result<Option<AccountRow>, StoreError> {
    on_tx!(tx, |t| mysql::account_named(t, username).await?, postgres::account_named(t, username).await?)
}

/// `findByKeycloakId`, compared as the column's unique constraint compares.
pub(crate) async fn account_bound_to(tx: &mut Tx, subject: &str) -> Result<Option<AccountRow>, StoreError> {
    on_tx!(tx, |t| mysql::account_bound_to(t, subject).await?, postgres::account_bound_to(t, subject).await?)
}

/// `findAllByOrderByUsernameAsc`.
pub(crate) async fn accounts(tx: &mut Tx) -> Result<Vec<AccountRow>, StoreError> {
    on_tx!(tx, |t| mysql::accounts(t).await?, postgres::accounts(t).await?)
}

pub(crate) async fn insert_account(tx: &mut Tx, row: &NewAccountRow) -> Result<i64, StoreError> {
    on_tx!(tx, |t| mysql::insert_account(t, row).await?, postgres::insert_account(t, row).await?)
}

/// The columns a directory sets, from `row`.
pub(crate) async fn update_account(tx: &mut Tx, row: &AccountRow) -> Result<(), StoreError> {
    on_tx!(tx, |t| mysql::update_account(t, row).await?, postgres::update_account(t, row).await?)
}

/// `AuthService.revokeAllForUser` — `sessions.deleteByUserId` — in the account's transaction.
pub(crate) async fn delete_sessions(tx: &mut Tx, user_id: i64) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_sessions(t, user_id).await?, postgres::delete_sessions(t, user_id).await?)
}

/// The row; what names it goes with it by the schema's cascades (memberships, grants, keys, challenges).
pub(crate) async fn delete_account(tx: &mut Tx, id: i64) -> Result<u64, StoreError> {
    on_tx!(tx, |t| mysql::delete_account(t, id).await?, postgres::delete_account(t, id).await?)
}

// ── memberships ──────────────────────────────────────────────────────────────────────────────────────────────────

/// `findMembershipsOf`: one team's members with their usernames, by account id.
pub(crate) async fn memberships_of(tx: &mut Tx, team_id: i64) -> Result<Vec<Membership>, StoreError> {
    on_tx!(tx, |t| mysql::memberships_of(t, team_id).await?, postgres::memberships_of(t, team_id).await?)
}

/// `findAllMemberships`: every team's, by team then account, in one statement.
pub(crate) async fn memberships(tx: &mut Tx) -> Result<Vec<Membership>, StoreError> {
    on_tx!(tx, |t| mysql::memberships(t).await?, postgres::memberships(t).await?)
}

/// `members.save(new TeamMemberEntity(team, user, origin))` — a merge, since the key is assigned: a pairing already
/// there takes `origin`, one that is not is inserted.
pub(crate) async fn put_member(tx: &mut Tx, team_id: i64, user_id: i64, origin: &str) -> Result<(), StoreError> {
    on_tx!(
        tx,
        |t| mysql::put_member(t, team_id, user_id, origin).await?,
        postgres::put_member(t, team_id, user_id, origin).await?
    )
}

/// `deleteById(new Id(team, user))`: nothing when the pairing is not there.
pub(crate) async fn delete_member(tx: &mut Tx, team_id: i64, user_id: i64) -> Result<u64, StoreError> {
    on_tx!(
        tx,
        |t| mysql::delete_member(t, team_id, user_id).await?,
        postgres::delete_member(t, team_id, user_id).await?
    )
}

#[cfg(feature = "mysql-queries")]
mod mysql {
    use sqlx::MySqlConnection;
    use vectispire_cp_db::types::UtcInstant;

    use super::{AccountRow, Membership, NewAccountRow};

    pub(super) async fn account(conn: &mut MySqlConnection, id: i64) -> sqlx::Result<Option<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            r#"/* mysql */ select id, username, email, display_name, avatar_url, role, is_active as "is_active: bool",
               github_id, keycloak_id, created_at as "created_at: _", updated_at as "updated_at: _",
               must_change_password as "must_change_password: bool", mfa_enabled as "mfa_enabled: bool"
               from t_user where id = ?"#,
            id
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn account_to_change(conn: &mut MySqlConnection, id: i64) -> sqlx::Result<Option<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            r#"/* mysql */ select id, username, email, display_name, avatar_url, role, is_active as "is_active: bool",
               github_id, keycloak_id, created_at as "created_at: _", updated_at as "updated_at: _",
               must_change_password as "must_change_password: bool", mfa_enabled as "mfa_enabled: bool"
               from t_user where id = ? for update"#,
            id
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn account_named(conn: &mut MySqlConnection, username: &str) -> sqlx::Result<Option<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            r#"/* mysql */ select id, username, email, display_name, avatar_url, role, is_active as "is_active: bool",
               github_id, keycloak_id, created_at as "created_at: _", updated_at as "updated_at: _",
               must_change_password as "must_change_password: bool", mfa_enabled as "mfa_enabled: bool"
               from t_user where username = ?"#,
            username
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn account_bound_to(
        conn: &mut MySqlConnection,
        subject: &str,
    ) -> sqlx::Result<Option<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            r#"/* mysql */ select id, username, email, display_name, avatar_url, role, is_active as "is_active: bool",
               github_id, keycloak_id, created_at as "created_at: _", updated_at as "updated_at: _",
               must_change_password as "must_change_password: bool", mfa_enabled as "mfa_enabled: bool"
               from t_user where keycloak_id = ?"#,
            subject
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn accounts(conn: &mut MySqlConnection) -> sqlx::Result<Vec<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            r#"/* mysql */ select id, username, email, display_name, avatar_url, role, is_active as "is_active: bool",
               github_id, keycloak_id, created_at as "created_at: _", updated_at as "updated_at: _",
               must_change_password as "must_change_password: bool", mfa_enabled as "mfa_enabled: bool"
               from t_user order by username asc"#
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn insert_account(conn: &mut MySqlConnection, row: &NewAccountRow) -> sqlx::Result<i64> {
        let done = sqlx::query!(
            "/* mysql */ insert into t_user (username, email, password, display_name, keycloak_id, role, is_active, \
             created_at, updated_at, must_change_password, mfa_enabled) \
             values (?, ?, ?, ?, ?, ?, ?, ?, ?, false, false)",
            row.username,
            row.email,
            row.password,
            row.display_name,
            row.keycloak_id,
            row.role,
            row.is_active,
            UtcInstant(row.at),
            UtcInstant(row.at)
        )
        .execute(conn)
        .await?;
        i64::try_from(done.last_insert_id()).map_err(|error| sqlx::Error::Decode(Box::new(error)))
    }

    pub(super) async fn update_account(conn: &mut MySqlConnection, row: &AccountRow) -> sqlx::Result<()> {
        sqlx::query!(
            "/* mysql */ update t_user set display_name = ?, email = ?, keycloak_id = ?, is_active = ?, role = ?, \
             updated_at = ? where id = ?",
            row.display_name,
            row.email,
            row.keycloak_id,
            row.is_active,
            row.role,
            UtcInstant(row.updated_at),
            row.id
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn delete_sessions(conn: &mut MySqlConnection, user_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_session where user_id = ?", user_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn delete_account(conn: &mut MySqlConnection, id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_user where id = ?", id).execute(conn).await?.rows_affected())
    }

    pub(super) async fn memberships_of(conn: &mut MySqlConnection, team_id: i64) -> sqlx::Result<Vec<Membership>> {
        sqlx::query_as!(
            Membership,
            r#"/* mysql */ select m.team_id, m.user_id, u.username as "username?" from t_team_member m
               left join t_user u on u.id = m.user_id where m.team_id = ? order by m.user_id"#,
            team_id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn memberships(conn: &mut MySqlConnection) -> sqlx::Result<Vec<Membership>> {
        sqlx::query_as!(
            Membership,
            r#"/* mysql */ select m.team_id, m.user_id, u.username as "username?" from t_team_member m
               left join t_user u on u.id = m.user_id order by m.team_id, m.user_id"#
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn put_member(
        conn: &mut MySqlConnection,
        team_id: i64,
        user_id: i64,
        origin: &str,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "/* mysql */ insert into t_team_member (team_id, user_id, origin) values (?, ?, ?) \
             on duplicate key update origin = ?",
            team_id,
            user_id,
            origin,
            origin
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn delete_member(conn: &mut MySqlConnection, team_id: i64, user_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* mysql */ delete from t_team_member where team_id = ? and user_id = ?", team_id, user_id)
            .execute(conn)
            .await?
            .rows_affected())
    }
}

#[cfg(feature = "postgres-queries")]
mod postgres {
    use sqlx::PgConnection;

    use super::{AccountRow, Membership, NewAccountRow};

    pub(super) async fn account(conn: &mut PgConnection, id: i64) -> sqlx::Result<Option<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            "/* postgres */ select id, username, email, display_name, avatar_url, role, is_active, github_id, \
             keycloak_id, created_at, updated_at, must_change_password, mfa_enabled from t_user where id = $1",
            id
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn account_to_change(conn: &mut PgConnection, id: i64) -> sqlx::Result<Option<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            "/* postgres */ select id, username, email, display_name, avatar_url, role, is_active, github_id, \
             keycloak_id, created_at, updated_at, must_change_password, mfa_enabled from t_user where id = $1 \
             for update",
            id
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn account_named(conn: &mut PgConnection, username: &str) -> sqlx::Result<Option<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            "/* postgres */ select id, username, email, display_name, avatar_url, role, is_active, github_id, \
             keycloak_id, created_at, updated_at, must_change_password, mfa_enabled from t_user where username = $1",
            username
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn account_bound_to(conn: &mut PgConnection, subject: &str) -> sqlx::Result<Option<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            "/* postgres */ select id, username, email, display_name, avatar_url, role, is_active, github_id, \
             keycloak_id, created_at, updated_at, must_change_password, mfa_enabled from t_user \
             where keycloak_id = $1",
            subject
        )
        .fetch_optional(conn)
        .await
    }

    pub(super) async fn accounts(conn: &mut PgConnection) -> sqlx::Result<Vec<AccountRow>> {
        sqlx::query_as!(
            AccountRow,
            "/* postgres */ select id, username, email, display_name, avatar_url, role, is_active, github_id, \
             keycloak_id, created_at, updated_at, must_change_password, mfa_enabled from t_user \
             order by username asc"
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn insert_account(conn: &mut PgConnection, row: &NewAccountRow) -> sqlx::Result<i64> {
        sqlx::query_scalar!(
            "/* postgres */ insert into t_user (username, email, password, display_name, keycloak_id, role, \
             is_active, created_at, updated_at, must_change_password, mfa_enabled) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $8, false, false) returning id",
            row.username,
            row.email,
            row.password,
            row.display_name,
            row.keycloak_id,
            row.role,
            row.is_active,
            row.at
        )
        .fetch_one(conn)
        .await
    }

    pub(super) async fn update_account(conn: &mut PgConnection, row: &AccountRow) -> sqlx::Result<()> {
        sqlx::query!(
            "/* postgres */ update t_user set display_name = $1, email = $2, keycloak_id = $3, is_active = $4, \
             role = $5, updated_at = $6 where id = $7",
            row.display_name,
            row.email,
            row.keycloak_id,
            row.is_active,
            row.role,
            row.updated_at,
            row.id
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn delete_sessions(conn: &mut PgConnection, user_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* postgres */ delete from t_session where user_id = $1", user_id)
            .execute(conn)
            .await?
            .rows_affected())
    }

    pub(super) async fn delete_account(conn: &mut PgConnection, id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!("/* postgres */ delete from t_user where id = $1", id).execute(conn).await?.rows_affected())
    }

    pub(super) async fn memberships_of(conn: &mut PgConnection, team_id: i64) -> sqlx::Result<Vec<Membership>> {
        sqlx::query_as!(
            Membership,
            r#"/* postgres */ select m.team_id, m.user_id, u.username as "username?" from t_team_member m
               left join t_user u on u.id = m.user_id where m.team_id = $1 order by m.user_id"#,
            team_id
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn memberships(conn: &mut PgConnection) -> sqlx::Result<Vec<Membership>> {
        sqlx::query_as!(
            Membership,
            r#"/* postgres */ select m.team_id, m.user_id, u.username as "username?" from t_team_member m
               left join t_user u on u.id = m.user_id order by m.team_id, m.user_id"#
        )
        .fetch_all(conn)
        .await
    }

    pub(super) async fn put_member(
        conn: &mut PgConnection,
        team_id: i64,
        user_id: i64,
        origin: &str,
    ) -> sqlx::Result<()> {
        sqlx::query!(
            "/* postgres */ insert into t_team_member (team_id, user_id, origin) values ($1, $2, $3) \
             on conflict (team_id, user_id) do update set origin = excluded.origin",
            team_id,
            user_id,
            origin
        )
        .execute(conn)
        .await
        .map(drop)
    }

    pub(super) async fn delete_member(conn: &mut PgConnection, team_id: i64, user_id: i64) -> sqlx::Result<u64> {
        Ok(sqlx::query!(
            "/* postgres */ delete from t_team_member where team_id = $1 and user_id = $2",
            team_id,
            user_id
        )
        .execute(conn)
        .await?
        .rows_affected())
    }
}
