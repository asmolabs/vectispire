//! `t_user` on either engine — `UserRepository` and the transactions of `AccountAdminService`.
//!
//! **Each statement is written once per engine**, in the engine's placeholders, and matched on [`Tx`] / [`Db`]:
//! `sqlx::Any` would erase the engine (cp-db's README). They are `sqlx::query!`, checked against the schema the
//! migrations build, as `cp-db`'s pattern has it: a column renamed by a migration, a parameter of the wrong type or a
//! nullable column read as a plain one does not build. The answers live in this crate's `.sqlx/`, both engines in one
//! directory, kept current by `crates/cp-db/scripts/sqlx-prepare.sh`; every statement carries its engine's tag,
//! because the cache file is named after the SQL text alone.
//!
//! **One statement is not checked: the count of the other active administrators on MySQL.** Its `in (…)` list is
//! as long as the caller's list of roles, and a checked statement has a fixed text. PostgreSQL says the same with
//! `= any($1)` over one array parameter, which is checked; MySQL has no array parameter, and the spellings that would
//! fake one (`find_in_set`, `json_contains`) compare under another collation than `in` — on MySQL `role in ('ADMIN')`
//! matches a stored `admin`, as Java's JPQL `in :roles` does there, and a JSON comparison would not. The statement
//! is built from placeholders only, nothing of the caller's text enters it.
//!
//! **The rehash writes the password column only** — Java saves the whole entity it loaded at the sign-in, so a
//! deactivation committed between that load and the rehash was written back as active. Rare (a rehash is due only
//! after a cost raise), and the one deliberate difference here.

use std::collections::HashMap;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, Tx};

use crate::persistence::model::{AccountStore, NewUser, PasswordHash, RevokedKey, SessionHash, StoreError, User};

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> StoreError {
        StoreError(Box::new(error))
    }
}

/// What the account transactions do to the sessions and keys of an account, inside the transaction they are given
/// — `SessionRepository` and `ApiKeyRepository` (Phase 1, task 1.2, implements it).
pub trait SessionsAndKeys {
    /// `sessions.deleteByUserId`.
    fn delete_sessions(
        &self,
        tx: &mut Tx,
        user_id: i64,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    /// `sessions.deleteByUserIdExcept`: every session of the account but the one named.
    fn delete_sessions_except(
        &self,
        tx: &mut Tx,
        user_id: i64,
        keep: &SessionHash,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    /// The keys the account owns, then revoked — `findByOwnerUserId` and `revokeOwnedBy`.
    fn revoke_owned_keys(
        &self,
        tx: &mut Tx,
        user_id: i64,
    ) -> impl std::future::Future<Output = Result<Vec<RevokedKey>, StoreError>> + Send;
    /// `sessions.countActiveByUser`: sessions whose expiry is after `at`, per account.
    fn count_active_by_user(
        &self,
        db: &Db,
        at: OffsetDateTime,
    ) -> impl std::future::Future<Output = Result<HashMap<i64, u64>, StoreError>> + Send;
}

/// [`AccountStore`] on the database.
#[derive(Debug, Clone)]
pub struct SqlAccountStore<K> {
    db: Db,
    credentials: K,
}

impl<K: SessionsAndKeys + Sync> SqlAccountStore<K> {
    pub fn new(db: Db, credentials: K) -> SqlAccountStore<K> {
        SqlAccountStore { db, credentials }
    }

    async fn update_row(tx: &mut Tx, user: &User) -> Result<(), StoreError> {
        match tx {
            Tx::MySql(tx) => mysql::update_row(tx, user).await,
            Tx::PostgreSql(tx) => postgres::update_row(tx, user).await,
        }
    }
}

/// A row of either engine's checked `select`, as a [`User`]: the record types differ per statement, their fields
/// do not.
macro_rules! user_from {
    ($row:expr) => {{
        let row = $row;
        User {
            id: row.id,
            username: row.username,
            email: row.email,
            password: row.password.map(PasswordHash::new),
            display_name: row.display_name,
            avatar_url: row.avatar_url,
            role: row.role,
            is_active: row.is_active,
            github_id: row.github_id,
            keycloak_id: row.keycloak_id,
            created_at: row.created_at.0,
            updated_at: row.updated_at.0,
            must_change_password: row.must_change_password,
            mfa_enabled: row.mfa_enabled,
            totp_secret: row.totp_secret.map(Sealed::new),
            mfa_backup_codes: row.mfa_backup_codes.map(Sealed::new),
            totp_last_step: row.totp_last_step,
        }
    }};
}

/// The MySQL statements. The `bit(1)` flags are read as `bool` and the `datetime(6)` instants as UTC, which is how
/// Hibernate writes them; the macro would otherwise offer bytes and a zone-less date.
#[cfg(feature = "mysql-queries")]
mod mysql {
    use sqlx::{MySqlConnection, MySqlPool};
    use time::OffsetDateTime;
    use vectispire_cp_db::types::UtcInstant;

    use crate::persistence::model::{NewUser, PasswordHash, Sealed, StoreError, User};

    pub(super) async fn find_by_id(pool: &MySqlPool, id: i64) -> Result<Option<User>, StoreError> {
        let row = sqlx::query!(
            r#"/* mysql */ select id, username, email, password, display_name, avatar_url, role,
               is_active as "is_active: bool", github_id, keycloak_id, created_at as "created_at: UtcInstant",
               updated_at as "updated_at: UtcInstant", must_change_password as "must_change_password: bool",
               mfa_enabled as "mfa_enabled: bool", totp_secret, mfa_backup_codes, totp_last_step
               from t_user where id = ?"#,
            id
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| user_from!(row)))
    }

    pub(super) async fn find_by_username(pool: &MySqlPool, username: &str) -> Result<Option<User>, StoreError> {
        let row = sqlx::query!(
            r#"/* mysql */ select id, username, email, password, display_name, avatar_url, role,
               is_active as "is_active: bool", github_id, keycloak_id, created_at as "created_at: UtcInstant",
               updated_at as "updated_at: UtcInstant", must_change_password as "must_change_password: bool",
               mfa_enabled as "mfa_enabled: bool", totp_secret, mfa_backup_codes, totp_last_step
               from t_user where username = ?"#,
            username
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| user_from!(row)))
    }

    pub(super) async fn all_by_username(pool: &MySqlPool) -> Result<Vec<User>, StoreError> {
        let rows = sqlx::query!(
            r#"/* mysql */ select id, username, email, password, display_name, avatar_url, role,
               is_active as "is_active: bool", github_id, keycloak_id, created_at as "created_at: UtcInstant",
               updated_at as "updated_at: UtcInstant", must_change_password as "must_change_password: bool",
               mfa_enabled as "mfa_enabled: bool", totp_secret, mfa_backup_codes, totp_last_step
               from t_user order by username asc"#
        )
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|row| user_from!(row)).collect())
    }

    pub(super) async fn insert(pool: &MySqlPool, user: &NewUser) -> Result<i64, StoreError> {
        let done = sqlx::query!(
            "/* mysql */ insert into t_user (username, email, password, display_name, role, is_active, created_at, \
             updated_at, must_change_password, mfa_enabled) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            user.username,
            user.email,
            user.password.as_ref().map(PasswordHash::encoded),
            user.display_name,
            user.role,
            user.is_active,
            UtcInstant(user.created_at),
            UtcInstant(user.created_at),
            user.must_change_password,
            false
        )
        .execute(pool)
        .await?;
        i64::try_from(done.last_insert_id()).map_err(|error| StoreError(Box::new(error)))
    }

    pub(super) async fn update_row(connection: &mut MySqlConnection, user: &User) -> Result<(), StoreError> {
        sqlx::query!(
            "/* mysql */ update t_user set username = ?, email = ?, password = ?, display_name = ?, avatar_url = ?, \
             role = ?, is_active = ?, github_id = ?, keycloak_id = ?, created_at = ?, updated_at = ?, \
             must_change_password = ?, mfa_enabled = ?, totp_secret = ?, mfa_backup_codes = ?, totp_last_step = ? \
             where id = ?",
            user.username,
            user.email,
            user.password.as_ref().map(PasswordHash::encoded),
            user.display_name,
            user.avatar_url,
            user.role,
            user.is_active,
            user.github_id,
            user.keycloak_id,
            UtcInstant(user.created_at),
            UtcInstant(user.updated_at),
            user.must_change_password,
            user.mfa_enabled,
            user.totp_secret.as_ref().map(Sealed::expose),
            user.mfa_backup_codes.as_ref().map(Sealed::expose),
            user.totp_last_step,
            user.id
        )
        .execute(connection)
        .await?;
        Ok(())
    }

    pub(super) async fn change_password(
        connection: &mut MySqlConnection,
        user_id: i64,
        hash: &str,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "/* mysql */ update t_user set password = ?, must_change_password = false, updated_at = ? where id = ?",
            hash,
            UtcInstant(at),
            user_id
        )
        .execute(connection)
        .await?;
        Ok(())
    }

    pub(super) async fn rehash(pool: &MySqlPool, user_id: i64, hash: &str) -> Result<(), StoreError> {
        sqlx::query!("/* mysql */ update t_user set password = ? where id = ?", hash, user_id).execute(pool).await?;
        Ok(())
    }

    pub(super) async fn delete(connection: &mut MySqlConnection, user_id: i64) -> Result<(), StoreError> {
        sqlx::query!("/* mysql */ delete from t_user where id = ?", user_id).execute(connection).await?;
        Ok(())
    }

    /// The one statement not checked (the module's comment says why): one placeholder per role, nothing else
    /// varies.
    pub(super) async fn count_other_active_admins(
        pool: &MySqlPool,
        roles: &[&str],
        excluding: i64,
    ) -> Result<i64, StoreError> {
        use sqlx::Row as _;
        let marks = vec!["?"; roles.len()].join(", ");
        let text = format!(
            "/* mysql */ select count(*) as n from t_user where is_active = true and role in ({marks}) and id <> ?"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(text));
        for role in roles {
            query = query.bind(*role);
        }
        Ok(query.bind(excluding).fetch_one(pool).await?.try_get("n")?)
    }
}

/// The PostgreSQL statements.
#[cfg(feature = "postgres-queries")]
mod postgres {
    use sqlx::{PgConnection, PgPool};
    use time::OffsetDateTime;
    use vectispire_cp_db::types::UtcInstant;

    use crate::persistence::model::{NewUser, PasswordHash, Sealed, StoreError, User};

    pub(super) async fn find_by_id(pool: &PgPool, id: i64) -> Result<Option<User>, StoreError> {
        let row = sqlx::query!(
            r#"/* postgres */ select id, username, email, password, display_name, avatar_url, role, is_active,
               github_id, keycloak_id, created_at as "created_at: UtcInstant", updated_at as "updated_at: UtcInstant",
               must_change_password, mfa_enabled, totp_secret, mfa_backup_codes, totp_last_step
               from t_user where id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| user_from!(row)))
    }

    pub(super) async fn find_by_username(pool: &PgPool, username: &str) -> Result<Option<User>, StoreError> {
        let row = sqlx::query!(
            r#"/* postgres */ select id, username, email, password, display_name, avatar_url, role, is_active,
               github_id, keycloak_id, created_at as "created_at: UtcInstant", updated_at as "updated_at: UtcInstant",
               must_change_password, mfa_enabled, totp_secret, mfa_backup_codes, totp_last_step
               from t_user where username = $1"#,
            username
        )
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| user_from!(row)))
    }

    pub(super) async fn all_by_username(pool: &PgPool) -> Result<Vec<User>, StoreError> {
        let rows = sqlx::query!(
            r#"/* postgres */ select id, username, email, password, display_name, avatar_url, role, is_active,
               github_id, keycloak_id, created_at as "created_at: UtcInstant", updated_at as "updated_at: UtcInstant",
               must_change_password, mfa_enabled, totp_secret, mfa_backup_codes, totp_last_step
               from t_user order by username asc"#
        )
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|row| user_from!(row)).collect())
    }

    pub(super) async fn insert(pool: &PgPool, user: &NewUser) -> Result<i64, StoreError> {
        let id = sqlx::query_scalar!(
            "/* postgres */ insert into t_user (username, email, password, display_name, role, is_active, created_at, \
             updated_at, must_change_password, mfa_enabled) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             returning id",
            user.username,
            user.email,
            user.password.as_ref().map(PasswordHash::encoded),
            user.display_name,
            user.role,
            user.is_active,
            user.created_at,
            user.created_at,
            user.must_change_password,
            false
        )
        .fetch_one(pool)
        .await?;
        Ok(id)
    }

    pub(super) async fn update_row(connection: &mut PgConnection, user: &User) -> Result<(), StoreError> {
        sqlx::query!(
            "/* postgres */ update t_user set username = $1, email = $2, password = $3, display_name = $4, \
             avatar_url = $5, role = $6, is_active = $7, github_id = $8, keycloak_id = $9, created_at = $10, \
             updated_at = $11, must_change_password = $12, mfa_enabled = $13, totp_secret = $14, \
             mfa_backup_codes = $15, totp_last_step = $16 where id = $17",
            user.username,
            user.email,
            user.password.as_ref().map(PasswordHash::encoded),
            user.display_name,
            user.avatar_url,
            user.role,
            user.is_active,
            user.github_id,
            user.keycloak_id,
            user.created_at,
            user.updated_at,
            user.must_change_password,
            user.mfa_enabled,
            user.totp_secret.as_ref().map(Sealed::expose),
            user.mfa_backup_codes.as_ref().map(Sealed::expose),
            user.totp_last_step,
            user.id
        )
        .execute(connection)
        .await?;
        Ok(())
    }

    pub(super) async fn change_password(
        connection: &mut PgConnection,
        user_id: i64,
        hash: &str,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "/* postgres */ update t_user set password = $1, must_change_password = false, updated_at = $2 \
             where id = $3",
            hash,
            at,
            user_id
        )
        .execute(connection)
        .await?;
        Ok(())
    }

    pub(super) async fn rehash(pool: &PgPool, user_id: i64, hash: &str) -> Result<(), StoreError> {
        sqlx::query!("/* postgres */ update t_user set password = $1 where id = $2", hash, user_id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub(super) async fn delete(connection: &mut PgConnection, user_id: i64) -> Result<(), StoreError> {
        sqlx::query!("/* postgres */ delete from t_user where id = $1", user_id).execute(connection).await?;
        Ok(())
    }

    /// `= any($1)` is `in (…)` over one array parameter, which a checked statement can hold.
    pub(super) async fn count_other_active_admins(
        pool: &PgPool,
        roles: &[&str],
        excluding: i64,
    ) -> Result<i64, StoreError> {
        let roles: Vec<String> = roles.iter().map(|role| (*role).to_owned()).collect();
        let count = sqlx::query_scalar!(
            r#"/* postgres */ select count(*) as "n!" from t_user where is_active = true and role = any($1)
               and id <> $2"#,
            &roles,
            excluding
        )
        .fetch_one(pool)
        .await?;
        Ok(count)
    }
}

/// An engine whose statements this build was compiled without — only the passes of
/// `crates/cp-db/scripts/sqlx-prepare.sh`, which compile one engine's checked statements at a time against a
/// database of that engine, build such a crate. It
/// answers an error rather than not compiling, so the pass compiles the other engine's arm of every `match`.
#[cfg(any(not(feature = "mysql-queries"), not(feature = "postgres-queries")))]
mod unprepared {
    use time::OffsetDateTime;

    use crate::persistence::model::{NewUser, StoreError, User};

    fn absent<T>() -> Result<T, StoreError> {
        Err(StoreError("this build has no statements for the engine".into()))
    }

    pub(super) async fn find_by_id<P>(_: &P, _: i64) -> Result<Option<User>, StoreError> {
        absent()
    }
    pub(super) async fn find_by_username<P>(_: &P, _: &str) -> Result<Option<User>, StoreError> {
        absent()
    }
    pub(super) async fn all_by_username<P>(_: &P) -> Result<Vec<User>, StoreError> {
        absent()
    }
    pub(super) async fn insert<P>(_: &P, _: &NewUser) -> Result<i64, StoreError> {
        absent()
    }
    pub(super) async fn update_row<C>(_: &mut C, _: &User) -> Result<(), StoreError> {
        absent()
    }
    pub(super) async fn change_password<C>(_: &mut C, _: i64, _: &str, _: OffsetDateTime) -> Result<(), StoreError> {
        absent()
    }
    pub(super) async fn rehash<P>(_: &P, _: i64, _: &str) -> Result<(), StoreError> {
        absent()
    }
    pub(super) async fn delete<C>(_: &mut C, _: i64) -> Result<(), StoreError> {
        absent()
    }
    pub(super) async fn count_other_active_admins<P>(_: &P, _: &[&str], _: i64) -> Result<i64, StoreError> {
        absent()
    }
}

#[cfg(not(feature = "mysql-queries"))]
use unprepared as mysql;
#[cfg(not(feature = "postgres-queries"))]
use unprepared as postgres;

impl<K: SessionsAndKeys + Sync> AccountStore for SqlAccountStore<K> {
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, StoreError> {
        match &self.db {
            Db::MySql(pool) => mysql::find_by_id(pool, id).await,
            Db::PostgreSql(pool) => postgres::find_by_id(pool, id).await,
        }
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        match &self.db {
            Db::MySql(pool) => mysql::find_by_username(pool, username).await,
            Db::PostgreSql(pool) => postgres::find_by_username(pool, username).await,
        }
    }

    async fn all_by_username(&self) -> Result<Vec<User>, StoreError> {
        match &self.db {
            Db::MySql(pool) => mysql::all_by_username(pool).await,
            Db::PostgreSql(pool) => postgres::all_by_username(pool).await,
        }
    }

    async fn insert(&self, user: NewUser) -> Result<User, StoreError> {
        let id = match &self.db {
            Db::MySql(pool) => mysql::insert(pool, &user).await?,
            Db::PostgreSql(pool) => postgres::insert(pool, &user).await?,
        };
        self.find_by_id(id)
            .await?
            .ok_or_else(|| StoreError(format!("the account {id} just inserted is not there").into()))
    }

    async fn save(&self, user: &User, revoke_sessions: bool) -> Result<(), StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        Self::update_row(&mut tx, user).await?;
        if revoke_sessions {
            self.credentials.delete_sessions(&mut tx, user.id).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn save_revoking_everything(&self, user: &User) -> Result<Vec<RevokedKey>, StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        Self::update_row(&mut tx, user).await?;
        self.credentials.delete_sessions(&mut tx, user.id).await?;
        let revoked = self.credentials.revoke_owned_keys(&mut tx, user.id).await?;
        tx.commit().await?;
        Ok(revoked)
    }

    async fn change_own_password(
        &self,
        user_id: i64,
        hash: PasswordHash,
        at: OffsetDateTime,
        keep_session: Option<SessionHash>,
    ) -> Result<Vec<RevokedKey>, StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        match &mut tx {
            Tx::MySql(inner) => mysql::change_password(inner, user_id, hash.encoded(), at).await?,
            Tx::PostgreSql(inner) => postgres::change_password(inner, user_id, hash.encoded(), at).await?,
        }
        if let Some(keep) = &keep_session {
            self.credentials.delete_sessions_except(&mut tx, user_id, keep).await?;
        }
        let revoked = self.credentials.revoke_owned_keys(&mut tx, user_id).await?;
        tx.commit().await?;
        Ok(revoked)
    }

    async fn rehash(&self, user_id: i64, hash: PasswordHash) -> Result<(), StoreError> {
        match &self.db {
            Db::MySql(pool) => mysql::rehash(pool, user_id, hash.encoded()).await,
            Db::PostgreSql(pool) => postgres::rehash(pool, user_id, hash.encoded()).await,
        }
    }

    async fn delete(&self, user_id: i64) -> Result<(), StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        self.credentials.delete_sessions(&mut tx, user_id).await?;
        match &mut tx {
            Tx::MySql(inner) => mysql::delete(inner, user_id).await?,
            Tx::PostgreSql(inner) => postgres::delete(inner, user_id).await?,
        }
        tx.commit().await?;
        Ok(())
    }

    async fn count_other_active_admins(&self, roles: &[&str], excluding: i64) -> Result<u64, StoreError> {
        if roles.is_empty() {
            return Ok(0);
        }
        let count = match &self.db {
            Db::MySql(pool) => mysql::count_other_active_admins(pool, roles, excluding).await?,
            Db::PostgreSql(pool) => postgres::count_other_active_admins(pool, roles, excluding).await?,
        };
        u64::try_from(count).map_err(|error| StoreError(Box::new(error)))
    }

    async fn active_sessions_by_user(&self, at: OffsetDateTime) -> Result<HashMap<i64, u64>, StoreError> {
        self.credentials.count_active_by_user(&self.db, at).await
    }
}
