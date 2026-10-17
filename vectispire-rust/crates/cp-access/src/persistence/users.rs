//! `t_user` on either engine — `UserRepository` and the transactions of `AccountAdminService`.
//!
//! **Each statement is written once per engine**, in the engine's placeholders, and matched on [`Tx`] / [`Db`]:
//! `sqlx::Any` would erase the engine (cp-db's README). These are plain `sqlx::query` with fixed text, not yet the
//! checked `query!` of `cp-db`'s pattern: that needs this crate's own offline cache and its generation script,
//! which belong with the second module that writes queries. `tests/engines.rs` runs every one of them against both
//! engines, on the schema the migrations build, so a column that does not exist fails a test today rather than the
//! compiler tomorrow.
//!
//! **The rehash writes the password column only** — Java saves the whole entity it loaded at the sign-in, so a
//! deactivation committed between that load and the rehash was written back as active. Rare (a rehash is due only
//! after a cost raise), and the one deliberate difference here.

use std::collections::HashMap;

use sqlx::Row;
use sqlx::mysql::MySqlRow;
use sqlx::postgres::PgRow;
use time::OffsetDateTime;
use vectispire_cp_db::types::UtcInstant;
use vectispire_cp_db::{Db, Mode, Tx};

use crate::persistence::model::{
    AccountStore, NewUser, PasswordHash, RevokedKey, Sealed, SessionHash, StoreError, User,
};

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
        let password = user.password.as_ref().map(PasswordHash::encoded);
        let totp = user.totp_secret.as_ref().map(Sealed::expose);
        let codes = user.mfa_backup_codes.as_ref().map(Sealed::expose);
        match tx {
            Tx::MySql(tx) => {
                sqlx::query(
                    "/* mysql */ update t_user set username = ?, email = ?, password = ?, display_name = ?, \
                     avatar_url = ?, role = ?, is_active = ?, github_id = ?, keycloak_id = ?, created_at = ?, \
                     updated_at = ?, must_change_password = ?, mfa_enabled = ?, totp_secret = ?, mfa_backup_codes = ?, \
                     totp_last_step = ? where id = ?",
                )
                .bind(&user.username)
                .bind(&user.email)
                .bind(password)
                .bind(&user.display_name)
                .bind(&user.avatar_url)
                .bind(&user.role)
                .bind(user.is_active)
                .bind(&user.github_id)
                .bind(&user.keycloak_id)
                .bind(UtcInstant(user.created_at))
                .bind(UtcInstant(user.updated_at))
                .bind(user.must_change_password)
                .bind(user.mfa_enabled)
                .bind(totp)
                .bind(codes)
                .bind(user.totp_last_step)
                .bind(user.id)
                .execute(&mut **tx)
                .await?;
            }
            Tx::PostgreSql(tx) => {
                sqlx::query(
                    "/* postgres */ update t_user set username = $1, email = $2, password = $3, display_name = $4, \
                     avatar_url = $5, role = $6, is_active = $7, github_id = $8, keycloak_id = $9, created_at = $10, \
                     updated_at = $11, must_change_password = $12, mfa_enabled = $13, totp_secret = $14, \
                     mfa_backup_codes = $15, totp_last_step = $16 where id = $17",
                )
                .bind(&user.username)
                .bind(&user.email)
                .bind(password)
                .bind(&user.display_name)
                .bind(&user.avatar_url)
                .bind(&user.role)
                .bind(user.is_active)
                .bind(&user.github_id)
                .bind(&user.keycloak_id)
                .bind(UtcInstant(user.created_at))
                .bind(UtcInstant(user.updated_at))
                .bind(user.must_change_password)
                .bind(user.mfa_enabled)
                .bind(totp)
                .bind(codes)
                .bind(user.totp_last_step)
                .bind(user.id)
                .execute(&mut **tx)
                .await?;
            }
        }
        Ok(())
    }
}

const COLUMNS: &str = "id, username, email, password, display_name, avatar_url, role, is_active, github_id, \
                       keycloak_id, created_at, updated_at, must_change_password, mfa_enabled, totp_secret, \
                       mfa_backup_codes, totp_last_step";

macro_rules! read_user {
    ($row:expr) => {{
        let row = $row;
        User {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            email: row.try_get("email")?,
            password: row.try_get::<Option<String>, _>("password")?.map(PasswordHash::new),
            display_name: row.try_get("display_name")?,
            avatar_url: row.try_get("avatar_url")?,
            role: row.try_get("role")?,
            is_active: row.try_get("is_active")?,
            github_id: row.try_get("github_id")?,
            keycloak_id: row.try_get("keycloak_id")?,
            created_at: row.try_get::<UtcInstant, _>("created_at")?.0,
            updated_at: row.try_get::<UtcInstant, _>("updated_at")?.0,
            must_change_password: row.try_get("must_change_password")?,
            mfa_enabled: row.try_get("mfa_enabled")?,
            totp_secret: row.try_get::<Option<String>, _>("totp_secret")?.map(Sealed::new),
            mfa_backup_codes: row.try_get::<Option<String>, _>("mfa_backup_codes")?.map(Sealed::new),
            totp_last_step: row.try_get("totp_last_step")?,
        }
    }};
}

fn mysql_user(row: &MySqlRow) -> Result<User, sqlx::Error> {
    Ok(read_user!(row))
}

fn postgres_user(row: &PgRow) -> Result<User, sqlx::Error> {
    Ok(read_user!(row))
}

/// The statement text with the column list in place — fixed text, assembled once.
fn statement(text: &'static str) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(text.replace("{columns}", COLUMNS))
}

impl<K: SessionsAndKeys + Sync> AccountStore for SqlAccountStore<K> {
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, StoreError> {
        Ok(match &self.db {
            Db::MySql(pool) => sqlx::query(statement("/* mysql */ select {columns} from t_user where id = ?"))
                .bind(id)
                .fetch_optional(pool)
                .await?
                .map(|row| mysql_user(&row))
                .transpose()?,
            Db::PostgreSql(pool) => sqlx::query(statement("/* postgres */ select {columns} from t_user where id = $1"))
                .bind(id)
                .fetch_optional(pool)
                .await?
                .map(|row| postgres_user(&row))
                .transpose()?,
        })
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, StoreError> {
        Ok(match &self.db {
            Db::MySql(pool) => sqlx::query(statement("/* mysql */ select {columns} from t_user where username = ?"))
                .bind(username)
                .fetch_optional(pool)
                .await?
                .map(|row| mysql_user(&row))
                .transpose()?,
            Db::PostgreSql(pool) => {
                sqlx::query(statement("/* postgres */ select {columns} from t_user where username = $1"))
                    .bind(username)
                    .fetch_optional(pool)
                    .await?
                    .map(|row| postgres_user(&row))
                    .transpose()?
            }
        })
    }

    async fn all_by_username(&self) -> Result<Vec<User>, StoreError> {
        Ok(match &self.db {
            Db::MySql(pool) => sqlx::query(statement("/* mysql */ select {columns} from t_user order by username asc"))
                .fetch_all(pool)
                .await?
                .iter()
                .map(mysql_user)
                .collect::<Result<_, _>>()?,
            Db::PostgreSql(pool) => {
                sqlx::query(statement("/* postgres */ select {columns} from t_user order by username asc"))
                    .fetch_all(pool)
                    .await?
                    .iter()
                    .map(postgres_user)
                    .collect::<Result<_, _>>()?
            }
        })
    }

    async fn insert(&self, user: NewUser) -> Result<User, StoreError> {
        let password = user.password.as_ref().map(PasswordHash::encoded);
        let at = UtcInstant(user.created_at);
        let id: i64 = match &self.db {
            Db::MySql(pool) => {
                let done = sqlx::query(
                    "/* mysql */ insert into t_user (username, email, password, display_name, role, is_active, \
                     created_at, updated_at, must_change_password, mfa_enabled) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&user.username)
                .bind(&user.email)
                .bind(password)
                .bind(&user.display_name)
                .bind(&user.role)
                .bind(user.is_active)
                .bind(at)
                .bind(at)
                .bind(user.must_change_password)
                .bind(false)
                .execute(pool)
                .await?;
                i64::try_from(done.last_insert_id()).map_err(|error| StoreError(Box::new(error)))?
            }
            Db::PostgreSql(pool) => sqlx::query(
                "/* postgres */ insert into t_user (username, email, password, display_name, role, is_active, \
                 created_at, updated_at, must_change_password, mfa_enabled) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 $10) returning id",
            )
            .bind(&user.username)
            .bind(&user.email)
            .bind(password)
            .bind(&user.display_name)
            .bind(&user.role)
            .bind(user.is_active)
            .bind(at)
            .bind(at)
            .bind(user.must_change_password)
            .bind(false)
            .fetch_one(pool)
            .await?
            .try_get("id")?,
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
            Tx::MySql(inner) => {
                sqlx::query(
                    "/* mysql */ update t_user set password = ?, must_change_password = false, updated_at = ? \
                     where id = ?",
                )
                .bind(hash.encoded())
                .bind(UtcInstant(at))
                .bind(user_id)
                .execute(&mut **inner)
                .await?;
            }
            Tx::PostgreSql(inner) => {
                sqlx::query(
                    "/* postgres */ update t_user set password = $1, must_change_password = false, updated_at = $2 \
                     where id = $3",
                )
                .bind(hash.encoded())
                .bind(UtcInstant(at))
                .bind(user_id)
                .execute(&mut **inner)
                .await?;
            }
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
            Db::MySql(pool) => {
                sqlx::query("/* mysql */ update t_user set password = ? where id = ?")
                    .bind(hash.encoded())
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Db::PostgreSql(pool) => {
                sqlx::query("/* postgres */ update t_user set password = $1 where id = $2")
                    .bind(hash.encoded())
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn delete(&self, user_id: i64) -> Result<(), StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        self.credentials.delete_sessions(&mut tx, user_id).await?;
        match &mut tx {
            Tx::MySql(inner) => {
                sqlx::query("/* mysql */ delete from t_user where id = ?").bind(user_id).execute(&mut **inner).await?;
            }
            Tx::PostgreSql(inner) => {
                sqlx::query("/* postgres */ delete from t_user where id = $1")
                    .bind(user_id)
                    .execute(&mut **inner)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    async fn count_other_active_admins(&self, roles: &[&str], excluding: i64) -> Result<u64, StoreError> {
        if roles.is_empty() {
            return Ok(0);
        }
        // One placeholder per role: the list is the caller's, two names today (`Role.administrative()`).
        let count: i64 = match &self.db {
            Db::MySql(pool) => {
                let marks = vec!["?"; roles.len()].join(", ");
                let text = format!(
                    "/* mysql */ select count(*) as n from t_user where is_active = true and role in ({marks}) and id <> ?"
                );
                let mut query = sqlx::query(sqlx::AssertSqlSafe(text));
                for role in roles {
                    query = query.bind(*role);
                }
                query.bind(excluding).fetch_one(pool).await?.try_get("n")?
            }
            Db::PostgreSql(pool) => {
                let marks: Vec<String> = (1..=roles.len()).map(|index| format!("${index}")).collect();
                let text = format!(
                    "/* postgres */ select count(*) as n from t_user where is_active = true and role in ({}) and id <> ${}",
                    marks.join(", "),
                    roles.len() + 1
                );
                let mut query = sqlx::query(sqlx::AssertSqlSafe(text));
                for role in roles {
                    query = query.bind(*role);
                }
                query.bind(excluding).fetch_one(pool).await?.try_get("n")?
            }
        };
        u64::try_from(count).map_err(|error| StoreError(Box::new(error)))
    }

    async fn active_sessions_by_user(&self, at: OffsetDateTime) -> Result<HashMap<i64, u64>, StoreError> {
        self.credentials.count_active_by_user(&self.db, at).await
    }
}
