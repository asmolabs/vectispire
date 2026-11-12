//! The account rows as the module holds them — `UserEntity` — and the store the account rules write through, the
//! Rust of `UserRepository` plus `AccountAdminService`'s transactions. Here, below the services, because the layers
//! read downwards only (`cp-arch-tests`): the services name these types, these types name nothing above them.

use std::collections::HashMap;
use std::fmt;

use time::OffsetDateTime;

/// A stored Argon2id hash. Not a secret in the sense a password is, but nothing prints it: a log line holding one
/// hands an offline guesser the salt and the digest.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn new(encoded: impl Into<String>) -> PasswordHash {
        PasswordHash(encoded.into())
    }

    pub fn encoded(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHash(***)")
    }
}

/// A column that holds a secret of the second factor (`totp_secret`, `mfa_backup_codes`): carried through a row's
/// round trip, never shown. The MFA task (1.3) reads them.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed(String);

impl Sealed {
    pub fn new(value: impl Into<String>) -> Sealed {
        Sealed(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Sealed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sealed(***)")
    }
}

/// An account, as `t_user` holds it — `UserEntity`. Only the services and the persistence see it; the layers
/// above hold a `UserView`, which has no secret.
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    /// Absent for an account federated through an identity provider that never had one.
    pub password: Option<PasswordHash>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    /// As stored: a name [`Role::of`] may not know, which every rule reads as no role.
    pub role: String,
    pub is_active: bool,
    pub github_id: Option<String>,
    pub keycloak_id: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub must_change_password: bool,
    pub mfa_enabled: bool,
    pub totp_secret: Option<Sealed>,
    pub mfa_backup_codes: Option<Sealed>,
    pub totp_last_step: Option<i64>,
}

/// An account before it has an id.
#[derive(Debug, Clone, PartialEq)]
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub password: Option<PasswordHash>,
    pub display_name: Option<String>,
    pub role: String,
    pub is_active: bool,
    pub must_change_password: bool,
    pub created_at: OffsetDateTime,
}

/// An integration key revoked with its account's password — `TargetGrants.RevokedKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedKey {
    pub id: uuid::Uuid,
    pub name: String,
}

/// The SHA-256 of a session token, as `t_session` stores it: what identifies the session to spare.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionHash(pub String);

impl fmt::Debug for SessionHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionHash(***)")
    }
}

/// A database failure, kept opaque above the persistence: a service names no driver.
#[derive(Debug, thiserror::Error)]
#[error("the account store failed: {0}")]
pub struct StoreError(pub Box<dyn std::error::Error + Send + Sync>);

/// Every write and read the account rules need, one method per transaction of `AccountAdminService` and per
/// query of `UserRepository` they use.
pub trait AccountStore {
    fn find_by_id(&self, id: i64) -> impl std::future::Future<Output = Result<Option<User>, StoreError>> + Send;
    /// By name, as the database's collation compares it — on MySQL, case- and accent-insensitive.
    fn find_by_username(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<User>, StoreError>> + Send;
    fn all_by_username(&self) -> impl std::future::Future<Output = Result<Vec<User>, StoreError>> + Send;
    fn insert(&self, user: NewUser) -> impl std::future::Future<Output = Result<User, StoreError>> + Send;
    /// Saves the row, and closes the account's sessions in the same transaction when asked.
    fn save(
        &self,
        user: &User,
        revoke_sessions: bool,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    /// Saves the row, closes every session and revokes every key the account owns, in one transaction.
    fn save_revoking_everything(
        &self,
        user: &User,
    ) -> impl std::future::Future<Output = Result<Vec<RevokedKey>, StoreError>> + Send;
    /// One's own password: the hash, `must_change_password` cleared, the other sessions closed — only when a
    /// session is named, as Java does — and the keys revoked, in one transaction.
    fn change_own_password(
        &self,
        user_id: i64,
        hash: PasswordHash,
        at: OffsetDateTime,
        keep_session: Option<SessionHash>,
    ) -> impl std::future::Future<Output = Result<Vec<RevokedKey>, StoreError>> + Send;
    /// Rewrites a hash under today's parameters, and nothing else.
    fn rehash(
        &self,
        user_id: i64,
        hash: PasswordHash,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    /// The sessions, then the account.
    fn delete(&self, user_id: i64) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    /// Active accounts holding one of `roles`, other than `excluding`, asked of the database: two administrators
    /// demoting each other in parallel is the case a loaded list gets wrong. The roles are the caller's, as Java's
    /// `countActiveAdministratorsExcluding(adminRoles, excluding)` takes them.
    fn count_other_active_admins(
        &self,
        roles: &[&str],
        excluding: i64,
    ) -> impl std::future::Future<Output = Result<u64, StoreError>> + Send;
    /// Live sessions per account, as of `at`.
    fn active_sessions_by_user(
        &self,
        at: OffsetDateTime,
    ) -> impl std::future::Future<Output = Result<HashMap<i64, u64>, StoreError>> + Send;
}
