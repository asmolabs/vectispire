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
    /// Written by the SCIM directory, which then owns the e-mail address (V102): set by every provisioning write.
    pub scim_managed: bool,
    /// The privileged role the SCIM directory lowered this unbound account out of (V93): until an administrator sets
    /// its role in Vectispire, the directory does not bind it to an identity-provider subject.
    pub scim_lowered_from: Option<String>,
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

/// What one administrator can do to another account that makes the account partly theirs — `AccountGesture`: create
/// it, choose its password, choose its role. Activating, deactivating or granting targets is none of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gesture {
    Created,
    PasswordReset,
    RoleChanged,
}

impl Gesture {
    /// The name stored and sent: lowercase, as every wire name here.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Gesture::Created => "created",
            Gesture::PasswordReset => "password_reset",
            Gesture::RoleChanged => "role_changed",
        }
    }

    pub fn from_wire_name(value: &str) -> Option<Gesture> {
        [Gesture::Created, Gesture::PasswordReset, Gesture::RoleChanged].into_iter().find(|g| g.wire_name() == value)
    }
}

/// The gestures a write makes, for `t_account_administration` — `ApproverIndependence.recorded`, written **in the
/// transaction that applies them**, so the account never changes without its record. A row per administrator and
/// per gesture; none for an administrator acting on their own account, which is no second identity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Recorded {
    /// The role the account held before the gesture (`held_role`); `None` for a creation.
    pub held_role: Option<String>,
    /// Every account behind the gesture: the one applying it, and the requester of an approved request.
    pub administrators: Vec<i64>,
    pub made: Vec<Gesture>,
    pub at: Option<OffsetDateTime>,
}

impl Recorded {
    /// A write that is none of the three gestures.
    pub fn nothing() -> Recorded {
        Recorded::default()
    }

    /// The rows to insert for `account_id`: `(administrator, gesture)`, one's own account left out.
    pub fn rows(&self, account_id: i64) -> Vec<(i64, Gesture)> {
        let mut rows = Vec::new();
        for administrator in self.administrators.iter().copied().filter(|administrator| *administrator != account_id) {
            for gesture in &self.made {
                rows.push((administrator, *gesture));
            }
        }
        rows
    }
}

/// `t_account_request`: an account change filed under four-eyes — `AccountRequestEntity`.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountRequest {
    pub id: i64,
    /// `create` or `change`.
    pub kind: String,
    /// `pending`, `approved` or `rejected`.
    pub status: String,
    pub account_id: Option<i64>,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub held_role: Option<String>,
    pub requested_role: Option<String>,
    /// The hash of the password the requester typed — never the password. Cleared once decided.
    pub password_hash: Option<PasswordHash>,
    pub requested_by_id: i64,
    pub requested_by: String,
    pub requested_at: OffsetDateTime,
    pub decided_by: Option<String>,
    pub decided_at: Option<OffsetDateTime>,
}

/// A request before it has an id; always filed `pending`.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAccountRequest {
    pub kind: &'static str,
    pub account_id: Option<i64>,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub held_role: Option<String>,
    pub requested_role: Option<String>,
    pub password_hash: Option<PasswordHash>,
    pub requested_by_id: i64,
    pub requested_by: String,
    pub requested_at: OffsetDateTime,
}

/// What filing came to, decided under the account's row lock.
#[derive(Debug, Clone, PartialEq)]
pub enum Filing {
    Filed(Box<AccountRequest>),
    /// A request about this account is already pending.
    AccountPending,
    /// A creation of this username is already pending.
    NamePending,
}

/// What an approval writes, besides the request's own row.
#[derive(Debug, Clone, PartialEq)]
pub enum Apply {
    /// A new account, and who made it.
    Create(NewUser, Recorded),
    /// The account as it is to be saved, written only if its stored role is still `held_role` once locked.
    Change { user: Box<User>, held_role: String, revoke_sessions: bool, revoke_keys: bool, recorded: Recorded },
}

/// A decision on a request — the request's row locked first, so that two administrators deciding at once are ordered.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub request_id: i64,
    /// `approved` or `rejected`.
    pub status: &'static str,
    pub decided_by: String,
    pub decided_at: OffsetDateTime,
    /// What an approval applies; `None` for a rejection.
    pub apply: Option<Apply>,
}

/// What a decision came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Decided {
    /// Written: the account an approval created or changed, the keys a reset revoked, and the request's requester.
    Done {
        account: Option<Box<User>>,
        revoked: Vec<RevokedKey>,
        requested_by: String,
    },
    NotFound,
    /// Decided by somebody else first: its status and who decided it.
    AlreadyDecided {
        status: String,
        decided_by: Option<String>,
    },
    /// The account's role moved since the request was filed; its username.
    RoleMoved(String),
    /// The account the change is about is gone.
    AccountGone,
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
    /// `existsByEmailIgnoreCaseAndIdNot`: another account holds this address, compared without case.
    fn email_taken(
        &self,
        email: &str,
        excluding: i64,
    ) -> impl std::future::Future<Output = Result<bool, StoreError>> + Send;
    /// Inserts the account and the gestures that made it, in one transaction.
    fn insert(
        &self,
        user: NewUser,
        recorded: &Recorded,
    ) -> impl std::future::Future<Output = Result<User, StoreError>> + Send;
    /// Saves the row and its gestures, and closes the account's sessions in the same transaction when asked.
    fn save(
        &self,
        user: &User,
        revoke_sessions: bool,
        recorded: &Recorded,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    /// Saves the row and its gestures, closes every session and revokes every key the account owns, in one
    /// transaction.
    fn save_revoking_everything(
        &self,
        user: &User,
        recorded: &Recorded,
    ) -> impl std::future::Future<Output = Result<Vec<RevokedKey>, StoreError>> + Send;
    /// `countAdministratorsExcluding`: accounts holding one of `roles` other than `excluding`, **deactivated ones
    /// included**.
    fn count_other_admins(
        &self,
        roles: &[&str],
        excluding: i64,
    ) -> impl std::future::Future<Output = Result<u64, StoreError>> + Send;
    /// The requests in one status, oldest first, the id after it.
    fn requests_in(
        &self,
        status: &str,
    ) -> impl std::future::Future<Output = Result<Vec<AccountRequest>, StoreError>> + Send;
    fn find_request(
        &self,
        id: i64,
    ) -> impl std::future::Future<Output = Result<Option<AccountRequest>, StoreError>> + Send;
    /// `existsByStatusAndAccountId(PENDING, account)`.
    fn request_pending_for(
        &self,
        account_id: i64,
    ) -> impl std::future::Future<Output = Result<bool, StoreError>> + Send;
    /// Files a request: a change under the account's row lock, refused when one is pending for it; a creation refused
    /// when one of the same name is pending.
    fn file_request(
        &self,
        request: NewAccountRequest,
    ) -> impl std::future::Future<Output = Result<Filing, StoreError>> + Send;
    /// Decides a request under its row lock, applying an approval's change in the same transaction, and clearing the
    /// password hash it carried.
    fn decide_request(
        &self,
        decision: Decision,
    ) -> impl std::future::Future<Output = Result<Decided, StoreError>> + Send;
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
