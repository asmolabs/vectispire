//! Accounts and their passwords — `UserEntity`, `UserView`, `AccountAdministrationService`, the password half of
//! `AuthService.login` and `AuthenticationFlowService.changePassword`, ported (plan, Phase 1, task 1.1).
//!
//! **What lives here and what plugs in.** The rules — who may be demoted, which gesture closes the sessions,
//! which takes the integration keys — are decided here, word for word as Java decides them. What they write goes
//! through [`AccountStore`]: one method per transaction of Java's `AccountAdminService`, so that a password reset
//! and the revocation it implies commit together or not at all. The SQL implementation is
//! [`SqlAccountStore`](crate::SqlAccountStore); the sessions and keys it revokes in the same transaction are
//! the credentials task's ([`crate::SessionsAndKeys`]). The audit log ([`Audit`]) and the sign-in throttle
//! ([`PasswordAttempts`]) are other tasks' too, behind traits.
//!
//! **The audit entry is written after the transaction**, as Java writes it after `AccountAdminService` returns:
//! an audited action that rolled back is then not recorded as done.

use time::OffsetDateTime;

use crate::account_rules::{
    self, Change, Role, java_length, java_trim, java_upper, refuse_deletion, refuse_governor_administration,
    refuse_own_role_change, refuse_self_lockout, validate_password, validate_username,
};
pub use crate::derivations::DerivationsSaturated;
pub use crate::independence::{ApproverIndependence, IndependenceError};
use crate::passwords;
pub use crate::persistence::model::StoreError;
pub use crate::persistence::{
    AccountRequest, AccountStore, Apply, Decided, Decision, Filing, Gesture, NewAccountRequest, NewUser, PasswordHash,
    Recorded, RevokedKey, Sealed, SessionHash, User,
};

/// The width of `email` and `display_name`.
const BOUNDED_COLUMN: usize = 255;

/// An account as the layers above the services hold it — `UserView`: every property of the row but its secrets
/// (`password`, `totpSecret`, `mfaBackupCodes`, `totpLastStep`), under the entity's names.
#[derive(Debug, Clone, PartialEq)]
pub struct UserView {
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
    /// Written by the SCIM directory, which then owns the e-mail address: see V102.
    pub scim_managed: bool,
}

impl UserView {
    pub fn of(user: &User) -> UserView {
        UserView {
            id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            display_name: user.display_name.clone(),
            avatar_url: user.avatar_url.clone(),
            role: user.role.clone(),
            is_active: user.is_active,
            github_id: user.github_id.clone(),
            keycloak_id: user.keycloak_id.clone(),
            created_at: user.created_at,
            updated_at: user.updated_at,
            must_change_password: user.must_change_password,
            mfa_enabled: user.mfa_enabled,
            scim_managed: user.scim_managed,
        }
    }

    /// Whether the server holds this account on the change-password routes — what `cp-http`'s
    /// `password-change` layer asks of the principal (`PasswordChangeInterceptor`).
    pub fn owes_password_change(&self) -> bool {
        self.must_change_password
    }
}

/// An account and how many live sessions it holds.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountView {
    pub user: UserView,
    pub active_sessions: u64,
}

/// One page of the administration list, and how many accounts every page holds.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountList {
    pub accounts: Vec<AccountView>,
    pub total: u64,
}

/// What an administrator sends to create an account. Every field as received: absent is `None`.
#[derive(Debug, Clone, Default)]
pub struct NewAccount {
    pub username: Option<String>,
    pub password: Option<vectispire_domain::secret::Secret>,
    pub role: Option<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

/// Every field optional: absent means "leave it as it is".
#[derive(Debug, Clone, Default)]
pub struct AccountChange {
    pub role: Option<String>,
    pub is_active: Option<bool>,
    pub password: Option<vectispire_domain::secret::Secret>,
    /// The address to set — blank clears it. Refused with 409 [`MANAGED_BY_DIRECTORY`] on an account the SCIM
    /// directory writes, unless it is the address the account already holds.
    pub email: Option<String>,
}

/// `DirectoryManagedException.CAUSE`: the token the problem's `type` ends with, and its code.
pub const MANAGED_BY_DIRECTORY: &str = "managed-by-directory";

/// Who is asking, as the audit entry names them — `RequestActor`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestActor {
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// The audit operations this module writes — `AuditOperation`'s names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperation {
    UserCreated,
    UserUpdated,
    UserDeleted,
    ApiKeyCreated,
    ApiKeyDeleted,
    TeamUpdated,
    TeamAccessChanged,
    LoginBlocked,
    LoginFailure,
    LoginSuccess,
    PasswordChanged,
    AccountRequestFiled,
    AccountRequestApproved,
    AccountRequestRejected,
}

impl AuditOperation {
    pub const fn name(self) -> &'static str {
        match self {
            AuditOperation::UserCreated => "USER_CREATED",
            AuditOperation::UserUpdated => "USER_UPDATED",
            AuditOperation::UserDeleted => "USER_DELETED",
            AuditOperation::ApiKeyCreated => "API_KEY_CREATED",
            AuditOperation::ApiKeyDeleted => "API_KEY_DELETED",
            AuditOperation::TeamUpdated => "TEAM_UPDATED",
            AuditOperation::TeamAccessChanged => "TEAM_ACCESS_CHANGED",
            AuditOperation::LoginBlocked => "LOGIN_BLOCKED",
            AuditOperation::LoginFailure => "LOGIN_FAILURE",
            AuditOperation::LoginSuccess => "LOGIN_SUCCESS",
            AuditOperation::PasswordChanged => "PASSWORD_CHANGED",
            AuditOperation::AccountRequestFiled => "ACCOUNT_REQUEST_FILED",
            AuditOperation::AccountRequestApproved => "ACCOUNT_REQUEST_APPROVED",
            AuditOperation::AccountRequestRejected => "ACCOUNT_REQUEST_REJECTED",
        }
    }
}

/// An entry for the audit log — `AuditLogService.Record`. `signal` names the SIEM event an entry raises beyond
/// its operation's own (`SecurityEventType`), as `SIGN_IN_THROTTLED` for a refused password change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub operation: AuditOperation,
    pub resource: String,
    pub description: String,
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub signal: Option<&'static str>,
}

/// The audit log (Phase 1, task 1.6). Recording never fails the action it describes, as Java's `record`.
pub trait Audit {
    fn record(&self, record: AuditRecord) -> impl std::future::Future<Output = ()> + Send;
}

/// The clock — Java's injected `Clock`, read once per gesture.
pub trait Clock {
    fn now(&self) -> OffsetDateTime;
}

/// The credentials' clock, shared by the sign-in services, serves the accounts too: one instant source per binary.
impl Clock for std::sync::Arc<dyn crate::credentials::Clock> {
    fn now(&self) -> OffsetDateTime {
        crate::credentials::Clock::now(&**self)
    }
}

/// The account's password budget — `AuthService.reservePassword` and `clearPasswordFailures` (task 1.3 owns the
/// counters). A reservation not released is a failure counted. Both are keyed on the client too: the low ceiling is the
/// account's from this client, and a right password clears that one only.
pub trait PasswordAttempts {
    /// The attempt counted — what [`PasswordAttempts::release`] takes back.
    type Held: Send + Sync;
    /// The attempt counted when admitted, otherwise the wait, in whole seconds as Java's `retryAfter().toSeconds()`.
    fn reserve(
        &self,
        account_id: i64,
        ip_address: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Self::Held, StoreOr<u64>>> + Send;
    /// `AuthService.release`: takes an admitted attempt back — one whose password was never compared, because no
    /// derivation permit came free (`verifyReserved`). Counted, a person retrying through a busy minute would spend
    /// their own budget on checks that never happened.
    fn release(&self, held: &Self::Held) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
    fn clear(
        &self,
        account_id: i64,
        ip_address: Option<&str>,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
}

/// Either the store failed, or the answer is a refusal carrying `T`.
#[derive(Debug)]
pub enum StoreOr<T> {
    Store(StoreError),
    Refused(T),
}

/// Why an account gesture was refused — the 400, 403 and 404 the handler maps, with the text for the screen.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    /// `InvalidInputException`: 400, the message shown as it is.
    #[error("{0}")]
    InvalidInput(String),
    /// `NotFoundException("Account not found.")`: 404.
    #[error("Account not found.")]
    NotFound,
    /// `AccessDeniedException`: 403.
    #[error("{0}")]
    AccessDenied(String),
    /// `DirectoryManagedException`: 409, type `urn:vectispire:problem:managed-by-directory`, code
    /// [`MANAGED_BY_DIRECTORY`]. A 409 rather than a 400: the request is well formed, and the same change succeeds on an
    /// account the directory does not provision. Accepted, the address would last until the directory's next write
    /// and then vanish, with nothing to say it had (V102). Carries the account's name.
    #[error(
        "The e-mail address of {0} is written by the SCIM directory, which would replace it on its next \
         synchronisation: change it in the directory."
    )]
    ManagedByDirectory(String),
    /// `ConflictException`: a plain 409 — a request already waiting, or decided, or gone stale.
    #[error("{0}")]
    Conflict(String),
    /// `NotFoundException("Account request not found.")`: 404.
    #[error("Account request not found.")]
    RequestNotFound,
    /// `OwnAccountRequestException`: 409, type `urn:vectispire:problem:own-account-request`, code
    /// [`OWN_ACCOUNT_REQUEST`].
    #[error("You filed this request: four-eyes needs another administrator to approve it.")]
    OwnAccountRequest,
    /// An approval refused by [`ApproverIndependence`] (409 with its cause), or its reading failed (500).
    #[error(transparent)]
    Independence(#[from] IndependenceError),
    /// `DerivationsSaturated`: 503 with `Retry-After` ([`DerivationsSaturated::problem`]) — every password derivation
    /// permit was taken, and nothing was compared or written.
    #[error(transparent)]
    Saturated(#[from] DerivationsSaturated),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// What changing one's own password came to — `AuthenticationFlowService.PasswordChange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordChange {
    Changed {
        revoked_api_keys: usize,
    },
    CurrentPasswordWrong,
    /// The account has spent its password attempts for this window; the wait in seconds.
    Throttled {
        retry_after_seconds: u64,
    },
}

/// What became of a creation or a change — `Outcome`: applied, or filed for a second administrator. A type with two
/// cases rather than an account that may or may not have changed: a caller reading an account from a request still
/// waiting would show a change nobody has made.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Applied: the account as it now stands.
    Applied(AccountView),
    /// Filed under four-eyes; nothing has changed yet.
    Queued(AccountRequestView),
}

/// An account change waiting for a second administrator, as the screen shows it — `AccountRequestView`: never the
/// password hash it carries, only whether there is one.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountRequestView {
    pub id: i64,
    /// `create` or `change`.
    pub kind: String,
    pub account_id: Option<i64>,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub held_role: Option<String>,
    pub requested_role: Option<String>,
    /// Whether the change sets a password the requester typed — a reset, or a creation's.
    pub password_reset: bool,
    pub requested_by_id: i64,
    pub requested_by: String,
    pub requested_at: OffsetDateTime,
}

impl Outcome {
    /// The account, when the change was applied rather than filed.
    pub fn applied(self) -> Option<AccountView> {
        match self {
            Outcome::Applied(account) => Some(account),
            Outcome::Queued(_) => None,
        }
    }
}

impl AccountRequestView {
    pub fn of(request: &AccountRequest) -> AccountRequestView {
        AccountRequestView {
            id: request.id,
            kind: request.kind.clone(),
            account_id: request.account_id,
            username: request.username.clone(),
            email: request.email.clone(),
            display_name: request.display_name.clone(),
            held_role: request.held_role.clone(),
            requested_role: request.requested_role.clone(),
            password_reset: request.password_hash.is_some(),
            requested_by_id: request.requested_by_id,
            requested_by: request.requested_by.clone(),
            requested_at: request.requested_at,
        }
    }
}

/// The requests waiting on one page, and how many wait on every page — `AccountRequestService.Pending`.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub requests: Vec<AccountRequestView>,
    pub total: u64,
}

/// `OwnAccountRequestException.CAUSE`.
pub const OWN_ACCOUNT_REQUEST: &str = "own-account-request";

/// A request whose kind is `create`.
const CREATE: &str = "create";
/// A role or password request on an existing account.
const CHANGE: &str = "change";
const PENDING: &str = "pending";
const APPROVED: &str = "approved";
const REJECTED: &str = "rejected";

/// A change ready to be written, and what its audit entry will say.
struct PreparedChange {
    user: User,
    revoke_sessions: bool,
    revoke_keys: bool,
    recorded: Recorded,
    changes: Vec<String>,
}

/// An administrator managing accounts, and an account changing its own password.
///
/// **Under four-eyes, a change that makes an approver waits for a second administrator** (#126, option 2): creating an
/// account with a role that approves, giving such a role, and resetting the password of an account that holds one are
/// filed as an account request rather than applied, and [`Accounts::approve`] applies them once another administrator
/// approves. Every other gesture applies at once: taking a privilege away must stay easy. **Who administered whom is
/// recorded beside the change**, in the transaction that writes it, which an approval under four-eyes reads
/// ([`ApproverIndependence`]). Built without [`Accounts::with_four_eyes`], four-eyes is off.
#[derive(Debug)]
pub struct Accounts<S, A, C> {
    store: S,
    audit: A,
    clock: C,
    four_eyes: Option<ApproverIndependence>,
}

impl<S: AccountStore + Sync, A: Audit + Sync, C: Clock + Sync> Accounts<S, A, C> {
    pub fn new(store: S, audit: A, clock: C) -> Accounts<S, A, C> {
        Accounts { store, audit, clock, four_eyes: None }
    }

    /// Reads four-eyes and its independence window from the settings, as the binary composes it.
    #[must_use]
    pub fn with_four_eyes(mut self, independence: ApproverIndependence) -> Accounts<S, A, C> {
        self.four_eyes = Some(independence);
        self
    }

    /// The accounts by username, every one or one page of them (`ListWindow` is the caller's: it hands the cut).
    pub async fn list(&self, window: Option<(usize, usize)>) -> Result<AccountList, AccountError> {
        let active = self.store.active_sessions_by_user(self.clock.now()).await?;
        let every = self.store.all_by_username().await?;
        let total = every.len() as u64;
        let page: Box<dyn Iterator<Item = &User>> = match window {
            Some((limit, offset)) => Box::new(every.iter().skip(offset).take(limit)),
            None => Box::new(every.iter()),
        };
        let accounts = page
            .map(|user| AccountView {
                user: UserView::of(user),
                active_sessions: active.get(&user.id).copied().unwrap_or(0),
            })
            .collect();
        Ok(AccountList { accounts, total })
    }

    /// Creates an account, with `must_change_password` set: the password typed here is known to the administrator
    /// who typed it — a pass, not the account's secret. Under four-eyes, one with a role that approves is filed for a
    /// second administrator instead.
    ///
    /// `acting_account_id` is the account creating it, `None` for a caller that is not one: who may grant the
    /// platform governor role depends on it.
    pub async fn create(
        &self,
        request: NewAccount,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<Outcome, AccountError> {
        let username = java_trim(request.username.as_deref().unwrap_or("")).to_owned();
        let password = request.password.as_ref().map(|secret| secret.expose()).unwrap_or("");
        let trimmed_role = java_trim(request.role.as_deref().unwrap_or(""));
        let role = if trimmed_role.is_empty() { Role::User.name().to_owned() } else { java_upper(trimmed_role) };

        refuse_if(validate_username(Some(&username)))?;
        refuse_if(validate_password(Some(password)))?;
        // Bounded like every column a form writes, and read as an address: "jdoe" went nowhere, and nobody heard of it
        // until the reminders did not arrive.
        let email = address(request.email.as_deref())?;
        let granted = self.refuse_invalid_creation(&username, &role, email.as_deref(), acting_account_id).await?;

        if self.needs_second_administrator(acting_account_id, granted).await? {
            let display_name = bounded_optional(request.display_name.as_deref(), "The display name")?;
            let hash = PasswordHash::new(passwords::hash_bounded(password).await?);
            let filed = NewAccountRequest {
                kind: CREATE,
                account_id: None,
                username: username.clone(),
                email,
                display_name,
                held_role: None,
                requested_role: Some(role.clone()),
                password_hash: Some(hash),
                requested_by_id: 0,
                requested_by: String::new(),
                requested_at: self.clock.now(),
            };
            return self
                .file(filed, acting_account_id, actor, format!("Account creation requested: {username} ({role})"))
                .await;
        }

        let hash = PasswordHash::new(passwords::hash_bounded(password).await?);
        let alone = self.applied_alone(acting_account_id, granted).await?;
        let (user, description) = self
            .prepare_creation(
                &username,
                &role,
                email.as_deref(),
                request.display_name.as_deref(),
                hash,
                acting_account_id,
                &alone,
            )
            .await?;
        let recorded = creation_recorded(acting_account_id.into_iter().collect(), user.created_at);
        let saved = self.store.insert(user, &recorded).await?;
        self.record(actor, saved.id, description).await;
        Ok(Outcome::Applied(AccountView { user: UserView::of(&saved), active_sessions: 0 }))
    }

    /// The rules a creation is held to when it is asked for and again when it is applied — with the approver acting
    /// then, since who may grant the governor role depends on who grants it. Answers the role granted.
    async fn refuse_invalid_creation(
        &self,
        username: &str,
        role: &str,
        email: Option<&str>,
        acting_account_id: Option<i64>,
    ) -> Result<Role, AccountError> {
        refuse_if(validate_username(Some(username)))?;
        let Some(granted) = Role::of(Some(role)) else {
            return Err(AccountError::InvalidInput(format!("Unknown role: {role}.")));
        };
        self.refuse_governor_administration(acting_account_id, None, Some(granted)).await?;
        if self.store.find_by_username(username).await?.is_some() {
            return Err(AccountError::InvalidInput(format!("The username \"{username}\" is already taken.")));
        }
        // Checked again when a filed creation is approved: another account may have taken it meanwhile.
        self.refuse_taken_address(email, -1).await?;
        Ok(granted)
    }

    /// `writeCreation`'s rules and row: the account to insert, and its audit sentence.
    #[allow(clippy::too_many_arguments)]
    async fn prepare_creation(
        &self,
        username: &str,
        role: &str,
        email: Option<&str>,
        display_name: Option<&str>,
        hash: PasswordHash,
        acting_account_id: Option<i64>,
        provenance: &str,
    ) -> Result<(NewUser, String), AccountError> {
        self.refuse_invalid_creation(username, role, email, acting_account_id).await?;
        let created_at = self.clock.now();
        let user = NewUser {
            username: username.to_owned(),
            // Checked again although `create` normalised it: a creation filed under four-eyes is applied here.
            email: address(email)?,
            display_name: bounded_optional(display_name, "The display name")?,
            password: Some(hash),
            role: role.to_owned(),
            is_active: true,
            must_change_password: true,
            created_at,
        };
        Ok((user, format!("Account created: {username} ({role}){provenance}")))
    }

    /// Role, activation, e-mail address and password reset, under one set of guard rails — or, under four-eyes, the
    /// role or the password filed for a second administrator when the change makes an approver.
    ///
    /// **Activation is never held back**: a filed change that also activates or deactivates the account applies that
    /// part at once, as does an e-mail address sent with it.
    pub async fn update(
        &self,
        id: i64,
        change: AccountChange,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<Outcome, AccountError> {
        let user = self.require_account(id).await?;

        let role = match change.role.as_deref() {
            None => user.role.clone(),
            Some(requested) => java_upper(java_trim(requested)),
        };
        let password = change.password.as_ref().map(|secret| secret.expose());

        let Some(next_role) = Role::of(Some(&role)) else {
            return Err(AccountError::InvalidInput(format!("Unknown role: {role}.")));
        };
        if let Some(password) = password {
            refuse_if(validate_password(Some(password)))?;
        }
        // Before anything is applied or filed, so a refusal of the address leaves nothing half done.
        let email = self.email_change(&user, change.email.as_deref()).await?;

        let role_changes = role != user.role;
        // A reset waits for the pending change to be decided first: applied at once beside a pending raise, it would
        // hand whoever typed the password the role the raise grants, under an approval that did not show it.
        if password.is_some() && self.store.request_pending_for(id).await? {
            return Err(already_waiting(&user.username));
        }
        let makes_an_approver =
            (role_changes && next_role.approves()) || (password.is_some() && (approves(&user.role) || approves(&role)));
        if !makes_an_approver || !self.needs_second_administrator(acting_account_id, next_role).await? {
            let alone =
                if makes_an_approver { self.applied_alone(acting_account_id, next_role).await? } else { String::new() };
            let hash = match password {
                Some(password) => Some(PasswordHash::new(passwords::hash_bounded(password).await?)),
                None => None,
            };
            let view = self
                .write_change(
                    user,
                    change.role.as_ref().map(|_| role.clone()),
                    change.is_active,
                    hash,
                    email,
                    acting_account_id,
                    acting_account_id.into_iter().collect(),
                    &alone,
                    actor,
                )
                .await?;
            return Ok(Outcome::Applied(view));
        }

        // Checked now, with the requester acting, so that a change the rules refuse is refused to the person asking
        // rather than filed and refused to the approver; checked again when it is applied.
        let is_active = change.is_active.unwrap_or(user.is_active);
        self.refuse_invalid_change(&user, &role, is_active, acting_account_id).await?;
        let requester = self.require_account(acting_account_id.unwrap_or(-1)).await?;
        if role_changes
            && next_role.approves()
            && let Some(independence) = &self.four_eyes
        {
            // Refused now rather than at the approval: the requester who created this account or typed its password may
            // know it, and the raise would hand them an approver (lower, reset, raise).
            independence
                .require_password_unknown(id, &user.username, requester.id, &requester.username, self.clock.now())
                .await?;
        }
        if self.store.request_pending_for(id).await? {
            return Err(already_waiting(&user.username));
        }
        let activation_changes = change.is_active.is_some_and(|active| active != user.is_active);
        let username = user.username.clone();
        let held_role = user.role.clone();
        if activation_changes || email.is_some() {
            self.write_change(
                user,
                None,
                if activation_changes { change.is_active } else { None },
                None,
                email,
                acting_account_id,
                acting_account_id.into_iter().collect(),
                "",
                actor,
            )
            .await?;
        }
        let hash = match password {
            Some(password) => Some(PasswordHash::new(passwords::hash_bounded(password).await?)),
            None => None,
        };
        let mut asked = Vec::new();
        if role_changes {
            asked.push(format!("role {held_role} → {role}"));
        }
        if password.is_some() {
            asked.push("password reset".to_owned());
        }
        let filed = NewAccountRequest {
            kind: CHANGE,
            account_id: Some(id),
            username: username.clone(),
            email: None,
            display_name: None,
            held_role: Some(held_role),
            requested_role: role_changes.then_some(role),
            password_hash: hash,
            requested_by_id: 0,
            requested_by: String::new(),
            requested_at: self.clock.now(),
        };
        self.file(
            filed,
            acting_account_id,
            actor,
            format!("Account change requested for {username}: {}", asked.join(", ")),
        )
        .await
    }

    /// The guard rails of [`Accounts::update`], with whoever is acting — the requester, then the approver.
    async fn refuse_invalid_change(
        &self,
        user: &User,
        role: &str,
        is_active: bool,
        acting_account_id: Option<i64>,
    ) -> Result<(), AccountError> {
        // On every change, not only a role change: resetting a governor's password, or deactivating it, is
        // administering it just as much.
        self.refuse_governor_administration(acting_account_id, Role::of(Some(&user.role)), Role::of(Some(role)))
            .await?;
        let is_self = is_self(acting_account_id, user.id);
        refuse_if(refuse_self_lockout(Change {
            is_self,
            was_admin: is_administrative(&user.role) && user.is_active,
            will_be_admin: is_administrative(role),
            will_be_active: is_active,
            remaining_active_admins: self
                .store
                .count_other_active_admins(&administrative_role_names(), user.id)
                .await?,
        }))?;
        refuse_if(refuse_own_role_change(is_self, Some(&user.role), Some(role)))
    }

    #[allow(clippy::too_many_arguments)]
    /// `writeChange`'s rules and row: the account as it is to be saved, what it revokes and records, and the changes
    /// its audit sentence lists. `role`, `is_active`, `hash` and `email` are `None` to keep; `email` as
    /// [`Accounts::email_change`] answers it.
    async fn prepare_change(
        &self,
        mut user: User,
        role: Option<String>,
        is_active: Option<bool>,
        hash: Option<PasswordHash>,
        email: Option<String>,
        acting_account_id: Option<i64>,
        administrators: Vec<i64>,
    ) -> Result<PreparedChange, AccountError> {
        let role_set = role.is_some();
        let next_role = role.unwrap_or_else(|| user.role.clone());
        let next_active = is_active.unwrap_or(user.is_active);
        self.refuse_invalid_change(&user, &next_role, next_active, acting_account_id).await?;
        // Again: the directory may have claimed the account, or another account taken the address, since the request
        // was read.
        let next_email = match email {
            Some(email) => self.email_change(&user, Some(&email)).await?,
            None => None,
        };

        let mut changes = Vec::new();
        let previous_role = user.role.clone();
        if next_role != user.role {
            changes.push(format!("role {} → {next_role}", user.role));
        }
        if next_active != user.is_active {
            changes.push(if next_active { "reactivated" } else { "deactivated" }.to_owned());
        }
        if hash.is_some() {
            changes.push("password reset".to_owned());
        }
        if let Some(next) = next_email {
            // Never the address itself: the audit log is read by people who are not the account's owner, and exported
            // to a SIEM that keeps it longer than the account.
            changes.push(
                if next.is_empty() {
                    "e-mail address cleared"
                } else if user.email.is_none() {
                    "e-mail address set"
                } else {
                    "e-mail address changed"
                }
                .to_owned(),
            );
            user.email = (!next.is_empty()).then_some(next);
        }
        if role_set && let Some(lowered) = user.scim_lowered_from.take() {
            // An administrator who sets the role has looked at the account: the directory's lowering no longer holds
            // its binding back (V93).
            changes.push(format!("role confirmed after the directory lowered it from {lowered}"));
        }

        let at = self.clock.now();
        user.role.clone_from(&next_role);
        user.is_active = next_active;
        user.updated_at = at;
        let reset = hash.is_some();
        if let Some(hash) = hash {
            user.password = Some(hash);
            user.must_change_password = true;
        }
        // **Three gestures close the sessions**: deactivating; resetting the password — the incident-response gesture,
        // which otherwise left a stolen token authenticating for up to twelve hours; and changing a role. **A reset
        // takes the account's integration keys too**: a key minted by whoever held the stolen credentials outlived the
        // reset meant to shut them out.
        let revoke_sessions = !next_active || reset || next_role != previous_role;
        let mut made = Vec::new();
        if reset {
            made.push(Gesture::PasswordReset);
        }
        if next_role != previous_role {
            made.push(Gesture::RoleChanged);
        }
        let recorded = Recorded { held_role: Some(previous_role), administrators, made, at: Some(at) };
        Ok(PreparedChange { user, revoke_sessions, revoke_keys: reset, recorded, changes })
    }

    /// `writeChange` applied at once: the row, its gestures and what it revokes in one transaction, then the entries.
    #[allow(clippy::too_many_arguments)]
    async fn write_change(
        &self,
        user: User,
        role: Option<String>,
        is_active: Option<bool>,
        hash: Option<PasswordHash>,
        email: Option<String>,
        acting_account_id: Option<i64>,
        administrators: Vec<i64>,
        provenance: &str,
        actor: &RequestActor,
    ) -> Result<AccountView, AccountError> {
        let prepared =
            self.prepare_change(user, role, is_active, hash, email, acting_account_id, administrators).await?;
        let revoked = if prepared.revoke_keys {
            self.store.save_revoking_everything(&prepared.user, &prepared.recorded).await?
        } else {
            self.store.save(&prepared.user, prepared.revoke_sessions, &prepared.recorded).await?;
            Vec::new()
        };
        self.record_change(&prepared.user, prepared.changes, &revoked, provenance, actor).await;
        let active_sessions = if prepared.revoke_sessions { 0 } else { self.sessions_of(prepared.user.id).await? };
        Ok(AccountView { user: UserView::of(&prepared.user), active_sessions })
    }

    /// The change's entry, then one entry per key revoked, under the key's id — as a revocation by hand leaves.
    async fn record_change(
        &self,
        user: &User,
        mut changes: Vec<String>,
        revoked: &[RevokedKey],
        provenance: &str,
        actor: &RequestActor,
    ) {
        if !revoked.is_empty() {
            let count = revoked.len();
            changes.push(format!("{count} API key{} revoked", if count == 1 { "" } else { "s" }));
        }
        if !changes.is_empty() {
            self.record(actor, user.id, format!("Account {}: {}{provenance}", user.username, changes.join(", "))).await;
        }
        for key in revoked {
            self.audit
                .record(AuditRecord {
                    operation: AuditOperation::ApiKeyDeleted,
                    resource: key.id.as_hyphenated().to_string(),
                    description: format!(
                        "API key revoked with its account's password reset: {} (account {})",
                        key.name, user.username
                    ),
                    username: actor.username.clone(),
                    ip_address: actor.ip_address.clone(),
                    user_agent: actor.user_agent.clone(),
                    signal: None,
                })
                .await;
        }
    }

    /// Whether a change that makes an approver waits for a second administrator: only under four-eyes, and only when
    /// a second administrator exists, active or not — with nobody to approve, the installation could never be staffed.
    async fn needs_second_administrator(
        &self,
        acting_account_id: Option<i64>,
        role: Role,
    ) -> Result<bool, AccountError> {
        let Some(acting) = acting_account_id else { return Ok(false) };
        if !role.approves() || !self.four_eyes_on().await? {
            return Ok(false);
        }
        Ok(self.count_other_admins(acting).await? > 0)
    }

    /// What the audit sentence adds when four-eyes would have held the change back and nobody else could approve it.
    async fn applied_alone(&self, acting_account_id: Option<i64>, role: Role) -> Result<String, AccountError> {
        let Some(acting) = acting_account_id else { return Ok(String::new()) };
        if role.approves() && self.four_eyes_on().await? && self.count_other_admins(acting).await? == 0 {
            return Ok(" — four-eyes: applied without a second administrator, as there is no other".to_owned());
        }
        Ok(String::new())
    }

    async fn four_eyes_on(&self) -> Result<bool, AccountError> {
        match &self.four_eyes {
            Some(independence) => Ok(independence.four_eyes_required().await?),
            None => Ok(false),
        }
    }

    /// Every other administrative account, **deactivated ones included** — and one lowered recently: lowering the
    /// others to a role that approves nothing applies at once, and would otherwise leave the lowerer alone.
    async fn count_other_admins(&self, excluded: i64) -> Result<u64, AccountError> {
        let roles = administrative_role_names();
        let now = self.store.count_other_admins(&roles, excluded).await?;
        if now > 0 {
            return Ok(now);
        }
        let lowered = match &self.four_eyes {
            Some(independence) => {
                independence.another_administrator_lowered_recently(excluded, &roles, self.clock.now()).await?
            }
            None => false,
        };
        Ok(u64::from(lowered))
    }

    /// Files a request, audited under its own id; nothing about the account changes.
    async fn file(
        &self,
        mut filed: NewAccountRequest,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
        description: String,
    ) -> Result<Outcome, AccountError> {
        let requester = self.require_account(acting_account_id.unwrap_or(-1)).await?;
        filed.requested_by_id = requester.id;
        filed.requested_by = requester.username;
        filed.requested_at = self.clock.now();
        let username = filed.username.clone();
        let saved = match self.store.file_request(filed).await? {
            Filing::Filed(saved) => saved,
            Filing::AccountPending => return Err(already_waiting(&username)),
            Filing::NamePending => {
                return Err(AccountError::Conflict(format!(
                    "An account named \"{username}\" is already waiting for approval."
                )));
            }
        };
        self.audit
            .record(self.entry(
                AuditOperation::AccountRequestFiled,
                saved.id.to_string(),
                format!("{description} — four-eyes: waiting for another administrator (account request #{})", saved.id),
                actor,
            ))
            .await;
        Ok(Outcome::Queued(AccountRequestView::of(&saved)))
    }

    /// The requests waiting, oldest first — every one, or one page (`ListWindow` is the caller's).
    pub async fn pending(&self, window: Option<(usize, usize)>) -> Result<Pending, AccountError> {
        let every = self.store.requests_in(PENDING).await?;
        let total = every.len() as u64;
        let page: Box<dyn Iterator<Item = &AccountRequest>> = match window {
            Some((limit, offset)) => Box::new(every.iter().skip(offset).take(limit)),
            None => Box::new(every.iter()),
        };
        Ok(Pending { requests: page.map(AccountRequestView::of).collect(), total })
    }

    /// Applies a request as its approver — `AccountRequestService.approve` — and answers the account as it now stands.
    ///
    /// Somebody other than the requester approves it, somebody the requester did not administer recently and who did
    /// not administer the requester; nobody approves a change to their own account. **Applied as the approver**: the
    /// change is checked again with the approver acting, and a role that moved since it was filed makes it stale.
    /// Decided under the request's row lock, in one transaction with the change.
    pub async fn approve(
        &self,
        id: i64,
        approver_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<AccountView, AccountError> {
        let approver = self.require_administrator(approver_id, "approve").await?;
        let request = self.require_pending(id).await?;
        if request.requested_by_id == approver.id {
            return Err(AccountError::OwnAccountRequest);
        }
        if request.account_id == Some(approver.id) {
            return Err(AccountError::InvalidInput("You cannot approve a change to your own account.".to_owned()));
        }
        // The requester's standing is read now, not when it filed: a request whose author has since been deactivated
        // or demoted has nobody left standing behind it.
        let requester_stands = self
            .store
            .find_by_id(request.requested_by_id)
            .await?
            .is_some_and(|account| account.is_active && is_administrative(&account.role));
        if !requester_stands {
            return Err(AccountError::Conflict(format!(
                "{} is no longer an active administrator: reject this request, and file the change again if it is \
                 still wanted.",
                request.requested_by
            )));
        }
        let now = self.clock.now();
        if let Some(independence) = &self.four_eyes {
            independence.require_mutual(request.requested_by_id, &request.requested_by, approver.id, now).await?;
        }

        let provenance = format!(
            ", requested by {} and approved by {} (account request #{})",
            request.requested_by, approver.username, request.id
        );
        let administrators = vec![request.requested_by_id, approver.id];
        let hash = request.password_hash.clone();
        let (apply, after) = if request.kind == CREATE {
            let role = request.requested_role.clone().unwrap_or_default();
            let Some(hash) = hash else {
                return Err(AccountError::Store(StoreError("a creation request carries no password".into())));
            };
            let (user, description) = self
                .prepare_creation(
                    &request.username,
                    &role,
                    request.email.as_deref(),
                    request.display_name.as_deref(),
                    hash,
                    Some(approver.id),
                    &provenance,
                )
                .await?;
            let recorded = creation_recorded(administrators, user.created_at);
            (Apply::Create(user, recorded), Applied::Created(description))
        } else {
            let account = self.require_account(request.account_id.unwrap_or(-1)).await?;
            let held_role = request.held_role.clone().unwrap_or_default();
            if account.role != held_role {
                return Err(role_moved(&account.username));
            }
            if raises_to_an_approver(&request)
                && let Some(independence) = &self.four_eyes
            {
                // Neither administrator behind the raise may know the account's password from a gesture of theirs:
                // lower, reset, raise would otherwise hand one of them an approver.
                independence
                    .require_password_unknown(
                        account.id,
                        &account.username,
                        request.requested_by_id,
                        &request.requested_by,
                        now,
                    )
                    .await?;
                independence
                    .require_password_unknown(account.id, &account.username, approver.id, &approver.username, now)
                    .await?;
            }
            let prepared = self
                .prepare_change(
                    account,
                    request.requested_role.clone(),
                    None,
                    hash,
                    None,
                    Some(approver.id),
                    administrators,
                )
                .await?;
            let revoke_sessions = prepared.revoke_sessions;
            (
                Apply::Change {
                    user: Box::new(prepared.user.clone()),
                    held_role,
                    revoke_sessions,
                    revoke_keys: prepared.revoke_keys,
                    recorded: prepared.recorded,
                },
                Applied::Changed { user: Box::new(prepared.user), changes: prepared.changes, revoke_sessions },
            )
        };

        let decision = Decision {
            request_id: id,
            status: APPROVED,
            decided_by: approver.username.clone(),
            decided_at: self.clock.now(),
            apply: Some(apply),
        };
        let (account, revoked, requester) = match self.store.decide_request(decision).await? {
            Decided::Done { account, revoked, requested_by } => (account, revoked, requested_by),
            refused => return Err(refusal_of(refused, &request)),
        };
        self.audit
            .record(self.entry(
                AuditOperation::AccountRequestApproved,
                id.to_string(),
                format!("Account request #{id} by {requester} approved"),
                actor,
            ))
            .await;
        let Some(account) = account else { return Err(AccountError::NotFound) };
        match after {
            Applied::Created(description) => {
                self.record(actor, account.id, description).await;
                Ok(AccountView { user: UserView::of(&account), active_sessions: 0 })
            }
            Applied::Changed { user, changes, revoke_sessions } => {
                self.record_change(&user, changes, &revoked, &provenance, actor).await;
                let active_sessions = if revoke_sessions { 0 } else { self.sessions_of(account.id).await? };
                Ok(AccountView { user: UserView::of(&account), active_sessions })
            }
        }
    }

    /// Drops a request, applying nothing — `AccountRequestService.reject`. Any administrator may, its requester
    /// included, which withdraws it.
    pub async fn reject(&self, id: i64, decider_id: Option<i64>, actor: &RequestActor) -> Result<(), AccountError> {
        let decider = self.require_administrator(decider_id, "reject").await?;
        let decision = Decision {
            request_id: id,
            status: REJECTED,
            decided_by: decider.username.clone(),
            decided_at: self.clock.now(),
            apply: None,
        };
        let requester = match self.store.decide_request(decision).await? {
            Decided::Done { requested_by, .. } => requested_by,
            Decided::NotFound => return Err(request_not_found()),
            Decided::AlreadyDecided { status, decided_by } => return Err(already_decided(&status, decided_by)),
            Decided::RoleMoved(_) | Decided::AccountGone => {
                return Err(AccountError::Store(StoreError("a rejection applies no change".into())));
            }
        };
        let verb = if requester == decider.username { "withdrawn" } else { "rejected" };
        self.audit
            .record(self.entry(
                AuditOperation::AccountRequestRejected,
                id.to_string(),
                format!("Account request #{id} by {requester} {verb}"),
                actor,
            ))
            .await;
        Ok(())
    }

    /// The request, still pending — read before the checks, and read again under its lock when decided.
    async fn require_pending(&self, id: i64) -> Result<AccountRequest, AccountError> {
        let request = self.store.find_request(id).await?.ok_or_else(request_not_found)?;
        if request.status != PENDING {
            return Err(already_decided(&request.status, request.decided_by));
        }
        Ok(request)
    }

    /// An account that administers today, whatever the route's marker admitted.
    async fn require_administrator(&self, account_id: Option<i64>, gesture: &str) -> Result<User, AccountError> {
        let account = match account_id {
            Some(id) => self.store.find_by_id(id).await?,
            None => None,
        };
        account.filter(|account| account.is_active && is_administrative(&account.role)).ok_or_else(|| {
            AccountError::AccessDenied(format!("Only an administrator can {gesture} an account request."))
        })
    }

    /// Clears another account's second factor, and closes its sessions — `resetSecondFactor`: the way back for an
    /// account locked out of its own factor. Never one's own, under the governor's rules as a password reset is; the
    /// account's API keys stay. Idempotent: an account without a factor is answered as it is, with no write and no
    /// entry.
    pub async fn reset_second_factor(
        &self,
        id: i64,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<AccountView, AccountError> {
        if !self.administers(acting_account_id).await? {
            return Err(AccountError::AccessDenied(
                "Only an administrator can reset another account's second factor.".to_owned(),
            ));
        }
        let mut user = self.require_account(id).await?;
        if is_self(acting_account_id, id) {
            return Err(AccountError::InvalidInput(
                "You cannot reset your own second factor: disable it with a current code.".to_owned(),
            ));
        }
        self.refuse_governor_administration(acting_account_id, Role::of(Some(&user.role)), None).await?;
        if !user.mfa_enabled {
            return Ok(AccountView { user: UserView::of(&user), active_sessions: self.sessions_of(id).await? });
        }
        user.mfa_enabled = false;
        user.totp_secret = None;
        user.mfa_backup_codes = None;
        user.totp_last_step = None;
        user.updated_at = self.clock.now();
        self.store.save(&user, true, &Recorded::nothing()).await?;
        self.record(
            actor,
            id,
            format!("Account {}: second factor reset by an administrator, sessions closed", user.username),
        )
        .await;
        Ok(AccountView { user: UserView::of(&user), active_sessions: 0 })
    }

    /// Whether the acting account holds an administrative role today — read, not trusted.
    async fn administers(&self, acting_account_id: Option<i64>) -> Result<bool, AccountError> {
        Ok(match acting_account_id {
            Some(acting) => self
                .store
                .find_by_id(acting)
                .await?
                .and_then(|account| Role::of(Some(&account.role)))
                .is_some_and(Role::is_administrative),
            None => false,
        })
    }

    /// Lifts another account's obligation to change its password, for an account that signs in through the
    /// identity provider (0.11.1's M1 fix): **the lift discards the local password**, replacing it with one
    /// nobody knows, and **closes the account's sessions; its integration keys stay**. Never on one's own account,
    /// and only by an account that is administrative today, whatever the route admitted. Idempotent: an account
    /// that owes nothing is answered as it is, with no write and no entry.
    pub async fn clear_password_change_requirement(
        &self,
        id: i64,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<AccountView, AccountError> {
        if !self.administers(acting_account_id).await? {
            return Err(AccountError::AccessDenied(
                "Only an administrator can lift another account's password-change requirement.".to_owned(),
            ));
        }
        let mut user = self.require_account(id).await?;
        if is_self(acting_account_id, id) {
            return Err(AccountError::InvalidInput(
                "You cannot lift your own password-change requirement: change your password.".to_owned(),
            ));
        }
        self.refuse_governor_administration(acting_account_id, Role::of(Some(&user.role)), None).await?;

        if !user.must_change_password {
            return Ok(AccountView { user: UserView::of(&user), active_sessions: self.sessions_of(id).await? });
        }
        if signs_in_with_its_password(&user) {
            return Err(AccountError::InvalidInput(
                "This account signs in with its password, which somebody else chose: it lifts the requirement \
                 itself by changing it. Only an account that signs in through the identity provider can have it \
                 lifted."
                    .to_owned(),
            ));
        }

        user.must_change_password = false;
        if user.password.is_some() {
            // Well-formed, so the sign-in's comparison runs as for any account, and nothing anybody typed matches.
            user.password = Some(PasswordHash::new(passwords::hash_of_nothing_anybody_knows_bounded().await?));
        }
        user.updated_at = self.clock.now();
        self.store.save(&user, true, &Recorded::nothing()).await?;
        self.record(
            actor,
            id,
            format!("Account {}: password-change requirement lifted, local password discarded", user.username),
        )
        .await;
        Ok(AccountView { user: UserView::of(&user), active_sessions: self.sessions_of(id).await? })
    }

    /// Deletes an account: its sessions, then the row. Never one's own, never the last active administrator.
    pub async fn delete(
        &self,
        id: i64,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<(), AccountError> {
        let user = self.require_account(id).await?;
        self.refuse_governor_administration(acting_account_id, Role::of(Some(&user.role)), None).await?;
        refuse_if(refuse_deletion(
            is_self(acting_account_id, id),
            is_administrative(&user.role) && user.is_active,
            self.store.count_other_active_admins(&administrative_role_names(), id).await?,
        ))?;
        self.store.delete(id).await?;
        self.record(actor, id, format!("Account deleted: {}", user.username)).await;
        Ok(())
    }

    /// Changes one's own password — `AuthenticationFlowService.changePassword`.
    ///
    /// The current password is required even when `must_change_password` is set: a workstation left unlocked for a
    /// minute would otherwise be enough to take the account. A wrong one spends the account's sign-in budget and is
    /// recorded. The other sessions close — only when the request came on a session, as Java does — and the keys
    /// the account issued are revoked, each audited under its id.
    ///
    /// `Err(NotFound)` when the account is gone: the bearer layer found it active at the start of the request, so
    /// only a deletion racing it lands there.
    #[allow(clippy::too_many_arguments)]
    pub async fn change_own_password<P: PasswordAttempts + Sync>(
        &self,
        attempts: &P,
        account_id: i64,
        current_session: Option<SessionHash>,
        current_password: Option<&str>,
        new_password: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<PasswordChange, AccountError> {
        let user = self.require_account(account_id).await?;
        let entry = |operation, description: String, signal| AuditRecord {
            operation,
            resource: user.id.to_string(),
            description,
            username: Some(user.username.clone()),
            ip_address: ip_address.map(str::to_owned),
            user_agent: user_agent.map(str::to_owned),
            signal,
        };
        let held = match attempts.reserve(user.id, ip_address).await {
            Ok(held) => held,
            Err(StoreOr::Store(error)) => return Err(error.into()),
            Err(StoreOr::Refused(retry_after_seconds)) => {
                self.audit
                    .record(entry(
                        AuditOperation::LoginBlocked,
                        format!("Password change refused by the throttle ({retry_after_seconds}s to wait)"),
                        Some("SIGN_IN_THROTTLED"),
                    ))
                    .await;
                return Ok(PasswordChange::Throttled { retry_after_seconds });
            }
        };
        if !verify_reserved(attempts, &held, current_password, user.password.as_ref()).await? {
            // The reservation stays: it is this failure.
            self.audit
                .record(entry(
                    AuditOperation::LoginFailure,
                    "Password change refused: the current password was wrong".to_owned(),
                    None,
                ))
                .await;
            return Ok(PasswordChange::CurrentPasswordWrong);
        }
        // The password was right: whatever the new one turns out to be, this was not a guess.
        attempts.clear(user.id, ip_address).await?;
        refuse_if(validate_password(new_password))?;
        let new_password = new_password.unwrap_or("");
        if Some(new_password) == current_password {
            return Err(AccountError::InvalidInput("The new password is the same as the old one.".to_owned()));
        }

        let revoked = self
            .store
            .change_own_password(
                user.id,
                PasswordHash::new(passwords::hash_bounded(new_password).await?),
                self.clock.now(),
                current_session,
            )
            .await?;
        let count = revoked.len();
        self.audit
            .record(entry(
                AuditOperation::PasswordChanged,
                format!(
                    "Password changed by {}{}",
                    user.username,
                    if revoked.is_empty() {
                        String::new()
                    } else {
                        format!("; {count} API key{} revoked", if count == 1 { "" } else { "s" })
                    }
                ),
                None,
            ))
            .await;
        for key in &revoked {
            self.audit
                .record(AuditRecord {
                    resource: key.id.as_hyphenated().to_string(),
                    ..entry(
                        AuditOperation::ApiKeyDeleted,
                        format!(
                            "API key revoked with its account's password change: {} (account {})",
                            key.name, user.username
                        ),
                        None,
                    )
                })
                .await;
        }
        Ok(PasswordChange::Changed { revoked_api_keys: count })
    }

    /// The password half of the sign-in — `AuthService.login` from the lookup to the rehash; the throttle, the
    /// second factor and the session are [`crate::sign_in`]'s, which calls the three steps itself with the throttle
    /// between the lookup and the derivation.
    ///
    /// **A name no account can hold opens no account**, and **one key derivation whatever the name**: an unknown
    /// name, an ill-formed one and a deactivated account are verified against a stand-in hash, so the answer's
    /// timing says nothing about whether the account exists. On success a hash made under weaker parameters is
    /// rewritten — the one moment the plaintext is in hand — and a failure to save it is logged, not fatal.
    ///
    /// Returns the account when the password is its own and it is active.
    pub async fn check_sign_in_password(
        &self,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Option<User>, AccountError> {
        let user = self.sign_in_lookup(username).await?;
        let Some(found) = verify_sign_in(user, password).await? else {
            return Ok(None);
        };
        self.rehash_if_stale(&found, password).await;
        Ok(Some(found))
    }

    /// The account a typed name opens, before the throttle — a query, and no hashing. A name outside
    /// `AccountRules`' grammar is not looked up: the database's collation ignores characters no account name holds
    /// (U+00AD, U+200B…), so `ali\u{AD}ce` opened `alice` and met its counter while its folded key was a counter of
    /// its own — the lockout then answered what the uniform refusal is built not to.
    pub async fn sign_in_lookup(&self, username: Option<&str>) -> Result<Option<User>, AccountError> {
        Ok(match username {
            Some(name) if account_rules::is_well_formed_username(Some(name)) => {
                self.store.find_by_username(name).await?
            }
            _ => None,
        })
    }

    /// `rehashIfStale`: rewrites a hash made under weaker parameters than today's, after the password was accepted.
    /// A failure to save is logged and swallowed: the stored hash is still valid under its own parameters, and
    /// refusing the session over a housekeeping write would turn a cost upgrade into an outage.
    pub async fn rehash_if_stale(&self, user: &User, password: Option<&str>) {
        if passwords::needs_rehash(user.password.as_ref().map(PasswordHash::encoded)) {
            // Under the bound too, as Java's `PasswordHasher.hash` is; saturated, the rewrite waits for the next
            // sign-in — Java's `catch (RuntimeException)` swallows the refusal the same way.
            let rewritten = match passwords::hash_bounded(password.unwrap_or("")).await {
                Ok(rewritten) => PasswordHash::new(rewritten),
                Err(saturated) => {
                    tracing::warn!(username = %user.username, %saturated, "Could not rewrite the password hash under current parameters.");
                    return;
                }
            };
            if let Err(error) = self.store.rehash(user.id, rewritten).await {
                tracing::warn!(username = %user.username, %error, "Could not rewrite the password hash under current parameters.");
            }
        }
    }

    /// The account store, for the sign-in services that share it.
    pub(crate) fn store(&self) -> &S {
        &self.store
    }

    /// `emailChange`: what a change does to the account's address — `None` when it leaves it as it is (absent, or the
    /// address it already holds), the empty string when it clears it, the address otherwise.
    ///
    /// **Resending the current address is no change**, so a screen that sends the whole form is not refused on an
    /// account the directory writes, and writes no audit entry for nothing. A real change on such an account is
    /// [`AccountError::ManagedByDirectory`]; an address another account holds is refused as a taken username is,
    /// rather than left to the unique key, whose violation was a 500.
    ///
    /// Java asks again inside the write's transaction, since the directory may claim the account meanwhile; here the
    /// row is written by [`AccountStore::save`] after this check, as every other rule of `update` is.
    async fn email_change(&self, user: &User, typed: Option<&str>) -> Result<Option<String>, AccountError> {
        let Some(typed) = typed else {
            return Ok(None);
        };
        let email = address(Some(typed))?;
        if email == user.email {
            return Ok(None);
        }
        if user.scim_managed {
            return Err(AccountError::ManagedByDirectory(user.username.clone()));
        }
        self.refuse_taken_address(email.as_deref(), user.id).await?;
        Ok(Some(email.unwrap_or_default()))
    }

    /// `refuseTakenAddress`.
    async fn refuse_taken_address(&self, email: Option<&str>, account_id: i64) -> Result<(), AccountError> {
        if let Some(email) = email
            && self.store.email_taken(email, account_id).await?
        {
            return Err(AccountError::InvalidInput(format!(
                "The e-mail address {email} is already used by another account."
            )));
        }
        Ok(())
    }

    async fn require_account(&self, id: i64) -> Result<User, AccountError> {
        self.store.find_by_id(id).await?.ok_or(AccountError::NotFound)
    }

    /// The acting role is read, not trusted.
    async fn refuse_governor_administration(
        &self,
        acting_account_id: Option<i64>,
        current: Option<Role>,
        next: Option<Role>,
    ) -> Result<(), AccountError> {
        let acting = match acting_account_id {
            Some(acting) => self.store.find_by_id(acting).await?.and_then(|account| Role::of(Some(&account.role))),
            None => None,
        };
        refuse_if(refuse_governor_administration(acting, current, next))
    }

    async fn sessions_of(&self, id: i64) -> Result<u64, AccountError> {
        Ok(self.store.active_sessions_by_user(self.clock.now()).await?.get(&id).copied().unwrap_or(0))
    }

    async fn record(&self, actor: &RequestActor, id: i64, description: String) {
        self.audit.record(self.entry(AuditOperation::UserUpdated, id.to_string(), description, actor)).await;
    }

    fn entry(
        &self,
        operation: AuditOperation,
        resource: String,
        description: String,
        actor: &RequestActor,
    ) -> AuditRecord {
        AuditRecord {
            operation,
            resource,
            description,
            username: actor.username.clone(),
            ip_address: actor.ip_address.clone(),
            user_agent: actor.user_agent.clone(),
            signal: None,
        }
    }
}

/// What an approval writes its entries from, once the decision has committed.
enum Applied {
    Created(String),
    Changed { user: Box<User>, changes: Vec<String>, revoke_sessions: bool },
}

/// The gestures of a creation: every administrator behind it created the account.
fn creation_recorded(administrators: Vec<i64>, at: OffsetDateTime) -> Recorded {
    Recorded { held_role: None, administrators, made: vec![Gesture::Created], at: Some(at) }
}

fn approves(role: &str) -> bool {
    Role::of(Some(role)).is_some_and(Role::approves)
}

/// A request raising its account to a role that approves.
fn raises_to_an_approver(request: &AccountRequest) -> bool {
    request
        .requested_role
        .as_ref()
        .is_some_and(|requested| Some(requested) != request.held_role.as_ref() && approves(requested))
}

fn already_waiting(username: &str) -> AccountError {
    AccountError::Conflict(format!(
        "A change to {username} is already waiting for approval: have it approved or rejected first."
    ))
}

fn request_not_found() -> AccountError {
    AccountError::RequestNotFound
}

fn already_decided(status: &str, decided_by: Option<String>) -> AccountError {
    // Java concatenates the field, so an absent decider reads "null".
    let decided_by = decided_by.unwrap_or_else(|| "null".to_owned());
    AccountError::Conflict(format!("This request was already {status} by {decided_by}."))
}

fn role_moved(username: &str) -> AccountError {
    AccountError::Conflict(format!(
        "The role of {username} changed since this request was filed: reject it, and file the change again if it is \
         still wanted."
    ))
}

/// A decision the store did not write, in the words the checks before it would have used.
fn refusal_of(decided: Decided, request: &AccountRequest) -> AccountError {
    match decided {
        Decided::NotFound => request_not_found(),
        Decided::AlreadyDecided { status, decided_by } => already_decided(&status, decided_by),
        Decided::RoleMoved(username) => role_moved(&username),
        Decided::AccountGone => AccountError::NotFound,
        Decided::Done { .. } => {
            AccountError::Store(StoreError(format!("the account request {} was decided twice", request.id).into()))
        }
    }
}

/// The one key derivation of a sign-in, whatever the name: the active account's own hash, or the stand-in for an
/// unknown name, a deactivated account and an account without a password — Java's `Optional.map` of a null password
/// is empty, so that one is verified against the stand-in too. The account when the password is its own and it is
/// active.
///
/// Under the derivation bound ([`crate::derivations`]): **busy is not a failure** — `Err` when no permit came free,
/// asked for in the same place whatever the name, the stand-in's included, so the refusal says nothing about whether
/// the account exists.
pub async fn verify_sign_in(user: Option<User>, password: Option<&str>) -> Result<Option<User>, DerivationsSaturated> {
    let active = user.filter(|found| found.is_active);
    let stand_in = stand_in_hash();
    let stored = active.as_ref().and_then(|found| found.password.as_ref().map(PasswordHash::encoded));
    let against = stored.unwrap_or(stand_in.as_str());
    let matches = passwords::verify_bounded(password, Some(against)).await?;
    Ok(active.filter(|_| matches))
}

/// `AuthService.verifyReserved`: a password checked under a reservation already made. When no derivation permit came
/// free, nothing was compared, so the reservation is taken back before [`DerivationsSaturated`] goes up as a 503 —
/// counted, a person retrying through a busy minute would spend their own budget on checks that never happened and be
/// locked out once it cleared. For the password asked of a signed-in account: a password change, an MFA enrolment.
pub(crate) async fn verify_reserved<P: PasswordAttempts + Sync>(
    attempts: &P,
    held: &P::Held,
    password: Option<&str>,
    encoded: Option<&PasswordHash>,
) -> Result<bool, AccountError> {
    match passwords::verify_bounded(password, encoded.map(PasswordHash::encoded)).await {
        Ok(matches) => Ok(matches),
        Err(saturated) => {
            attempts.release(held).await?;
            Err(saturated.into())
        }
    }
}

/// A real Argon2 hash of nothing anybody knows, computed once per process, for the unknown-name path.
fn stand_in_hash() -> String {
    static STAND_IN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    STAND_IN.get_or_init(passwords::hash_of_nothing_anybody_knows).clone()
}

/// Holds a password and no provider subject: the password is how it signs in.
fn signs_in_with_its_password(user: &User) -> bool {
    user.password.is_some() && user.keycloak_id.is_none()
}

/// `Role.administrative()`'s names, the list the count takes.
fn administrative_role_names() -> Vec<&'static str> {
    Role::administrative().into_iter().map(Role::name).collect()
}

fn is_self(acting_account_id: Option<i64>, id: i64) -> bool {
    acting_account_id == Some(id)
}

fn is_administrative(role: &str) -> bool {
    Role::of(Some(role)).is_some_and(Role::is_administrative)
}

fn refuse_if(refusal: Option<String>) -> Result<(), AccountError> {
    refusal.map_or(Ok(()), |message| Err(AccountError::InvalidInput(message)))
}

/// `address`: an address as typed, bounded like every column a form writes and read as an address — `None` when blank.
fn address(typed: Option<&str>) -> Result<Option<String>, AccountError> {
    let email = bounded_optional(typed, "The e-mail address")?;
    if let Some(email) = &email {
        refuse_if(account_rules::validate_email(Some(email)))?;
    }
    Ok(email)
}

/// `BoundedText.optional`: trimmed as Java trims, `None` when blank, refused rather than cut when too long.
fn bounded_optional(value: Option<&str>, what: &str) -> Result<Option<String>, AccountError> {
    let trimmed = java_trim(value.unwrap_or(""));
    if trimmed.is_empty() {
        return Ok(None);
    }
    if java_length(trimmed) > BOUNDED_COLUMN {
        return Err(AccountError::InvalidInput(format!("{what} is longer than {BOUNDED_COLUMN} characters.")));
    }
    Ok(Some(trimmed.to_owned()))
}
