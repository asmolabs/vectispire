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
use crate::passwords;
pub use crate::persistence::model::StoreError;
pub use crate::persistence::{AccountStore, NewUser, PasswordHash, RevokedKey, Sealed, SessionHash, User};

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
}

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
    UserUpdated,
    ApiKeyDeleted,
    LoginBlocked,
    LoginFailure,
    LoginSuccess,
    PasswordChanged,
}

impl AuditOperation {
    pub const fn name(self) -> &'static str {
        match self {
            AuditOperation::UserUpdated => "USER_UPDATED",
            AuditOperation::ApiKeyDeleted => "API_KEY_DELETED",
            AuditOperation::LoginBlocked => "LOGIN_BLOCKED",
            AuditOperation::LoginFailure => "LOGIN_FAILURE",
            AuditOperation::LoginSuccess => "LOGIN_SUCCESS",
            AuditOperation::PasswordChanged => "PASSWORD_CHANGED",
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
/// counters). A reservation not released is a failure counted.
pub trait PasswordAttempts {
    /// `Ok(())` when admitted, otherwise the wait, in whole seconds as Java's `retryAfter().toSeconds()`.
    fn reserve(&self, account_id: i64) -> impl std::future::Future<Output = Result<(), StoreOr<u64>>> + Send;
    fn clear(&self, account_id: i64) -> impl std::future::Future<Output = Result<(), StoreError>> + Send;
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

/// An administrator managing accounts, and an account changing its own password.
#[derive(Debug)]
pub struct Accounts<S, A, C> {
    store: S,
    audit: A,
    clock: C,
}

impl<S: AccountStore + Sync, A: Audit + Sync, C: Clock + Sync> Accounts<S, A, C> {
    pub fn new(store: S, audit: A, clock: C) -> Accounts<S, A, C> {
        Accounts { store, audit, clock }
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
    /// who typed it — a pass, not the account's secret.
    ///
    /// `acting_account_id` is the account creating it, `None` for a caller that is not one: who may grant the
    /// platform governor role depends on it.
    pub async fn create(
        &self,
        request: NewAccount,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<AccountView, AccountError> {
        let username = java_trim(request.username.as_deref().unwrap_or("")).to_owned();
        let password = request.password.as_ref().map(|secret| secret.expose()).unwrap_or("");
        let trimmed_role = java_trim(request.role.as_deref().unwrap_or(""));
        let role = if trimmed_role.is_empty() { Role::User.name().to_owned() } else { java_upper(trimmed_role) };

        refuse_if(validate_username(Some(&username)))?;
        refuse_if(validate_password(Some(password)))?;
        let Some(granted) = Role::of(Some(&role)) else {
            return Err(AccountError::InvalidInput(format!("Unknown role: {role}.")));
        };
        self.refuse_governor_administration(acting_account_id, None, Some(granted)).await?;
        if self.store.find_by_username(&username).await?.is_some() {
            return Err(AccountError::InvalidInput(format!("The username \"{username}\" is already taken.")));
        }

        let created_at = self.clock.now();
        let user = NewUser {
            username: username.clone(),
            // Bounded like every column a form writes: past 255 the database refused the row at the write, and the
            // administrator got a 500 for a pasted signature block.
            email: bounded_optional(request.email.as_deref(), "The e-mail address")?,
            display_name: bounded_optional(request.display_name.as_deref(), "The display name")?,
            password: Some(PasswordHash::new(passwords::hash(password))),
            role: role.clone(),
            is_active: true,
            must_change_password: true,
            created_at,
        };
        let saved = self.store.insert(user).await?;
        self.record(actor, saved.id, format!("Account created: {username} ({role})")).await;
        Ok(AccountView { user: UserView::of(&saved), active_sessions: 0 })
    }

    /// Role, activation and password reset, under one set of guard rails.
    ///
    /// **Three gestures close the sessions**: deactivating; resetting the password — the incident-response
    /// gesture, which otherwise left a stolen token authenticating for up to twelve hours; and changing a role. A
    /// reset also revokes the account's integration keys: a key acts for its account, so one minted by whoever held
    /// the stolen credentials outlived the reset meant to shut them out.
    pub async fn update(
        &self,
        id: i64,
        change: AccountChange,
        acting_account_id: Option<i64>,
        actor: &RequestActor,
    ) -> Result<AccountView, AccountError> {
        let mut user = self.require_account(id).await?;

        let role = match change.role.as_deref() {
            None => user.role.clone(),
            Some(requested) => java_upper(java_trim(requested)),
        };
        let is_active = change.is_active.unwrap_or(user.is_active);
        let password = change.password.as_ref().map(|secret| secret.expose());

        if Role::of(Some(&role)).is_none() {
            return Err(AccountError::InvalidInput(format!("Unknown role: {role}.")));
        }
        if let Some(password) = password {
            refuse_if(validate_password(Some(password)))?;
        }

        // On every change, not only a role change: resetting a governor's password, or deactivating it, is
        // administering it just as much.
        self.refuse_governor_administration(acting_account_id, Role::of(Some(&user.role)), Role::of(Some(&role)))
            .await?;
        let is_self = is_self(acting_account_id, id);
        refuse_if(refuse_self_lockout(Change {
            is_self,
            was_admin: is_administrative(&user.role) && user.is_active,
            will_be_admin: is_administrative(&role),
            will_be_active: is_active,
            remaining_active_admins: self.store.count_other_active_admins(&administrative_role_names(), id).await?,
        }))?;
        refuse_if(refuse_own_role_change(is_self, Some(&user.role), Some(&role)))?;

        let mut changes = Vec::new();
        let previous_role = user.role.clone();
        if role != user.role {
            changes.push(format!("role {} → {role}", user.role));
        }
        if is_active != user.is_active {
            changes.push(if is_active { "reactivated" } else { "deactivated" }.to_owned());
        }
        if password.is_some() {
            changes.push("password reset".to_owned());
        }

        user.role = role.clone();
        user.is_active = is_active;
        user.updated_at = self.clock.now();
        if let Some(password) = password {
            user.password = Some(PasswordHash::new(passwords::hash(password)));
            user.must_change_password = true;
        }
        let revoke = !is_active || password.is_some() || role != previous_role;
        let revoked_keys = if password.is_some() {
            let revoked = self.store.save_revoking_everything(&user).await?;
            if !revoked.is_empty() {
                let count = revoked.len();
                changes.push(format!("{count} API key{} revoked", if count == 1 { "" } else { "s" }));
            }
            revoked
        } else {
            self.store.save(&user, revoke).await?;
            Vec::new()
        };

        if !changes.is_empty() {
            self.record(actor, id, format!("Account {}: {}", user.username, changes.join(", "))).await;
        }
        // One entry per key, under the key's id, as a revocation by hand leaves.
        for key in &revoked_keys {
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
        let active_sessions = if revoke { 0 } else { self.sessions_of(id).await? };
        Ok(AccountView { user: UserView::of(&user), active_sessions })
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
        let administers = match acting_account_id {
            Some(acting) => self
                .store
                .find_by_id(acting)
                .await?
                .and_then(|account| Role::of(Some(&account.role)))
                .is_some_and(Role::is_administrative),
            None => false,
        };
        if !administers {
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
            user.password = Some(PasswordHash::new(passwords::hash_of_nothing_anybody_knows()));
        }
        user.updated_at = self.clock.now();
        self.store.save(&user, true).await?;
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
        match attempts.reserve(user.id).await {
            Ok(()) => {}
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
        }
        if !passwords::verify(current_password, user.password.as_ref().map(PasswordHash::encoded)) {
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
        attempts.clear(user.id).await?;
        refuse_if(validate_password(new_password))?;
        let new_password = new_password.unwrap_or("");
        if Some(new_password) == current_password {
            return Err(AccountError::InvalidInput("The new password is the same as the old one.".to_owned()));
        }

        let revoked = self
            .store
            .change_own_password(
                user.id,
                PasswordHash::new(passwords::hash(new_password)),
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
        let Some(found) = verify_sign_in(user, password) else {
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
            let rewritten = PasswordHash::new(passwords::hash(password.unwrap_or("")));
            if let Err(error) = self.store.rehash(user.id, rewritten).await {
                tracing::warn!(username = %user.username, %error, "Could not rewrite the password hash under current parameters.");
            }
        }
    }

    /// The account store, for the sign-in services that share it.
    pub(crate) fn store(&self) -> &S {
        &self.store
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
        self.audit
            .record(AuditRecord {
                operation: AuditOperation::UserUpdated,
                resource: id.to_string(),
                description,
                username: actor.username.clone(),
                ip_address: actor.ip_address.clone(),
                user_agent: actor.user_agent.clone(),
                signal: None,
            })
            .await;
    }
}

/// The one key derivation of a sign-in, whatever the name: the active account's own hash, or the stand-in for an
/// unknown name, a deactivated account and an account without a password — Java's `Optional.map` of a null password
/// is empty, so that one is verified against the stand-in too. The account when the password is its own and it is
/// active.
pub fn verify_sign_in(user: Option<User>, password: Option<&str>) -> Option<User> {
    let active = user.filter(|found| found.is_active);
    let stand_in = stand_in_hash();
    let stored = active.as_ref().and_then(|found| found.password.as_ref().map(PasswordHash::encoded));
    let against = stored.unwrap_or(stand_in.as_str());
    let matches = passwords::verify(password, Some(against));
    active.filter(|_| matches)
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
