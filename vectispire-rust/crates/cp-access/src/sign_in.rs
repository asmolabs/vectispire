//! The steps between a person and a session — `AuthService.login` and `AuthenticationFlowService`: the password, the
//! second factor, the single sign-on hand-off's exchange, and changing one's own password. `SignInMethodPolicy` too.
//!
//! **Every outcome is a type, and none of them is an HTTP status.** The routes (task 1.7) decide what each answers —
//! 401, 403, 429 with `Retry-After`, 503 — and this decides which one happened. The split matters most on the second
//! factor, where the wording is itself part of the control: a wrong code and the code that destroyed the challenge are
//! one [`Verification::WrongCode`], so that the answer cannot tell an attacker how many tries are left.
//!
//! **No transaction spans a flow**, as in Java: each write commits by itself, and the throttle's reservation commits
//! before it counts ([`crate::throttle`]).
//!
//! **The order is the behaviour.** The throttle comes before any password comparison — a locked account costs no key
//! derivation — and the derivation happens whatever the name, so the answer's timing says nothing about whether the
//! account exists. On the second factor: an expired challenge, then the account, then the challenge's own count, then
//! the account's budget, then the code.
//!
//! The federated sign-in (`completeFederatedSignIn`) is task 1.4's and is not here.

use std::future::Future;
use std::sync::Arc;

use time::Duration;
use vectispire_cp_crypto::EncryptionError;
use vectispire_domain::secret::Secret;

use crate::accounts::{
    AccountError, AccountStore, Accounts, Audit, AuditOperation, AuditRecord, PasswordChange, SessionHash, StoreError,
    User, UserView, verify_sign_in,
};
use crate::credentials::{CredentialService, IssuedSession, SessionView, hash_of};
use crate::login_throttle::{self, MAX_ATTEMPTS_PER_CLIENT, MAX_ATTEMPTS_PER_USER};
pub use crate::persistence::sign_in::Challenge;
use crate::persistence::sign_in::SignInStore;
use crate::second_factor::{SecondFactor, SecondFactorError, SecretSeal};
use crate::throttle::{SharedClock, Throttle};

/// **A TOTP code is six digits, so the number of tries is the whole security of the second factor.** Three, then the
/// challenge is destroyed and the password exchange starts again.
pub const MAX_MFA_ATTEMPTS: i32 = 3;
/// How many live challenges may be held at once: the sweep clears what expired, this stops the table growing between
/// two sweeps.
pub const MAX_MFA_CHALLENGES: u64 = 10_000;

/// `t_mfa_challenge.user_agent`'s width, as `t_session`'s.
const USER_AGENT_MAX: usize = 255;

/// How long a challenge waits for its code.
pub const CHALLENGE_LIFETIME: Duration = Duration::seconds(300);
/// `labelOf`'s answer for a provider that names itself nothing.
pub const DEFAULT_PROVIDER_LABEL: &str = "single sign-on";

/// The sessions a sign-in opens and a hand-off trades — [`CredentialService`]'s, behind a port so that the flows are
/// tested with sessions in memory.
pub trait SessionDoor: Send + Sync {
    /// A session for an account: the token is its only copy.
    fn open(
        &self,
        user_id: i64,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> impl Future<Output = Result<IssuedSession, StoreError>> + Send;
    /// `resolveHandoff`.
    fn resolve_handoff(&self, token: &str) -> impl Future<Output = Result<Option<SessionView>, StoreError>> + Send;
    /// `exchangeOnce`: `None` when the hand-off was already consumed.
    fn exchange_once(
        &self,
        handoff: &SessionView,
    ) -> impl Future<Output = Result<Option<IssuedSession>, StoreError>> + Send;
    /// `revoke`.
    fn revoke(&self, session: &SessionView) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// `sessions.deleteExpired(now)`: the hourly purge.
    fn purge_expired(&self) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

fn opaque(error: crate::credentials::StoreError) -> StoreError {
    StoreError(Box::new(error))
}

impl SessionDoor for CredentialService {
    async fn open(
        &self,
        user_id: i64,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<IssuedSession, StoreError> {
        self.open_session(user_id, user_agent, ip_address).await.map_err(opaque)
    }

    async fn resolve_handoff(&self, token: &str) -> Result<Option<SessionView>, StoreError> {
        CredentialService::resolve_handoff(self, token).await.map_err(opaque)
    }

    async fn exchange_once(&self, handoff: &SessionView) -> Result<Option<IssuedSession>, StoreError> {
        CredentialService::exchange_once(self, handoff).await.map_err(opaque)
    }

    async fn revoke(&self, session: &SessionView) -> Result<(), StoreError> {
        CredentialService::revoke(self, session).await.map_err(opaque)
    }

    async fn purge_expired(&self) -> Result<u64, StoreError> {
        CredentialService::purge_expired(self).await.map_err(opaque)
    }
}

impl<D: SessionDoor> SessionDoor for Arc<D> {
    async fn open(
        &self,
        user_id: i64,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<IssuedSession, StoreError> {
        (**self).open(user_id, user_agent, ip_address).await
    }

    async fn resolve_handoff(&self, token: &str) -> Result<Option<SessionView>, StoreError> {
        (**self).resolve_handoff(token).await
    }

    async fn exchange_once(&self, handoff: &SessionView) -> Result<Option<IssuedSession>, StoreError> {
        (**self).exchange_once(handoff).await
    }

    async fn revoke(&self, session: &SessionView) -> Result<(), StoreError> {
        (**self).revoke(session).await
    }

    async fn purge_expired(&self) -> Result<u64, StoreError> {
        (**self).purge_expired().await
    }
}

/// Which ways in this deployment accepts — `SignInMethodPolicy`.
///
/// `VECTISPIRE_PASSWORD_LOGIN=false` closes the password door, **but only when an identity provider is configured**:
/// closing the only door that works locks everybody out of a security tool, and the person best placed to notice is
/// the one who can no longer sign in. Asked for without a provider, the password stays and the reason is logged at
/// error level. The way back is an operator's restart, never a button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignInMethodPolicy {
    single_sign_on: bool,
    password: bool,
}

impl SignInMethodPolicy {
    pub fn new(single_sign_on: bool, password_requested: bool) -> SignInMethodPolicy {
        if !password_requested && !single_sign_on {
            tracing::error!(
                "VECTISPIRE_PASSWORD_LOGIN is false and no identity provider is configured, so password sign-in stays \
                 enabled: honouring it would leave no way to sign in at all. Set VECTISPIRE_OIDC_ISSUER, or leave \
                 password sign-in on."
            );
        }
        SignInMethodPolicy { single_sign_on, password: password_requested || !single_sign_on }
    }

    /// Whether a password may be exchanged for a session at all.
    pub fn password_allowed(&self) -> bool {
        self.password
    }

    pub fn single_sign_on_available(&self) -> bool {
        self.single_sign_on
    }
}

/// `AuthService.LoginRequest`. `ip_address` is the client's address as the trusted proxies resolve it, and the key of
/// the second counter — never an id the caller chooses, which would be a counter the caller resets.
#[derive(Clone, Debug)]
pub struct LoginRequest<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub user_agent: Option<&'a str>,
    pub ip_address: Option<&'a str>,
}

/// `AuthService.Outcome`.
#[derive(Debug)]
pub enum LoginOutcome {
    /// A session, and the clear token — which exists nowhere else.
    Success {
        issued: IssuedSession,
        user: Box<User>,
    },
    /// Wrong password, unknown account or a deactivated one: one case on purpose, or the form is an oracle.
    Invalid,
    /// The password was right and the account owes a code. No session exists yet.
    SecondFactorRequired(Box<User>),
    Blocked(Duration),
}

/// A login's outcome and the entry the caller writes — `AuthService.LoginResult`.
#[derive(Debug)]
pub struct LoginResult {
    pub outcome: LoginOutcome,
    pub audit: AuditRecord,
}

/// What a password exchange came to — `AuthenticationFlowService.SignIn`.
#[derive(Debug)]
pub enum SignIn {
    /// The deployment accepts single sign-on only. Recorded before returning.
    PasswordDisabled,
    Throttled(Duration),
    Refused,
    /// The password was right and the account owes a code; the token is the only copy.
    ChallengeIssued(Secret),
    /// The password was right, but ten thousand live challenges are already waiting: transient by construction.
    ChallengesSaturated,
    SignedIn {
        issued: IssuedSession,
        user: Box<UserView>,
    },
}

/// What presenting a second-factor code came to — `AuthenticationFlowService.Verification`.
#[derive(Debug)]
pub enum Verification {
    /// Unknown, expired, or destroyed earlier: sign in again.
    ChallengeInvalid,
    AccountMissing,
    /// A wrong code, whether or not it was the last one allowed — deliberately one case.
    WrongCode,
    /// The account has absorbed its wrong codes for this window, whatever challenge carries it.
    Throttled(Duration),
    Verified {
        issued: IssuedSession,
        user: Box<UserView>,
    },
}

/// What trading a single sign-on hand-off came to — `AuthenticationFlowService.Handoff`.
#[derive(Debug)]
pub enum Handoff {
    Expired,
    AccountMissing,
    /// A session of its own, not the hand-off's — which no longer exists.
    Exchanged {
        issued: IssuedSession,
        user: Box<UserView>,
    },
}

/// `SignInOptions`: whether a provider is wired, its name, and whether a password may still be exchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignInOptions {
    pub single_sign_on: bool,
    pub label: Option<String>,
    pub password: bool,
}

/// Why a flow could not be carried out — the store, or a second factor whose codes cannot be re-encrypted.
#[derive(Debug, thiserror::Error)]
pub enum SignInError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
}

impl From<AccountError> for SignInError {
    fn from(error: AccountError) -> SignInError {
        match error {
            AccountError::Store(store) => SignInError::Store(store),
            // The lookup and the derivation raise nothing else; kept opaque rather than lost.
            other => SignInError::Store(StoreError(other.to_string().into())),
        }
    }
}

impl From<SecondFactorError> for SignInError {
    fn from(error: SecondFactorError) -> SignInError {
        match error {
            SecondFactorError::Store(store) => SignInError::Store(store),
            SecondFactorError::Encryption(encryption) => SignInError::Encryption(encryption),
            // `verify` raises neither a refusal nor a missing account.
            other => SignInError::Store(StoreError(other.to_string().into())),
        }
    }
}

/// What the flows are made of.
#[derive(Debug)]
pub struct SignInParts<S, A, T, D, V> {
    pub users: S,
    pub audit: A,
    pub store: T,
    pub sessions: D,
    pub seal: V,
    pub clock: SharedClock,
    pub methods: SignInMethodPolicy,
    /// The identity provider's display name when one is configured (task 1.4 fills it from the client registration).
    pub provider_label: Option<String>,
}

/// `AuthService.login` and `AuthenticationFlowService`.
#[derive(Debug)]
pub struct SignInFlow<S, A, T, D, V> {
    accounts: Accounts<S, A, SharedClock>,
    audit: A,
    store: T,
    totp: SecondFactor<S, A, T, V>,
    sessions: D,
    methods: SignInMethodPolicy,
    provider_label: Option<String>,
    clock: SharedClock,
}

impl<S, A, T, D, V> SignInFlow<S, A, T, D, V>
where
    S: AccountStore + Clone + Sync,
    A: Audit + Clone + Sync,
    T: SignInStore + Clone,
    D: SessionDoor,
    V: SecretSeal,
{
    pub fn new(parts: SignInParts<S, A, T, D, V>) -> SignInFlow<S, A, T, D, V> {
        let SignInParts { users, audit, store, sessions, seal, clock, methods, provider_label } = parts;
        SignInFlow {
            accounts: Accounts::new(users.clone(), audit.clone(), clock.clone()),
            totp: SecondFactor::new(users, audit.clone(), store.clone(), seal, clock.clone()),
            audit,
            store,
            sessions,
            methods,
            provider_label,
            clock,
        }
    }

    /// The second factor's own gestures — enrolment, disabling, the enrolment counts.
    pub fn second_factor(&self) -> &SecondFactor<S, A, T, V> {
        &self.totp
    }

    fn throttle(&self) -> &Throttle<T> {
        self.totp.throttle()
    }

    /// `AuthService.login`: the throttle, one derivation, then a session or a challenge owed.
    ///
    /// **The account is looked up before the throttle** — a query and no hashing — because the account is what the
    /// counter protects and the name typed is not the account: the collation opens `alice` for `Alice`, so each
    /// spelling would have been five tries of its own. The folded name is counted as well, for an existing account
    /// and an unknown one alike, and the client's address beside them; the strictest decides.
    pub async fn login(&self, request: &LoginRequest<'_>) -> Result<LoginResult, SignInError> {
        let user = self.accounts.sign_in_lookup(Some(request.username)).await?;
        let name_key = login_throttle::user_key(request.username);
        // `String.valueOf(ipAddress)`: an absent address is counted under the four letters.
        let client_key = login_throttle::client_key(request.ip_address.unwrap_or("null"));
        let mut ceilings = Vec::with_capacity(3);
        if let Some(found) = &user {
            ceilings.push((login_throttle::account_key(found.id), MAX_ATTEMPTS_PER_USER));
        }
        ceilings.push((name_key, MAX_ATTEMPTS_PER_USER));
        ceilings.push((client_key.clone(), MAX_ATTEMPTS_PER_CLIENT));

        let throttle = self.throttle().reserve(&ceilings).await?;
        if !throttle.admitted() {
            // Refused before any hashing: that is the point of checking first.
            return Ok(LoginResult {
                outcome: LoginOutcome::Blocked(throttle.retry_after),
                audit: entry(
                    AuditOperation::LoginBlocked,
                    request.username,
                    format!("Attempt refused by the throttle ({}s to wait)", throttle.retry_after_seconds()),
                    request.username,
                    // The ceiling, and not "password sign-in is off", which shares the operation: only the writer can
                    // tell the two apart.
                    Some("SIGN_IN_THROTTLED"),
                ),
            });
        }

        let Some(found) = verify_sign_in(user, Some(request.password)) else {
            // The reservation's rows stay: they are this failure.
            return Ok(LoginResult {
                outcome: LoginOutcome::Invalid,
                // Silent on whether the account exists.
                audit: entry(
                    AuditOperation::LoginFailure,
                    request.username,
                    "Login failed".to_owned(),
                    request.username,
                    None,
                ),
            });
        };

        // **A success clears what it proves, and the address is not among it**: the account and the name start again,
        // the address keeps its failures — one sign-in to one's own account every nineteen tries used to wipe what the
        // address had tried against others — and this attempt's own rows go, a success not being a failure.
        self.throttle().release(&throttle).await?;
        for (key, _) in ceilings.iter().filter(|(key, _)| *key != client_key) {
            self.throttle().clear(key).await?;
        }

        self.accounts.rehash_if_stale(&found, Some(request.password)).await;
        if found.mfa_enabled {
            // **No session yet**: it is opened when the code is verified, and not before.
            let audit = entry(
                AuditOperation::LoginSuccess,
                &found.username,
                "Password accepted, second factor required".to_owned(),
                &found.username,
                None,
            );
            return Ok(LoginResult { outcome: LoginOutcome::SecondFactorRequired(Box::new(found)), audit });
        }
        let issued = self.sessions.open(found.id, request.user_agent, request.ip_address).await?;
        let audit =
            entry(AuditOperation::LoginSuccess, &found.username, "Login succeeded".to_owned(), &found.username, None);
        Ok(LoginResult { outcome: LoginOutcome::Success { issued, user: Box::new(found) }, audit })
    }

    /// A password presented for exchange.
    pub async fn sign_in(&self, attempt: &LoginRequest<'_>) -> Result<SignIn, SignInError> {
        if !self.methods.password_allowed() {
            self.audit
                .record(AuditRecord {
                    operation: AuditOperation::LoginBlocked,
                    resource: attempt.username.to_owned(),
                    description: "Password sign-in is disabled on this deployment".to_owned(),
                    username: Some(attempt.username.to_owned()),
                    ip_address: attempt.ip_address.map(str::to_owned),
                    user_agent: attempt.user_agent.map(str::to_owned),
                    signal: None,
                })
                .await;
            return Ok(SignIn::PasswordDisabled);
        }

        let result = self.login(attempt).await?;
        // Carried across with its signal: rebuilt without it, the throttle's entry reached the log and the SOC never
        // heard of it.
        self.audit
            .record(AuditRecord {
                ip_address: attempt.ip_address.map(str::to_owned),
                user_agent: attempt.user_agent.map(str::to_owned),
                ..result.audit
            })
            .await;

        Ok(match result.outcome {
            LoginOutcome::Blocked(retry_after) => SignIn::Throttled(retry_after),
            LoginOutcome::Invalid => SignIn::Refused,
            LoginOutcome::SecondFactorRequired(owed) => {
                // A locked second factor issues no challenge.
                let locked = self.throttle().second_factor_lockout(owed.id).await?;
                if !locked.is_zero() {
                    return Ok(SignIn::Throttled(locked));
                }
                let token = uuid::Uuid::new_v4().as_hyphenated().to_string();
                let expires_at = self.clock.now().saturating_add(CHALLENGE_LIFETIME);
                if self.remember_challenge(&token, owed.id, expires_at, attempt).await? {
                    SignIn::ChallengeIssued(Secret::new(token))
                } else {
                    SignIn::ChallengesSaturated
                }
            }
            LoginOutcome::Success { issued, user } => SignIn::SignedIn { issued, user: Box::new(UserView::of(&user)) },
        })
    }

    /// Stores a challenge, sweeping the ones nobody came back for: an abandoned sign-in leaves a row only a later
    /// presentation of the same token would remove, and there will not be one. The cap after the sweep is the backstop
    /// for ten thousand **live** challenges — something generating them faster than they expire, which is refused
    /// rather than grown. In the database, so that any instance can answer the code.
    ///
    /// The user agent is stored as it came, as Java stores it (the README's note: Java does not clip it to the
    /// column).
    async fn remember_challenge(
        &self,
        token: &str,
        user_id: i64,
        expires_at: time::OffsetDateTime,
        attempt: &LoginRequest<'_>,
    ) -> Result<bool, StoreError> {
        let now = self.clock.now();
        self.store.delete_expired_challenges(now).await?;
        if self.store.count_live_challenges(now).await? >= MAX_MFA_CHALLENGES {
            return Ok(false);
        }
        self.store
            .insert_challenge(&Challenge {
                token_hash: hash_of(token),
                user_id,
                expires_at,
                attempts: 0,
                // Clipped as a session's is: unclipped, a User-Agent past the column failed the insert after the
                // password had been accepted — the defect fixed on the Java side in the same terms.
                user_agent: vectispire_domain::bounded_text::clip(attempt.user_agent, USER_AGENT_MAX)
                    .map(str::to_owned),
                ip_address: attempt.ip_address.map(str::to_owned),
            })
            .await?;
        Ok(true)
    }

    /// A second-factor code presented against a challenge.
    pub async fn verify(
        &self,
        mfa_token: &str,
        code: &str,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<Verification, SignInError> {
        // Hashed before it touches the store, like a session token.
        let key = hash_of(mfa_token);
        let challenge = match self.store.find_challenge(&key).await? {
            Some(challenge) if self.clock.now() <= challenge.expires_at => challenge,
            _ => {
                self.store.discard_challenge(&key).await?;
                return Ok(Verification::ChallengeInvalid);
            }
        };

        // **A deactivated account is refused here too**: the code may arrive minutes after an administrator
        // deactivated it, which is exactly when a session must not be issued.
        let Some(user) = self.accounts.store().find_by_id(challenge.user_id).await?.filter(|user| user.is_active)
        else {
            self.store.discard_challenge(&key).await?;
            return Ok(Verification::AccountMissing);
        };

        // **Counted before the code is checked**, on the challenge by the database and read back — the fourth
        // presentation of a token is refused whatever the timing — and on the account by a reservation.
        self.store.count_challenge_attempt(&key).await?;
        let presented = self
            .store
            .find_challenge(&key)
            .await?
            .map_or(MAX_MFA_ATTEMPTS.saturating_add(1), |challenge| challenge.attempts);
        if presented > MAX_MFA_ATTEMPTS {
            self.store.discard_challenge(&key).await?;
            return Ok(Verification::ChallengeInvalid);
        }
        let attempt = self.throttle().reserve_second_factor(user.id).await?;
        if !attempt.admitted() {
            // The challenge goes too: it would otherwise outlive the lockout and resume the search where it stopped.
            self.store.discard_challenge(&key).await?;
            return Ok(Verification::Throttled(attempt.retry_after));
        }

        if !self.totp.verify(&user, Some(code)).await? {
            // The reservation stays: it is this failure. Then whether the account just locked, which with a destroyed
            // challenge is the moment a guessing attempt stops — what a SOC wants to hear.
            let account_locked = !self.throttle().second_factor_lockout(user.id).await?.is_zero();
            // **The challenge dies on the last try, and that is the control**: alive after a wrong code, a six-digit
            // secret is a five-minute exhaustive search.
            let exhausted = presented >= MAX_MFA_ATTEMPTS;
            if exhausted {
                self.store.discard_challenge(&key).await?;
            }
            let description = format!(
                "{}{}",
                if exhausted {
                    format!("MFA challenge destroyed after {MAX_MFA_ATTEMPTS} invalid verification codes")
                } else {
                    "Invalid MFA verification code attempt".to_owned()
                },
                if account_locked { "; second factor locked for this account" } else { "" }
            );
            self.audit
                .record(AuditRecord {
                    operation: AuditOperation::LoginFailure,
                    resource: user.username.clone(),
                    description,
                    username: Some(user.username.clone()),
                    ip_address: ip_address.map(str::to_owned),
                    user_agent: user_agent.map(str::to_owned),
                    signal: (exhausted || account_locked).then_some("MFA_FAILURE_CEILING"),
                })
                .await;
            return Ok(Verification::WrongCode);
        }

        self.store.discard_challenge(&key).await?;
        self.throttle().clear_second_factor_failures(user.id).await?;
        let issued =
            self.sessions.open(user.id, challenge.user_agent.as_deref(), challenge.ip_address.as_deref()).await?;
        self.audit
            .record(AuditRecord {
                operation: AuditOperation::LoginSuccess,
                resource: user.username.clone(),
                description: format!("Signed in with MFA / TOTP: {}", user.username),
                username: Some(user.username.clone()),
                ip_address: ip_address.map(str::to_owned),
                user_agent: user_agent.map(str::to_owned),
                signal: None,
            })
            .await;
        Ok(Verification::Verified { issued, user: Box::new(UserView::of(&user)) })
    }

    /// Trades a single sign-on hand-off for a session, **once**: the hand-off is consumed and a new session issued, so
    /// a second presentation of the cookie finds nothing.
    pub async fn exchange(&self, token: &str) -> Result<Handoff, SignInError> {
        let Some(handoff) = self.sessions.resolve_handoff(token).await? else {
            return Ok(Handoff::Expired);
        };
        let Some(user) = self.accounts.store().find_by_id(handoff.user_id).await?.filter(|user| user.is_active) else {
            self.sessions.revoke(&handoff).await?;
            return Ok(Handoff::AccountMissing);
        };
        Ok(match self.sessions.exchange_once(&handoff).await? {
            Some(issued) => Handoff::Exchanged { issued, user: Box::new(UserView::of(&user)) },
            None => Handoff::Expired,
        })
    }

    /// Whether single sign-on is wired, its label, and whether a password is accepted.
    pub fn options(&self) -> SignInOptions {
        SignInOptions {
            single_sign_on: self.methods.single_sign_on_available(),
            label: self
                .methods
                .single_sign_on_available()
                .then(|| self.provider_label.clone().unwrap_or_else(|| DEFAULT_PROVIDER_LABEL.to_owned())),
            password: self.methods.password_allowed(),
        }
    }

    /// Changes one's own password — [`Accounts::change_own_password`], spending the sign-in's password budget.
    #[allow(clippy::too_many_arguments)]
    pub async fn change_password(
        &self,
        account_id: i64,
        current_session: Option<SessionHash>,
        current_password: Option<&str>,
        new_password: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<PasswordChange, AccountError> {
        self.accounts
            .change_own_password(
                self.throttle(),
                account_id,
                current_session,
                current_password,
                new_password,
                ip_address,
                user_agent,
            )
            .await
    }
}

/// `AuditLogService.Record.of`: no address and no user agent — the caller adds its own.
fn entry(
    operation: AuditOperation,
    resource: &str,
    description: String,
    username: &str,
    signal: Option<&'static str>,
) -> AuditRecord {
    AuditRecord {
        operation,
        resource: resource.to_owned(),
        description,
        username: Some(username.to_owned()),
        ip_address: None,
        user_agent: None,
        signal,
    }
}
