//! The second factor — `TotpService`: enrolment, verification, emergency recovery, and how far it reaches.
//!
//! **A factor enrolled on one control plane opens the account on the other.** The secret and the backup codes are
//! encrypted under the contexts `TotpService` binds them to — `user:totp_secret:<id>` and `user:backup_codes:<id>`,
//! which `cp-crypto` builds ([`secret_context`], [`backup_context`]) —
//! with the same `Encryption` (cp-crypto, held to Java's `SecretCipher`), the codes are joined by `,` as
//! `String.join` joins them, and a code is spent by the same compare-and-set statements: a code used on one side is
//! refused on the other.

use std::sync::Arc;

use time::Duration;
use vectispire_cp_crypto::{Encryption, EncryptionError, SecretState};
use vectispire_domain::java;
use vectispire_domain::secret::Secret;

use crate::accounts::{AccountStore, Audit, AuditOperation, AuditRecord, StoreError, User};
pub use crate::persistence::sign_in::Enrolled;
use crate::persistence::sign_in::SignInStore;
use crate::throttle::{SharedClock, Throttle};
use crate::totp;

/// The issuer an authenticator shows beside the account.
pub const ISSUER: &str = "Vectispire";
/// How many backup codes an enrolment hands out.
pub const BACKUP_CODES: usize = 8;

/// `SecondFactorLockedException`'s sentence, answered 429.
pub const LOCKED: &str = "Too many wrong verification codes. Try again later.";
/// Enrolling over an active factor.
pub const ALREADY_ENABLED: &str =
    "MFA is already enabled. Disable it with a current code before enrolling a new device.";
/// The enrolment's code did not match the secret.
pub const INVALID_ENROLMENT_CODE: &str = "Invalid TOTP verification code.";
/// Disabling with a wrong code.
pub const INVALID_DISABLE_CODE: &str = "Invalid code or backup code. MFA could not be disabled.";

/// Encryption at rest, as far as the second factor needs it — `EncryptionService.encrypt` and `inspect`.
pub trait SecretSeal: Send + Sync {
    /// `encrypt(plain, context)`.
    fn seal(&self, plain: &str, context: &str) -> impl Future<Output = Result<String, EncryptionError>> + Send;
    /// `inspect(sealed, context)`: the clear value, or `None` when no configured key reads it (`UNREADABLE`).
    fn open(&self, sealed: &str, context: &str) -> impl Future<Output = Option<Secret>> + Send;
}

impl SecretSeal for Encryption {
    async fn seal(&self, plain: &str, context: &str) -> Result<String, EncryptionError> {
        self.encrypt(plain, context).await
    }

    async fn open(&self, sealed: &str, context: &str) -> Option<Secret> {
        let decrypted = self.inspect(sealed, context).await;
        (decrypted.state() != SecretState::Unreadable).then(|| decrypted.into_plain())
    }
}

impl<V: SecretSeal> SecretSeal for Arc<V> {
    async fn seal(&self, plain: &str, context: &str) -> Result<String, EncryptionError> {
        (**self).seal(plain, context).await
    }

    async fn open(&self, sealed: &str, context: &str) -> Option<Secret> {
        (**self).open(sealed, context).await
    }
}

/// `SetupResponse`: a fresh secret, its enrolment URI and the issuer. Nothing is stored until it is enabled.
#[derive(Debug)]
pub struct Setup {
    pub secret: Secret,
    pub qr_code_uri: Secret,
    pub issuer: &'static str,
}

/// `Enrolment`: the active accounts holding a local password, and of those the ones with no TOTP enrolled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enrolment {
    pub password_accounts: u64,
    pub without_second_factor: u64,
}

/// Why a second-factor gesture was refused.
#[derive(Debug, thiserror::Error)]
pub enum SecondFactorError {
    /// `InvalidInputException`: 400, the sentence shown as it is.
    #[error("{0}")]
    InvalidInput(&'static str),
    /// `SecondFactorLockedException`: 429 with the wait.
    #[error("{}", LOCKED)]
    Locked { retry_after: Duration },
    /// The account is gone — only a deletion racing the request, which the bearer layer found active.
    #[error("Account not found.")]
    AccountMissing,
    /// No key to encrypt with, or the KMS refused: Java's 412 or its sentence.
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// `TotpService`.
#[derive(Clone, Debug)]
pub struct SecondFactor<S, A, T, V> {
    users: S,
    audit: A,
    store: T,
    throttle: Throttle<T>,
    seal: V,
    clock: SharedClock,
}

impl<S, A, T, V> SecondFactor<S, A, T, V>
where
    S: AccountStore + Sync,
    A: Audit + Sync,
    T: SignInStore + Clone,
    V: SecretSeal,
{
    pub fn new(users: S, audit: A, store: T, seal: V, clock: SharedClock) -> SecondFactor<S, A, T, V> {
        let throttle = Throttle::new(store.clone(), clock.clone());
        SecondFactor { users, audit, store, throttle, seal, clock }
    }

    /// How far the local second factor reaches. Two statements, which no isolation level reads from one snapshot: an
    /// account created between them is clamped out rather than reported as "3 of 2".
    pub async fn enrolment(&self) -> Result<Enrolment, StoreError> {
        let accounts = self.store.count_active_with_password().await?;
        let without = self.store.count_active_with_password_and_no_second_factor().await?;
        Ok(Enrolment { password_accounts: accounts, without_second_factor: accounts.min(without) })
    }

    /// A secret to enrol, and the URI an authenticator reads it from.
    pub fn setup(&self, username: &str) -> Setup {
        let secret = totp::generate_secret();
        let uri = totp::qr_code_uri(username, &secret, ISSUER);
        Setup { secret: Secret::new(secret), qr_code_uri: Secret::new(uri), issuer: ISSUER }
    }

    /// Enables the factor the code proves, and hands out the backup codes — their only copy in the clear.
    ///
    /// Enrolling over an active factor is refused: a session left open on somebody's desk was enough to move their
    /// second factor onto one's own phone. Replacing goes through disabling, which asks for a code.
    pub async fn enable(&self, account_id: i64, secret: &str, code: &str) -> Result<Vec<Secret>, SecondFactorError> {
        let user = self.users.find_by_id(account_id).await?.ok_or(SecondFactorError::AccountMissing)?;
        if user.mfa_enabled {
            return Err(SecondFactorError::InvalidInput(ALREADY_ENABLED));
        }
        let now = self.clock.now();
        let Some(step) = totp::matching_step(Some(secret), Some(code), now) else {
            return Err(SecondFactorError::InvalidInput(INVALID_ENROLMENT_CODE));
        };

        let codes = totp::generate_backup_codes(BACKUP_CODES);
        let serialized = Secret::new(codes.join(","));
        let sealed_secret = self.seal.seal(secret, &secret_context(user.id)).await?;
        let sealed_codes = self.seal.seal(serialized.expose(), &backup_context(user.id)).await?;
        // The code that proved the enrolment was seen on this request: its step opens no sign-in after.
        self.store
            .enable_second_factor(
                user.id,
                &Enrolled { totp_secret: sealed_secret, backup_codes: sealed_codes, last_step: step, at: now },
            )
            .await?;
        self.record(&user, format!("MFA / TOTP enabled for user: {}", user.username), None).await;
        Ok(codes.into_iter().map(Secret::new).collect())
    }

    /// Disables the factor, on a current code or a backup code — under the same budget of wrong codes as the
    /// sign-in's challenge, reserved before the code is checked: a session left open could otherwise try codes here
    /// without limit and eventually disarm the factor.
    pub async fn disable(&self, account_id: i64, code: &str) -> Result<(), SecondFactorError> {
        let user = self.users.find_by_id(account_id).await?.ok_or(SecondFactorError::AccountMissing)?;
        let attempt = self.throttle.reserve_second_factor(user.id).await?;
        if !attempt.admitted() {
            return Err(SecondFactorError::Locked { retry_after: attempt.retry_after });
        }
        if !self.verify(&user, Some(code)).await? {
            // The reservation stays: it is this failure.
            return Err(SecondFactorError::InvalidInput(INVALID_DISABLE_CODE));
        }
        self.throttle.clear_second_factor_failures(user.id).await?;
        self.store.disable_second_factor(user.id, self.clock.now()).await?;
        self.record(&user, format!("MFA / TOTP disabled for user: {}", user.username), None).await;
        Ok(())
    }

    /// Whether `code` is a current TOTP code not used before, or one of the backup codes — which it then spends.
    ///
    /// A six-character code is tried as TOTP first; a right code already used is refused like a wrong one (it is the
    /// replay), and falls through to the backup codes like any other. A backup code is spent only if the codes stored
    /// are still the ones read: otherwise another sign-in spent one in between, and a second success would be the
    /// same code accepted twice.
    pub async fn verify(&self, user: &User, code: Option<&str>) -> Result<bool, SecondFactorError> {
        let Some(code) = code else {
            return Ok(false);
        };
        if !user.mfa_enabled || java::is_blank(code) {
            return Ok(false);
        }
        let cleaned = java::trim(code);

        if java::utf16_len(cleaned) == CODE_LENGTH
            && let Some(sealed) = &user.totp_secret
            && let Some(secret) = self.seal.open(sealed.expose(), &secret_context(user.id)).await
            && let Some(step) = totp::matching_step(Some(secret.expose()), Some(cleaned), self.clock.now())
            && self.store.advance_totp_step(user.id, step).await? == 1
        {
            return Ok(true);
        }

        let Some(stored) = &user.mfa_backup_codes else {
            return Ok(false);
        };
        let Some(plain) = self.seal.open(stored.expose(), &backup_context(user.id)).await else {
            return Ok(false);
        };
        let mut codes = java_split_on_comma(plain.expose());
        let Some(position) = codes.iter().position(|candidate| *candidate == cleaned) else {
            return Ok(false);
        };
        codes.remove(position);
        // No key to write with — read by a previous one — is Java's exception too, answered 412: a code that cannot
        // be spent opens nothing, and is not a wrong code either.
        let remaining = self.seal.seal(&codes.join(","), &backup_context(user.id)).await?;
        if self.store.replace_backup_codes(user.id, stored.expose(), &remaining, self.clock.now()).await? != 1 {
            return Ok(false);
        }
        self.record(
            user,
            format!("Emergency backup recovery code used by: {}", user.username),
            Some("MFA_BACKUP_CODE_USED"),
        )
        .await;
        Ok(true)
    }

    /// The throttle the factor's gestures spend, which the sign-in shares.
    pub(crate) fn throttle(&self) -> &Throttle<T> {
        &self.throttle
    }

    async fn record(&self, user: &User, description: String, signal: Option<&'static str>) {
        self.audit
            .record(AuditRecord {
                operation: AuditOperation::UserUpdated,
                resource: user.id.to_string(),
                description,
                username: Some(user.username.clone()),
                ip_address: None,
                user_agent: None,
                signal,
            })
            .await;
    }
}

/// A TOTP code's length, in UTF-16 units (`String.length()`).
const CODE_LENGTH: usize = 6;

/// `TOTP_CONTEXT + ":" + id`, built by `cp-crypto` beside every other context.
pub fn secret_context(user_id: i64) -> String {
    vectispire_cp_crypto::totp_secret_context(user_id)
}

/// `BACKUP_CONTEXT + ":" + id`, the same.
pub fn backup_context(user_id: i64) -> String {
    vectispire_cp_crypto::backup_codes_context(user_id)
}

/// `String.split(",")`: the trailing empty strings dropped, and the empty string one empty element.
fn java_split_on_comma(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return vec![""];
    }
    let mut parts: Vec<&str> = text.split(',').collect();
    while parts.last().is_some_and(|last| last.is_empty()) {
        parts.pop();
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_as_java_splits() {
        assert_eq!(java_split_on_comma(""), vec![""]);
        assert_eq!(java_split_on_comma("a,b"), vec!["a", "b"]);
        assert_eq!(java_split_on_comma("a,,b,,"), vec!["a", "", "b"]);
        assert!(java_split_on_comma(",,").is_empty());
    }

    /// The contexts Java's `TotpService` binds the two columns to: anything else and a factor enrolled on one side
    /// is unreadable on the other.
    #[test]
    fn the_contexts_are_java_s() {
        assert_eq!(secret_context(42), "user:totp_secret:42");
        assert_eq!(backup_context(42), "user:backup_codes:42");
    }
}
