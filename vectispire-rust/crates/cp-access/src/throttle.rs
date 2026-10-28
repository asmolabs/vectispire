//! The sign-in throttle's counters — `AuthService`'s throttle half: [`Reservation`], `reserve`, `release`, the second
//! factor's and the password's budgets. The arithmetic and the keys are [`crate::login_throttle`]'s; this is what
//! writes and counts `t_login_attempt`.
//!
//! **An attempt is counted before it is checked.** The counters used to be read, then the secret verified, then a
//! failure written: attempts arriving together all read four failures and were all admitted, and a ceiling of five let
//! through as many guesses as the attacker could send at once — an Argon2 derivation or a TOTP check is a long window.
//! Each attempt now writes its rows and commits, **then** counts the others': whichever commits k-th sees the k-1
//! before it, so at most the ceiling are admitted however many arrive together. A refused attempt takes its rows back,
//! so being refused does not extend the lockout; an admitted one keeps them as its failure, and a success clears the
//! counter. The cost, accepted as Java accepts it: a burst may be refused whole, each attempt counting the others'
//! rows before they are taken back.

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::accounts::{PasswordAttempts, StoreError, StoreOr};
use crate::login_throttle::{self, MAX_ATTEMPTS_PER_USER, MAX_SECOND_FACTOR_FAILURES, WINDOW};
pub use crate::persistence::sign_in::{AttemptRow, SignInStore};

/// The instant source every sign-in service reads — the credentials' clock, at the microsecond both engines keep.
pub type SharedClock = Arc<dyn crate::credentials::Clock>;

/// An attempt counted before it is checked — `AuthService.Reservation`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// This attempt's own rows, which a success or a refusal removes.
    pub rows: Vec<Uuid>,
    /// Zero when admitted.
    pub retry_after: Duration,
}

impl Reservation {
    pub fn admitted(&self) -> bool {
        self.retry_after.is_zero()
    }

    /// `retryAfter().toSeconds()`: whole seconds, truncated — the figure every message and `Retry-After` carries.
    pub fn retry_after_seconds(&self) -> u64 {
        u64::try_from(self.retry_after.whole_seconds()).unwrap_or(0)
    }
}

/// The counters of `t_login_attempt`.
#[derive(Clone, Debug)]
pub struct Throttle<T> {
    store: T,
    clock: SharedClock,
}

impl<T: SignInStore> Throttle<T> {
    pub fn new(store: T, clock: SharedClock) -> Throttle<T> {
        Throttle { store, clock }
    }

    /// Writes one failure per counter, commits, then decides against each ceiling — the strictest wins. A refused
    /// reservation takes its rows back before it is answered.
    ///
    /// The keys are distinct, as the keys of Java's map are; the order is the caller's and decides nothing but the
    /// order of the statements.
    pub async fn reserve(&self, ceilings: &[(String, usize)]) -> Result<Reservation, StoreError> {
        let now = self.clock.now();
        let keys: Vec<String> = ceilings.iter().map(|(key, _)| key.clone()).collect();
        let own = self.store.record_attempts(&keys, now).await?;

        let since = now.saturating_sub(WINDOW);
        let mut wait = Duration::ZERO;
        for (key, limit) in ceilings {
            let others: Vec<OffsetDateTime> = self
                .store
                .attempts_after(key, since)
                .await?
                .into_iter()
                .filter(|row| !own.contains(&row.id))
                .map(|row| row.occurred_at)
                .collect();
            let retry_after = login_throttle::decide_one(&others, *limit, now).retry_after;
            if retry_after > wait {
                wait = retry_after;
            }
        }

        let reservation = Reservation { rows: own, retry_after: wait };
        if !reservation.admitted() {
            self.release(&reservation).await?;
        }
        Ok(reservation)
    }

    /// Takes a reservation's rows back — a refused attempt, or one whose outcome is not a failure.
    pub async fn release(&self, reservation: &Reservation) -> Result<(), StoreError> {
        if !reservation.rows.is_empty() {
            self.store.delete_attempts(&reservation.rows).await?;
        }
        Ok(())
    }

    /// A second-factor attempt, against the account's budget of wrong codes across challenges.
    pub async fn reserve_second_factor(&self, account_id: i64) -> Result<Reservation, StoreError> {
        self.reserve(&[(login_throttle::second_factor_key(account_id), MAX_SECOND_FACTOR_FAILURES)]).await
    }

    /// A password presented by a signed-in account — changing its own — against the sign-in form's budget: a session
    /// is not a licence to guess the password behind it.
    pub async fn reserve_password(&self, account_id: i64) -> Result<Reservation, StoreError> {
        self.reserve(&[(login_throttle::account_key(account_id), MAX_ATTEMPTS_PER_USER)]).await
    }

    /// A right password: the account's counter starts again, as a sign-in's does.
    pub async fn clear_password_failures(&self, account_id: i64) -> Result<(), StoreError> {
        self.store.delete_attempts_by_key(&login_throttle::account_key(account_id)).await?;
        Ok(())
    }

    /// How long this account must wait before presenting another second-factor code; zero when it may. Asked before a
    /// challenge is issued, and after a wrong code to tell the audit trail whether the account just locked.
    pub async fn second_factor_lockout(&self, account_id: i64) -> Result<Duration, StoreError> {
        let now = self.clock.now();
        let occurrences: Vec<OffsetDateTime> = self
            .store
            .attempts_after(&login_throttle::second_factor_key(account_id), now.saturating_sub(WINDOW))
            .await?
            .into_iter()
            .map(|row| row.occurred_at)
            .collect();
        Ok(login_throttle::decide_one(&occurrences, MAX_SECOND_FACTOR_FAILURES, now).retry_after)
    }

    /// Only a right code clears it — never a right password, which is the whole point.
    pub async fn clear_second_factor_failures(&self, account_id: i64) -> Result<(), StoreError> {
        self.store.delete_attempts_by_key(&login_throttle::second_factor_key(account_id)).await?;
        Ok(())
    }

    /// Clears one counter after a success — `attempts.deleteByCounterKey`.
    pub(crate) async fn clear(&self, key: &str) -> Result<(), StoreError> {
        self.store.delete_attempts_by_key(key).await?;
        Ok(())
    }
}

/// The password budget [`crate::accounts::Accounts::change_own_password`] spends: `reservePassword` and
/// `clearPasswordFailures`, the wait truncated to whole seconds as Java's `toSeconds()` truncates it.
impl<T: SignInStore> PasswordAttempts for Throttle<T> {
    async fn reserve(&self, account_id: i64) -> Result<(), StoreOr<u64>> {
        let reservation = self.reserve_password(account_id).await.map_err(StoreOr::Store)?;
        if reservation.admitted() { Ok(()) } else { Err(StoreOr::Refused(reservation.retry_after_seconds())) }
    }

    async fn clear(&self, account_id: i64) -> Result<(), StoreError> {
        self.clear_password_failures(account_id).await
    }
}
