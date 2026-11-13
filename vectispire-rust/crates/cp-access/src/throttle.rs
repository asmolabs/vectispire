//! The sign-in throttle's counters — `AuthService`'s throttle half: [`Reservation`], `reserve`, `release`, the second
//! factor's and the password's budgets, and the clients each account signs in from. The arithmetic and the keys are
//! [`crate::login_throttle`]'s; this is what writes and counts `t_login_attempt` and `t_sign_in_client`.
//!
//! **An attempt is counted before it is checked.** The counters used to be read, then the secret verified, then a
//! failure written: attempts arriving together all read four failures and were all admitted, and a ceiling of five let
//! through as many guesses as the attacker could send at once — an Argon2 derivation or a TOTP check is a long window.
//! Each attempt now writes its rows and commits, **then** counts the others': whichever commits k-th sees the k-1
//! before it, so at most the ceiling are admitted however many arrive together. A refused attempt takes its rows back,
//! so being refused does not extend the lockout; an admitted one keeps them as its failure, and a success clears the
//! counter. The cost, accepted as Java accepts it: a burst may be refused whole, each attempt counting the others'
//! rows before they are taken back.
//!
//! **Some ceilings are soft** — the account's budget across every client. Their verdict is
//! [`Reservation::budget_retry_after`], not a refusal: whether it refuses is the caller's to decide, by whether this
//! client is one the account signs in from ([`Throttle::is_known_client`]) or sent the second factor with the password.

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::accounts::{PasswordAttempts, StoreError, StoreOr};
use crate::login_throttle::{self, MAX_SECOND_FACTOR_FAILURES, SignInLimits, WINDOW};
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
    /// The soft ceilings' verdict, which [`Reservation::retry_after`] leaves out: zero when the account's budget across
    /// clients is not spent.
    pub budget_retry_after: Duration,
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

/// The counters of `t_login_attempt`, under the deployment's ceilings.
#[derive(Clone, Debug)]
pub struct Throttle<T> {
    store: T,
    clock: SharedClock,
    limits: SignInLimits,
}

impl<T: SignInStore> Throttle<T> {
    /// Under the shipped ceilings.
    pub fn new(store: T, clock: SharedClock) -> Throttle<T> {
        Throttle::with_limits(store, clock, SignInLimits::default())
    }

    /// Under the ceilings `vectispire.sign-in.*` sets.
    pub fn with_limits(store: T, clock: SharedClock, limits: SignInLimits) -> Throttle<T> {
        Throttle { store, clock, limits }
    }

    pub fn limits(&self) -> SignInLimits {
        self.limits
    }

    /// Writes one failure per counter, commits, then decides against each ceiling — the strictest wins. A refused
    /// reservation takes its rows back before it is answered.
    ///
    /// The keys are distinct, as the keys of Java's map are; the order is the caller's and decides nothing but the
    /// order of the statements.
    pub async fn reserve(&self, ceilings: &[(String, usize)]) -> Result<Reservation, StoreError> {
        self.reserve_with_soft(ceilings, &[]).await
    }

    /// The same, with the ceilings whose keys are in `soft` answered in [`Reservation::budget_retry_after`] rather than
    /// refused. Their rows are written and counted like any other's.
    pub async fn reserve_with_soft(
        &self,
        ceilings: &[(String, usize)],
        soft: &[String],
    ) -> Result<Reservation, StoreError> {
        let now = self.clock.now();
        let keys: Vec<String> = ceilings.iter().map(|(key, _)| key.clone()).collect();
        let own = self.store.record_attempts(&keys, now).await?;

        let since = now.saturating_sub(WINDOW);
        let (mut wait, mut budget) = (Duration::ZERO, Duration::ZERO);
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
            if soft.contains(key) {
                budget = budget.max(retry_after);
            } else {
                wait = wait.max(retry_after);
            }
        }

        let reservation = Reservation { rows: own, retry_after: wait, budget_retry_after: budget };
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

    /// `reservePassword`: a password presented by a signed-in account — changing its own — against the sign-in
    /// form's budget from the same client, and the account's across every client. A session is not a licence to guess
    /// the password behind it.
    ///
    /// The budget across clients is soft here as at sign-in, by the same rule: a session is no exemption of its own —
    /// it may be a stolen one, used from anywhere — but the client the owner signs in from is. Past the budget from
    /// another client, the rows go back and the refusal carries the budget's wait.
    pub async fn reserve_password(&self, account_id: i64, ip_address: Option<&str>) -> Result<Reservation, StoreError> {
        let everywhere = login_throttle::account_key(account_id);
        let reservation = self
            .reserve_with_soft(
                &[
                    (
                        login_throttle::account_key_from_client(account_id, client(ip_address)),
                        self.limits.failures_per_account_from_client,
                    ),
                    (everywhere.clone(), self.limits.failures_per_account),
                ],
                &[everywhere],
            )
            .await?;
        if reservation.admitted()
            && !reservation.budget_retry_after.is_zero()
            && !self.is_known_client(Some(account_id), None, ip_address).await?
        {
            self.release(&reservation).await?;
            return Ok(Reservation {
                rows: Vec::new(),
                retry_after: reservation.budget_retry_after,
                budget_retry_after: Duration::ZERO,
            });
        }
        Ok(reservation)
    }

    /// `clearPasswordFailures`: a right password — the account's counter from this client starts again, as a
    /// sign-in's does. The global one keeps the other clients' failures.
    pub async fn clear_password_failures(&self, account_id: i64, ip_address: Option<&str>) -> Result<(), StoreError> {
        self.store
            .delete_attempts_by_key(&login_throttle::account_key_from_client(account_id, client(ip_address)))
            .await?;
        Ok(())
    }

    /// `isKnownClient`: whether this client has signed in to the account within the retention. **Asked for an unknown
    /// name too**, of a key no account holds: the question is a query, and asked only when the account exists it would
    /// time the answer to "does it exist". An absent address is known to nobody.
    pub async fn is_known_client(
        &self,
        account_id: Option<i64>,
        username: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<bool, StoreError> {
        let Some(ip_address) = ip_address else { return Ok(false) };
        let key = match account_id {
            Some(id) => login_throttle::known_client_key(id, ip_address),
            None => login_throttle::no_account_key(username, ip_address),
        };
        let since = self.clock.now().saturating_sub(self.limits.known_client_retention);
        let known = self.store.known_client_after(&key, since).await?;
        Ok(account_id.is_some() && known)
    }

    /// `rememberClient`: the client a session was opened for, **never failing the sign-in** — a sign-in that succeeded
    /// is not refused over the record that makes the next one easier, and a concurrent sign-in inserting the same key
    /// first is the same record.
    pub async fn remember_client(&self, account_id: i64, ip_address: Option<&str>) {
        let Some(ip_address) = ip_address else { return };
        let key = login_throttle::known_client_key(account_id, ip_address);
        let now = self.clock.now();
        let outcome = match self.store.touch_known_client(&key, now).await {
            Ok(0) => self.store.insert_known_client(&key, account_id, now).await,
            Ok(_) => Ok(()),
            Err(failed) => Err(failed),
        };
        if let Err(could_not_record) = outcome {
            tracing::debug!("Could not record the client of account {account_id}: {could_not_record}");
        }
    }

    /// The known clients past the retention — the hourly purge. A client known past it is not exempted anyway, since
    /// the read asks for the retention too: this only bounds the table.
    pub async fn forget_stale_clients(&self) -> Result<u64, StoreError> {
        self.store
            .delete_known_clients_before(self.clock.now().saturating_sub(self.limits.known_client_retention))
            .await
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

/// `String.valueOf(ipAddress)`: an absent address is counted under the four letters.
pub(crate) fn client(ip_address: Option<&str>) -> &str {
    ip_address.unwrap_or("null")
}

/// The password budget [`crate::accounts::Accounts::change_own_password`] spends: `reservePassword` and
/// `clearPasswordFailures`, the wait truncated to whole seconds as Java's `toSeconds()` truncates it.
impl<T: SignInStore> PasswordAttempts for Throttle<T> {
    type Held = Reservation;

    async fn reserve(&self, account_id: i64, ip_address: Option<&str>) -> Result<Reservation, StoreOr<u64>> {
        let reservation = self.reserve_password(account_id, ip_address).await.map_err(StoreOr::Store)?;
        if reservation.admitted() { Ok(reservation) } else { Err(StoreOr::Refused(reservation.retry_after_seconds())) }
    }

    async fn release(&self, held: &Reservation) -> Result<(), StoreError> {
        Throttle::release(self, held).await
    }

    async fn clear(&self, account_id: i64, ip_address: Option<&str>) -> Result<(), StoreError> {
        self.clear_password_failures(account_id, ip_address).await
    }
}
