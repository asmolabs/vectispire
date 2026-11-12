//! The sign-in's tables — `t_login_attempt` (`LoginAttemptRepository`), `t_mfa_challenge` (`MfaChallengeRepository`),
//! `t_rate_window` (`RateWindowRepository`), and the second factor's columns of `t_user` (`UserRepository`'s
//! `advanceTotpStep`, `replaceBackupCodes`, the two enrolment counts, and the writes `TotpService` makes through
//! `save`).
//!
//! **Behind ports, as the accounts' store is** ([`SignInStore`], [`RateWindowStore`]): the services above are written
//! against the traits, so that their order of operations is tested with a store in memory, and every statement is run
//! on both engines by `tests/sign_in_on_both_engines.rs`. [`SqlSignInStore`] is the one implementation that ships.
//!
//! **Checked at compile time**, each engine's statements behind its feature, as the credentials' are. One statement is
//! not checked: taking a reservation's rows back on **MySQL**, whose `in (…)` holds one placeholder per row — MySQL has
//! no array parameter, and the spellings that fake one compare under another collation (the README's note on the
//! administrator count). PostgreSQL's `= any($1)` is checked.
//!
//! **No statement here is a read-modify-write.** A wrong code is counted by `attempts = attempts + 1`, a TOTP step is
//! recorded only when it is later than the stored one, the backup codes are replaced only when they are still the
//! ciphertext read, a window is incremented by the database and its first hit is a bare insert the primary key
//! arbitrates: each of those was a race on the Java side before it was a statement.

mod attempts;
mod challenges;
mod rate_windows;
mod second_factor;

use std::future::Future;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::{Db, Mode};

use crate::persistence::model::StoreError;

/// A failed attempt as counted: its id, so a reservation can tell its own rows from the others', and its instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptRow {
    pub id: Uuid,
    pub occurred_at: OffsetDateTime,
}

/// A sign-in waiting for its code — `MfaChallengeEntity`. The key is the token's hash, never the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub token_hash: String,
    pub user_id: i64,
    pub expires_at: OffsetDateTime,
    pub attempts: i32,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

/// The second factor an enrolment writes: the four columns `TotpService.enable` sets, and `updated_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolled {
    pub totp_secret: String,
    pub backup_codes: String,
    pub last_step: i64,
    pub at: OffsetDateTime,
}

/// Every statement of the sign-in, the attempts, the challenges and the second factor's columns.
pub trait SignInStore: Send + Sync {
    /// One row per key at `at`, in one transaction that commits before this returns — answers the rows' ids.
    fn record_attempts(
        &self,
        keys: &[String],
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<Vec<Uuid>, StoreError>> + Send;
    /// `findByCounterKeyAndOccurredAtAfter`: strictly after `after`.
    fn attempts_after(
        &self,
        key: &str,
        after: OffsetDateTime,
    ) -> impl Future<Output = Result<Vec<AttemptRow>, StoreError>> + Send;
    /// `deleteByCounterKey`.
    fn delete_attempts_by_key(&self, key: &str) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// `deleteByIdIn`: one statement.
    fn delete_attempts(&self, ids: &[Uuid]) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// `deleteBefore`: strictly before `cutoff`.
    fn delete_attempts_before(&self, cutoff: OffsetDateTime) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// `findById(tokenHash)`.
    fn find_challenge(&self, token_hash: &str) -> impl Future<Output = Result<Option<Challenge>, StoreError>> + Send;
    /// `save(new MfaChallengeEntity)`.
    fn insert_challenge(&self, challenge: &Challenge) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// `countAttempt`: one more presentation, counted by the database.
    fn count_challenge_attempt(&self, token_hash: &str) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// `discard`: one statement, whatever the row's state.
    fn discard_challenge(&self, token_hash: &str) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// `deleteExpired`: expired strictly before `now`.
    fn delete_expired_challenges(&self, now: OffsetDateTime) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// `countByExpiresAtAfter`: live strictly after `now`.
    fn count_live_challenges(&self, now: OffsetDateTime) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// `advanceTotpStep`: 1 when `step` is later than the last one used (or none was), 0 otherwise.
    fn advance_totp_step(&self, user_id: i64, step: i64) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// `replaceBackupCodes`: 1 when the stored codes were still `expected`, 0 when somebody spent one first.
    fn replace_backup_codes(
        &self,
        user_id: i64,
        expected: &str,
        replacement: &str,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// What `TotpService.enable` saves: the factor on, its secret, its codes, its step, `updated_at`.
    fn enable_second_factor(
        &self,
        user_id: i64,
        enrolled: &Enrolled,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// What `TotpService.disable` saves: the factor off, the three secrets' columns null, `updated_at`.
    fn disable_second_factor(
        &self,
        user_id: i64,
        at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    /// `countActiveWithPassword`.
    fn count_active_with_password(&self) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// `countActiveWithPasswordAndNoSecondFactor`.
    fn count_active_with_password_and_no_second_factor(&self) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// The shared request counters — `RateWindowRepository`. Each write one statement, none a `save`.
pub trait RateWindowStore: Send + Sync {
    /// One more hit in a window that has a row; 0 when it has none yet.
    fn increment(&self, key: &str) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// The window's first hit, a bare insert: the primary key refuses a second one.
    fn insert_first(
        &self,
        key: &str,
        expires_at: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn hits_of(&self, key: &str) -> impl Future<Output = Result<Option<i32>, StoreError>> + Send;
    /// The windows closed strictly before `now`.
    fn delete_expired(&self, now: OffsetDateTime) -> impl Future<Output = Result<u64, StoreError>> + Send;
    /// Every window whose key is `like` the pattern.
    fn delete_by_key_prefix(&self, pattern: &str) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// [`SignInStore`] and [`RateWindowStore`] on the database.
#[derive(Clone, Debug)]
pub struct SqlSignInStore {
    db: Db,
}

impl SqlSignInStore {
    pub fn new(db: Db) -> SqlSignInStore {
        SqlSignInStore { db }
    }
}

/// The engine's statements are not in this build — only a pass of the cache script compiles one engine alone.
#[cfg(not(all(feature = "mysql-queries", feature = "postgres-queries")))]
fn not_built() -> StoreError {
    StoreError("this build carries no statement for this engine".into())
}

fn count(rows: i64) -> Result<u64, StoreError> {
    u64::try_from(rows).map_err(|error| StoreError(Box::new(error)))
}

impl SignInStore for SqlSignInStore {
    async fn record_attempts(&self, keys: &[String], at: OffsetDateTime) -> Result<Vec<Uuid>, StoreError> {
        let mut tx = self.db.begin(Mode::ReadWrite).await?;
        let mut written = Vec::with_capacity(keys.len());
        for key in keys {
            let id = random_uuid();
            attempts::insert(&mut tx, id, key, at).await?;
            written.push(id);
        }
        tx.commit().await?;
        Ok(written)
    }

    async fn attempts_after(&self, key: &str, after: OffsetDateTime) -> Result<Vec<AttemptRow>, StoreError> {
        attempts::find_after(&self.db, key, after).await
    }

    async fn delete_attempts_by_key(&self, key: &str) -> Result<u64, StoreError> {
        attempts::delete_by_key(&self.db, key).await
    }

    async fn delete_attempts(&self, ids: &[Uuid]) -> Result<u64, StoreError> {
        attempts::delete_ids(&self.db, ids).await
    }

    async fn delete_attempts_before(&self, cutoff: OffsetDateTime) -> Result<u64, StoreError> {
        attempts::delete_before(&self.db, cutoff).await
    }

    async fn find_challenge(&self, token_hash: &str) -> Result<Option<Challenge>, StoreError> {
        challenges::find(&self.db, token_hash).await
    }

    async fn insert_challenge(&self, challenge: &Challenge) -> Result<(), StoreError> {
        challenges::insert(&self.db, challenge).await
    }

    async fn count_challenge_attempt(&self, token_hash: &str) -> Result<u64, StoreError> {
        challenges::count_attempt(&self.db, token_hash).await
    }

    async fn discard_challenge(&self, token_hash: &str) -> Result<u64, StoreError> {
        challenges::discard(&self.db, token_hash).await
    }

    async fn delete_expired_challenges(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        challenges::delete_expired(&self.db, now).await
    }

    async fn count_live_challenges(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        count(challenges::count_live(&self.db, now).await?)
    }

    async fn advance_totp_step(&self, user_id: i64, step: i64) -> Result<u64, StoreError> {
        second_factor::advance_step(&self.db, user_id, step).await
    }

    async fn replace_backup_codes(
        &self,
        user_id: i64,
        expected: &str,
        replacement: &str,
        at: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        second_factor::replace_backup_codes(&self.db, user_id, expected, replacement, at).await
    }

    async fn enable_second_factor(&self, user_id: i64, enrolled: &Enrolled) -> Result<(), StoreError> {
        second_factor::enable(&self.db, user_id, enrolled).await
    }

    async fn disable_second_factor(&self, user_id: i64, at: OffsetDateTime) -> Result<(), StoreError> {
        second_factor::disable(&self.db, user_id, at).await
    }

    async fn count_active_with_password(&self) -> Result<u64, StoreError> {
        count(second_factor::count_with_password(&self.db).await?)
    }

    async fn count_active_with_password_and_no_second_factor(&self) -> Result<u64, StoreError> {
        count(second_factor::count_with_password_and_no_second_factor(&self.db).await?)
    }
}

impl RateWindowStore for SqlSignInStore {
    async fn increment(&self, key: &str) -> Result<u64, StoreError> {
        rate_windows::increment(&self.db, key).await
    }

    async fn insert_first(&self, key: &str, expires_at: OffsetDateTime) -> Result<(), StoreError> {
        rate_windows::insert_first(&self.db, key, expires_at).await
    }

    async fn hits_of(&self, key: &str) -> Result<Option<i32>, StoreError> {
        rate_windows::hits_of(&self.db, key).await
    }

    async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, StoreError> {
        rate_windows::delete_expired(&self.db, now).await
    }

    async fn delete_by_key_prefix(&self, pattern: &str) -> Result<u64, StoreError> {
        rate_windows::delete_by_key_prefix(&self.db, pattern).await
    }
}

/// A version-4 UUID, as Hibernate's `GenerationType.UUID` makes one for `t_login_attempt.id`.
fn random_uuid() -> Uuid {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}
