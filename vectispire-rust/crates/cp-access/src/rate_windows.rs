//! A request limit counted by every instance together, in fixed windows, in the database — `RateWindows`, behind
//! `cp-http`'s [`SharedWindow`]: the tracker webhook's second budget.
//!
//! **Why the database.** The webhook's ceiling was a bucket per address in each instance's memory, so behind a load
//! balancer of three instances an operator who set three hundred a minute got nine hundred. The database is the one
//! store every instance shares.
//!
//! **Fixed windows**, a count one `update … set hits = hits + 1` can keep. A subject can spend its allowance at the end
//! of one window and again at the start of the next — accepted for a limit meant to stop a flood. **Never more than the
//! ceiling admitted, perhaps a little early refused**: the count is read after the increment, so each caller sees at
//! least its own position.
//!
//! **A database failure admits**, with a warning: the request behind the limit needs the database too and will fail on
//! its own, and the in-memory bucket in front of this still bounds one instance.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use vectispire_cp_http::credentials::{BoxFuture, SharedWindow};

use crate::accounts::StoreError;
pub use crate::persistence::sign_in::RateWindowStore;
use crate::throttle::SharedClock;

/// The limits counted here. The key enters every row's key, so it never changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    TicketWebhook,
}

impl Limit {
    pub const fn key(self) -> &'static str {
        match self {
            Limit::TicketWebhook => "webhook",
        }
    }
}

/// `RateWindows.Outcome`: admitted, or refused with the time until the window closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub admitted: bool,
    pub retry_after: std::time::Duration,
}

/// `RateWindows`.
#[derive(Clone, Debug)]
pub struct RateWindows<W> {
    windows: W,
    clock: SharedClock,
}

const NANOS_PER_MILLI: i128 = 1_000_000;

impl<W: RateWindowStore> RateWindows<W> {
    pub fn new(windows: W, clock: SharedClock) -> RateWindows<W> {
        RateWindows { windows, clock }
    }

    /// Counts one request of `subject` against `limit`, and says whether it is within `ceiling` for the window it
    /// falls in.
    ///
    /// **No transaction**, deliberately: the first hit of a window is an insert that may lose to another instance's,
    /// and on PostgreSQL a failed statement poisons the transaction around it — the increment that follows would be
    /// refused. Each statement commits on its own.
    pub async fn hit(&self, limit: Limit, subject: Option<&str>, ceiling: i64, window: std::time::Duration) -> Outcome {
        let now = self.clock.now();
        // `Math.max(1, window.toMillis())` and `Math.floorDiv(now.toEpochMilli(), length)`.
        let length = i128::try_from(window.as_millis()).unwrap_or(i128::MAX).max(1);
        let millis = now.unix_timestamp_nanos().div_euclid(NANOS_PER_MILLI);
        let number = millis.div_euclid(length);
        let closes_nanos = number.saturating_add(1).saturating_mul(length).saturating_mul(NANOS_PER_MILLI);
        let closes = OffsetDateTime::from_unix_timestamp_nanos(closes_nanos).unwrap_or(now);
        // `Duration.between(now, closes)`, to the nanosecond.
        let until_closed = closes_nanos.saturating_sub(now.unix_timestamp_nanos());
        // A digest, not the address: the table is a counter, not a record of who called.
        let key = format!("{}:{number}:{}", limit.key(), sha256_hex(subject.unwrap_or("")));
        match self.count(&key, closes).await {
            Ok(hits) if i64::from(hits) <= ceiling => {
                Outcome { admitted: true, retry_after: std::time::Duration::ZERO }
            }
            Ok(_) => Outcome {
                admitted: false,
                retry_after: std::time::Duration::from_nanos(u64::try_from(until_closed).unwrap_or(0)),
            },
            Err(unavailable) => {
                tracing::warn!(
                    "The shared {} limit could not be counted, the request is admitted: {unavailable}",
                    limit.key()
                );
                Outcome { admitted: true, retry_after: std::time::Duration::ZERO }
            }
        }
    }

    /// The increment, the first hit's insert — and the increment again when another instance inserted first.
    async fn count(&self, key: &str, closes: OffsetDateTime) -> Result<i32, StoreError> {
        if self.windows.increment(key).await? == 0 && self.windows.insert_first(key, closes).await.is_err() {
            self.windows.increment(key).await?;
        }
        Ok(self.windows.hits_of(key).await?.unwrap_or(0))
    }

    /// Drops the windows that have closed — the hourly purge, through the session cleanup.
    pub async fn purge_closed(&self) -> Result<u64, StoreError> {
        self.windows.delete_expired(self.clock.now()).await
    }

    /// Forgets every window of a limit. For the tests, which all deliver from one address.
    pub async fn forget(&self, limit: Limit) -> Result<u64, StoreError> {
        self.windows.delete_by_key_prefix(&format!("{}:%", limit.key())).await
    }
}

fn sha256_hex(text: &str) -> String {
    use std::fmt::Write as _;
    Sha256::digest(text.as_bytes()).iter().fold(String::with_capacity(64), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

/// The webhook's shared budget, as the chain asks for it.
impl<W: RateWindowStore + std::fmt::Debug + 'static> SharedWindow for RateWindows<W> {
    fn hit<'a>(
        &'a self,
        subject: &'a str,
        ceiling: u64,
        window: std::time::Duration,
    ) -> BoxFuture<'a, Result<(), std::time::Duration>> {
        Box::pin(async move {
            let ceiling = i64::try_from(ceiling).unwrap_or(i64::MAX);
            let outcome = RateWindows::hit(self, Limit::TicketWebhook, Some(subject), ceiling, window).await;
            if outcome.admitted { Ok(()) } else { Err(outcome.retry_after) }
        })
    }
}

/// The shared window as the chain holds it.
pub fn shared_webhook_window<W: RateWindowStore + std::fmt::Debug + 'static>(
    windows: W,
    clock: SharedClock,
) -> Arc<dyn SharedWindow> {
    Arc::new(RateWindows::new(windows, clock))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_digest_is_lower_case_hex() {
        assert_eq!(sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
