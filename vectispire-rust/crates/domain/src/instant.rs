//! `Instant`: a point on the UTC time line as Java's `java.time.Instant` holds it — whole seconds from the
//! epoch and a nanosecond within the second.
//!
//! The domain crate links no time library (the agent links it too, and a calculation here needs none):
//! callers convert at their edge, `time::OffsetDateTime::unix_timestamp` and `nanosecond` being exactly
//! these two fields.

use serde::{Deserialize, Serialize};

/// Seconds from 1970-01-01T00:00:00Z and the nanosecond within that second, ordered as time is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Instant {
    pub epoch_second: i64,
    /// Always below 1,000,000,000.
    pub nano: u32,
}

impl Instant {
    pub const SECONDS_PER_DAY: i64 = 86_400;

    /// Whole seconds, no fraction.
    pub fn of_epoch_second(epoch_second: i64) -> Instant {
        Instant { epoch_second, nano: 0 }
    }

    /// `minus(Duration.ofDays(days))`; `None` past the range of an `i64` of seconds, where Java throws.
    pub fn minus_days(self, days: i64) -> Option<Instant> {
        let seconds = days.checked_mul(Instant::SECONDS_PER_DAY)?;
        Some(Instant { epoch_second: self.epoch_second.checked_sub(seconds)?, nano: self.nano })
    }

    /// `minus(duration)` for a non-negative duration; `None` past the range of an `i64` of seconds.
    pub fn minus(self, duration: std::time::Duration) -> Option<Instant> {
        let seconds = i64::try_from(duration.as_secs()).ok()?;
        let (borrow, nano) = match self.nano.checked_sub(duration.subsec_nanos()) {
            Some(nano) => (0, nano),
            None => (1, self.nano.checked_add(1_000_000_000)?.checked_sub(duration.subsec_nanos())?),
        };
        Some(Instant { epoch_second: self.epoch_second.checked_sub(seconds)?.checked_sub(borrow)?, nano })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fraction_larger_than_the_instant_s_borrows_a_second() {
        let at = Instant { epoch_second: 10, nano: 100 };
        assert_eq!(at.minus(std::time::Duration::new(1, 200)), Some(Instant { epoch_second: 8, nano: 999_999_900 }));
        assert_eq!(at.minus(std::time::Duration::new(1, 100)), Some(Instant { epoch_second: 9, nano: 0 }));
    }
}
