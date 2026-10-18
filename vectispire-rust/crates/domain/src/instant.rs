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

    /// `plusSeconds(seconds)`, either sign; `None` past the range of an `i64` of seconds, where Java throws.
    pub fn plus_seconds(self, seconds: i64) -> Option<Instant> {
        Some(Instant { epoch_second: self.epoch_second.checked_add(seconds)?, nano: self.nano })
    }

    /// `plus(duration)` for a non-negative duration; `None` past the range of an `i64` of seconds.
    pub fn plus(self, duration: std::time::Duration) -> Option<Instant> {
        let total = self.nano.checked_add(duration.subsec_nanos())?;
        let (carry, nano) = if total >= 1_000_000_000 { (1, total - 1_000_000_000) } else { (0, total) };
        let seconds = i64::try_from(duration.as_secs()).ok()?;
        Some(Instant { epoch_second: self.epoch_second.checked_add(seconds)?.checked_add(carry)?, nano })
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

    #[test]
    fn a_fraction_past_the_second_carries_one() {
        let at = Instant { epoch_second: 10, nano: 999_999_900 };
        assert_eq!(at.plus(std::time::Duration::new(1, 100)), Some(Instant { epoch_second: 12, nano: 0 }));
        assert_eq!(at.plus(std::time::Duration::new(0, 99)), Some(Instant { epoch_second: 10, nano: 999_999_999 }));
        assert_eq!(at.plus_seconds(-11), Some(Instant { epoch_second: -1, nano: 999_999_900 }));
        assert_eq!(Instant::of_epoch_second(i64::MAX).plus_seconds(1), None);
    }
}
