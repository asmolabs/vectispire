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
        let (carry, nano) = if total >= 1_000_000_000 { (1, total.saturating_sub(1_000_000_000)) } else { (0, total) };
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

/// A UTC date and time of day, as the proleptic Gregorian calendar `java.time` uses spells an instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcDateTime {
    pub year: i64,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub nano: u32,
}

impl Instant {
    /// `toEpochMilli`: the fraction truncated towards the past, as Java's floor division does; `None` past the
    /// range of an `i64` of milliseconds, where Java throws.
    pub fn to_epoch_milli(self) -> Option<i64> {
        self.epoch_second.checked_mul(1_000)?.checked_add(i64::from(self.nano.checked_div(1_000_000)?))
    }

    /// The instant on the UTC calendar; `None` only past a year no `i64` of days reaches.
    pub fn to_utc(self) -> Option<UtcDateTime> {
        let days = self.epoch_second.div_euclid(Instant::SECONDS_PER_DAY);
        let of_day = u32::try_from(self.epoch_second.rem_euclid(Instant::SECONDS_PER_DAY)).ok()?;
        let (year, month, day) = civil_from_days(days)?;
        Some(UtcDateTime {
            year,
            month,
            day,
            hour: of_day.checked_div(3_600)?,
            minute: of_day.checked_rem(3_600)?.checked_div(60)?,
            second: of_day.checked_rem(60)?,
            nano: self.nano,
        })
    }

    /// The instant at a UTC calendar date and time, whole seconds; `None` for a date that does not exist.
    pub fn of_utc(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> Option<Instant> {
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 {
            return None;
        }
        if second > 59 {
            return None;
        }
        let days = days_from_civil(year, month, day)?;
        let of_day = i64::from(hour).checked_mul(3_600)?.checked_add(i64::from(minute).checked_mul(60)?)?;
        let epoch_second =
            days.checked_mul(Instant::SECONDS_PER_DAY)?.checked_add(of_day)?.checked_add(i64::from(second))?;
        Some(Instant { epoch_second, nano: 0 })
    }

    /// `Instant.toString` (`ISO_INSTANT`) for the years 0000 to 9999 — every year a certificate can state:
    /// `2026-10-01T12:00:00Z`, the fraction only when there is one, in groups of three digits. `None` outside
    /// those years, where Java signs the year and this has no caller.
    pub fn to_java_string(self) -> Option<String> {
        let at = self.to_utc()?;
        if !(0..=9_999).contains(&at.year) {
            return None;
        }
        let fraction = if at.nano == 0 {
            String::new()
        } else if at.nano.checked_rem(1_000_000)? == 0 {
            format!(".{:03}", at.nano.checked_div(1_000_000)?)
        } else if at.nano.checked_rem(1_000)? == 0 {
            format!(".{:06}", at.nano.checked_div(1_000)?)
        } else {
            format!(".{:09}", at.nano)
        };
        Some(format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}Z",
            at.year, at.month, at.day, at.hour, at.minute, at.second
        ))
    }
}

fn is_leap(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to a civil date — Howard Hinnant's `days_from_civil`, every step checked.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let year = if month <= 2 { year.checked_sub(1)? } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = i64::from(if month > 2 { month.checked_sub(3)? } else { month.checked_add(9)? });
    let day_of_year =
        shifted_month.checked_mul(153)?.checked_add(2)?.checked_div(5)?.checked_add(i64::from(day))?.checked_sub(1)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era.checked_div(4)?)?
        .checked_sub(year_of_era.checked_div(100)?)?
        .checked_add(day_of_year)?;
    era.checked_mul(146_097)?.checked_add(day_of_era)?.checked_sub(719_468)
}

/// The civil date of a day counted from 1970-01-01 — Hinnant's `civil_from_days`, every step checked.
fn civil_from_days(days: i64) -> Option<(i64, u32, u32)> {
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = day_of_era
        .checked_sub(day_of_era.checked_div(1_460)?)?
        .checked_add(day_of_era.checked_div(36_524)?)?
        .checked_sub(day_of_era.checked_div(146_096)?)?
        .checked_div(365)?;
    let day_of_year = day_of_era.checked_sub(
        year_of_era
            .checked_mul(365)?
            .checked_add(year_of_era.checked_div(4)?)?
            .checked_sub(year_of_era.checked_div(100)?)?,
    )?;
    let shifted_month = day_of_year.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let day =
        day_of_year.checked_sub(shifted_month.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?.checked_add(1)?;
    let month = if shifted_month < 10 { shifted_month.checked_add(3)? } else { shifted_month.checked_sub(9)? };
    let year = year_of_era.checked_add(era.checked_mul(400)?)?.checked_add(if month <= 2 { 1 } else { 0 })?;
    Some((year, u32::try_from(month).ok()?, u32::try_from(day).ok()?))
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
    fn the_calendar_agrees_with_java_time() {
        // `Instant.parse("2026-09-26T10:00:00.123Z")` and its neighbours, as java.time reads them.
        let at = Instant { epoch_second: 1_790_416_800, nano: 123_000_000 };
        assert_eq!(at.to_java_string().as_deref(), Some("2026-09-26T10:00:00.123Z"));
        assert_eq!(at.to_epoch_milli(), Some(1_790_416_800_123));
        assert_eq!(Instant::of_utc(2026, 9, 26, 10, 0, 0), Some(Instant::of_epoch_second(1_790_416_800)));
        assert_eq!(Instant::of_epoch_second(0).to_java_string().as_deref(), Some("1970-01-01T00:00:00Z"));
        assert_eq!(Instant::of_epoch_second(951_782_400).to_java_string().as_deref(), Some("2000-02-29T00:00:00Z"));
        assert_eq!(Instant::of_epoch_second(-1).to_java_string().as_deref(), Some("1969-12-31T23:59:59Z"));
        assert_eq!(Instant { epoch_second: -1, nano: 500_000_000 }.to_epoch_milli(), Some(-500));
        assert_eq!(
            Instant { epoch_second: 0, nano: 1_000 }.to_java_string().as_deref(),
            Some("1970-01-01T00:00:00.000001Z")
        );
        assert_eq!(
            Instant::of_utc(0, 1, 1, 0, 0, 0).and_then(Instant::to_java_string).as_deref(),
            Some("0000-01-01T00:00:00Z")
        );
        assert_eq!(Instant::of_utc(9999, 12, 31, 23, 59, 59).map(|at| at.epoch_second), Some(253_402_300_799));
        assert_eq!(Instant::of_utc(2100, 2, 29, 0, 0, 0), None);
        assert_eq!(Instant::of_utc(2026, 13, 1, 0, 0, 0), None);
        for epoch_second in (-62_167_219_200i64..253_402_300_800).step_by(86_399 * 37) {
            let at = Instant::of_epoch_second(epoch_second).to_utc().unwrap();
            assert_eq!(
                Instant::of_utc(at.year, at.month, at.day, at.hour, at.minute, at.second).map(|i| i.epoch_second),
                Some(epoch_second)
            );
        }
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
