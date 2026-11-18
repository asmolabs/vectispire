//! The instants and days of the module, as `java.time` reads and writes them: `Instant` at the nanosecond, a day
//! (`LocalDate`) in UTC, `plusMonths` clamped to the month's last day, `LocalDate.parse` in ISO's strict form.

use time::{Date, Month, OffsetDateTime, Time};
use vectispire_domain::instant::Instant;

use crate::statement::LocalDate;

/// An `OffsetDateTime` as the domain's `Instant`.
pub fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

/// The domain's `Instant` as an `OffsetDateTime`; the epoch for one out of range, which no stored row holds.
pub fn offset(at: Instant) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(at.epoch_second)
        .ok()
        .and_then(|seconds| seconds.replace_nanosecond(at.nano).ok())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// `LocalDate.ofInstant(instant, UTC)`.
pub fn day_of(at: OffsetDateTime) -> Date {
    at.to_offset(time::UtcOffset::UTC).date()
}

/// `day.atStartOfDay(UTC).toInstant()`.
pub fn start_of(day: Date) -> OffsetDateTime {
    day.with_time(Time::MIDNIGHT).assume_utc()
}

/// `LocalDate.toString()`: `yyyy-MM-dd`, a sign and more digits past four.
pub fn written(day: Date) -> String {
    let year = day.year();
    let month = u8::from(day.month());
    let date = day.day();
    if (0..=9_999).contains(&year) {
        format!("{year:04}-{month:02}-{date:02}")
    } else if year > 9_999 {
        format!("+{year}-{month:02}-{date:02}")
    } else {
        format!("-{:04}-{month:02}-{date:02}", year.unsigned_abs())
    }
}

/// A day as the statement holds it.
pub fn local(day: Date) -> LocalDate {
    LocalDate { year: day.year(), month: u32::from(u8::from(day.month())), day: u32::from(day.day()) }
}

/// `LocalDate.plusMonths`: the same day of the month, clamped to the month's last day.
pub fn plus_months(day: Date, months: i32) -> Option<Date> {
    let index =
        i64::from(day.year()).checked_mul(12)?.checked_add(i64::from(u8::from(day.month()).saturating_sub(1)))?;
    let moved = index.checked_add(i64::from(months))?;
    let year = i32::try_from(moved.div_euclid(12)).ok()?;
    let month = Month::try_from(u8::try_from(moved.rem_euclid(12)).ok()?.checked_add(1)?).ok()?;
    let last = time::util::days_in_month(month, year);
    Date::from_calendar_date(year, month, day.day().min(last)).ok()
}

/// `LocalDate.parse(text)` with `ISO_LOCAL_DATE`, strict: four digits of year (a sign and more past four), two of
/// month and of day, and a date that exists. `None` where Java throws `DateTimeParseException`.
pub fn parse(text: &str) -> Option<Date> {
    let (sign, rest) = match text.as_bytes().first() {
        Some(b'+') => (1, text.get(1..)?),
        Some(b'-') => (-1, text.get(1..)?),
        _ => (0, text),
    };
    let mut parts = rest.split('-');
    let (year, month, date) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if !digits(year) || !digits(month) || !digits(date) || month.len() != 2 || date.len() != 2 {
        return None;
    }
    // EXCEEDS_PAD: no sign on four digits, a sign required past them; never more than ten.
    let fits = match sign {
        0 => year.len() == 4,
        1 => (5..=10).contains(&year.len()),
        _ => (4..=10).contains(&year.len()),
    };
    if !fits {
        return None;
    }
    let year: i32 = year.parse::<i32>().ok()?.checked_mul(if sign < 0 { -1 } else { 1 })?;
    let month = Month::try_from(month.parse::<u8>().ok()?).ok()?;
    Date::from_calendar_date(year, month, date.parse::<u8>().ok()?).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn plus_months_clamps_to_the_last_day_as_java_does() {
        let day = parse("2026-01-31").unwrap();
        assert_eq!(written(plus_months(day, 1).unwrap()), "2026-02-28");
        assert_eq!(written(plus_months(day, 13).unwrap()), "2027-02-28");
        assert_eq!(written(plus_months(parse("2024-01-31").unwrap(), 1).unwrap()), "2024-02-29");
        assert_eq!(written(plus_months(parse("2026-09-28").unwrap(), 120).unwrap()), "2036-09-28");
    }

    #[test]
    fn parse_is_iso_strict() {
        assert!(parse("2026-09-28").is_some());
        for refused in ["2026-9-28", "26-09-28", "2026-02-30", "2026-09-28T00:00", "", "+2026-09-28", "2026/09/28"] {
            assert!(parse(refused).is_none(), "{refused}");
        }
    }
}
