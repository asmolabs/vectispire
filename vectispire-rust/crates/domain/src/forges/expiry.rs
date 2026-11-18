//! `TokenExpiry`: when a GitLab or GitHub token stops working, as the server reports it, and where that date stands
//! now — one reading for the forge connections' probe and, once ported, the tracker integration's token check.

use crate::instant::Instant;

/// How long before an expiry it is announced: fourteen days (decision 0037 §2).
pub const NOTICE_SECONDS: i64 = 14 * Instant::SECONDS_PER_DAY;

/// `TokenExpiry.ofDate`: GitLab's `expires_at`, a date whose midnight UTC the token stops at. `LocalDate.parse` of
/// ISO `yyyy-MM-dd` after a trim; `None` when blank or unreadable.
pub fn of_date(value: Option<&str>) -> Option<Instant> {
    let value = crate::java::trim(value?);
    let (year, month, day) = iso_date(value)?;
    Instant::of_utc(year, month, day, 0, 0, 0)
}

/// `TokenExpiry.ofGithubHeader`: `github-authentication-token-expiration`, `yyyy-MM-dd HH:mm:ss` then a zone written
/// as a name or as an offset. The names read are those GitHub writes (`UTC`, and `GMT`, `UT`, `Z`): a region's name
/// (`Europe/Paris`) would need the zone rules this crate does not carry, and reads as unknown — the expiry is then
/// "not reported", which the list says rather than guessing.
pub fn of_github_header(value: Option<&str>) -> Option<Instant> {
    let value = crate::java::trim(value?);
    let (date, rest) = value.split_once(' ')?;
    let (time, zone) = rest.split_once(' ')?;
    let (year, month, day) = iso_date(date)?;
    let mut parts = time.split(':');
    let hour = two_digits(parts.next()?)?;
    let minute = two_digits(parts.next()?)?;
    let second = two_digits(parts.next()?)?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let offset = zone_offset(zone)?;
    Instant::of_utc(year, month, day, hour, minute, second)?.plus_seconds(-offset)
}

/// Where an expiry stands at `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// No expiry is known. Said, never left blank.
    Unknown,
    Valid,
    /// Within [`NOTICE_SECONDS`] of it.
    Soon,
    Expired,
}

impl Standing {
    pub fn of(expires_at: Option<Instant>, now: Instant) -> Standing {
        let Some(expires_at) = expires_at else {
            return Standing::Unknown;
        };
        if now >= expires_at {
            return Standing::Expired;
        }
        // `Duration.between(now, expiresAt).compareTo(NOTICE) <= 0`, to the nanosecond.
        match now.plus_seconds(NOTICE_SECONDS) {
            Some(cut) if expires_at <= cut => Standing::Soon,
            _ => Standing::Valid,
        }
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Standing::Unknown => "unknown",
            Standing::Valid => "valid",
            Standing::Soon => "soon",
            Standing::Expired => "expired",
        }
    }
}

fn iso_date(text: &str) -> Option<(i64, u32, u32)> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year = text.get(0..4).filter(|year| year.bytes().all(|b| b.is_ascii_digit()))?.parse().ok()?;
    let month = two_digits(text.get(5..7)?)?;
    let day = two_digits(text.get(8..10)?)?;
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    Some((year, month, day))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn two_digits(text: &str) -> Option<u32> {
    if text.len() == 2 && text.bytes().all(|b| b.is_ascii_digit()) { text.parse().ok() } else { None }
}

/// The offset in seconds a zone names: `UTC`, `GMT`, `UT`, `Z`, or `±HHMM` (the `Z` pattern letter's form).
fn zone_offset(zone: &str) -> Option<i64> {
    if matches!(zone, "UTC" | "GMT" | "UT" | "Z") {
        return Some(0);
    }
    let (sign, digits) = match zone.as_bytes().first()? {
        b'+' => (1, &zone[1..]),
        b'-' => (-1, &zone[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i64 = digits[..2].parse().ok()?;
    let minutes: i64 = digits[2..].parse().ok()?;
    if hours > 18 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitlab_dates_stop_at_midnight_utc() {
        assert_eq!(of_date(Some(" 2027-01-31 ")), Instant::of_utc(2027, 1, 31, 0, 0, 0));
        assert_eq!(of_date(Some("2027-02-30")), None);
        assert_eq!(of_date(Some("")), None);
        assert_eq!(of_date(None), None);
    }

    #[test]
    fn github_headers_name_a_zone_or_an_offset() {
        assert_eq!(of_github_header(Some("2026-12-31 08:00:00 UTC")), Instant::of_utc(2026, 12, 31, 8, 0, 0));
        assert_eq!(of_github_header(Some("2026-12-31 08:00:00 +0200")), Instant::of_utc(2026, 12, 31, 6, 0, 0));
        assert_eq!(of_github_header(Some("2026-12-31 08:00 UTC")), None);
        assert_eq!(of_github_header(Some("tomorrow")), None);
    }

    #[test]
    fn standing_within_fourteen_days_is_soon() {
        let now = Instant::of_epoch_second(1_000_000_000);
        assert_eq!(Standing::of(None, now), Standing::Unknown);
        assert_eq!(Standing::of(Some(now), now), Standing::Expired);
        assert_eq!(Standing::of(now.plus_seconds(NOTICE_SECONDS), now), Standing::Soon);
        assert_eq!(Standing::of(now.plus_seconds(NOTICE_SECONDS + 1), now), Standing::Valid);
    }
}
