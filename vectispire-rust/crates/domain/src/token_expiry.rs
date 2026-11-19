//! `TokenExpiry`: when a GitLab or GitHub token stops working, as the server reports it, and where that date stands
//! now — read by the forge connections' probe and by the tracker's token check, so that a forge connection and the
//! tracker token issued by the same GitLab cannot be told two different expiries (decision 0037 §2).

use crate::instant::Instant;

/// How long before an expiry it is announced: fourteen days.
pub const NOTICE_SECONDS: i64 = 14 * Instant::SECONDS_PER_DAY;

/// GitLab's `expires_at` — a date, the token stopping at midnight UTC of it — and the date an administrator declares:
/// `LocalDate.parse`, so `yyyy-MM-dd` exactly, after `trim`; nothing for absent, blank or unreadable.
pub fn of_date(value: Option<&str>) -> Option<Instant> {
    let value = crate::java::trim(value?);
    let (year, month, day) = iso_date(value)?;
    Instant::of_utc(year, month, day, 0, 0, 0)
}

/// GitHub's `github-authentication-token-expiration` header: `yyyy-MM-dd HH:mm:ss` and a zone written as a name
/// (`UTC`, `GMT`, `Z`) or as an offset (`+0000`, `-0700`). Java's formatter also reads a region's name
/// (`Europe/Paris`); GitHub writes `UTC`, and a region is not read here — the expiry is then unknown, never wrong.
pub fn of_github_header(value: Option<&str>) -> Option<Instant> {
    let value = crate::java::trim(value?);
    let (date, rest) = value.split_once(' ')?;
    let (time, zone) = rest.split_once(' ')?;
    let (year, month, day) = iso_date(date)?;
    let mut fields = time.split(':');
    let hour = two_digits(fields.next()?)?;
    let minute = two_digits(fields.next()?)?;
    let second = two_digits(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    let offset = zone_offset_seconds(zone)?;
    let local = Instant::of_utc(year, month, day, hour, minute, second)?;
    local.plus_seconds(offset.checked_neg()?)
}

/// Where an expiry stands at `now` — the states the forge connections' list shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// No expiry is known: said, never left blank.
    Unknown,
    Valid,
    /// Within [`NOTICE_SECONDS`] of it.
    Soon,
    Expired,
}

impl Standing {
    pub fn of(expires_at: Option<Instant>, now: Instant) -> Standing {
        let Some(expires_at) = expires_at else { return Standing::Unknown };
        if now >= expires_at {
            return Standing::Expired;
        }
        // `Duration.between(now, expiresAt).compareTo(NOTICE) <= 0`, to the nanosecond.
        match now.plus_seconds(NOTICE_SECONDS) {
            Some(limit) if expires_at <= limit => Standing::Soon,
            Some(_) => Standing::Valid,
            None => Standing::Soon,
        }
    }
}

fn iso_date(value: &str) -> Option<(i64, u32, u32)> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    let year: i64 = digits(value.get(0..4)?)?.into();
    let month = digits(value.get(5..7)?)?;
    let day = digits(value.get(8..10)?)?;
    // `of_utc` refuses a day the month does not have, as `LocalDate.parse` does.
    Instant::of_utc(year, month, day, 0, 0, 0)?;
    Some((year, month, day))
}

fn two_digits(value: &str) -> Option<u32> {
    (value.len() == 2).then(|| digits(value)).flatten()
}

fn digits(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn zone_offset_seconds(zone: &str) -> Option<i64> {
    match zone {
        "UTC" | "GMT" | "Z" | "UT" => return Some(0),
        _ => {}
    }
    let (sign, digits_part): (i64, &str) = match zone.as_bytes().first()? {
        b'+' => (1, zone.get(1..)?),
        b'-' => (-1, zone.get(1..)?),
        _ => return None,
    };
    if digits_part.len() != 4 {
        return None;
    }
    let hours = i64::from(two_digits(digits_part.get(0..2)?)?);
    let minutes = i64::from(two_digits(digits_part.get(2..4)?)?);
    if hours > 18 || minutes > 59 {
        return None;
    }
    sign.checked_mul(hours.checked_mul(3_600)?.checked_add(minutes.checked_mul(60)?)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_headers_read_as_java_reads_them() {
        assert_eq!(of_date(Some(" 2026-12-01 ")), Instant::of_utc(2026, 12, 1, 0, 0, 0));
        assert_eq!(of_date(Some("2026-02-30")), None);
        assert_eq!(of_date(Some("2026-2-3")), None);
        assert_eq!(of_date(Some("")), None);
        assert_eq!(of_github_header(Some("2026-12-01 10:00:00 UTC")), Instant::of_utc(2026, 12, 1, 10, 0, 0));
        assert_eq!(of_github_header(Some("2026-12-01 10:00:00 +0200")), Instant::of_utc(2026, 12, 1, 8, 0, 0));
        assert_eq!(of_github_header(Some("2026-12-01T10:00:00Z")), None);
    }

    #[test]
    fn the_notice_window_is_fourteen_days_inclusive() {
        let now = Instant::of_epoch_second(1_000_000);
        assert_eq!(Standing::of(None, now), Standing::Unknown);
        assert_eq!(Standing::of(Some(now), now), Standing::Expired);
        assert_eq!(Standing::of(now.plus_seconds(NOTICE_SECONDS), now), Standing::Soon);
        assert_eq!(Standing::of(now.plus_seconds(NOTICE_SECONDS + 1), now), Standing::Valid);
    }
}
