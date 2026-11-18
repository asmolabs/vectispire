//! The two clocks this crate meets: the parsers' `Instant` and the store's `OffsetDateTime` — converted, and written
//! as Java's `Instant.toString` writes them in the sentences the status and the audit carry.

use time::OffsetDateTime;
use vectispire_domain::instant::Instant;

/// The store's instant for a parsed one; none outside what the store can hold.
pub(crate) fn of_instant(instant: Instant) -> Option<OffsetDateTime> {
    let seconds = OffsetDateTime::from_unix_timestamp(instant.epoch_second).ok()?;
    seconds.checked_add(time::Duration::nanoseconds(i64::from(instant.nano)))
}

pub(crate) fn to_instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

/// `at` moved by `by`, held at the edge of what the store can hold rather than wrapping: a clock that far out is not
/// one these claims are measured against.
pub(crate) fn shifted(at: OffsetDateTime, by: time::Duration) -> OffsetDateTime {
    at.checked_add(by).unwrap_or(if by.is_negative() { OffsetDateTime::UNIX_EPOCH } else { at })
}

/// `Instant.toString()`.
pub(crate) fn java_string(at: OffsetDateTime) -> String {
    to_instant(at).to_java_string().unwrap_or_else(|| at.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_ways_and_as_java_writes_it() {
        let parsed = Instant { epoch_second: 1_790_000_000, nano: 120_000_000 };
        let stored = of_instant(parsed).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(to_instant(stored), parsed);
        assert_eq!(java_string(stored), "2026-09-21T14:13:20.120Z");
        assert_eq!(java_string(OffsetDateTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }
}
