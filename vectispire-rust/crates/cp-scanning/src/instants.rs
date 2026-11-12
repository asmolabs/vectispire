//! The module's instants: `time::OffsetDateTime` at the database and on the wire, the domain's `Instant` for the pure
//! rules (`schedules`, `scan_queue`), which link no time library because the agent links them too.

use time::OffsetDateTime;
use vectispire_domain::instant::Instant;

/// The same point on the time line, as the domain's rules read it.
pub fn instant(at: OffsetDateTime) -> Instant {
    Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

/// The same point, back. An instant past what `OffsetDateTime` holds (year ±9999) is clamped to its end: no clock and
/// no stored stamp reaches it, and a scan claimable "at the end of time" is still never claimed early.
pub fn offset(at: Instant) -> OffsetDateTime {
    let seconds = OffsetDateTime::from_unix_timestamp(at.epoch_second).unwrap_or(if at.epoch_second < 0 {
        OffsetDateTime::UNIX_EPOCH.replace_year(-9999).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    } else {
        OffsetDateTime::UNIX_EPOCH.replace_year(9999).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    });
    seconds.replace_nanosecond(at.nano).unwrap_or(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_instant_goes_there_and_back() {
        let at =
            OffsetDateTime::from_unix_timestamp_nanos(1_792_326_896_789_000_123).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(offset(instant(at)), at);
        assert_eq!(instant(at), Instant { epoch_second: 1_792_326_896, nano: 789_000_123 });
    }
}
