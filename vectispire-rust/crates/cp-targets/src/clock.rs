//! The instant a row is stamped with — `CoreConfiguration.clock()`, truncated to the microsecond the columns store,
//! so that what a create answers is what a read of the row answers.

use time::OffsetDateTime;

/// Where the module's instants come from.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> OffsetDateTime;
}

/// The system's clock, in UTC, to the microsecond.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        microseconds(OffsetDateTime::now_utc())
    }
}

/// `instant`, truncated to the microsecond — what `datetime(6)` and `timestamp` keep.
pub fn microseconds(instant: OffsetDateTime) -> OffsetDateTime {
    let nanoseconds = instant.nanosecond();
    instant.replace_nanosecond(nanoseconds - nanoseconds % 1_000).unwrap_or(instant)
}
