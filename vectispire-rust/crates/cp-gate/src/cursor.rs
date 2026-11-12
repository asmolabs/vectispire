//! `RegisterCursor`: where a register's next page starts.
//!
//! # Why a cursor and not an offset
//!
//! Visibility is applied after the read here, not in the query. A cursor names a row
//! rather than a count, so rows inserted while somebody reads do not shift what comes next.
//!
//! Carrying the row's identifier as well as the instant makes the order total even
//! when multiple verdicts share the exact same millisecond.

use time::OffsetDateTime;

/// Where a register's next page starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterCursor {
    pub at: OffsetDateTime,
    pub id: String,
}

const SEPARATOR: char = ':';

impl RegisterCursor {
    pub fn new(at: OffsetDateTime, id: impl Into<String>) -> Self {
        Self { at, id: id.into() }
    }

    /// Reads a cursor a client sent back, or `None`.
    ///
    /// Unreadable reads as absent, which means "start at the beginning".
    pub fn parse(encoded: Option<&str>) -> Option<Self> {
        let encoded = encoded?.trim();
        if encoded.is_empty() {
            return None;
        }
        let split = encoded.find(SEPARATOR)?;
        if split == 0 || split == encoded.len().saturating_sub(1) {
            return None;
        }
        let (millis_str, id_str) = encoded.split_at(split);
        let id = id_str.strip_prefix(SEPARATOR)?;
        let millis = millis_str.parse::<i64>().ok()?;
        let nanos = i128::from(millis).checked_mul(1_000_000)?;
        let at = OffsetDateTime::from_unix_timestamp_nanos(nanos).ok()?;
        Some(Self { at, id: id.to_owned() })
    }

    /// The form a client sends back: epoch milliseconds and UUID separated by a colon.
    pub fn encoded(&self) -> String {
        let millis = self
            .at
            .unix_timestamp()
            .checked_mul(1_000)
            .and_then(|ms| ms.checked_add(i64::from(self.at.millisecond())))
            .unwrap_or(0);
        format!("{millis}{SEPARATOR}{}", self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn parse_and_encode() {
        let cursor = RegisterCursor::new(datetime!(2026-09-14 08:00:00.123 UTC), "41");
        let encoded = cursor.encoded();
        let parsed = RegisterCursor::parse(Some(&encoded)).unwrap();
        assert_eq!(parsed.id, "41");
        assert_eq!(parsed.at.unix_timestamp(), cursor.at.unix_timestamp());
    }

    #[test]
    fn parse_invalid() {
        assert_eq!(RegisterCursor::parse(None), None);
        assert_eq!(RegisterCursor::parse(Some("")), None);
        assert_eq!(RegisterCursor::parse(Some("  ")), None);
        assert_eq!(RegisterCursor::parse(Some("not-a-cursor")), None);
        assert_eq!(RegisterCursor::parse(Some("abc:41")), None);
        assert_eq!(RegisterCursor::parse(Some(":41")), None);
        assert_eq!(RegisterCursor::parse(Some("1757836800000:")), None);
    }
}
