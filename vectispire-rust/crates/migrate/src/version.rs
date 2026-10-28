//! A migration's version, compared as Flyway's `MigrationVersion` compares it.

use std::cmp::Ordering;
use std::fmt;

/// `1`, `1.2`, `1_2` — numeric segments, compared one by one, a missing segment counting as zero.
///
/// Kept as the digits written, not as integers: Flyway's segments are `BigInteger`s, and a version
/// longer than a `u64` must still compare and print as it does there.
#[derive(Debug, Clone, Eq)]
pub struct Version {
    segments: Vec<String>,
}

impl Version {
    /// Parses a version as a file name or the `version` column writes it; `None` if it is not one.
    pub fn parse(text: &str) -> Option<Version> {
        if text.is_empty() {
            return None;
        }
        let segments: Vec<String> = text.split(['.', '_']).map(str::to_owned).collect();
        if segments.iter().any(|segment| segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit())) {
            return None;
        }
        Some(Version { segments })
    }

    fn segment(&self, index: usize) -> &str {
        self.segments.get(index).map_or("0", |segment| segment.trim_start_matches('0'))
    }
}

/// Compares two runs of digits as the numbers they write.
fn compare_digits(left: &str, right: &str) -> Ordering {
    let (left, right) = (left.trim_start_matches('0'), right.trim_start_matches('0'));
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let length = self.segments.len().max(other.segments.len());
        (0..length)
            .map(|index| compare_digits(self.segment(index), other.segment(index)))
            .find(|ordering| ordering.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

/// As the `version` column stores it: the segments joined with dots.
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.segments.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn versions_compare_as_numbers_segment_by_segment() {
        assert!(v("9") < v("10"));
        assert!(v("91") > v("9000").min(v("90")));
        assert!(v("1.2") < v("1.10"));
        assert_eq!(v("1"), v("1.0"));
        assert_eq!(v("007"), v("7"));
        assert!(v("99999999999999999999999") > v("18446744073709551615"));
    }

    #[test]
    fn a_version_prints_as_the_column_stores_it() {
        assert_eq!(v("91").to_string(), "91");
        assert_eq!(v("1_2").to_string(), "1.2");
    }

    #[test]
    fn what_is_not_a_version_is_refused() {
        for text in ["", "1..2", "a", "1.a", "-1", "1 2"] {
            assert!(Version::parse(text).is_none(), "{text}");
        }
    }
}
