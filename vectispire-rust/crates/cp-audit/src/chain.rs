//! The audit log's integrity chain — `common.domain.audit.AuditChain`, byte for byte.
//!
//! Each entry carries the previous one's hash, so modifying or deleting a past row breaks every hash that
//! follows. This does not make the log immutable — whoever can write the table can rewrite the whole chain —
//! but it makes *selective* modification detectable, which is the realistic threat when the interesting row is
//! one among thousands.
//!
//! **The hash is a data contract with every installation's existing log.** The Rust control plane continues a
//! chain the Java one started, and Java may continue one Rust extended: one character of difference in how an
//! entry is hashed reads as tampering of the whole log from the switchover on. So the formula is Java's to the
//! byte — the NUL separator, the field order, absent and empty alike, the instant written as ISO-8601 UTC with
//! exactly three fraction digits, truncated — and `reference/audit/chain.json`, written by the Java side, holds
//! this module to it.

use std::collections::HashSet;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// The separator of every composite hash: NUL, which no hashed value can contain without it being visible —
/// a printable one could be imitated, and two inputs would collapse onto one hash (`Digests.SEPARATOR`).
const SEPARATOR: char = '\0';

/// The fields of an entry that go into its hash, in this order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub previous_hash: Option<String>,
    /// The instant as the database returns it; canonicalised by [`entry_hash`], not by the caller.
    pub timestamp: Option<OffsetDateTime>,
    pub operation_type: Option<String>,
    pub resource_id: Option<String>,
    pub user_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub description: Option<String>,
}

/// An entry as it is read back for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiableEntry {
    pub id: String,
    /// Absent or empty for a row written before the chaining.
    pub entry_hash: Option<String>,
    pub entry: Entry,
}

impl VerifiableEntry {
    fn chained_hash(&self) -> Option<&str> {
        self.entry_hash.as_deref().filter(|hash| !hash.is_empty())
    }
}

/// What a verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    /// `None` when the log is intact, otherwise the first break, in Java's words.
    pub broken: Option<String>,
    /// How many entries predate the chaining.
    pub unverifiable: usize,
}

/// `Digests.canonical`: ISO-8601 in UTC with the fraction fixed at three digits, **truncated** — what
/// `DateTimeFormatterBuilder.appendInstant(3)` prints. The width is the contract: `Instant::toString` drops a
/// zero fraction and prints six or nine digits when it has them, so an entry landing exactly on the second
/// would hash one way here and another way in a process that always writes milliseconds.
///
/// Years 0 to 9999, which is every instant a log holds; outside them Java writes a sign and more digits, and
/// so does this (`+10000-…`, `-0001-…`), as `LocalDateTime` prints a year.
pub fn canonical(instant: OffsetDateTime) -> String {
    let utc = instant.to_offset(time::UtcOffset::UTC);
    let year = utc.year();
    let mut out = String::with_capacity(24);
    if year > 9999 {
        let _ = write!(out, "+{year}");
    } else if year < 0 {
        let _ = write!(out, "-{:04}", year.unsigned_abs());
    } else {
        let _ = write!(out, "{year:04}");
    }
    let _ = write!(
        out,
        "-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.millisecond()
    );
    out
}

/// `Digests.sha256Fields`: the fields joined by NUL, absent as empty, SHA-256 of the UTF-8, lower-case hex.
pub fn sha256_fields(fields: &[Option<&str>]) -> String {
    let mut joined = String::new();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            joined.push(SEPARATOR);
        }
        joined.push_str(field.unwrap_or(""));
    }
    let digest = Sha256::digest(joined.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// `H(previous | timestamp | operation | resource | user | ip | user_agent | description)`.
///
/// Absent and empty are indistinguishable here, deliberately: both mean "this field has no value", and telling
/// them apart would make the hash depend on how a driver renders an empty column.
pub fn entry_hash(entry: &Entry) -> String {
    let timestamp = entry.timestamp.map(canonical);
    sha256_fields(&[
        entry.previous_hash.as_deref(),
        timestamp.as_deref(),
        entry.operation_type.as_deref(),
        entry.resource_id.as_deref(),
        entry.user_id.as_deref(),
        entry.ip_address.as_deref(),
        entry.user_agent.as_deref(),
        entry.description.as_deref(),
    ])
}

/// Verifies the log — `AuditChain.verifyChain`: a graph, not a queue.
///
/// 1. **Each entry matches its own hash**: a row modified.
/// 2. **Each entry's predecessor still exists**: an entry somebody descends from deleted.
/// 3. **No entry without a hash is later than the start of the chaining**: a row placed by hand. Rows from
///    before the chaining are counted, not reported.
///
/// Two instances writing at the same instant read the same tail and fork the chain; that is not a break, and a
/// false alarm in an integrity check is worse than none. What this cannot see, and says so: the deletion of an
/// entry nobody descends from — the last one written, or a branch's tip. The audit mirror covers that case.
pub fn verify(entries: &[VerifiableEntry]) -> Verification {
    let chained: Vec<&VerifiableEntry> = entries.iter().filter(|entry| entry.chained_hash().is_some()).collect();
    let unverifiable = entries.len().saturating_sub(chained.len());
    let known: HashSet<&str> = chained.iter().filter_map(|entry| entry.chained_hash()).collect();

    // Strictly later, not "from onwards": an inherited row written in the same millisecond as the first chained
    // entry — the switchover's instant — is not an alarm.
    let oldest_chained = chained.iter().filter_map(|entry| entry.entry.timestamp).min();
    if let Some(oldest) = oldest_chained {
        for entry in entries.iter().filter(|entry| entry.chained_hash().is_none()) {
            if entry.entry.timestamp.is_some_and(|at| at > oldest) {
                return Verification {
                    broken: Some(format!(
                        "Entry {} has no hash although the chaining had started: the row was inserted or modified.",
                        entry.id
                    )),
                    unverifiable,
                };
            }
        }
    }

    for entry in chained {
        let stored = entry.chained_hash().unwrap_or_default();
        if stored != entry_hash(&entry.entry) {
            return Verification {
                broken: Some(format!("Entry {}: its own content no longer matches its hash.", entry.id)),
                unverifiable,
            };
        }
        // An absent predecessor is a root: one per branch, one branch per instance that wrote alongside another.
        if let Some(previous) = entry.entry.previous_hash.as_deref()
            && !known.contains(previous)
        {
            return Verification {
                broken: Some(format!(
                    "Entry {}: its predecessor \"{previous}\" has vanished from the log — an earlier entry was deleted.",
                    entry.id
                )),
                unverifiable,
            };
        }
    }
    Verification { broken: None, unverifiable }
}

/// Recomputes the whole chain, oldest to newest — the switchover operation, **to run once, with somebody
/// watching**: rewriting an integrity log is what that log exists to make detectable, so nothing calls this at
/// startup or from a route. Content is untouched; only the two hashes change.
pub fn rebuild(entries: &[VerifiableEntry]) -> Vec<VerifiableEntry> {
    let mut previous: Option<String> = None;
    entries
        .iter()
        .map(|entry| {
            let relinked = Entry { previous_hash: previous.clone(), ..entry.entry.clone() };
            let hash = entry_hash(&relinked);
            previous = Some(hash.clone());
            VerifiableEntry { id: entry.id.clone(), entry_hash: Some(hash), entry: relinked }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(nanos: i128) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap()
    }

    #[test]
    fn the_instant_is_written_to_the_millisecond_and_truncated() {
        assert_eq!(canonical(at(1_760_688_000_000_000_000)), "2025-10-17T08:00:00.000Z");
        assert_eq!(canonical(at(1_760_688_000_999_999_999)), "2025-10-17T08:00:00.999Z");
        assert_eq!(canonical(at(-1_000_000)), "1969-12-31T23:59:59.999Z");
    }

    #[test]
    fn absent_and_empty_hash_alike_and_the_separator_cannot_be_imitated() {
        assert_eq!(sha256_fields(&[None, Some("a")]), sha256_fields(&[Some(""), Some("a")]));
        assert_ne!(sha256_fields(&[Some("ab"), Some("")]), sha256_fields(&[Some("a"), Some("b")]));
    }
}
