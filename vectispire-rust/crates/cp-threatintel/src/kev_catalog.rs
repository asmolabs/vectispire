//! CISA's catalogue of Known Exploited Vulnerabilities, as one document read whole — Java's `KevCatalog`.
//!
//! **Read whole, or not at all.** The catalogue is a replacement, not a delta: a CVE the document does not list is
//! taken as not listed, and an issue flagged exploited is un-flagged when its CVE leaves it. A partial document is
//! therefore worse than an unreachable one — a truncated mirror would un-flag every exploited vulnerability it lost,
//! and the gate would go green on them — so one without its `vulnerabilities` array, one that lists nothing, or one
//! carrying fewer entries than the `count` it declares is [`Unreadable`], and the catalogue already stored stays.

use std::collections::HashSet;

use serde_json::Value;
use vectispire_domain::instant::Instant;
use vectispire_domain::java;

use crate::status::is_cve;

/// The column the version is stored in, in UTF-16 units.
pub const VERSION_MAX: usize = 32;

/// A document that is not the catalogue, or not all of it. Never read as an empty catalogue.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unreadable(pub String);

/// The catalogue: CISA's `catalogVersion` and `dateReleased` where readable, and every listed CVE, upper-case, with
/// the day CISA added it — in the document's order, the first of a repeated CVE kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevCatalog {
    pub version: Option<String>,
    pub released: Option<Instant>,
    pub added: Vec<(String, Option<Instant>)>,
}

impl KevCatalog {
    /// `KevCatalog.parse`.
    pub fn parse(payload: &Value) -> Result<KevCatalog, Unreadable> {
        let Some(Value::Array(vulnerabilities)) = payload.get("vulnerabilities") else {
            return Err(Unreadable(
                "the document has no \"vulnerabilities\" list: it is not the KEV catalogue".to_owned(),
            ));
        };
        let mut seen = HashSet::new();
        let mut added = Vec::new();
        for entry in vulnerabilities {
            let Some(Value::String(id)) = entry.get("cveID") else {
                continue;
            };
            let cve = java::to_upper_root(java::trim(id));
            if !is_cve(&cve) {
                continue;
            }
            // `putIfAbsent`, which also replaces a key mapped to null: a repeated CVE stating its day fills in the
            // first one's unknown day, in the first one's place.
            if seen.insert(cve.clone()) {
                added.push((cve, day(entry.get("dateAdded"))));
            } else if let Some((_, known @ None)) = added.iter_mut().find(|(listed, _)| *listed == cve) {
                *known = day(entry.get("dateAdded"));
            }
        }
        if added.is_empty() {
            return Err(Unreadable("the document lists no vulnerability".to_owned()));
        }
        // `isIntegralNumber`: an integer, not `2.0` nor `"2"`.
        let declared = payload.get("count").and_then(|count| count.as_i64().or_else(|| count.as_u64().map(saturate)));
        if let Some(declared) = declared
            && declared > i64::try_from(added.len()).unwrap_or(i64::MAX)
        {
            return Err(Unreadable(format!(
                "the document declares {declared} entries and carries {}: it is incomplete",
                added.len()
            )));
        }
        Ok(KevCatalog {
            version: version(payload.get("catalogVersion")),
            released: instant(payload.get("dateReleased")),
            added,
        })
    }

    /// Whether the catalogue lists this upper-case CVE.
    pub fn lists(&self, cve: &str) -> bool {
        self.added.iter().any(|(listed, _)| listed == cve)
    }
}

fn saturate(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// A textual, non-blank version, `String.trim`med, cut to [`VERSION_MAX`] UTF-16 units.
fn version(node: Option<&Value>) -> Option<String> {
    let Some(Value::String(text)) = node else {
        return None;
    };
    if java::is_blank(text) {
        return None;
    }
    let trimmed = java::trim(text);
    let units: Vec<u16> = trimmed.encode_utf16().collect();
    Some(match units.get(..VERSION_MAX) {
        Some(head) if units.len() > VERSION_MAX => java::from_utf16(head),
        _ => trimmed.to_owned(),
    })
}

/// `Instant.parse` of the trimmed text; **unknown rather than invented** when it cannot be read.
fn instant(node: Option<&Value>) -> Option<Instant> {
    match node {
        Some(Value::String(text)) => Instant::parse_iso(java::trim(text)),
        _ => None,
    }
}

/// `LocalDate.parse` of the trimmed text, at the start of that day in UTC.
fn day(node: Option<&Value>) -> Option<Instant> {
    let Some(Value::String(text)) = node else {
        return None;
    };
    let (year, month, day) = java::iso_local_date(java::trim(text))?;
    Instant::of_utc(year, u32::from(month), u32::from(day), 0, 0, 0)
}
