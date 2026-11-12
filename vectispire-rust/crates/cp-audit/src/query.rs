//! Reading the audit trail and reporting its integrity — `AuditLogQueryService`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::Arc;

use time::OffsetDateTime;

use crate::listener::{AuditChainBroken, ChainBrokenListener};
use crate::log::{AuditError, AuditLog};
use crate::persistence::{self, Filter};
use crate::record::{Clock, StoredEntry};
use crate::text::java_trim;

const MAX_PAGE_SIZE: i32 = 200;

/// `BoundedText.SEARCH_MAX`: every list route's free text is bounded, and refused in words past it.
pub const SEARCH_MAX: usize = 500;

/// Why a read was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// A 400: the request said something this route does not accept, in words the client shows.
    #[error("{0}")]
    InvalidInput(String),
    #[error(transparent)]
    Audit(#[from] AuditError),
}

impl From<persistence::DbError> for QueryError {
    fn from(failure: persistence::DbError) -> QueryError {
        QueryError::Audit(AuditError::Database(failure))
    }
}

/// A page, with `limit` and `offset` as actually applied, after clamping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entries {
    pub items: Vec<StoredEntry>,
    pub total: i64,
    pub limit: i32,
    pub offset: i32,
}

/// What a verification says, every figure a reader needs (`AuditLogQueryService.Integrity`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    pub total: i64,
    pub unverifiable: usize,
    pub verified: i64,
    /// The chain holds **and** the mirror lost nothing from the table: an entry the mirror has and the table lost
    /// leaves the chain intact by construction, so the chain alone would call a deletion a clean bill of health.
    pub intact: bool,
    pub broken: Option<String>,
    pub mirrored: bool,
    pub missing_from_table: usize,
    pub missing_from_mirror: usize,
    pub checked_at: OffsetDateTime,
}

/// The whole trail, one document per entry, and how many: the evidence bundle's
/// `02_immutable_audit_log.jsonl` (`AuditLogQueryService.JsonLines`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonLines {
    pub text: String,
    pub entries: usize,
}

/// The read side of the audit module.
#[derive(Clone)]
pub struct AuditLogQuery {
    log: AuditLog,
    clock: Arc<dyn Clock>,
    chain_broken: Vec<Arc<dyn ChainBrokenListener>>,
}

impl std::fmt::Debug for AuditLogQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AuditLogQuery").field("log", &self.log).finish_non_exhaustive()
    }
}

/// `BoundedText.search`: trimmed as `String.trim` does, empty as absent, refused past [`SEARCH_MAX`] UTF-16
/// units with the sentence the client shows.
pub fn bounded_search(value: Option<&str>, parameter: &str) -> Result<Option<String>, QueryError> {
    let trimmed = java_trim(value.unwrap_or(""));
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.encode_utf16().count() > SEARCH_MAX {
        return Err(QueryError::InvalidInput(format!("{parameter} is longer than {SEARCH_MAX} characters.")));
    }
    Ok(Some(trimmed.to_owned()))
}

fn blank_to_none(value: Option<&str>) -> Option<String> {
    value.filter(|value| !crate::text::is_blank(value)).map(str::to_owned)
}

impl AuditLogQuery {
    pub fn new(log: AuditLog, clock: Arc<dyn Clock>, chain_broken: Vec<Arc<dyn ChainBrokenListener>>) -> AuditLogQuery {
        AuditLogQuery { log, clock, chain_broken }
    }

    /// A page of the trail, newest first — `limit`/`offset` as on `/issues`, one pagination convention across
    /// the API. The offset is applied as Spring Data's page of that size applies it: the page that holds it.
    pub async fn page(
        &self,
        operation_type: Option<&str>,
        user_id: Option<&str>,
        search: Option<&str>,
        limit: i32,
        offset: i32,
    ) -> Result<Entries, QueryError> {
        let size = limit.clamp(1, MAX_PAGE_SIZE);
        let from = offset.max(0);
        let term = bounded_search(search, "search")?;
        let filter = Filter {
            operation_type: blank_to_none(operation_type),
            user_id: blank_to_none(user_id),
            pattern: term.map(|term| format!("%{}%", term.to_lowercase())),
        };
        // `size` is at least one: the clamp above.
        let applied = from.checked_div(size).map_or(0, |page| i64::from(page).saturating_mul(i64::from(size)));
        let (rows, total) = persistence::filtered(self.log.db(), &filter, i64::from(size), applied).await?;
        let items = rows.into_iter().map(StoredEntry::from_row).collect();
        Ok(Entries { items, total, limit: size, offset: from })
    }

    /// How many entries of one operation were written since `since` — whether this week's digest already went
    /// out is answered by the entry its sending writes.
    pub async fn count_since(&self, operation_type: &str, since: OffsetDateTime) -> Result<i64, QueryError> {
        Ok(persistence::count_since(self.log.db(), operation_type, since).await?)
    }

    /// Which of these resources at least one entry of `operation_type` names, a thousand identifiers a
    /// statement: the list is the caller's, and every engine stops binding somewhere.
    pub async fn resources_named(
        &self,
        operation_type: &str,
        resource_ids: &[String],
    ) -> Result<BTreeSet<String>, QueryError> {
        let distinct: Vec<String> = resource_ids.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
        let mut named = BTreeSet::new();
        for batch in distinct.chunks(1_000) {
            named.extend(persistence::resources_named(self.log.db(), operation_type, batch).await?);
        }
        Ok(named)
    }

    /// The values actually present, so the filter offers nothing empty.
    pub async fn operation_types(&self) -> Result<Vec<String>, QueryError> {
        Ok(persistence::distinct_operation_types(self.log.db()).await?)
    }

    /// The whole trail, oldest first, **each row as the evidence bundle's mapper writes the entity**: Jackson 2
    /// with the time module, dates as text and `INDENT_OUTPUT` on — so each "line" is an indented document
    /// followed by one line feed, as every bundle an auditor already holds has it. The bytes are the contract:
    /// the same trail must produce the same file it did before the audit log was ported.
    pub async fn as_json_lines(&self) -> Result<JsonLines, QueryError> {
        let all: Vec<StoredEntry> =
            persistence::all_in_chain_order(self.log.db()).await?.into_iter().map(StoredEntry::from_row).collect();
        let mut text = String::new();
        for entry in &all {
            text.push_str(&crate::export::entity_document(entry));
            text.push('\n');
        }
        Ok(JsonLines { text, entries: all.len() })
    }

    /// The chain and the mirror, verified; a break is told to every [`ChainBrokenListener`] — synchronously,
    /// since this opens no transaction for an after-commit hook to wait on, and dropping the alarm is the one
    /// outcome this path exists to prevent.
    pub async fn verify(&self) -> Result<Integrity, QueryError> {
        let result = self.log.verify().await?;
        let mirror = self.log.verify_against_mirror().await?;
        let total = persistence::count(self.log.db()).await?;
        let intact = result.broken.is_none() && mirror.missing_from_table == 0;
        if !intact {
            let event =
                AuditChainBroken { broken_at: result.broken.clone(), missing_from_table: mirror.missing_from_table };
            for listener in &self.chain_broken {
                listener.chain_broken(&event).await;
            }
        }
        Ok(Integrity {
            total,
            unverifiable: result.unverifiable,
            verified: total.saturating_sub(i64::try_from(result.unverifiable).unwrap_or(i64::MAX)),
            intact,
            broken: result.broken,
            mirrored: mirror.configured,
            missing_from_table: mirror.missing_from_table,
            missing_from_mirror: mirror.missing_from_mirror,
            checked_at: self.clock.now(),
        })
    }
}

/// `DateTimeFormatter.ISO_INSTANT`, which Jackson's `InstantSerializer` writes when dates are text: the fraction
/// only when there is one, in groups of three digits.
pub fn iso_instant(instant: OffsetDateTime) -> String {
    let utc = instant.to_offset(time::UtcOffset::UTC);
    let mut out = String::with_capacity(30);
    let _ = write!(
        out,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    );
    let nanos = utc.nanosecond();
    if nanos != 0 {
        if nanos.is_multiple_of(1_000_000) {
            let _ = write!(out, ".{:03}", nanos / 1_000_000);
        } else if nanos.is_multiple_of(1_000) {
            let _ = write!(out, ".{:06}", nanos / 1_000);
        } else {
            let _ = write!(out, ".{nanos:09}");
        }
    }
    out.push('Z');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ISO_INSTANT`, as `Instant.toString` and Jackson print it: no fraction on the second, else in groups of three.
    #[test]
    fn the_bundle_instant_is_iso_instant() {
        let at = |nanos: i128| iso_instant(OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap());
        assert_eq!(at(1_792_224_000_000_000_000), "2026-10-17T08:00:00Z");
        assert_eq!(at(1_792_224_000_120_000_000), "2026-10-17T08:00:00.120Z");
        assert_eq!(at(1_792_224_000_123_400_000), "2026-10-17T08:00:00.123400Z");
        assert_eq!(at(1_792_224_000_000_000_001), "2026-10-17T08:00:00.000000001Z");
    }
}
