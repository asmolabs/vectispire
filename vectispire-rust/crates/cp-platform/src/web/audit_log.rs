//! The audit trail, and its integrity — `AuditLogController`, administrators and CISOs (`@RequiresGovernanceRead` on
//! the class):
//!
//! - `GET /api/v1/audit-log` (`list`): a page, newest first, `limit`/`offset` as on `/issues` and clamped by the service;
//! - `GET /api/v1/audit-log/operation-types` (`operationTypes`): the values actually present;
//! - `GET /api/v1/audit-log/verify` (`verify`): the chain and the mirror checked, **and said so on the screen** — a
//!   break is told to the chain's listeners by the service.
//!
//! None names a target: the trail is the deployment's.

use std::sync::Arc;

use axum::extract::RawQuery;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use vectispire_cp_audit::{AuditLogQuery, Entries, Integrity, QueryError, StoredEntry, iso_instant};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{Route, RouteEntry};

use super::{bad_request, ok, read, unexpected};

pub(super) const LIST: &str = "/api/v1/audit-log";
pub(super) const OPERATION_TYPES: &str = "/api/v1/audit-log/operation-types";
pub(super) const VERIFY: &str = "/api/v1/audit-log/verify";

/// `AuditEntryView`: the row's fields, hashes included — they are what lets a reader check the chain themselves.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct EntryView {
    id: String,
    description: String,
    operation_type: String,
    resource_id: String,
    /// `Instant`, as Jackson writes it with dates as text.
    timestamp: String,
    user_id: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    previous_hash: Option<String>,
    entry_hash: Option<String>,
}

impl EntryView {
    fn of(entry: StoredEntry) -> EntryView {
        EntryView {
            id: entry.id.as_hyphenated().to_string(),
            description: entry.description,
            operation_type: entry.operation_type,
            resource_id: entry.resource_id,
            timestamp: iso_instant(entry.timestamp),
            user_id: entry.user_id,
            ip_address: entry.ip_address,
            user_agent: entry.user_agent,
            previous_hash: entry.previous_hash,
            entry_hash: entry.entry_hash,
        }
    }
}

/// `AuditLogPage`: `limit` and `offset` as the service applied them.
#[derive(Debug, Serialize)]
struct Page {
    items: Vec<EntryView>,
    total: i64,
    limit: i32,
    offset: i32,
}

impl Page {
    fn of(entries: Entries) -> Page {
        Page {
            items: entries.items.into_iter().map(EntryView::of).collect(),
            total: entries.total,
            limit: entries.limit,
            offset: entries.offset,
        }
    }
}

/// `Verification`, every figure a reader needs: `broken` is `null` while the chain holds, and `checkedAt` is this
/// server's clock — the attestation screen showed the browser's, which says when a page was opened, not when the chain
/// was found intact.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct Verification {
    total: i64,
    unverifiable: usize,
    verified: i64,
    intact: bool,
    broken: Option<String>,
    mirrored: bool,
    missing_from_table: usize,
    missing_from_mirror: usize,
    checked_at: String,
}

impl Verification {
    fn of(integrity: Integrity) -> Verification {
        Verification {
            total: integrity.total,
            unverifiable: integrity.unverifiable,
            verified: integrity.verified,
            intact: integrity.intact,
            broken: integrity.broken,
            mirrored: integrity.mirrored,
            missing_from_table: integrity.missing_from_table,
            missing_from_mirror: integrity.missing_from_mirror,
            checked_at: iso_instant(integrity.checked_at),
        }
    }
}

/// A refusal in the service's words (`InvalidInputException`, 400); a failure as the referenced 500 it is.
fn refuse(path: &str, error: QueryError) -> Response {
    match error {
        QueryError::InvalidInput(message) => bad_request(message),
        failure @ QueryError::Audit(_) => unexpected("GET", path, &failure),
    }
}

pub(super) fn routes(trail: Arc<AuditLogQuery>, entries: &mut Vec<RouteEntry>) {
    let list = trail.clone();
    entries.push(Route::get(LIST).requires(Access::GovernanceRead).names_no_target().handler(
        move |RawQuery(query): RawQuery| {
            let trail = list.clone();
            async move {
                let query = query.as_deref();
                // Spring binds every argument before the controller runs, in the declared order: an unreadable
                // `limit` is the refusal even when `offset` is unreadable too.
                let limit = match read::int_or(query, "limit", 50) {
                    Ok(limit) => limit,
                    Err(refused) => return refused.into_response(),
                };
                let offset = match read::int_or(query, "offset", 0) {
                    Ok(offset) => offset,
                    Err(refused) => return refused.into_response(),
                };
                let operation_type = read::text(query, "operation_type");
                let user_id = read::text(query, "user_id");
                let search = read::text(query, "search");
                match trail.page(operation_type.as_deref(), user_id.as_deref(), search.as_deref(), limit, offset).await
                {
                    Ok(page) => ok(&Page::of(page)),
                    Err(failure) => refuse(LIST, failure),
                }
            }
        },
    ));

    let types = trail.clone();
    entries.push(Route::get(OPERATION_TYPES).requires(Access::GovernanceRead).names_no_target().handler(move || {
        let trail = types.clone();
        async move {
            match trail.operation_types().await {
                Ok(types) => ok(&types),
                Err(failure) => refuse(OPERATION_TYPES, failure),
            }
        }
    }));

    entries.push(Route::get(VERIFY).requires(Access::GovernanceRead).names_no_target().handler(move || {
        let trail = trail.clone();
        async move {
            match trail.verify().await {
                Ok(integrity) => ok(&Verification::of(integrity)),
                Err(failure) => refuse(VERIFY, failure),
            }
        }
    }));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn an_entry_is_written_as_jackson_writes_the_view_nulls_included() {
        let entry = StoredEntry {
            id: uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            description: "Saved".to_owned(),
            operation_type: "SETTINGS_UPDATED".to_owned(),
            resource_id: "k".to_owned(),
            timestamp: OffsetDateTime::from_unix_timestamp_nanos(1_792_224_000_120_000_000).unwrap(),
            user_id: Some("admin".to_owned()),
            ip_address: None,
            user_agent: None,
            previous_hash: None,
            entry_hash: Some("ab".to_owned()),
        };
        assert_eq!(
            vectispire_domain::wire::to_wire_string(&EntryView::of(entry)),
            r#"{"id":"01234567-89ab-cdef-0123-456789abcdef","description":"Saved","operationType":"SETTINGS_UPDATED","resourceId":"k","timestamp":"2026-10-17T08:00:00.120Z","userId":"admin","ipAddress":null,"userAgent":null,"previousHash":null,"entryHash":"ab"}"#
        );
    }

    #[test]
    fn a_verification_names_every_figure_in_the_controllers_order() {
        let integrity = Integrity {
            total: 3,
            unverifiable: 1,
            verified: 2,
            intact: false,
            broken: Some("x".to_owned()),
            mirrored: true,
            missing_from_table: 4,
            missing_from_mirror: 5,
            checked_at: OffsetDateTime::from_unix_timestamp(1_792_224_000).unwrap(),
        };
        assert_eq!(
            vectispire_domain::wire::to_wire_string(&Verification::of(integrity)),
            r#"{"total":3,"unverifiable":1,"verified":2,"intact":false,"broken":"x","mirrored":true,"missingFromTable":4,"missingFromMirror":5,"checkedAt":"2026-10-17T08:00:00Z"}"#
        );
    }
}
