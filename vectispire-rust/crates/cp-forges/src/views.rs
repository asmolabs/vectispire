//! What the routes show — `ForgeConnectionView`, `ForgeDiscoveryView`, `ForgeRepositoryView` — members in the records'
//! order, every one written, `null` included, as Jackson writes a record. **Never a token.**

use serde::Serialize;
use time::OffsetDateTime;
use vectispire_domain::forges::{DiscoveryReason, DiscoveryState, UnreadableNamespace};
use vectispire_domain::instant::Instant;

use crate::error::ForgeError;
use crate::persistence::{DiscoveryRow, RepositoryRow};

/// `Instant.toString` of a stored instant.
pub(crate) fn iso(at: OffsetDateTime) -> String {
    vectispire_cp_audit::iso_instant(at)
}

pub(crate) fn iso_opt(at: Option<OffsetDateTime>) -> Option<String> {
    at.map(iso)
}

/// The domain's instant of a stored one, to the nanosecond.
pub(crate) fn instant(at: OffsetDateTime) -> Instant {
    let utc = at.to_offset(time::UtcOffset::UTC);
    Instant { epoch_second: utc.unix_timestamp(), nano: utc.nanosecond() }
}

/// A stored instant of the domain's, `None` past what a timestamp holds.
pub(crate) fn stored(at: Instant) -> Option<OffsetDateTime> {
    let seconds = OffsetDateTime::from_unix_timestamp(at.epoch_second).ok()?;
    seconds.replace_nanosecond(at.nano).ok()
}

/// `ForgeConnectionView`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ForgeConnectionView {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub edition: String,
    pub base_url: String,
    pub owner: Option<String>,
    pub internal_network: bool,
    pub ca_subject: Option<String>,
    pub ca_not_after: Option<String>,
    pub credential_kind: String,
    pub scopes: Option<Vec<String>>,
    pub can_write: Option<bool>,
    pub token_expires_at: Option<String>,
    pub forge_version: Option<String>,
    pub probed_at: String,
    pub encryption_state: String,
    pub state: &'static str,
    pub integration: String,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
    pub last_discovery: Option<ForgeDiscoveryView>,
    pub imported_targets: i64,
}

/// `UnreadableNamespace` as Jackson writes the record.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NamespaceView {
    pub path: Option<String>,
    pub reason: String,
}

/// `ForgeDiscoveryView`.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ForgeDiscoveryView {
    pub id: i64,
    pub connection_id: String,
    pub state: &'static str,
    pub reason: Option<&'static str>,
    pub detail: Option<String>,
    pub requested_at: String,
    pub requested_by: String,
    pub attempts: i32,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub namespaces_seen: i32,
    pub repositories_seen: i32,
    pub repositories_skipped: i32,
    pub requests_made: i32,
    pub rate_limit_wait_seconds: i64,
    pub rate_limit_reset_at: Option<String>,
    pub new_count: Option<i32>,
    pub changed_count: Option<i32>,
    pub gone_count: Option<i32>,
    pub unreadable_namespaces: Vec<NamespaceView>,
}

impl ForgeDiscoveryView {
    /// `ForgeDiscoveryService.view`: a stored state or reason this version does not know is a fault of the row.
    pub(crate) fn of(run: &DiscoveryRow) -> Result<ForgeDiscoveryView, ForgeError> {
        let state = DiscoveryState::of_stored(&run.state).map_err(ForgeError::Unexpected)?;
        let reason = DiscoveryReason::of_stored(run.reason.as_deref()).map_err(ForgeError::Unexpected)?;
        Ok(ForgeDiscoveryView {
            id: run.id,
            connection_id: run.connection_id.clone(),
            state: state.wire_name(),
            reason: reason.map(DiscoveryReason::wire_name),
            detail: run.detail.clone(),
            requested_at: iso(run.requested_at),
            requested_by: run.requested_by.clone(),
            attempts: run.attempts,
            started_at: iso_opt(run.started_at),
            finished_at: iso_opt(run.finished_at),
            namespaces_seen: run.namespaces_seen,
            repositories_seen: run.repositories_seen,
            repositories_skipped: run.repositories_skipped,
            requests_made: run.requests_made,
            rate_limit_wait_seconds: run.rate_limit_wait_seconds,
            rate_limit_reset_at: iso_opt(run.rate_limit_reset_at),
            new_count: run.new_count,
            changed_count: run.changed_count,
            gone_count: run.gone_count,
            unreadable_namespaces: UnreadableNamespace::decode(run.unreadable_namespaces.as_deref())
                .into_iter()
                .map(|namespace| NamespaceView { path: namespace.path, reason: namespace.reason })
                .collect(),
        })
    }
}

/// `ForgeRepositoryView`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ForgeRepositoryView {
    pub id: i64,
    pub connection_id: String,
    pub forge_id: String,
    pub full_path: String,
    pub namespace_path: String,
    pub personal: bool,
    pub name: String,
    pub default_branch: Option<String>,
    pub archived: Option<bool>,
    pub fork: Option<bool>,
    pub visibility: Option<String>,
    pub last_activity_at: Option<String>,
    pub language: Option<String>,
    pub size_bytes: Option<i64>,
    pub http_url: Option<String>,
    pub ssh_url: Option<String>,
    pub web_url: Option<String>,
    pub first_seen_by: i64,
    pub first_seen_at: String,
    pub last_seen_by: i64,
    pub last_seen_at: String,
    pub changed_by: Option<i64>,
    pub change_summary: Option<String>,
    pub gone_by: Option<i64>,
    pub gone_at: Option<String>,
}

impl ForgeRepositoryView {
    pub(crate) fn of(row: &RepositoryRow) -> ForgeRepositoryView {
        ForgeRepositoryView {
            id: row.id,
            connection_id: row.connection_id.clone(),
            forge_id: row.forge_id.clone(),
            full_path: row.full_path.clone(),
            namespace_path: row.namespace_path.clone(),
            personal: row.personal,
            name: row.name.clone(),
            default_branch: row.default_branch.clone(),
            archived: row.archived,
            fork: row.fork,
            visibility: row.visibility.clone(),
            last_activity_at: iso_opt(row.last_activity_at),
            language: row.language.clone(),
            size_bytes: row.size_bytes,
            http_url: row.http_url.clone(),
            ssh_url: row.ssh_url.clone(),
            web_url: row.web_url.clone(),
            first_seen_by: row.first_seen_by,
            first_seen_at: iso(row.first_seen_at),
            last_seen_by: row.last_seen_by,
            last_seen_at: iso(row.last_seen_at),
            changed_by: row.changed_by,
            change_summary: row.change_summary.clone(),
            gone_by: row.gone_by,
            gone_at: iso_opt(row.gone_at),
        }
    }
}
