//! The manifest sealing an audit evidence package — Java's `EvidenceBundleManifest`.
//!
//! Its JSON is what the bundle's detached signature covers, so the field names, their order and the nulls are
//! Jackson's, held to `reference/compliance/records.json`.

use serde::{Deserialize, Serialize};

use crate::instant_text;
use vectispire_domain::instant::Instant;

/// `total_audit_log_entries` is absent when section 02 was withheld — a count of an estate's audit trail is not zero
/// merely because this archive does not include it; `withheld` names each section left out and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundleManifest {
    pub version: String,
    #[serde(with = "instant_text")]
    pub generated_at: Instant,
    pub generated_by: String,
    pub audit_chain_status: String,
    pub total_audit_log_entries: Option<i64>,
    pub files: Vec<EvidenceFileEntry>,
    pub withheld: Vec<WithheldSection>,
}

/// A section left out of the archive, and the reason a reader of the manifest is given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldSection {
    pub path: String,
    pub reason: String,
}

/// One bundled file and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceFileEntry {
    pub path: String,
    pub description: String,
    pub size_bytes: i64,
    pub sha256: String,
}
