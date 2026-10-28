//! `IssueFingerprint`: an issue's identity across scans — **the most critical data contract in the system**.
//!
//! Two successive scans produce findings with no identity; this hash decides whether what a scanner saw
//! is yesterday's issue, with its history and its triage, or a new one. Getting it wrong fails nowhere:
//! the backlog is resolved and recreated, triage lost, and the dashboard looks healthier (AGENTS.md).
//!
//! `SHA-256(target NUL type NUL identifier NUL (purl or name) NUL path)`, lowercase hex, over the UTF-8
//! bytes Java's `getBytes(UTF_8)` writes. Held to `reference/fingerprints/` — Java's answers for the
//! cases of `IssueFingerprintTest` and `ToolFingerprintTest`, each Java quirk, and a seeded corpus —
//! with no tolerance.
//!
//! **Computed on the scanner's whole value, before any clipping** (`bounded_text::clip`): the stored
//! column is a display copy, the key is what the scanner said.

use sha2::{Digest, Sha256};

use crate::{FindingType, ScanTarget};

/// What a finding is fingerprinted by. Every text is the scanner's own, unclipped; `None` and `""` hash
/// alike (`sha256_fields`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Input<'a> {
    /// Which repository or image the finding belongs to.
    pub target: ScanTarget,
    pub finding_type: FindingType,
    /// The scanner's own identity for the finding — a CVE, a rule id.
    pub identifier: Option<&'a str>,
    /// The ecosystem-qualified package identity, when there is one.
    pub purl: Option<&'a str>,
    /// The fallback when the purl is absent **or empty**.
    pub package_name: Option<&'a str>,
    /// Where it was found, when the finding is located. The line is never in it.
    pub file_path: Option<&'a str>,
}

/// Why a tool-scoped fingerprint was refused, in Java's sentences.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToolRefusal {
    #[error("Only a tool-scoped type is fingerprinted by tool; {0} is fingerprinted by package.")]
    NotToolScoped(&'static str),
    #[error("A {0} finding carries the key of the tool that made it.")]
    NoToolKey(&'static str),
}

/// `IssueFingerprint.of`.
pub fn of(input: &Input<'_>) -> String {
    // An *empty* purl falls back to the package name, not just an absent one: an analyzer writing "" for
    // "no purl here" is common enough that telling the two apart would split one issue into two.
    let package = match input.purl {
        Some(purl) if !purl.is_empty() => Some(purl),
        _ => input.package_name,
    };
    let target = input.target.fingerprint_key();
    sha256_fields(&[Some(&target), Some(input.finding_type.wire_name()), input.identifier, package, input.file_path])
}

/// `IssueFingerprint.ofTool`: a plugin's or an imported finding, its tool key in the package's place —
/// the same formula, so no second hash exists to drift.
///
/// The type is checked before the key, as Java checks them; a key blank to `String.isBlank` — not to
/// Rust's notion of white space — is refused, since a finding with no tool would share its identity with
/// every tool's finding on the same rule and file.
pub fn of_tool(
    target: ScanTarget,
    finding_type: FindingType,
    tool_key: Option<&str>,
    rule_id: Option<&str>,
    file_path: Option<&str>,
) -> Result<String, ToolRefusal> {
    if !finding_type.tool_scoped() {
        return Err(ToolRefusal::NotToolScoped(finding_type.wire_name()));
    }
    let tool_key =
        tool_key.filter(|key| !crate::java::is_blank(key)).ok_or(ToolRefusal::NoToolKey(finding_type.wire_name()))?;
    Ok(of(&Input { target, finding_type, identifier: rule_id, purl: None, package_name: Some(tool_key), file_path }))
}

/// `Digests.sha256Fields`: the fields joined by NUL — which no hashed value can contain, so no content
/// imitates a boundary — `None` written as `""`, SHA-256, lowercase hex.
pub fn sha256_fields(fields: &[Option<&str>]) -> String {
    let mut hasher = Sha256::new();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            hasher.update([0u8]);
        }
        hasher.update(field.unwrap_or("").as_bytes());
    }
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}
