//! An uploaded Semgrep rule set: what is accepted, and what is deliberately not done to it.
//!
//! A port of `RuleSet` and `InvalidRuleSetException`.
//!
//! ## Invariant: Vectispire never parses these rules
//!
//! YAML parsing is deliberately avoided to protect against parser exploits and CPU denial-of-service.
//! Rule counts and rule IDs are extracted using bounded regex over size-capped inputs.
//!
//! ## Filenames
//!
//! Uploaded files are stored flat as `rule-0001.yaml`, `rule-0002.yaml`, etc.
//! Uploaded filenames are recorded for display and tracing back, never used as file paths.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vectispire_domain::bounded_text;
pub use vectispire_protocol::StoredFile;

/// Three caps, all load-bearing:
/// - Maximum number of files in an upload: 8,000
/// - Maximum file size: 512 KB
/// - Maximum total size: 32 MB
pub const MAX_FILES: usize = 8_000;
pub const MAX_FILE_BYTES: usize = 512 * 1024;
pub const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;

pub const MAX_NAME_LENGTH: usize = 255;

static YAML_NAME: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?i)\.ya?ml$").expect("a fixed pattern")
});

static RULE_ID: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r#"^\s*-?\s*id:\s*["']?([A-Za-z0-9._\-/]+)["']?\s*$"#).expect("a fixed pattern")
});

/// One uploaded file as received by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadedFile {
    /// The operator's name for it. Recorded, displayed, never used as a path.
    pub name: Option<String>,
    pub content: Option<String>,
}

/// Why an uploaded rule set was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidRuleSetError(pub String);

/// Validates an upload and returns it under Vectispire's generated filenames (`rule-%04d.yaml`).
pub fn accept(files: &[UploadedFile]) -> Result<Vec<StoredFile>, InvalidRuleSetError> {
    if files.is_empty() {
        return Err(InvalidRuleSetError("No file was uploaded.".to_owned()));
    }
    if files.len() > MAX_FILES {
        return Err(InvalidRuleSetError(format!("Too many files: {}, the limit is {}.", files.len(), MAX_FILES)));
    }

    let mut total: usize = 0;
    let mut stored = Vec::with_capacity(files.len());

    for (index, file) in files.iter().enumerate() {
        let name = file.name.as_deref().unwrap_or("").trim();
        if !YAML_NAME.is_match(name) {
            let label = if name.is_empty() { "(unnamed)" } else { name };
            return Err(InvalidRuleSetError(format!(
                "\"{label}\" is not a YAML file. Semgrep rules are .yaml or .yml."
            )));
        }

        let content = file.content.as_deref().unwrap_or("");
        let bytes = content.len();
        if bytes == 0 {
            return Err(InvalidRuleSetError(format!("\"{name}\" is empty.")));
        }
        if bytes > MAX_FILE_BYTES {
            return Err(InvalidRuleSetError(format!(
                "\"{name}\" is {bytes} bytes, over the {MAX_FILE_BYTES} limit for one file."
            )));
        }
        total = total.saturating_add(bytes);
        if total > MAX_TOTAL_BYTES {
            return Err(InvalidRuleSetError(format!("The upload exceeds {MAX_TOTAL_BYTES} bytes in total.")));
        }

        stored.push(StoredFile {
            path: format!("rule-{:04}.yaml", index.saturating_add(1)),
            original_name: Some(name.to_owned()),
            content: content.to_owned(),
        });
    }

    Ok(stored)
}

/// The rule IDs a file declares, by pattern match rather than by parsing.
pub fn rule_ids_in(content: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in content.split('\n') {
        if let Some(id_match) = RULE_ID.captures(line).and_then(|caps| caps.get(1)) {
            ids.push(id_match.as_str().to_owned());
        }
    }
    ids
}

/// Every rule ID in a rule set, deduplicated, in encounter order.
pub fn rule_ids_of(files: &[StoredFile]) -> Vec<String> {
    let mut ids = Vec::new();
    let mut seen = BTreeSet::new();
    for file in files {
        for id in rule_ids_in(&file.content) {
            if seen.insert(id.clone()) {
                ids.push(id);
            }
        }
    }
    ids
}

/// The content hash an executor caches on: SHA-256 over paths and contents joined with NUL.
pub fn content_hash(files: &[StoredFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update([0u8]);
        hasher.update(file.content.as_bytes());
        hasher.update([0u8]);
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// What activating or deactivating a rule set would do to the existing backlog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageImpact {
    pub losing_issues: Vec<String>,
    pub affected_issues: i64,
    pub added_rules: i32,
    pub removed_rules: i32,
}

/// Computes what replacing the current rule set with the next rule set would do to open SAST issues.
pub fn impact(
    current: &BTreeSet<String>,
    next: &BTreeSet<String>,
    open_issues_by_rule_id: &BTreeMap<String, i64>,
) -> TriageImpact {
    let mut losing = BTreeSet::new();
    let mut affected: i64 = 0;

    for (rule_id, count) in open_issues_by_rule_id {
        if next.contains(rule_id) {
            continue;
        }
        losing.insert(rule_id.clone());
        affected = affected.saturating_add(*count);
    }

    let added_count = next.iter().filter(|id| !current.contains(*id)).count();
    let removed_count = current.iter().filter(|id| !next.contains(*id)).count();
    let added = i32::try_from(added_count).unwrap_or(i32::MAX);
    let removed = i32::try_from(removed_count).unwrap_or(i32::MAX);

    TriageImpact {
        losing_issues: losing.into_iter().collect(),
        affected_issues: affected,
        added_rules: added,
        removed_rules: removed,
    }
}

/// Validates rule set name.
pub fn validate_name(name: &str) -> Result<String, InvalidRuleSetError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(InvalidRuleSetError("A rule set needs a name.".to_owned()));
    }
    if trimmed.len() > MAX_NAME_LENGTH {
        return Err(InvalidRuleSetError(format!("A rule set's name is at most {MAX_NAME_LENGTH} characters.")));
    }
    Ok(trimmed.to_owned())
}

/// Validates activation note.
pub fn validate_activation_note(note: Option<&str>) -> Result<Option<String>, InvalidRuleSetError> {
    match note {
        Some(s) if s.len() > bounded_text::TEXT_MAX => Err(InvalidRuleSetError(format!(
            "The activation note is longer than {} characters.",
            bounded_text::TEXT_MAX
        ))),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => Ok(Some(s.trim().to_owned())),
        None => Ok(None),
    }
}
