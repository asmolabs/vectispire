//! The search for hardcoded secrets — `SecretsScanner`'s report reading.
//!
//! **What is kept about a secret is where it is and which rule found it, never its value.** The
//! report carries the plaintext; a finding carrying it would put it in the database, the SARIF
//! exports, the tickets and the notifications.

use crate::container_paths;
use crate::jackson;
use serde::Serialize;

/// A secret found — the wire form the agent sends, field for field and in this order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretFinding {
    pub rule: String,
    pub description: String,
    pub file: String,
    pub line: i32,
    /// The one the tool computes itself; `null` on the wire when the report has none.
    pub fingerprint: Option<String>,
}

/// The findings of a report as gitleaks writes it — `SecretsScanner.read` — or `None` when the text is
/// not such a report.
///
/// **Absent, never an empty list, for anything but `[]`** (decision 0007). Text that is not JSON, JSON
/// that is not an array, an array holding something other than objects, a blank file, a document with
/// something after its end: each is absent, and the scan fails the step rather than send "analysed, no
/// secrets", which would resolve every secret issue of the target. The fields of an object stay
/// leniently read: a version that drops one is a finding with less detail, not a report to refuse.
/// Pinned by `reference/secrets/`.
pub fn read(content: &str) -> Option<Vec<SecretFinding>> {
    let serde_json::Value::Array(entries) = jackson::read_tree_strict(content)? else {
        return None;
    };
    entries
        .iter()
        .map(|entry| {
            entry.is_object().then(|| SecretFinding {
                rule: jackson::as_text(jackson::path(entry, "RuleID"), ""),
                description: jackson::as_text(jackson::path(entry, "Description"), ""),
                // The path the tool returns is the container's; a finding's is relative to the tree.
                file: container_paths::relative_to_source(&jackson::as_text(jackson::path(entry, "File"), ""), None),
                line: jackson::as_int(jackson::path(entry, "StartLine"), 0),
                fingerprint: match jackson::path(entry, "Fingerprint") {
                    Some(serde_json::Value::String(text)) => Some(text.clone()),
                    _ => None,
                },
            })
        })
        .collect()
}

// -------------------------------------------------------------------------------------- the run

use crate::failure::ScannerError;
use std::path::Path;
use vectispire_container::{ContainerRun, ContainerRunner, Mount};

/// The report's name, **at the workspace root and never inside the scanned tree**: it holds every
/// detected secret in the clear, and leaving it in the tree would hand it to the next step.
pub const REPORT_FILENAME: &str = "vectispire-gitleaks-report.json";

/// What the containers are labelled, and what an error names.
pub const LABEL: &str = "gitleaks (secret detection)";

/// The run of the secret scanner over the workspace at `workspace_root`.
pub fn request(workspace_root: &Path, sub_path: Option<&str>, image: &str) -> ContainerRun {
    ContainerRun::new(
        image,
        vec![
            "detect".to_owned(),
            format!("--source={}", container_paths::source(sub_path)),
            // The configuration is Vectispire's, never the target's: without `--config` the tool reads
            // `.gitleaks.toml` from the scanned repository — written by whoever is audited — and an
            // empty one switches detection off.
            format!("--config={}", container_paths::rules(&["gitleaks", "gitleaks.toml"])),
            // Cloned at depth 1: history would cost the time to walk it and find almost nothing.
            "--no-git".to_owned(),
            "--report-format=json".to_owned(),
            format!("--report-path={}/{REPORT_FILENAME}", container_paths::MOUNT),
            // It exits 1 on finding secrets, which is the expected result; any other code is a failure.
            "--exit-code=0".to_owned(),
        ],
        // Writable: the container deposits its report there.
        vec![Mount::writable(workspace_root.display().to_string(), container_paths::MOUNT)],
        LABEL,
    )
    .running_as_owner_of(workspace_root)
}

/// What the step says when gitleaks exited 0 and its report is not one — `SecretsScanner.scan`'s words.
pub const NOT_A_REPORT: &str = "gitleaks exited 0, and its report is not the JSON array of findings it writes — empty, \
truncated or of another shape; it is not read as a tree without secrets.";

/// What the step says when gitleaks exited 0 and wrote no report.
pub const NO_REPORT: &str = "gitleaks exited 0 without writing its report, which says nothing about the tree: a \
gitleaks that could not write the file exits 0 too.";

/// The secrets found, `Ok(None)` when the report could not be read — absent, not empty — and an error
/// when gitleaks wrote no report or one of another shape.
///
/// **No report is not "no secrets".** Gitleaks also exits 0 *without a report* when it cannot write
/// one — after logging "leaks found: 1" (measured on v8.0.0, v8.8.0 and v8.12.0) — so a missing file
/// fails the step. The pinned version writes `[]` on a clean tree.
pub async fn scan(
    runner: &ContainerRunner,
    workspace_root: &Path,
    sub_path: Option<&str>,
    image: &str,
) -> Result<Option<Vec<SecretFinding>>, ScannerError> {
    let result = runner.run(&request(workspace_root, sub_path, image)).await?;
    if result.exit_code != 0 {
        return Err(ScannerError::exited(LABEL, result.exit_code, &result.stderr));
    }
    let report = workspace_root.join(REPORT_FILENAME);
    let read_file = std::fs::read_to_string(&report);
    // Deleted the moment it is read: a file of plaintext secrets exists for as long as it must.
    let _ = std::fs::remove_file(&report);
    match read_file {
        Ok(content) => read(&content).map(Some).ok_or_else(|| ScannerError::of(LABEL, NOT_A_REPORT)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(ScannerError::of(LABEL, NO_REPORT)),
        // Absent: the container ran and may have found secrets; what failed is reading them.
        Err(_) => Ok(None),
    }
}
