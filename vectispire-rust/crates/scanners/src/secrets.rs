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

/// The findings of a report file's content, as the Java side reads the file: stripped, an empty
/// file meaning no secrets.
pub fn read_report(content: &str) -> Vec<SecretFinding> {
    let stripped = content.trim_matches(jackson::is_java_whitespace);
    if stripped.is_empty() { Vec::new() } else { parse(stripped) }
}

/// The findings of a gitleaks JSON report.
///
/// **Known defect, reproduced on purpose and reported:** a report that is not JSON, or not an
/// array, gives no findings — which the scan then sends as "analysed, nothing found", and that
/// resolves every secret issue of the target (decision 0007 says it must be absent). The Java parser
/// does this today; the port does the same until the Java side is fixed, so that the two agents never
/// disagree about a target's backlog. Pinned by `reference/secrets/reports/04-not-json.json`.
pub fn parse(content: &str) -> Vec<SecretFinding> {
    let Some(serde_json::Value::Array(entries)) = jackson::read_tree(content) else {
        return Vec::new();
    };
    entries
        .iter()
        .map(|entry| SecretFinding {
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

/// The secrets found, `Ok(None)` when the report could not be read — absent, not empty.
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
    let read = std::fs::read_to_string(&report);
    // Deleted the moment it is read: a file of plaintext secrets exists for as long as it must.
    let _ = std::fs::remove_file(&report);
    match read {
        Ok(content) => Ok(Some(read_report(&content))),
        // Depending on its version the tool writes nothing when it finds nothing, and the exit code
        // has already told a failure apart.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Some(Vec::new())),
        // Absent: the container ran and may have found secrets; what failed is reading them.
        Err(_) => Ok(None),
    }
}
