//! Analysis of infrastructure manifests — `IacScanner`: Terraform, Kubernetes, Dockerfiles, through
//! checkov.
//!
//! **Absent, never an empty list, when the checker fails** (decision 0007). An empty list means
//! "analysed, clean", which ingestion reads as permission to resolve every IaC issue on the target: a
//! crash would declare a repository fixed. This checker's command line and output vary by version, so
//! every failure — an exit code, a stdout that is not JSON — ends as absent, and the rest of the scan
//! goes on.

use crate::container_paths;
use crate::jackson;
use crate::output::{self, children, index, path, text_or_none};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use vectispire_container::{ContainerResult, ContainerRun, ContainerRunner, Mount};

/// What the containers are labelled, and what an error names.
pub const LABEL: &str = "checkov (IaC analysis)";

/// A failed control — the wire form the agent sends, field for field and in this order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IacFinding {
    /// The control's identifier, `CKV_AWS_20` and the like — fingerprint material.
    pub check_id: String,
    pub check_name: String,
    pub file: String,
    pub line: i32,
    pub guideline: Option<String>,
    /// The resource concerned: `aws_s3_bucket.example`.
    pub resource: Option<String>,
}

/// The run of the checker over the scanned tree, mounted read-only.
pub fn request(workspace_root: &Path, sub_path: Option<&str>, image: &str) -> ContainerRun {
    ContainerRun::new(
        image,
        vec![
            "-d".to_owned(),
            container_paths::source(sub_path),
            "-o".to_owned(),
            "json".to_owned(),
            // It exits 1 when a control fails. That is the expected result, not a container failure —
            // the same reason the secrets scanner neutralises its exit code.
            "--soft-fail".to_owned(),
            "--compact".to_owned(),
        ],
        vec![Mount::read_only(workspace_root.display().to_string(), container_paths::MOUNT)],
        LABEL,
    )
    .running_as_owner_of(workspace_root)
}

/// What the IaC step makes of the container's result: the findings, or `None` — absent.
pub fn outcome(result: &ContainerResult, sub_path: Option<&str>) -> Option<Vec<IacFinding>> {
    // Deliberately broad, as the Java side's `catch (RuntimeException)`: every failure is absent.
    let payload = output::parse_json(result, LABEL, &[0]).ok()??;
    findings(&payload, sub_path)
}

/// The failed controls of a checkov JSON document — `IacScanner.findings` — or `None` when the document
/// is not a report checkov wrote.
///
/// **Three shapes are checkov's, measured on the pinned 3.3.9**: one report object (`check_type`,
/// `results`, `summary`) when one framework is detected, a list of them when several are, and — when
/// there is nothing to check — a bare summary (`resource_count`, `checkov_version`, …) with no
/// `results` at all. The last is a clean answer: an empty list.
///
/// **Anything else is absent, never an empty list** (decision 0007): a scalar, `{}`, an empty list, a
/// list holding something other than reports, `results` that is not an object, `failed_checks` that
/// is not an array, a check that is not an object. Each used to read as "no control failed" and
/// resolved the target's whole IaC backlog. Pinned by `reference/iac/`.
pub fn findings(payload: &Value, sub_path: Option<&str>) -> Option<Vec<IacFinding>> {
    if let Value::Object(members) = payload
        && !members.contains_key("results")
    {
        return is_bare_summary(payload).then(Vec::new);
    }
    let reports: Vec<&Value> = match payload {
        Value::Array(items) if !items.is_empty() => items.iter().collect(),
        Value::Object(_) => vec![payload],
        _ => return None,
    };
    let mut found = Vec::new();
    for report in reports {
        let failed = path(path(Some(report), "results"), "failed_checks");
        if !report.is_object() || !matches!(failed, Some(Value::Array(_))) {
            return None;
        }
        for check in children(failed) {
            if !check.is_object() {
                return None;
            }
            found.push(IacFinding {
                check_id: jackson::as_text(jackson::path(check, "check_id"), "unknown"),
                check_name: jackson::as_text(jackson::path(check, "check_name"), ""),
                // A path relative to its target, sometimes with a leading slash: both forms are reduced
                // to one relative to the scanned tree, or one file carries two identities by version.
                file: container_paths::relative_to_source(
                    &jackson::as_text(jackson::path(check, "file_path"), ""),
                    sub_path,
                ),
                line: jackson::as_int(index(jackson::path(check, "file_line_range"), 0), 0),
                guideline: text_or_none(jackson::path(check, "guideline")),
                resource: text_or_none(jackson::path(check, "resource")),
            });
        }
    }
    Some(found)
}

/// What checkov prints when no framework found anything to check: `isIntegralNumber` and `isTextual`.
fn is_bare_summary(payload: &Value) -> bool {
    let integral =
        matches!(jackson::path(payload, "resource_count"), Some(Value::Number(n)) if n.is_i64() || n.is_u64());
    integral && matches!(jackson::path(payload, "checkov_version"), Some(Value::String(_)))
}

/// The IaC findings of the workspace at `workspace_root`, `None` when the checker failed.
pub async fn scan(
    runner: &ContainerRunner,
    workspace_root: &Path,
    sub_path: Option<&str>,
    image: &str,
) -> Option<Vec<IacFinding>> {
    let result = runner.run(&request(workspace_root, sub_path, image)).await.ok()?;
    outcome(&result, sub_path)
}
