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
///
/// **Known defect, reproduced and reported (decision 0007):** a JSON document that is not a checkov
/// report — a scalar, `{}`, a `results` that is not an object — gives an empty list, "analysed,
/// clean", as on the Java side today. Pinned by `reference/iac/runs/18-…` to `20-…`; the corrected
/// outcome is asserted by the ignored test `pending_0007_a_document_that_is_no_report_is_absent`.
pub fn outcome(result: &ContainerResult, sub_path: Option<&str>) -> Option<Vec<IacFinding>> {
    // Deliberately broad, as the Java side's `catch (RuntimeException)`: every failure is absent.
    let payload = output::parse_json(result, LABEL, &[0]).ok()??;
    Some(findings(&payload, sub_path))
}

/// The findings of a checkov JSON document.
///
/// It prints **one** report object when a single framework is detected, and a **list** when several
/// are — Terraform and Kubernetes in one repository. Both shapes are read, or a mixed repository
/// reports nothing.
pub fn findings(payload: &Value, sub_path: Option<&str>) -> Vec<IacFinding> {
    let reports: Vec<&Value> = match payload {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    let mut found = Vec::new();
    for report in reports {
        for check in children(path(path(Some(report), "results"), "failed_checks")) {
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
    found
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
