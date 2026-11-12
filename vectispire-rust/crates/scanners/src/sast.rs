//! Analysis of the source code itself — `SastScanner`, through semgrep.
//!
//! Established against the real image rather than assumed, each with its consequence:
//!
//! - **The command opens with the tool's own name**: the image has no entrypoint.
//! - **`--no-rewrite-rule-ids`**: with a directory as `--config`, every `check_id` would be prefixed
//!   with the rule file's path — and the id enters the fingerprint, so reorganising the rule tree
//!   would resolve the whole SAST backlog and recreate it, triage lost.
//! - **`--no-git-ignore`**: the tree is the audited repository's clone, and a committed `*` in its
//!   `.gitignore` excluded everything into an empty success.
//! - **No error flag**: a scan exits 0 when it finds something, so any other code is a failure.
//! - **A memory cap under the container's**, so a large repository degrades through the tool's own
//!   limiter rather than being killed with 137.

use crate::container_paths;
use crate::failure::ScannerError;
use crate::jackson;
use crate::output::{self, array_len, as_text_or_none, path, text_or_none};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::sync::LazyLock;
use vectispire_container::{ContainerResult, ContainerRun, ContainerRunner, Mount};

/// What the containers are labelled, and what an error names.
pub const LABEL: &str = "semgrep (source code analysis)";

/// The share of failed files past which the result counts as "did not run": the tool exits 0 when
/// individual files time out, and a run that skipped most of the repository would read as clean.
pub const MAX_ERROR_RATIO: f64 = 0.25;

pub use vectispire_domain::Severity;

/// A source finding — the wire form the agent sends, field for field and in this order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SastFinding {
    /// Enters the fingerprint: it must not move.
    pub rule_id: String,
    /// `security` or a quality category — where the finding goes, and whether it can fail a build.
    pub category: String,
    pub severity: Severity,
    pub confidence: Option<String>,
    pub file: String,
    pub line: i32,
    /// For a SAST finding, the message is the finding.
    pub message: String,
    /// The OWASP 2021 id the rule declares about itself — **read, never inferred**; `None` is the
    /// ordinary case and places the finding in no category rather than a guessed one.
    pub owasp_category: Option<String>,
}

/// The run of semgrep over the scanned tree with Vectispire's rules, both mounted read-only.
pub fn request(workspace_root: &Path, sub_path: Option<&str>, image: &str) -> ContainerRun {
    // `rules/semgrep`, not `rules`: the workspace also carries the secrets scanner's configuration,
    // and pointing at the parent would walk a tree that is not this tool's.
    let rules = container_paths::rules(&["semgrep"]);
    let command = [
        "semgrep",
        "scan",
        &format!("--config={rules}"),
        "--no-rewrite-rule-ids",
        "--no-git-ignore",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        "--timeout=30",
        "--timeout-threshold=3",
        "--max-target-bytes=1000000",
        "--max-memory=1500",
        "--jobs=2",
        &container_paths::source(sub_path),
    ]
    .iter()
    .map(|part| (*part).to_owned())
    .collect();
    ContainerRun::new(
        image,
        command,
        vec![Mount::read_only(workspace_root.display().to_string(), container_paths::MOUNT)],
        LABEL,
    )
    .running_as_owner_of(workspace_root)
}

/// What the SAST step makes of the container's result: `Ok(Some)` the findings, `Ok(None)` absent —
/// the tool ended well and covered too little to be read — and `Err` a failure, which the step
/// records with what actually happened.
///
/// A report of another shape — `results` not an array, a result that is not an object — is a failure,
/// never "analysed, clean" (decision 0007): see [`findings`].
pub fn outcome(result: &ContainerResult, sub_path: Option<&str>) -> Result<Option<Vec<SastFinding>>, ScannerError> {
    // **The refusal is read before the exit code is judged**: semgrep reports a bad configuration on
    // stdout, inside the JSON, and leaves stderr empty.
    if result.exit_code != 0 {
        return Err(ScannerError::exited(LABEL, result.exit_code, &diagnosis(result)));
    }
    let Some(payload) = output::parse_json(result, LABEL, &[0])? else {
        return Ok(None);
    };
    if mostly_failed(&payload) {
        return Ok(None);
    }
    findings(&payload, sub_path).map(Some)
}

/// What the tool said about its own failure, wherever it put it: a refused configuration is
/// `"errors": [{"type": …}, {"message": …}]` on stdout and nothing on stderr.
pub fn diagnosis(result: &ContainerResult) -> String {
    let stderr = result.stderr.trim_matches(jackson::is_java_whitespace).to_owned();
    let stdout_only = ContainerResult { stdout: result.stdout.clone(), stderr: String::new(), exit_code: 0 };
    let Ok(Some(payload)) = output::parse_json(&stdout_only, LABEL, &[0]) else {
        return stderr;
    };
    let errors = jackson::path(&payload, "errors");
    let Some(Value::Array(errors)) = errors else {
        return stderr;
    };
    let mut said = String::new();
    for error in errors {
        let kind = jackson::as_text(jackson::path(error, "type"), "");
        let message = jackson::as_text(jackson::path(error, "message"), "");
        let kind_blank = is_blank(&kind);
        let message_blank = is_blank(&message);
        if !kind_blank || !message_blank {
            if !said.is_empty() {
                said.push_str("; ");
            }
            said.push_str(if kind_blank { &message } else { &kind });
            if !kind_blank && !message_blank {
                said.push_str(": ");
                said.push_str(&message);
            }
        }
    }
    if said.is_empty() { stderr } else { said }
}

/// `String.isBlank`: empty or Java white space only.
fn is_blank(text: &str) -> bool {
    text.chars().all(jackson::is_java_whitespace)
}

/// Did the analysis fail on enough files to be worth nothing?
///
/// **Zero files examined is not a clean tree, it is an analysis that did not happen**: file selection
/// can be influenced from the repository (its own ignore file), and a run that excluded everything
/// would otherwise resolve the target's whole SAST and quality backlog.
pub fn mostly_failed(payload: &Value) -> bool {
    let errors = array_len(jackson::path(payload, "errors"));
    let scanned = array_len(path(jackson::path(payload, "paths"), "scanned"));
    if scanned == 0 {
        return true;
    }
    if errors == 0 {
        return false;
    }
    errors as f64 / (errors + scanned) as f64 > MAX_ERROR_RATIO
}

/// The findings of a semgrep JSON report.
pub fn findings(payload: &Value, sub_path: Option<&str>) -> Result<Vec<SastFinding>, ScannerError> {
    let Some(Value::Array(results)) = jackson::path(payload, "results") else {
        return Err(ScannerError::of(LABEL, NO_RESULTS));
    };
    results
        .iter()
        .map(|entry| {
            if !entry.is_object() {
                // Read on, it became a finding of rule "unknown" at no path — one issue standing in for
                // the real ones, which then resolved.
                return Err(ScannerError::of(LABEL, RESULT_NOT_AN_OBJECT));
            }
            let extra = jackson::path(entry, "extra");
            let metadata = path(extra, "metadata");
            Ok(SastFinding {
                rule_id: jackson::as_text(jackson::path(entry, "check_id"), "unknown"),
                // Absent means "security", the cautious reading: filed as quality, an unknown finding
                // could never fail a gate.
                category: text_or_none(path(metadata, "category")).unwrap_or_else(|| "security".to_owned()),
                severity: severity_of(as_text_or_none(path(extra, "severity")).as_deref()),
                confidence: text_or_none(path(metadata, "confidence")),
                file: container_paths::relative_to_source(
                    &jackson::as_text(jackson::path(entry, "path"), ""),
                    sub_path,
                ),
                line: jackson::as_int(path(jackson::path(entry, "start"), "line"), 0),
                message: jackson::as_text(path(extra, "message"), ""),
                owasp_category: owasp_of(path(metadata, "owasp")),
            })
        })
        .collect()
}

/// What the step says when semgrep exited 0 with no `results` array — `SastScanner.findings`' words.
pub const NO_RESULTS: &str = "semgrep exited 0, and its report carries no \"results\" array; a report of another \
shape is not read as a tree without findings.";

/// What the step says when a result is not an object.
pub const RESULT_NOT_AN_OBJECT: &str = "semgrep's report holds a result that is not an object; the report is not read.";

/// The 2021 edition's own spelling — `OwaspTag.CATEGORY_2021`. `A01:2017` is Injection and
/// `A01:2021` access control: the year is what separates the editions, so it is not optional. The
/// word boundary is ASCII, as Java's `\b` is.
static CATEGORY_2021: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?-u:\b)(A0[1-9]|A10):2021(?-u:\b)").expect("a fixed pattern")
});

/// `OwaspTag.categoryOf`: the first 2021 category a declaration names.
pub fn category_of(declaration: &str) -> Option<String> {
    CATEGORY_2021.captures(declaration).and_then(|found| found.get(1)).map(|group| group.as_str().to_owned())
}

/// The OWASP category the rule declares: a string on some rules, an array on others; the first usable
/// value when it names several, so a finding is never counted in two categories.
pub fn owasp_of(declared: Option<&Value>) -> Option<String> {
    match declared {
        Some(Value::String(text)) => category_of(text),
        Some(Value::Array(values)) => values.iter().find_map(|value| category_of(&jackson::as_text(Some(value), ""))),
        _ => None,
    }
}

/// The tool's vocabulary into Vectispire's — an explicit table, since `ERROR` lowercased is no
/// policy threshold. The default is `MEDIUM`: an unknown level from a tool that emits three is more
/// likely a new one, and `UNKNOWN` ranks below `LOW`, exempting it from every gate.
pub fn severity_of(severity: Option<&str>) -> Severity {
    match severity {
        Some("ERROR") => Severity::High,
        Some("INFO") => Severity::Low,
        _ => Severity::Medium,
    }
}

/// The SAST findings of the workspace at `workspace_root`.
pub async fn scan(
    runner: &ContainerRunner,
    workspace_root: &Path,
    sub_path: Option<&str>,
    image: &str,
) -> Result<Option<Vec<SastFinding>>, ScannerError> {
    let result = runner.run(&request(workspace_root, sub_path, image)).await?;
    outcome(&result, sub_path)
}
