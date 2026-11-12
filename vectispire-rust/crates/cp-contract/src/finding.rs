//! What the conformance checks report.
//!
//! One enum, so that a test can say *which* way the router drifted from the document and a failure
//! prints every drift at once instead of the first one.

use std::fmt;

/// One way the control plane and `openapi.json` disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// The document lists the route and the router does not answer it, and it is not allowlisted.
    NotServed { method: String, path: String },
    /// The router answers a route the document does not list.
    NotDocumented { method: String, path: String },
    /// The router has the path but not the method.
    MethodNotServed { method: String, path: String },
    /// Two registrations of one method and path.
    DuplicateRoute { method: String, path: String },
    /// The operation id the route is registered with is not the document's.
    OperationId { method: String, path: String, served: String, documented: String },
    /// A parameter the document declares and the route does not, or the reverse, or with another
    /// `required`.
    Parameters { method: String, path: String, difference: String },
    /// The security schemes of the route are not the document's.
    Security { method: String, path: String, served: Vec<String>, documented: Vec<String> },
    /// An allowlist entry for a route the router now serves: delete the entry.
    AllowlistedButServed { method: String, path: String },
    /// An allowlist entry for a route the document does not list.
    AllowlistUnknownRoute { method: String, path: String },
    /// More entries in a file of the list than its ceiling: the list only shrinks.
    AllowlistGrew { file: String, entries: usize, ceiling: usize },
    /// Fewer entries in a file of the list than its ceiling: lower the ceiling to what was earned.
    CeilingNotLowered { file: String, entries: usize, ceiling: usize },
    /// A line of the allowlist or of the published list that is not `METHOD /path`.
    Malformed { file: String, line: usize, text: String },
    /// The list itself is wrong: a file without its ceiling, a route twice, a file that lists nothing, a directory
    /// that cannot be read.
    ListProblem { problem: String },
    /// A published operation the document no longer lists.
    PublishedMissing { method: String, path: String, operation_id: String },
    /// A published operation whose id the document changed.
    PublishedChanged { method: String, path: String, published: String, documented: String },
    /// A published line twice.
    PublishedDuplicate { method: String, path: String },
    /// Two operations of the document with one id.
    DuplicateOperationId { operation_id: String },
}

impl fmt::Display for Finding {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::NotServed { method, path } => {
                write!(out, "{method} {path}: documented, and the router does not answer it")
            }
            Finding::NotDocumented { method, path } => {
                write!(out, "{method} {path}: answered by the router, absent from openapi.json")
            }
            Finding::MethodNotServed { method, path } => {
                write!(out, "{method} {path}: the path is routed, this method is not")
            }
            Finding::DuplicateRoute { method, path } => write!(out, "{method} {path}: registered twice"),
            Finding::OperationId { method, path, served, documented } => {
                write!(out, "{method} {path}: operation id {served:?}, the document says {documented:?}")
            }
            Finding::Parameters { method, path, difference } => {
                write!(out, "{method} {path}: parameters differ — {difference}")
            }
            Finding::Security { method, path, served, documented } => {
                write!(out, "{method} {path}: security {served:?}, the document says {documented:?}")
            }
            Finding::AllowlistedButServed { method, path } => {
                write!(out, "{method} {path}: now served — delete its line from reference/not-yet-ported/")
            }
            Finding::AllowlistUnknownRoute { method, path } => {
                write!(out, "{method} {path}: in reference/not-yet-ported/, and openapi.json does not list it")
            }
            Finding::AllowlistGrew { file, entries, ceiling } => {
                write!(out, "{file} has {entries} routes, above its ceiling of {ceiling}: the list only shrinks")
            }
            Finding::CeilingNotLowered { file, entries, ceiling } => {
                write!(out, "{file} has {entries} routes and a ceiling of {ceiling}: lower the ceiling to {entries}")
            }
            Finding::Malformed { file, line, text } => write!(out, "{file}:{line}: not `METHOD /path …`: {text:?}"),
            Finding::ListProblem { problem } => write!(out, "{problem}"),
            Finding::PublishedMissing { method, path, operation_id } => {
                write!(out, "{method} {path} ({operation_id}): published, and the document no longer lists it")
            }
            Finding::PublishedChanged { method, path, published, documented } => {
                write!(out, "{method} {path}: published as {published:?}, the document now calls it {documented:?}")
            }
            Finding::PublishedDuplicate { method, path } => write!(out, "{method} {path}: published twice"),
            Finding::DuplicateOperationId { operation_id } => {
                write!(out, "operation id {operation_id:?} is used by two operations")
            }
        }
    }
}

/// Every finding, one per line, or the empty string.
#[must_use]
pub fn render(findings: &[Finding]) -> String {
    findings.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
}

/// Fails — with every finding — unless there are none. For a test.
///
/// # Panics
/// When `findings` is not empty.
#[track_caller]
pub fn assert_none(findings: &[Finding]) {
    assert!(findings.is_empty(), "{} finding(s) against openapi.json:\n{}", findings.len(), render(findings));
}
