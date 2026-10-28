//! The operation ids a release has published are never changed.
//!
//! A generated client names its methods after them: renaming `listIssues` to `issues` breaks every
//! consumer's build, and the document's own regeneration would hide the rename, which is why the
//! list is a copy that moves only by hand (`ci/openapi/published-operation-ids.txt` on the Java
//! side, `PublishedOperationIdsTest`). The Rust control plane is held to the same list: every line
//! must still be in the document under the same id, and — for a route the router serves — be the id
//! the route is registered with.

use std::collections::{BTreeMap, BTreeSet};

use crate::document::Document;
use crate::finding::Finding;
use crate::routes::RouteSource;

const PUBLISHED: &str = include_str!("../reference/published-operation-ids.txt");

/// The list of `METHOD /path operationId` lines.
#[derive(Clone, Debug)]
pub struct Published {
    entries: Vec<(String, String, String)>,
    malformed: Vec<Finding>,
}

impl Published {
    /// The committed list.
    #[must_use]
    pub fn embedded() -> Published {
        Published::parse(PUBLISHED)
    }

    /// Reads `METHOD /path operationId` lines; `#` starts a comment.
    #[must_use]
    pub fn parse(text: &str) -> Published {
        let mut entries = Vec::new();
        let mut malformed = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(method), Some(path), Some(id), None) if path.starts_with('/') => {
                    entries.push((method.to_ascii_uppercase(), path.to_owned(), id.to_owned()));
                }
                _ => malformed.push(Finding::Malformed {
                    file: "published-operation-ids.txt".to_owned(),
                    line: index + 1,
                    text: line.to_owned(),
                }),
            }
        }
        Published { entries, malformed }
    }

    /// The published `(method, path, operation id)` lines, in file order.
    #[must_use]
    pub fn entries(&self) -> &[(String, String, String)] {
        &self.entries
    }
}

/// Every published id is still in the document, unchanged, and — when `served` is given — is the id
/// the router registers the route with. Also: no two operations of the document share an id.
#[must_use]
pub fn check_published(document: &Document, published: &Published, served: Option<&dyn RouteSource>) -> Vec<Finding> {
    let mut findings = published.malformed.clone();

    let mut ids: BTreeMap<&str, usize> = BTreeMap::new();
    for operation in document.operations() {
        *ids.entry(operation.operation_id.as_str()).or_insert(0) += 1;
    }
    for (id, count) in &ids {
        if *count > 1 {
            findings.push(Finding::DuplicateOperationId { operation_id: (*id).to_owned() });
        }
    }

    let served_ids: BTreeMap<(String, String), String> = served
        .map(|source| {
            source.routes().into_iter().map(|route| ((route.method, route.path), route.operation_id)).collect()
        })
        .unwrap_or_default();

    let mut seen = BTreeSet::new();
    for (method, path, id) in &published.entries {
        if !seen.insert((method.clone(), path.clone())) {
            findings.push(Finding::PublishedDuplicate { method: method.clone(), path: path.clone() });
            continue;
        }
        match document.operation(method, path) {
            None => findings.push(Finding::PublishedMissing {
                method: method.clone(),
                path: path.clone(),
                operation_id: id.clone(),
            }),
            Some(operation) if operation.operation_id != *id => findings.push(Finding::PublishedChanged {
                method: method.clone(),
                path: path.clone(),
                published: id.clone(),
                documented: operation.operation_id.clone(),
            }),
            Some(_) => {}
        }
        if let Some(served_id) = served_ids.get(&(method.clone(), path.clone()))
            && served_id != id
        {
            findings.push(Finding::OperationId {
                method: method.clone(),
                path: path.clone(),
                served: served_id.clone(),
                documented: id.clone(),
            });
        }
    }
    findings
}
