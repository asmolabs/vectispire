//! The router against the document, route by route.
//!
//! An axum `Router` cannot be asked which routes it holds, so the check does not ask it: routes are
//! **declared** as they are registered (the control plane's route builder, or [`crate::RecordingRouter`]
//! in a test) and the declarations are compared with `openapi.json` in both directions. That a
//! declaration is not a lie — that the router really answers what was declared — is the other half,
//! checked by [`crate::probe`], which sends each documented request to the router itself.
//!
//! Routes not yet ported are listed in `reference/not-yet-ported/`, one file per module ([`crate::shrinking`]). The
//! list **only shrinks**: an entry for a route that is now served fails, an entry the document does not know fails,
//! a file longer than its `ceiling` fails, and so does a file *shorter* than it — the ceiling is lowered in the
//! commit that ports the route, so that nobody can spend the slack on a route they have not ported.
//!
//! A module's own contract test holds its routes to the document with [`check_module`], which needs no knowledge of
//! the other modules' routes; the binary's test (`cp-app`'s `tests/route_authorization.rs`) holds the whole registry to
//! the committed list with [`check_partition`], so that the routes served and the routes listed are the document,
//! exactly, without either a gap or an overlap.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use crate::document::{Document, In, Operation, Parameter, path_parameters};
use crate::finding::Finding;
use crate::shrinking::{ListFile, count, not_yet_ported_dir, read_dir};

/// A parameter a route reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamDecl {
    pub name: String,
    pub required: bool,
}

/// The security a route declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecurityDecl {
    /// Whatever the document applies to every operation — what every operation of today's
    /// document does, since none sets its own.
    Inherited,
    /// These schemes and no others.
    Schemes(Vec<String>),
}

/// One route, as it was registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteDecl {
    /// Upper case.
    pub method: String,
    /// The template, `{name}` for a path parameter — the syntax of both axum 0.8 and OpenAPI.
    pub path: String,
    pub operation_id: String,
    pub query: Vec<ParamDecl>,
    pub headers: Vec<ParamDecl>,
    pub security: SecurityDecl,
}

impl RouteDecl {
    /// A route with no query or header parameter and the document's security.
    #[must_use]
    pub fn new(method: &str, path: &str, operation_id: &str) -> RouteDecl {
        RouteDecl {
            method: method.to_ascii_uppercase(),
            path: path.to_owned(),
            operation_id: operation_id.to_owned(),
            query: Vec::new(),
            headers: Vec::new(),
            security: SecurityDecl::Inherited,
        }
    }

    /// Adds a query parameter.
    #[must_use]
    pub fn query(mut self, name: &str, required: bool) -> RouteDecl {
        self.query.push(ParamDecl { name: name.to_owned(), required });
        self
    }

    /// Adds a header parameter.
    #[must_use]
    pub fn header(mut self, name: &str, required: bool) -> RouteDecl {
        self.headers.push(ParamDecl { name: name.to_owned(), required });
        self
    }

    /// Sets the security schemes the route declares itself.
    #[must_use]
    pub fn security(mut self, schemes: &[&str]) -> RouteDecl {
        let mut names: Vec<String> = schemes.iter().map(|scheme| (*scheme).to_owned()).collect();
        names.sort();
        self.security = SecurityDecl::Schemes(names);
        self
    }

    fn parameters(&self) -> BTreeSet<Parameter> {
        let mut found = BTreeSet::new();
        for name in path_parameters(&self.path) {
            found.insert(Parameter { location: In::Path, name, required: true });
        }
        for param in &self.query {
            found.insert(Parameter { location: In::Query, name: param.name.clone(), required: param.required });
        }
        for param in &self.headers {
            found.insert(Parameter {
                location: In::Header,
                name: param.name.to_ascii_lowercase(),
                required: param.required,
            });
        }
        found
    }
}

/// Something that knows the routes it serves.
pub trait RouteSource {
    fn routes(&self) -> Vec<RouteDecl>;
}

impl RouteSource for Vec<RouteDecl> {
    fn routes(&self) -> Vec<RouteDecl> {
        self.clone()
    }
}

impl RouteSource for [RouteDecl] {
    fn routes(&self) -> Vec<RouteDecl> {
        self.to_vec()
    }
}

/// The routes the control plane has not ported yet.
#[derive(Clone, Debug)]
pub struct Allowlist {
    entries: BTreeSet<(String, String)>,
    /// Each file's label, entries and ceiling, for the ratchet; none for a list made in a test.
    files: Vec<(String, usize, usize)>,
    malformed: Vec<Finding>,
}

impl Allowlist {
    /// The committed list: every file of `reference/not-yet-ported/`.
    #[must_use]
    pub fn committed() -> Allowlist {
        match read_dir(&not_yet_ported_dir()) {
            Ok(files) => Allowlist::parse(&files),
            Err(problem) => Allowlist {
                entries: BTreeSet::new(),
                files: Vec::new(),
                malformed: vec![Finding::ListProblem { problem }],
            },
        }
    }

    /// An empty list: every documented route must be served.
    #[must_use]
    pub fn none() -> Allowlist {
        Allowlist { entries: BTreeSet::new(), files: Vec::new(), malformed: Vec::new() }
    }

    /// Every documented route but `served`'s, held to no ceiling: what a module's own contract test hands
    /// [`check_routes`] and [`crate::probe`] for the routes that are not its own — another module's, ported or not.
    #[must_use]
    pub fn all_but(document: &Document, served: &BTreeSet<(String, String)>) -> Allowlist {
        let entries = document.routes().into_iter().filter(|route| !served.contains(route)).collect();
        Allowlist { entries, files: Vec::new(), malformed: Vec::new() }
    }

    /// Reads the files of a list (`METHOD /path` per line, `#` comments, one `ceiling N`).
    #[must_use]
    pub fn parse(files: &[ListFile]) -> Allowlist {
        let mut entries = BTreeSet::new();
        let mut malformed = Vec::new();
        let mut counted = Vec::new();
        for file in files {
            let read = count(file);
            let mut in_file = 0_usize;
            for (line, text) in read.lines {
                let mut parts = text.split_whitespace();
                match (parts.next(), parts.next(), parts.next()) {
                    (Some(method), Some(path), None) if path.starts_with('/') => {
                        in_file = in_file.saturating_add(1);
                        if !entries.insert((method.to_ascii_uppercase(), path.to_owned())) {
                            malformed.push(Finding::ListProblem {
                                problem: format!("{}:{line}: {method} {path} is listed twice", file.label),
                            });
                        }
                    }
                    _ => malformed.push(Finding::Malformed { file: file.label.clone(), line, text: text.to_owned() }),
                }
            }
            match read.ceiling {
                Ok(ceiling) => counted.push((file.label.clone(), in_file, ceiling)),
                Err(problem) => malformed.push(Finding::ListProblem { problem }),
            }
        }
        Allowlist { entries, files: counted, malformed }
    }

    /// The routes listed.
    #[must_use]
    pub fn entries(&self) -> &BTreeSet<(String, String)> {
        &self.entries
    }

    /// How many routes the files may hold, together: the total the summary prints.
    #[must_use]
    pub fn ceiling(&self) -> usize {
        self.files.iter().fold(0_usize, |total, (_, _, ceiling)| total.saturating_add(*ceiling))
    }

    /// Each file's label, entries and ceiling.
    #[must_use]
    pub fn files(&self) -> &[(String, usize, usize)] {
        &self.files
    }

    fn contains(&self, method: &str, path: &str) -> bool {
        self.entries.contains(&(method.to_owned(), path.to_owned()))
    }
}

/// The partition, by method and path alone: every documented route is served or listed, never both; nothing served
/// or listed is undocumented; each file of the list is at its ceiling. What the binary's test holds the whole
/// registry to — the operation ids, parameters and security of each route are its module's own test's.
#[must_use]
pub fn check_partition(
    document: &Document,
    served: &BTreeSet<(String, String)>,
    allowlist: &Allowlist,
) -> Vec<Finding> {
    let mut findings = allowlist.malformed.clone();
    let documented = document.routes();
    for operation in document.operations() {
        let key = (operation.method.clone(), operation.path.clone());
        let listed = allowlist.contains(&operation.method, &operation.path);
        if served.contains(&key) {
            if listed {
                findings.push(Finding::AllowlistedButServed {
                    method: operation.method.clone(),
                    path: operation.path.clone(),
                });
            }
        } else if !listed {
            let path_is_routed = served.iter().any(|(_, path)| *path == operation.path);
            findings.push(if path_is_routed {
                Finding::MethodNotServed { method: operation.method.clone(), path: operation.path.clone() }
            } else {
                Finding::NotServed { method: operation.method.clone(), path: operation.path.clone() }
            });
        }
    }
    for (method, path) in served {
        if !documented.contains(&(method.clone(), path.clone())) {
            findings.push(Finding::NotDocumented { method: method.clone(), path: path.clone() });
        }
    }
    for (method, path) in allowlist.entries() {
        if !documented.contains(&(method.clone(), path.clone())) {
            findings.push(Finding::AllowlistUnknownRoute { method: method.clone(), path: path.clone() });
        }
    }
    for (label, entries, ceiling) in &allowlist.files {
        let (file, entries, ceiling) = (label.clone(), *entries, *ceiling);
        if entries == 0 {
            findings.push(Finding::ListProblem { problem: format!("{file} lists nothing: delete the file") });
        } else if entries > ceiling {
            findings.push(Finding::AllowlistGrew { file, entries, ceiling });
        } else if entries < ceiling {
            findings.push(Finding::CeilingNotLowered { file, entries, ceiling });
        }
    }
    findings
}

/// A module's own routes against the document — operation ids, parameters, security, nothing undocumented, nothing
/// registered twice — and against the committed list, which none of them may still be on. Knows nothing of the other
/// modules' routes, so that a port does not edit every other module's test.
#[must_use]
pub fn check_module(document: &Document, served: &dyn RouteSource, committed: &Allowlist) -> Vec<Finding> {
    let routes: BTreeSet<(String, String)> =
        served.routes().into_iter().map(|route| (route.method, route.path)).collect();
    let mut findings = check_routes(document, served, &Allowlist::all_but(document, &routes));
    findings.extend(committed.malformed.iter().cloned());
    for (method, path) in &routes {
        if committed.contains(method, path) {
            findings.push(Finding::AllowlistedButServed { method: method.clone(), path: path.clone() });
        }
    }
    findings
}

/// Compares what is served with the document, both ways, and the allowlist with both: [`check_partition`], then each
/// served route's operation id, parameters and security.
#[must_use]
pub fn check_routes(document: &Document, served: &dyn RouteSource, allowlist: &Allowlist) -> Vec<Finding> {
    let mut duplicates = Vec::new();
    let mut by_route: BTreeMap<(String, String), RouteDecl> = BTreeMap::new();
    for route in served.routes() {
        let key = (route.method.clone(), route.path.clone());
        match by_route.entry(key) {
            Entry::Occupied(_) => duplicates.push(Finding::DuplicateRoute { method: route.method, path: route.path }),
            Entry::Vacant(slot) => {
                slot.insert(route);
            }
        }
    }
    let keys: BTreeSet<(String, String)> = by_route.keys().cloned().collect();
    let mut findings = check_partition(document, &keys, allowlist);
    findings.extend(duplicates);
    for operation in document.operations() {
        if let Some(route) = by_route.get(&(operation.method.clone(), operation.path.clone())) {
            compare_route(document, operation, route, &mut findings);
        }
    }
    findings
}

fn compare_route(document: &Document, operation: &Operation, route: &RouteDecl, findings: &mut Vec<Finding>) {
    let method = operation.method.clone();
    let path = operation.path.clone();
    if route.operation_id != operation.operation_id {
        findings.push(Finding::OperationId {
            method: method.clone(),
            path: path.clone(),
            served: route.operation_id.clone(),
            documented: operation.operation_id.clone(),
        });
    }

    let documented: BTreeSet<Parameter> = operation
        .parameters
        .iter()
        .map(|parameter| Parameter {
            location: parameter.location,
            name: if parameter.location == In::Header {
                parameter.name.to_ascii_lowercase()
            } else {
                parameter.name.clone()
            },
            required: parameter.required,
        })
        .collect();
    let declared = route.parameters();
    if declared != documented {
        let missing: Vec<String> = documented.difference(&declared).map(describe).collect();
        let extra: Vec<String> = declared.difference(&documented).map(describe).collect();
        let mut difference = Vec::new();
        if !missing.is_empty() {
            difference.push(format!("documented, not declared: {}", missing.join(", ")));
        }
        if !extra.is_empty() {
            difference.push(format!("declared, not documented: {}", extra.join(", ")));
        }
        findings.push(Finding::Parameters {
            method: method.clone(),
            path: path.clone(),
            difference: difference.join("; "),
        });
    }

    let wanted = document.effective_security(operation);
    let have: Vec<String> = match &route.security {
        SecurityDecl::Inherited => wanted.to_vec(),
        SecurityDecl::Schemes(schemes) => schemes.clone(),
    };
    if have != wanted {
        findings.push(Finding::Security { method, path, served: have, documented: wanted.to_vec() });
    }
}

fn describe(parameter: &Parameter) -> String {
    let place = match parameter.location {
        In::Path => "path",
        In::Query => "query",
        In::Header => "header",
        In::Cookie => "cookie",
    };
    format!("{place} {}{}", parameter.name, if parameter.required { " (required)" } else { "" })
}
