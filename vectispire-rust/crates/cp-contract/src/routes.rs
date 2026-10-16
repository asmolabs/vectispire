//! The router against the document, route by route.
//!
//! An axum `Router` cannot be asked which routes it holds, so the check does not ask it: routes are
//! **declared** as they are registered (the control plane's route builder, or [`crate::RecordingRouter`]
//! in a test) and the declarations are compared with `openapi.json` in both directions. That a
//! declaration is not a lie — that the router really answers what was declared — is the other half,
//! checked by [`crate::probe`], which sends each documented request to the router itself.
//!
//! Routes not yet ported are listed in `reference/not-yet-ported.txt`. The list **only shrinks**: an
//! entry for a route that is now served fails, an entry the document does not know fails, a list
//! longer than `reference/not-yet-ported.ceiling` fails, and so does a list *shorter* than it — the
//! ceiling is lowered in the commit that ports the route, so that nobody can spend the slack on a
//! route they have not ported.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use crate::document::{Document, In, Operation, Parameter, path_parameters};
use crate::finding::Finding;

const ALLOWLIST: &str = include_str!("../reference/not-yet-ported.txt");
const CEILING: &str = include_str!("../reference/not-yet-ported.ceiling");

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
    ceiling: usize,
    malformed: Vec<Finding>,
}

impl Allowlist {
    /// The committed list and its ceiling.
    #[must_use]
    pub fn embedded() -> Allowlist {
        Allowlist::parse(ALLOWLIST, CEILING)
    }

    /// An empty list with a ceiling of zero: every documented route must be served.
    #[must_use]
    pub fn none() -> Allowlist {
        Allowlist { entries: BTreeSet::new(), ceiling: 0, malformed: Vec::new() }
    }

    /// Reads a list (`METHOD /path` per line, `#` comments) and its ceiling.
    #[must_use]
    pub fn parse(text: &str, ceiling: &str) -> Allowlist {
        let mut entries = BTreeSet::new();
        let mut malformed = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some(method), Some(path), None) if path.starts_with('/') => {
                    entries.insert((method.to_ascii_uppercase(), path.to_owned()));
                }
                _ => malformed.push(Finding::Malformed {
                    file: "not-yet-ported.txt",
                    line: index + 1,
                    text: line.to_owned(),
                }),
            }
        }
        let ceiling_value = ceiling.trim().parse::<usize>();
        if ceiling_value.is_err() {
            malformed.push(Finding::Malformed {
                file: "not-yet-ported.ceiling",
                line: 1,
                text: ceiling.trim().to_owned(),
            });
        }
        Allowlist { entries, ceiling: ceiling_value.unwrap_or(0), malformed }
    }

    /// The routes listed.
    #[must_use]
    pub fn entries(&self) -> &BTreeSet<(String, String)> {
        &self.entries
    }

    /// How many routes the list may hold.
    #[must_use]
    pub fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// The text of a list covering every route of `document` that `served` does not answer — what
    /// `allowlist-write` commits at the start, and never again to make a check pass.
    #[must_use]
    pub fn text_for(document: &Document, served: &dyn RouteSource) -> String {
        let answered: BTreeSet<(String, String)> =
            served.routes().into_iter().map(|route| (route.method, route.path)).collect();
        let mut out = String::from(
            "# The routes of openapi.json the Rust control plane does not answer yet: `METHOD /path`.\n\
             #\n\
             # This list only shrinks. A route that is served must be deleted from it, a route the document\n\
             # does not list cannot be added, and `not-yet-ported.ceiling` is lowered in the same commit.\n\
             # Never edited to make a check pass.\n",
        );
        for (method, path) in document.routes() {
            if !answered.contains(&(method.clone(), path.clone())) {
                out.push_str(&format!("{method} {path}\n"));
            }
        }
        out
    }

    fn contains(&self, method: &str, path: &str) -> bool {
        self.entries.contains(&(method.to_owned(), path.to_owned()))
    }
}

/// Compares what is served with the document, both ways, and the allowlist with both.
#[must_use]
pub fn check_routes(document: &Document, served: &dyn RouteSource, allowlist: &Allowlist) -> Vec<Finding> {
    let mut findings = allowlist.malformed.clone();

    let mut by_route: BTreeMap<(String, String), RouteDecl> = BTreeMap::new();
    for route in served.routes() {
        let key = (route.method.clone(), route.path.clone());
        match by_route.entry(key) {
            Entry::Occupied(_) => findings.push(Finding::DuplicateRoute { method: route.method, path: route.path }),
            Entry::Vacant(slot) => {
                slot.insert(route);
            }
        }
    }

    let documented = document.routes();
    for operation in document.operations() {
        let key = (operation.method.clone(), operation.path.clone());
        match by_route.get(&key) {
            Some(route) => {
                if allowlist.contains(&operation.method, &operation.path) {
                    findings.push(Finding::AllowlistedButServed {
                        method: operation.method.clone(),
                        path: operation.path.clone(),
                    });
                }
                compare_route(document, operation, route, &mut findings);
            }
            None if allowlist.contains(&operation.method, &operation.path) => {}
            None => {
                let path_is_routed = by_route.keys().any(|(_, path)| *path == operation.path);
                findings.push(if path_is_routed {
                    Finding::MethodNotServed { method: operation.method.clone(), path: operation.path.clone() }
                } else {
                    Finding::NotServed { method: operation.method.clone(), path: operation.path.clone() }
                });
            }
        }
    }
    for (method, path) in by_route.keys() {
        if !documented.contains(&(method.clone(), path.clone())) {
            findings.push(Finding::NotDocumented { method: method.clone(), path: path.clone() });
        }
    }
    for (method, path) in allowlist.entries() {
        if !documented.contains(&(method.clone(), path.clone())) {
            findings.push(Finding::AllowlistUnknownRoute { method: method.clone(), path: path.clone() });
        }
    }
    let entries = allowlist.entries().len();
    if entries > allowlist.ceiling() {
        findings.push(Finding::AllowlistGrew { entries, ceiling: allowlist.ceiling() });
    } else if entries < allowlist.ceiling() {
        findings.push(Finding::CeilingNotLowered { entries, ceiling: allowlist.ceiling() });
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
