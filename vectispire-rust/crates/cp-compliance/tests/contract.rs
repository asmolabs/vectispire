//! Compliance's routes served so far against the contract they must not change (`openapi.json`):
//! documented under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported/` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, Routes};

type QueryParam = (&'static str, bool);
type DeclaredRoute = (&'static str, &'static str, &'static str, &'static [QueryParam]);

mod support;

const DECLARED: &[DeclaredRoute] = &[
    ("GET", "/api/v1/compliance/summary", "summary", &[("targetId", false)]),
    ("GET", "/api/v1/compliance/frameworks/{framework}", "framework", &[]),
    ("GET", "/api/v1/projects/{id}/compliance", "project", &[]),
    ("GET", "/api/v1/solutions/{id}/compliance", "solution", &[]),
    ("GET", "/api/v1/compliance/soa", "all", &[]),
    ("GET", "/api/v1/compliance/soa/reviews/overdue", "reviewOverdue", &[]),
    ("GET", "/api/v1/compliance/soa/{framework}", "one", &[]),
    ("PUT", "/api/v1/compliance/soa/{framework}/{controlId}", "declare_1", &[]),
    ("GET", "/api/v1/compliance/scope", "scope", &[]),
    ("PUT", "/api/v1/compliance/scope/repositories/{id}", "setRepository", &[("in_scope", true)]),
    ("PUT", "/api/v1/compliance/scope/containers/{id}", "setContainer", &[("in_scope", true)]),
    ("GET", "/api/v1/compliance/history", "history_2", &[]),
    ("GET", "/api/v1/owasp/coverage", "grid", &[("project_id", false), ("solution_id", false)]),
    (
        "GET",
        "/api/v1/owasp/coverage/export.csv",
        "exportOwaspCoverageCsv",
        &[("project_id", false), ("solution_id", false), ("language", false)],
    ),
    (
        "GET",
        "/api/v1/owasp/coverage/weekly",
        "weeklyCoverage",
        &[("from", false), ("to", false), ("project_id", false), ("solution_id", false)],
    ),
    ("PUT", "/api/v1/owasp/coverage/{category}/declaration", "declare", &[]),
    ("GET", "/api/v1/repositories/{id}/owasp-review", "latest", &[]),
];

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let entries = vectispire_cp_compliance::routes(support::services());
    assert_eq!(entries.len(), DECLARED.len());

    let declared: Vec<RouteDecl> = DECLARED
        .iter()
        .map(|(method, path, id, query)| {
            query.iter().fold(RouteDecl::new(method, path, id), |route, (name, required)| route.query(name, *required))
        })
        .collect();
    let document = Document::embedded();
    // Every documented route this module does not declare is another's: the test names none of them, and `cp-app`'s
    // registry test holds the whole partition to the document.
    let ours: BTreeSet<(String, String)> =
        declared.iter().map(|route| (route.method.clone(), route.path.clone())).collect();
    let not_ours = Allowlist::all_but(&document, &ours);
    assert_none(&check_module(&document, &declared, &Allowlist::committed()));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));

    let mut routes = Routes::new(NoVisibility);
    for entry in entries {
        routes = routes.route(entry);
    }
    let chain = Arc::new(Chain::new(
        ChainConfig::default(),
        Arc::new(StaticCredentials::default()),
        Arc::new(RecordingAudit::default()),
    ));
    let router = routes.build(&chain, None).unwrap();
    assert_none(&probe(&router, &document, &not_ours).await);
}
