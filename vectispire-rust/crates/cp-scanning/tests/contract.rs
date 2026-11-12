//! The three scan routes against the contract they must not change (`openapi.json` of the 0.11.1 line): documented
//! under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported/` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_http::credentials::StaticCredentials;

const DECLARED: &[(&str, &str, &str, &[&str])] = &[
    ("GET", "/api/v1/scans", "list_17", &["repo_id", "container_id", "limit", "offset"]),
    ("GET", "/api/v1/scans/{id}", "detail", &[]),
    ("GET", "/api/v1/scans/{id}/sbom", "sbom", &[]),
];

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let db = support::unreachable();
    let composed = support::compose(&db, support::system_clock(), Default::default());
    let entries = vectispire_cp_scanning::routes(composed.scanning.clone());
    assert_eq!(entries.len(), 3);
    let declared: Vec<RouteDecl> = entries
        .iter()
        .map(|entry| {
            let decl = entry.decl();
            let (_, _, id, query) = DECLARED
                .iter()
                .find(|(method, path, _, _)| *method == decl.method && *path == decl.path)
                .unwrap_or_else(|| panic!("{} {} is registered and declares no operation", decl.method, decl.path));
            query.iter().fold(RouteDecl::new(&decl.method, &decl.path, id), |route, name| route.query(name, false))
        })
        .collect();
    // `targets`' (29) and `agents`' (17) routes are held to the document by their own contract tests; here they are
    // read as not this module's.
    let document = Document::embedded();
    // Every documented route this module does not declare is another's, ported or not: the test names none of them,
    // and `cp-app`'s registry test holds the whole partition — what is served and what is listed — to the document.
    let ours: BTreeSet<(String, String)> =
        declared.iter().map(|route| (route.method.clone(), route.path.clone())).collect();
    assert_none(&check_module(&document, &declared, &Allowlist::committed()));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));
    // Probed with `targets`' routes beside them, as the binary serves both: the router answers those two modules'
    // routes, and no other.
    let mut on_router = ours;
    on_router.extend(
        vectispire_cp_targets::routes(composed.targets.clone())
            .iter()
            .map(|entry| (entry.decl().method.clone(), entry.decl().path.clone())),
    );
    let router = support::router_with_targets(
        &db,
        composed.targets,
        composed.scanning,
        StaticCredentials::default(),
        "everyone",
    );
    let not_on_router = Allowlist::all_but(&document, &on_router);
    assert_none(&probe(&router, &document, &not_on_router).await);
}
