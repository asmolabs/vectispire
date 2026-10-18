//! The three scan routes against the contract they must not change (`openapi.json` of the 0.11.1 line): documented
//! under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported.txt` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_published, check_routes, probe,
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
    let document = Document::embedded();
    // `targets`' routes are held to the document by its own contract test; here they are read as not this module's.
    let targets_routes: String = vectispire_cp_targets::routes(composed.targets.clone())
        .iter()
        .map(|entry| format!("{} {}\n", entry.decl().method, entry.decl().path))
        .collect();
    let ceiling: usize = include_str!("../../cp-contract/reference/not-yet-ported.ceiling").trim().parse().unwrap();
    let not_ours = Allowlist::parse(
        &format!("{}{targets_routes}", include_str!("../../cp-contract/reference/not-yet-ported.txt")),
        &(ceiling + 29).to_string(),
    );
    assert_none(&check_routes(&document, &declared, &not_ours));
    let allowlist = Allowlist::embedded();
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));
    // Probed with `targets`' routes beside them, as the binary will serve both: every documented route out of the
    // list is answered by one of the two.
    let router = support::router_with_targets(
        &db,
        composed.targets,
        composed.scanning,
        StaticCredentials::default(),
        "everyone",
    );
    assert_none(&probe(&router, &document, &allowlist).await);
}
