//! Forges' routes served so far against the contract they must not change (`openapi.json`): documented under the
//! same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s `not-yet-ported/`
//! since the commit that ported them — then the router probed, so a route declared and not registered is caught too.

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
    ("GET", "/api/v1/forge-connections", "listForgeConnections", &[("limit", false), ("offset", false)]),
    ("GET", "/api/v1/forge-connections/{id}", "getForgeConnection", &[]),
    ("POST", "/api/v1/forge-connections", "createForgeConnection", &[]),
    ("PUT", "/api/v1/forge-connections/{id}/token", "replaceForgeConnectionToken", &[]),
    ("PATCH", "/api/v1/forge-connections/{id}", "updateForgeConnection", &[]),
    ("DELETE", "/api/v1/forge-connections/{id}", "deleteForgeConnection", &[]),
    ("POST", "/api/v1/forge-connections/{connectionId}/discoveries", "requestForgeDiscovery", &[]),
    (
        "GET",
        "/api/v1/forge-connections/{connectionId}/discoveries",
        "listForgeDiscoveries",
        &[("limit", false), ("offset", false)],
    ),
    ("GET", "/api/v1/forge-connections/{connectionId}/discoveries/{discoveryId}", "getForgeDiscovery", &[]),
    (
        "GET",
        "/api/v1/forge-connections/{connectionId}/discoveries/{discoveryId}/repositories",
        "listDiscoveredRepositories",
        &[("change", false), ("limit", false), ("offset", false)],
    ),
    (
        "GET",
        "/api/v1/forge-connections/{connectionId}/discoveries/{discoveryId}/selection",
        "listForgeImportCandidates",
        &[
            ("archived", false),
            ("forks", false),
            ("inactiveDays", false),
            ("language", false),
            ("visibility", false),
            ("namespace", false),
            ("path", false),
            ("personal", false),
            ("present", false),
            ("limit", false),
            ("offset", false),
        ],
    ),
    (
        "POST",
        "/api/v1/forge-connections/{connectionId}/discoveries/{discoveryId}/selection",
        "changeForgeImportSelection",
        &[],
    ),
    ("POST", "/api/v1/forge-connections/{connectionId}/imports/preview", "previewForgeImport", &[]),
    ("POST", "/api/v1/forge-connections/{connectionId}/imports", "importForgeRepositories", &[]),
];

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let entries = vectispire_cp_forges::routes(support::services());
    assert_eq!(entries.len(), DECLARED.len());

    let declared: Vec<RouteDecl> = DECLARED
        .iter()
        .map(|(method, path, id, query)| {
            query.iter().fold(RouteDecl::new(method, path, id), |route, (name, required)| route.query(name, *required))
        })
        .collect();
    let document = Document::embedded();
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
