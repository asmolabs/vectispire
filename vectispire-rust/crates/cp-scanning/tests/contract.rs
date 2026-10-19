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
    // `targets`' (29) and `agents`' (17) routes are held to the document by their own contract tests; here they are
    // read as not this module's.
    let document = Document::embedded();
    let targets_routes: String = vectispire_cp_targets::routes(composed.targets.clone())
        .iter()
        .map(|entry| format!("{} {}\n", entry.decl().method, entry.decl().path))
        .collect();
    let other_ported_s = "\
GET /api/v1/admin/agents\n\
POST /api/v1/admin/agents\n\
GET /api/v1/admin/agents/activity\n\
GET /api/v1/admin/agents/credentialed-backlog\n\
GET /api/v1/admin/agents/non-routables\n\
DELETE /api/v1/admin/agents/{id}\n\
PATCH /api/v1/admin/agents/{id}\n\
DELETE /api/v1/admin/agents/{id}/sealing-key\n\
PUT /api/v1/admin/agents/{id}/signing-key\n\
POST /api/v1/agent/hello\n\
GET /api/v1/agent/jobs\n\
POST /api/v1/agent/jobs/{scanId}/failure\n\
POST /api/v1/agent/jobs/{scanId}/heartbeat\n\
POST /api/v1/agent/jobs/{scanId}/result\n\
GET /api/v1/agent/plugins/{id}/{digest}\n\
GET /api/v1/agent/rules/{hash}\n\
POST /api/v1/agent/sealing-key\n\
GET /api/v1/rule-sets\n\
POST /api/v1/rule-sets\n\
GET /api/v1/rule-sets/catalogue\n\
POST /api/v1/rule-sets/catalogue\n\
GET /api/v1/rule-sets/coverage\n\
POST /api/v1/rule-sets/deactivate\n\
GET /api/v1/rule-sets/deactivate/impact\n\
POST /api/v1/rule-sets/{id}/activate\n\
GET /api/v1/rule-sets/{id}/impact\n";
    let ceiling: usize = include_str!("../../cp-contract/reference/not-yet-ported.ceiling").trim().parse().unwrap();
    let not_ours = Allowlist::parse(
        &format!("{}{targets_routes}{other_ported_s}", include_str!("../../cp-contract/reference/not-yet-ported.txt")),
        &(ceiling + 29 + 17 + 9).to_string(),
    );
    assert_none(&check_routes(&document, &declared, &not_ours));
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
    let not_on_router = Allowlist::parse(
        &format!("{}{other_ported_s}", include_str!("../../cp-contract/reference/not-yet-ported.txt")),
        &(ceiling + 17 + 9).to_string(),
    );
    assert_none(&probe(&router, &document, &not_on_router).await);
}
