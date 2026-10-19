//! The module's routes against the contract they must not change (`openapi.json` of the 0.11.1 line): every route of
//! its table documented under the same method and path, with the operation id and query parameters Java publishes,
//! and every documented route that has left the list of routes not yet ported served by it — then the router itself
//! probed, so a route declared and not registered is caught too.
//!
//! The twenty-nine left `cp-contract`'s `not-yet-ported.txt` in the commit that ported them; until the binary's
//! registry carries every module's routes (task 2.11), this is where they are held to the document.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_published, check_routes, probe,
};
use vectispire_cp_http::credentials::StaticCredentials;
use vectispire_cp_targets::deletion::PurgeRegistry;

/// What each route declares beyond its method and path: Java's operation id (`<method>_<n>` where Spring numbered a
/// name taken twice) and its query parameters.
const DECLARED: &[(&str, &str, &str, &[&str])] = &[
    ("GET", "/api/v1/repositories", "list_7", &["limit", "offset"]),
    ("POST", "/api/v1/repositories", "create_4", &[]),
    ("GET", "/api/v1/repositories/duplicates", "duplicates", &[]),
    ("PATCH", "/api/v1/repositories/{id}", "update_5", &[]),
    ("POST", "/api/v1/repositories/{id}/scan", "triggerScan", &[]),
    ("DELETE", "/api/v1/repositories/{id}", "remove_3", &[]),
    ("GET", "/api/v1/containers", "list_14", &["limit", "offset"]),
    ("POST", "/api/v1/containers", "create_7", &[]),
    ("PATCH", "/api/v1/containers/{id}", "update_7", &[]),
    ("POST", "/api/v1/containers/{id}/scan", "triggerScan_1", &[]),
    ("DELETE", "/api/v1/containers/{id}", "remove_5", &[]),
    ("GET", "/api/v1/solutions", "list_4", &[]),
    ("POST", "/api/v1/solutions", "create_3", &[]),
    ("PATCH", "/api/v1/solutions/{id}", "update_4", &[]),
    ("DELETE", "/api/v1/solutions/{id}", "remove_2", &[]),
    ("POST", "/api/v1/solutions/{id}/projects", "createProject", &[]),
    ("GET", "/api/v1/projects/{id}", "get_2", &[]),
    ("PATCH", "/api/v1/projects/{id}", "update_6", &[]),
    ("DELETE", "/api/v1/projects/{id}", "remove_4", &[]),
    ("PUT", "/api/v1/projects/{id}/repositories/{repositoryId}", "file", &[]),
    ("DELETE", "/api/v1/projects/{id}/repositories/{repositoryId}", "unfile", &[]),
    ("PUT", "/api/v1/projects/{id}/containers/{containerId}", "fileContainer", &[]),
    ("DELETE", "/api/v1/projects/{id}/containers/{containerId}", "unfileContainer", &[]),
    ("GET", "/api/v1/git-tokens", "list_13", &[]),
    ("POST", "/api/v1/git-tokens", "create_6", &[]),
    ("DELETE", "/api/v1/git-tokens/{id}", "remove_8", &[]),
    ("GET", "/api/v1/ssh-keys", "list_3", &[]),
    ("POST", "/api/v1/ssh-keys", "create_2", &[]),
    ("DELETE", "/api/v1/ssh-keys/{id}", "remove_7", &[]),
];

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    // Nothing here runs a statement: a pool that never connects is enough to build the router.
    let db = support::unreachable();
    let (targets, _) = support::targets(&db, PurgeRegistry::stand_ins());
    let entries = vectispire_cp_targets::routes(targets.clone());
    assert_eq!(entries.len(), 29);
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
    // The scan (3) and agent (17) routes are ported in modules above, which this crate cannot compose (the dependency
    // runs the other way): here they are read as not served by this module.
    let others_s = "\
GET /api/v1/scans\n\
GET /api/v1/scans/{id}\n\
GET /api/v1/scans/{id}/sbom\n\
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
POST /api/v1/agent/sealing-key\n";
    let ceiling: usize = include_str!("../../cp-contract/reference/not-yet-ported.ceiling").trim().parse().unwrap();
    let allowlist = Allowlist::parse(
        &format!("{}{others_s}", include_str!("../../cp-contract/reference/not-yet-ported.txt")),
        &(ceiling + 3 + 17).to_string(),
    );
    assert_none(&check_routes(&document, &declared, &allowlist));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));
    // The router as built, behind the chain: an unauthenticated probe is answered 401 by a registered route, and by
    // the sentinel only where nothing is registered.
    let router = support::router(&db, targets, StaticCredentials::default(), "everyone");
    assert_none(&probe(&router, &document, &allowlist).await);
}
