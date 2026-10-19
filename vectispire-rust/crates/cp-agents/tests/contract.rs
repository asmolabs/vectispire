//! The seventeen agent routes against the contract they must not change (`openapi.json` of the 0.11.1 line):
//! documented under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported.txt` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::type_complexity)]

mod support;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_published, check_routes, probe,
};
use vectispire_cp_http::credentials::StaticCredentials;

const DECLARED: &[(&str, &str, &str, &[&str], &[&str])] = &[
    ("GET", "/api/v1/admin/agents", "list_16", &["limit", "offset"], &[]),
    ("POST", "/api/v1/admin/agents", "create_9", &[], &[]),
    ("GET", "/api/v1/admin/agents/activity", "activity", &[], &[]),
    ("GET", "/api/v1/admin/agents/credentialed-backlog", "credentialedBacklog", &[], &[]),
    ("GET", "/api/v1/admin/agents/non-routables", "unroutable", &[], &[]),
    ("PATCH", "/api/v1/admin/agents/{id}", "update_8", &[], &[]),
    ("DELETE", "/api/v1/admin/agents/{id}", "remove_6", &[], &[]),
    ("DELETE", "/api/v1/admin/agents/{id}/sealing-key", "resetSealingKey", &[], &[]),
    ("PUT", "/api/v1/admin/agents/{id}/signing-key", "pinSigningKey", &[], &[]),
    ("POST", "/api/v1/agent/hello", "hello", &[], &[]),
    ("GET", "/api/v1/agent/jobs", "claimJob", &["wait"], &[]),
    ("POST", "/api/v1/agent/jobs/{scanId}/failure", "reportFailure", &[], &["X-Vectispire-Agent-Signature"]),
    ("POST", "/api/v1/agent/jobs/{scanId}/heartbeat", "heartbeat", &[], &[]),
    ("POST", "/api/v1/agent/jobs/{scanId}/result", "submitResult", &[], &["X-Vectispire-Agent-Signature"]),
    ("GET", "/api/v1/agent/plugins/{id}/{digest}", "plugin", &[], &[]),
    ("GET", "/api/v1/agent/rules/{hash}", "ruleSet", &[], &[]),
    ("POST", "/api/v1/agent/sealing-key", "announceSealingKey", &[], &[]),
];

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let db = support::unreachable();
    let composed = support::compose(&db, support::system_clock());
    let entries = vectispire_cp_agents::routes(composed.agents.clone());
    assert_eq!(entries.len(), 17);
    let declared: Vec<RouteDecl> = entries
        .iter()
        .map(|entry| {
            let decl = entry.decl();
            let (_, _, id, query, headers) = DECLARED
                .iter()
                .find(|(method, path, _, _, _)| *method == decl.method && *path == decl.path)
                .unwrap_or_else(|| panic!("{} {} is registered and declares no operation", decl.method, decl.path));
            let mut r =
                query.iter().fold(RouteDecl::new(&decl.method, &decl.path, id), |route, name| route.query(name, false));
            for h in *headers {
                r = r.header(h, false);
            }
            r
        })
        .collect();
    let document = Document::embedded();

    let targets_routes: String = vectispire_cp_targets::routes(composed.targets.clone())
        .iter()
        .map(|entry| format!("{} {}\n", entry.decl().method, entry.decl().path))
        .collect();
    let scanning_routes: String = vectispire_cp_scanning::routes(composed.scanning.clone())
        .iter()
        .map(|entry| format!("{} {}\n", entry.decl().method, entry.decl().path))
        .collect();

    let rules_s = "\
GET /api/v1/rule-sets\n\
POST /api/v1/rule-sets\n\
GET /api/v1/rule-sets/catalogue\n\
POST /api/v1/rule-sets/catalogue\n\
GET /api/v1/rule-sets/coverage\n\
POST /api/v1/rule-sets/deactivate\n\
GET /api/v1/rule-sets/deactivate/impact\n\
POST /api/v1/rule-sets/{id}/activate\n\
GET /api/v1/rule-sets/{id}/impact\n\
DELETE /api/v1/attack-surface\n\
GET /api/v1/attack-surface\n\
GET /api/v1/blast-radius/explore\n\
GET /api/v1/blast-radius/top-impact\n\
GET /api/v1/inventory/search\n\
GET /api/v1/inventory/versions\n\
GET /api/v1/licenses/conflicts\n\
GET /api/v1/licenses/inventory\n\
GET /api/v1/licenses/matrix\n\
GET /api/v1/licenses/policy\n\
PUT /api/v1/licenses/policy\n\
GET /api/v1/licenses/summary\n\
GET /api/v1/projects/{id}/components\n\
DELETE /api/v1/repositories/{id}/apis\n\
GET /api/v1/repositories/{id}/apis\n\
GET /api/v1/repositories/{id}/apis/export/openapi\n\
GET /api/v1/sbom/diff\n\
GET /api/v1/sbom/diff/latest\n\
GET /api/v1/exceptions\n\
POST /api/v1/exceptions/{issueId}/reviews\n\
GET /api/v1/history/repositories\n\
GET /api/v1/history/repositories/{id}\n\
GET /api/v1/history/repositories/{id}/export.csv\n\
GET /api/v1/issues\n\
POST /api/v1/issues/triage\n\
GET /api/v1/issues/{id}\n\
PUT /api/v1/issues/{id}/ticket\n\
POST /api/v1/issues/{id}/triage\n";

    let ceiling: usize = include_str!("../../cp-contract/reference/not-yet-ported.ceiling").trim().parse().unwrap();
    let not_ours = Allowlist::parse(
        &format!(
            "{}{targets_routes}{scanning_routes}{rules_s}",
            include_str!("../../cp-contract/reference/not-yet-ported.txt")
        ),
        &(ceiling + 29 + 3 + 9 + 18 + 10).to_string(),
    );
    assert_none(&check_routes(&document, &declared, &not_ours));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));

    let router = support::router(
        &db,
        composed.targets,
        composed.scanning,
        composed.agents,
        StaticCredentials::default(),
        "everyone",
    );
    let not_on_router = Allowlist::parse(
        &format!("{}{rules_s}", include_str!("../../cp-contract/reference/not-yet-ported.txt")),
        &(ceiling + 9 + 18).to_string(),
    );
    assert_none(&probe(&router, &document, &not_on_router).await);
}
