//! The seventeen agent routes against the contract they must not change (`openapi.json` of the 0.11.1 line):
//! documented under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported/` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::type_complexity)]

mod support;

use std::collections::BTreeSet;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
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
    // Every documented route this module does not declare is another's, ported or not: the test names none of them,
    // and `cp-app`'s registry test holds the whole partition — what is served and what is listed — to the document.
    let ours: BTreeSet<(String, String)> =
        declared.iter().map(|route| (route.method.clone(), route.path.clone())).collect();
    assert_none(&check_module(&document, &declared, &Allowlist::committed()));
    assert_none(&check_published(&document, &Published::embedded(), Some(&declared)));

    // The router serves `targets`' and `scanning`'s routes beside these, as the binary does: it answers the three
    // modules' routes, and no other.
    let mut on_router = ours;
    for entry in vectispire_cp_targets::routes(composed.targets.clone())
        .iter()
        .chain(vectispire_cp_scanning::routes(composed.scanning.clone()).iter())
    {
        on_router.insert((entry.decl().method.clone(), entry.decl().path.clone()));
    }
    let router = support::router(
        &db,
        composed.targets,
        composed.scanning,
        composed.agents,
        StaticCredentials::default(),
        "everyone",
    );
    let not_on_router = Allowlist::all_but(&document, &on_router);
    assert_none(&probe(&router, &document, &not_on_router).await);
}
