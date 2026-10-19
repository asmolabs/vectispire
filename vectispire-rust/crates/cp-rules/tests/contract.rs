//! The nine rule-sets routes against the contract they must not change (`openapi.json` of the 0.11.1 line):
//! documented under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported.txt` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_published, check_routes, probe,
};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, Routes};
use vectispire_cp_rules::{RulesModule, StandInInventory, StandInIssues};
const DECLARED: &[(&str, &str, &str, &[&str])] = &[
    ("GET", "/api/v1/rule-sets", "list_6", &[]),
    ("POST", "/api/v1/rule-sets", "upload", &[]),
    ("GET", "/api/v1/rule-sets/catalogue", "catalogue", &[]),
    ("POST", "/api/v1/rule-sets/catalogue", "fetchCatalogue", &[]),
    ("GET", "/api/v1/rule-sets/coverage", "coverage", &[]),
    ("POST", "/api/v1/rule-sets/deactivate", "deactivate_2", &[]),
    ("GET", "/api/v1/rule-sets/deactivate/impact", "deactivationImpact", &[]),
    ("POST", "/api/v1/rule-sets/{id}/activate", "activate_2", &[]),
    ("GET", "/api/v1/rule-sets/{id}/impact", "impact", &[]),
];

fn unreachable_db() -> vectispire_cp_db::Db {
    let settings = DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    };
    vectispire_cp_db::Db::connect_lazy(&settings).unwrap()
}

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let db = unreachable_db();
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let module = Arc::new(RulesModule::new(db, Arc::new(StandInInventory), Arc::new(StandInIssues), audit));
    let entries = module.routes();
    assert_eq!(entries.len(), 9);

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

    let others_s = "\
GET /api/v1/repositories\n\
POST /api/v1/repositories\n\
GET /api/v1/repositories/duplicates\n\
PATCH /api/v1/repositories/{id}\n\
POST /api/v1/repositories/{id}/scan\n\
DELETE /api/v1/repositories/{id}\n\
GET /api/v1/containers\n\
POST /api/v1/containers\n\
PATCH /api/v1/containers/{id}\n\
POST /api/v1/containers/{id}/scan\n\
DELETE /api/v1/containers/{id}\n\
GET /api/v1/solutions\n\
POST /api/v1/solutions\n\
PATCH /api/v1/solutions/{id}\n\
DELETE /api/v1/solutions/{id}\n\
POST /api/v1/solutions/{id}/projects\n\
GET /api/v1/projects/{id}\n\
PATCH /api/v1/projects/{id}\n\
DELETE /api/v1/projects/{id}\n\
PUT /api/v1/projects/{id}/repositories/{repositoryId}\n\
DELETE /api/v1/projects/{id}/repositories/{repositoryId}\n\
PUT /api/v1/projects/{id}/containers/{containerId}\n\
DELETE /api/v1/projects/{id}/containers/{containerId}\n\
GET /api/v1/git-tokens\n\
POST /api/v1/git-tokens\n\
DELETE /api/v1/git-tokens/{id}\n\
GET /api/v1/ssh-keys\n\
POST /api/v1/ssh-keys\n\
DELETE /api/v1/ssh-keys/{id}\n\
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
    let not_ours = Allowlist::parse(
        &format!("{}{others_s}", include_str!("../../cp-contract/reference/not-yet-ported.txt")),
        &(ceiling + 29 + 3 + 17).to_string(),
    );
    assert_none(&check_routes(&document, &declared, &not_ours));
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
