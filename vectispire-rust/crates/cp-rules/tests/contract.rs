//! The nine rule-sets routes against the contract they must not change (`openapi.json` of the 0.11.1 line):
//! documented under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported/` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
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
    // Every documented route this module does not declare is another's, ported or not: the test names none of them,
    // and `cp-app`'s registry test holds the whole partition — what is served and what is listed — to the document.
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
