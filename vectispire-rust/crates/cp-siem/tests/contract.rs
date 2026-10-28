//! The three SIEM routes against the contract they must not change (`openapi.json` of the 0.11.1 line): documented
//! under the same method and path, with Java's operation ids, out of `cp-contract`'s `not-yet-ported/` since the commit
//! that ported them — then the router probed, so a route declared and not registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, Routes};
use vectispire_cp_siem::SiemExporterService;

const DECLARED: &[(&str, &str, &str)] = &[
    ("GET", "/api/v1/siem/config", "getConfig"),
    ("PUT", "/api/v1/siem/config", "updateConfig"),
    ("POST", "/api/v1/siem/test", "testConnection"),
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
    let audit = vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    );
    let service = Arc::new(SiemExporterService::new(
        db,
        Arc::new(support::Recording::default()),
        support::encryption(),
        audit,
        support::TestClock::system(),
    ));
    let entries = vectispire_cp_siem::routes(service);
    assert_eq!(entries.len(), 3);
    // `SiemController`'s markers: governance read on the class, security lead on the save and the test. Any marker
    // passes the registry's rules, so the one each route must carry is held here.
    let markers: Vec<(String, String, Access)> = entries
        .iter()
        .map(|entry| (entry.decl().method.clone(), entry.decl().path.clone(), entry.decl().access))
        .collect();
    assert_eq!(
        markers,
        vec![
            ("GET".to_owned(), "/api/v1/siem/config".to_owned(), Access::GovernanceRead),
            ("PUT".to_owned(), "/api/v1/siem/config".to_owned(), Access::SecurityLead),
            ("POST".to_owned(), "/api/v1/siem/test".to_owned(), Access::SecurityLead),
        ]
    );

    let declared: Vec<RouteDecl> = DECLARED.iter().map(|(method, path, id)| RouteDecl::new(method, path, id)).collect();
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
