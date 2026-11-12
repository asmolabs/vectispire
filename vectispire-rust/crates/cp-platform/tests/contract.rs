//! The platform routes served so far against the contract they must not change (`openapi.json` of the 0.11.1 line):
//! documented under the same method and path, with Java's operation ids, out of `cp-contract`'s `not-yet-ported/` since
//! the commit that ported them — then the router probed, so a route declared and not registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_crypto::{Encryption, EncryptionConfig, SigningKeys, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, Routes};

/// Method, path, operation id, and the query parameters the handler reads — all optional, as `@RequestParam(required =
/// false)` declares them.
const DECLARED: &[(&str, &str, &str, &[&str])] = &[
    ("GET", "/api/v1/audit-log", "list_22", &["operation_type", "user_id", "search", "limit", "offset"]),
    ("GET", "/api/v1/audit-log/operation-types", "operationTypes", &[]),
    ("GET", "/api/v1/audit-log/verify", "verify", &[]),
    ("GET", "/api/v1/crypto/public-key.pub", "getPublicKey", &[]),
    ("POST", "/api/v1/crypto/verify", "verifySignature", &[]),
    ("GET", "/api/v1/crypto/cosign-cli-helper", "getCosignCliHelper", &[]),
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
    let trail = Arc::new(vectispire_cp_audit::AuditLogQuery::new(
        audit,
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let door = VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
    };
    let encryption = Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap());
    let signing = Arc::new(SigningKeys::new("", vectispire_cp_settings::Settings::new(db), encryption).unwrap());
    let entries = vectispire_cp_platform::routes(trail, signing);
    assert_eq!(entries.len(), DECLARED.len());
    // The controllers' markers: governance read on `AuditLogController`'s class; on `CryptoController`'s methods, the
    // public key open to anybody and the two others an account's. Any marker passes the registry's rules, so the one
    // each route must carry is held here.
    let markers: Vec<(String, String, Access)> = entries
        .iter()
        .map(|entry| (entry.decl().method.clone(), entry.decl().path.clone(), entry.decl().access))
        .collect();
    let route = |method: &str, path: &str, access| (method.to_owned(), path.to_owned(), access);
    assert_eq!(
        markers,
        vec![
            route("GET", "/api/v1/audit-log", Access::GovernanceRead),
            route("GET", "/api/v1/audit-log/operation-types", Access::GovernanceRead),
            route("GET", "/api/v1/audit-log/verify", Access::GovernanceRead),
            route("GET", "/api/v1/crypto/public-key.pub", Access::Anonymous),
            route("POST", "/api/v1/crypto/verify", Access::Account),
            route("GET", "/api/v1/crypto/cosign-cli-helper", Access::Account),
        ]
    );
    assert!(entries.iter().all(|entry| entry.decl().accepts_api_key.is_none()), "no route here invites an API key");

    let declared: Vec<RouteDecl> = DECLARED
        .iter()
        .map(|(method, path, id, query)| {
            query.iter().fold(RouteDecl::new(method, path, id), |route, name| route.query(name, false))
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
