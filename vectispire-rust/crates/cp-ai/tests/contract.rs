//! The advisor's routes against the contract they must not change (`openapi.json`): documented under the same method
//! and path, with Java's operation ids and query parameters, out of `cp-contract`'s `not-yet-ported/` — then the
//! router probed, so a route declared and not registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_module, check_published, probe,
};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, RouteEntry, Routes};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};

type QueryParam = (&'static str, bool);
type DeclaredRoute = (&'static str, &'static str, &'static str, &'static [QueryParam]);

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

fn encryption() -> Arc<vectispire_cp_crypto::Encryption> {
    let config = vectispire_cp_crypto::EncryptionConfig {
        key: Some(vectispire_domain::secret::Secret::new("dGhyb3dhd2F5LWZvcmdlcy1rZXktMzItYnl0ZXMhISE=")),
        ..vectispire_cp_crypto::EncryptionConfig::default()
    };
    let door = vectispire_cp_crypto::VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(vectispire_cp_crypto::Encryption::new(&config, door).expect("encryption"))
}

async fn the_routes_are(entries: Vec<RouteEntry>, declared_routes: &[DeclaredRoute]) {
    assert_eq!(entries.len(), declared_routes.len());
    let declared: Vec<RouteDecl> = declared_routes
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

const DECLARED: &[DeclaredRoute] = &[
    ("GET", "/api/v1/ai-advisor/status", "getStatus_1", &[]),
    ("POST", "/api/v1/ai-advisor/explain/issue/{issueId}", "explainIssue", &[("language", false)]),
    ("POST", "/api/v1/ai-advisor/explain/cve/{cveId}", "explainCve", &[("language", false)]),
];

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let db = unreachable_db();
    let services = vectispire_cp_ai::Services::new(vectispire_cp_ai::AiParts {
        settings: vectispire_cp_settings::Settings::new(db.clone()),
        integrations: Arc::new(vectispire_cp_settings::Integrations::new(
            db.clone(),
            Vec::new(),
            Arc::new(time::OffsetDateTime::now_utc),
        )),
        post: vectispire_cp_outbound::post::OutboundPost::new(
            OutboundUrlGuard::new(Vec::new()),
            PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        ),
        encryption: encryption(),
        issues: Arc::new(vectispire_cp_issues::IssueCatalog::new(db.clone())),
        feeds: vectispire_cp_threatintel::feeds::ThreatIntel::new(db, Arc::new(vectispire_cp_targets::SystemClock)),
    });
    the_routes_are(vectispire_cp_ai::routes(Arc::new(services)), DECLARED).await;
}
