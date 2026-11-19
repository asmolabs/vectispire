//! Threat intelligence's routes against the contract they must not change (`openapi.json`): documented under the same
//! method and path, with Java's operation ids, out of `cp-contract`'s `not-yet-ported/` — then the router probed, so a
//! route declared and not registered is caught too.

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
    ("POST", "/api/v1/threat-intel/sync", "sync", &[]),
    ("POST", "/api/v1/epss/sync", "sync_1", &[]),
    ("GET", "/api/v1/threat-intel/status", "getStatus", &[]),
    ("GET", "/api/v1/epss/priorities", "getPriorities", &[]),
    ("GET", "/api/v1/epss/cve/{cveId}", "lookupCve", &[]),
];

#[tokio::test]
async fn the_routes_are_the_documented_ones() {
    let db = unreachable_db();
    let clock: Arc<dyn vectispire_cp_targets::Clock> = Arc::new(vectispire_cp_targets::SystemClock);
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: Arc::new(vectispire_cp_targets::ScanningStandIn),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins(),
        encryption: encryption(),
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: clock.clone(),
        visibility: None,
    }));
    let locations = vectispire_cp_threatintel::sources::FeedLocations::default();
    let sender = PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn);
    let services = vectispire_cp_threatintel::Services::new(vectispire_cp_threatintel::ThreatIntelParts {
        db: db.clone(),
        issues: Arc::new(vectispire_cp_issues::queries::IssueCatalog::new(db)),
        targets,
        clock,
        events: Arc::new(vectispire_cp_outbox::NotExported),
        audit,
        catalogue: Arc::new(vectispire_cp_threatintel::sources::KevCatalogSource::new(
            vectispire_cp_outbound::json::OutboundJson::new(sender.clone(), OutboundUrlGuard::new(Vec::new())),
            &locations,
        )),
        file: Arc::new(vectispire_cp_threatintel::sources::EpssFileSource::new(
            vectispire_cp_outbound::download::OutboundDownload::new(sender, OutboundUrlGuard::new(Vec::new())),
            &locations,
        )),
    });
    the_routes_are(vectispire_cp_threatintel::routes(Arc::new(services)), DECLARED).await;
}
