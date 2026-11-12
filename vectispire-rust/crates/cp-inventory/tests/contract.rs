//! The eighteen inventory routes against the contract they must not change (`openapi.json` of the 0.11.1 line):
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
use vectispire_cp_inventory::{Inventory, InventoryConfig, routes};

type QueryParam = (&'static str, bool);
type DeclaredRoute = (&'static str, &'static str, &'static str, &'static [QueryParam]);

const DECLARED: &[DeclaredRoute] = &[
    ("GET", "/api/v1/licenses/policy", "getPolicy", &[]),
    ("PUT", "/api/v1/licenses/policy", "updatePolicy", &[]),
    ("GET", "/api/v1/licenses/matrix", "getCompatibilityMatrix", &[]),
    (
        "GET",
        "/api/v1/licenses/inventory",
        "getInventory",
        &[("repo_id", false), ("container_id", false), ("limit", false), ("offset", false)],
    ),
    (
        "GET",
        "/api/v1/licenses/conflicts",
        "getConflicts",
        &[("repo_id", false), ("container_id", false), ("proprietary", false), ("limit", false), ("offset", false)],
    ),
    ("GET", "/api/v1/licenses/summary", "getSummary", &[("repo_id", false), ("container_id", false)]),
    ("GET", "/api/v1/blast-radius/explore", "explore", &[("q", false)]),
    ("GET", "/api/v1/blast-radius/top-impact", "getTopImpact", &[("limit", false)]),
    ("GET", "/api/v1/sbom/diff", "diff", &[("fromScanId", true), ("toScanId", true)]),
    ("GET", "/api/v1/sbom/diff/latest", "diffLatest", &[("repoId", false), ("containerId", false)]),
    ("GET", "/api/v1/inventory/search", "search", &[("name", true), ("version", false)]),
    ("GET", "/api/v1/inventory/versions", "versions", &[("name", true)]),
    ("GET", "/api/v1/projects/{id}/components", "components", &[]),
    ("GET", "/api/v1/attack-surface", "globalAttackSurface", &[]),
    ("DELETE", "/api/v1/attack-surface", "clearAllAttackSurfaces", &[]),
    ("GET", "/api/v1/repositories/{id}/apis", "repositoryApis", &[]),
    ("DELETE", "/api/v1/repositories/{id}/apis", "clearRepositoryAttackSurface", &[]),
    ("GET", "/api/v1/repositories/{id}/apis/export/openapi", "exportOpenApi", &[]),
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
    let clock = Arc::new(vectispire_cp_targets::SystemClock);
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let config = vectispire_cp_crypto::EncryptionConfig {
        key: Some(vectispire_domain::secret::Secret::new("dGhyb3dhd2F5LXRhcmdldHMta2V5LTMyLWJ5dGVzISE=")),
        ..vectispire_cp_crypto::EncryptionConfig::default()
    };
    let door = vectispire_cp_crypto::VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
    };
    let encryption = Arc::new(vectispire_cp_crypto::Encryption::new(&config, door).expect("encryption"));
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: Arc::new(vectispire_cp_targets::ScanningStandIn),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins(),
        encryption,
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: clock.clone(),
        visibility: None,
    }));
    let scans = Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), clock.clone()));
    let inventory = Arc::new(Inventory::new(InventoryConfig {
        db: db.clone(),
        scans: scans.clone(),
        targets: targets.clone(),
        audit: audit.clone(),
    }));

    let entries = routes(inventory.clone(), targets.clone());
    assert_eq!(entries.len(), 18);

    let declared: Vec<RouteDecl> = entries
        .iter()
        .map(|entry| {
            let decl = entry.decl();
            let (_, _, id, query) = DECLARED
                .iter()
                .find(|(method, path, _, _)| *method == decl.method && *path == decl.path)
                .unwrap_or_else(|| panic!("route {} {} not in DECLARED list", decl.method, decl.path));
            query
                .iter()
                .fold(RouteDecl::new(&decl.method, &decl.path, id), |route, (name, req)| route.query(name, *req))
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
