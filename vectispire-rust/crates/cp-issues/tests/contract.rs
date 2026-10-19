//! The ten issues routes against the contract they must not change (`openapi.json` of the 0.11.1 line):
//! documented under the same method and path, with Java's operation ids and query parameters, out of `cp-contract`'s
//! `not-yet-ported.txt` since the commit that ported them — then the router probed, so a route declared and not
//! registered is caught too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use vectispire_cp_contract::{
    Allowlist, Document, Published, RouteDecl, assert_none, check_published, check_routes, probe,
};
use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::chain::{Chain, ChainConfig};
use vectispire_cp_http::credentials::{RecordingAudit, StaticCredentials};
use vectispire_cp_http::routes::{NoVisibility, Routes};
use vectispire_cp_issues::{Issues, IssuesConfig, routes};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};

type QueryParam = (&'static str, bool);
type DeclaredRoute = (&'static str, &'static str, &'static str, &'static [QueryParam]);

const DECLARED: &[DeclaredRoute] = &[
    (
        "GET",
        "/api/v1/issues",
        "list_20",
        &[
            ("state", false),
            ("severity", false),
            ("type", false),
            ("triage_status", false),
            ("repository_id", false),
            ("container_id", false),
            ("project_id", false),
            ("solution_id", false),
            ("only_direct", false),
            ("is_kev", false),
            ("overdue", false),
            ("unsettled", false),
            ("search", false),
            ("identifier", false),
            ("limit", false),
            ("offset", false),
            ("owasp_category", false),
            ("open_at", false),
            ("first_seen_from", false),
            ("first_seen_to", false),
            ("resolved_from", false),
            ("resolved_to", false),
            ("reopened_from", false),
            ("reopened_to", false),
        ],
    ),
    ("GET", "/api/v1/issues/{id}", "detail_1", &[]),
    ("PUT", "/api/v1/issues/{id}/ticket", "attachTicket", &[]),
    ("POST", "/api/v1/issues/{id}/triage", "triage", &[]),
    ("POST", "/api/v1/issues/triage", "triageMany", &[]),
    ("GET", "/api/v1/history/repositories", "repositories", &[("limit", false), ("offset", false)]),
    ("GET", "/api/v1/history/repositories/{id}", "dossier", &[("limit", false)]),
    ("GET", "/api/v1/history/repositories/{id}/export.csv", "csv_1", &[]),
    ("GET", "/api/v1/exceptions", "register_3", &[("limit", false), ("cursor", false)]),
    ("POST", "/api/v1/exceptions/{issueId}/reviews", "review", &[]),
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
    let config = EncryptionConfig {
        key: Some(vectispire_domain::secret::Secret::new("dGhyb3dhd2F5LXRhcmdldHMta2V5LTMyLWJ5dGVzISE=")),
        ..EncryptionConfig::default()
    };
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    let encryption = Arc::new(Encryption::new(&config, door).expect("encryption"));
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
    let scans = vectispire_cp_scanning::ScanCatalog::new(db.clone(), clock.clone());
    let settings = Arc::new(vectispire_cp_settings::Settings::new(db.clone()));
    let issues = Arc::new(Issues::new(IssuesConfig { db: db.clone(), targets, scans, settings, audit }));

    let entries = routes(issues);
    assert_eq!(entries.len(), 10);

    let declared: Vec<RouteDecl> = DECLARED
        .iter()
        .map(|(method, path, id, query)| {
            query.iter().fold(RouteDecl::new(method, path, id), |route, (name, required)| route.query(name, *required))
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
POST /api/v1/agent/sealing-key\n\
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
GET /api/v1/sbom/diff/latest\n";

    let ceiling: usize = include_str!("../../cp-contract/reference/not-yet-ported.ceiling").trim().parse().unwrap();
    let not_ours = Allowlist::parse(
        &format!("{}{others_s}", include_str!("../../cp-contract/reference/not-yet-ported.txt")),
        &(ceiling + 29 + 3 + 17 + 9 + 18).to_string(),
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
