//! `RouteAuthorizationTest` and `AuthorizationCoverageTest`, over the routes the control plane registers.
//!
//! `cp-http`'s route builder will not register a route without its requirement and its answer on visibility
//! (proven there, with `trybuild`); this is the second line, read from what the registry actually holds, by the
//! rules `cp-arch-tests` carries over from Java. The adapter below is the one place the two meet: `cp-arch-tests`
//! depends on neither the HTTP stack nor the application, so the boundary tests could be built before them.
//!
//! **The registry is empty today**, so reading it proves nothing yet about any route: what proves the wiring is
//! the registries built here, with a route of each kind, and what keeps the real one honest is that every
//! anonymous route the review accepted must be either registered or still on the contract's list of routes not
//! yet ported — an accepted way in cannot go missing quietly while the list is shrinking.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use vectispire_cp_app::registry;
use vectispire_cp_arch_tests::routes::{ANONYMOUS, Requirement, RouteDescriptor, Scope, check, parse_anonymous};
use vectispire_cp_contract::Allowlist;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::{NoVisibility, Route, RouteDecl, Routes, Visibility};

/// `RouteDecl`, what the registry says a route declared, as the rules read it.
fn describe(decl: &RouteDecl) -> RouteDescriptor {
    RouteDescriptor {
        method: decl.method.clone(),
        path: decl.path.clone(),
        requirement: Some(match decl.access {
            Access::Anonymous => Requirement::Anonymous,
            Access::Account => Requirement::Account,
            Access::Administrator => Requirement::Administrator,
            Access::GovernanceRead => Requirement::GovernanceRead,
            Access::PlatformGovernor => Requirement::PlatformGovernor,
            Access::SecurityLead => Requirement::SecurityLead,
            Access::WriteAccount => Requirement::WriteAccount,
            Access::AgentKey => Requirement::AgentKey,
        }),
        accepts_api_key: decl.accepts_api_key.is_some(),
        names_target: decl.visibility == Visibility::Scoped,
        scope: match decl.visibility {
            // The gate resolves the caller's visibility before the handler runs, and the handler applies it.
            Visibility::Scoped => Scope::Resolved,
            // The builder asks for no reason (`names_no_target()` takes none); the rule wants one it can read.
            Visibility::NamesNoTarget => {
                Scope::NotTargetScoped { reason: "declared names_no_target() at registration".to_owned() }
            }
        },
    }
}

fn descriptors(routes: &Routes<()>) -> Vec<RouteDescriptor> {
    routes.table().iter().map(describe).collect()
}

fn anonymous() -> BTreeMap<String, String> {
    parse_anonymous(ANONYMOUS).expect("anonymous-routes.txt is well formed")
}

async fn handler() {}

use std::sync::Arc;

struct Silent;

impl vectispire_cp_targets::AuditSink for Silent {
    fn record(&self, _: vectispire_cp_audit::Record) -> vectispire_cp_http::credentials::BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

type StandIns = (
    Arc<vectispire_cp_targets::Targets>,
    Arc<vectispire_cp_scanning::Scanning>,
    Arc<vectispire_cp_agents::Agents>,
    Arc<vectispire_cp_rules::RulesModule>,
    Arc<vectispire_cp_inventory::Inventory>,
);

fn stand_ins() -> StandIns {
    use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
    use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
    use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};

    let settings = DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&settings).unwrap();
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    let encryption = Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap());

    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: Arc::new(Silent),
        scans: vectispire_cp_scanning::target_scans(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins().with(vectispire_cp_scanning::purge::listeners()),
        encryption: encryption.clone(),
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        visibility: None,
    }));

    let scanning = Arc::new(vectispire_cp_scanning::Scanning::new(vectispire_cp_scanning::ScanningConfig {
        db: db.clone(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        targets: targets.clone(),
        encryption,
        audit: Arc::new(Silent),
        claim_lock: Arc::new(vectispire_cp_agents::AgentRowLock),
        rule_sets: Arc::new(vectispire_cp_scanning::ports::BundledRules),
        plugins: Arc::new(vectispire_cp_scanning::ports::NoPlugins),
        ingestor: Arc::new(vectispire_cp_scanning::ports::IngestionStandIn::default()),
        policy: vectispire_domain::scan_queue::Policy::default(),
        leader_lease: vectispire_cp_scanning::DEFAULT_LEASE,
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        image_platform: None,
        runner: None,
        scanned: Vec::new(),
    }));

    let catalog = Arc::new(scanning.catalog().clone());
    let dispatcher = scanning.dispatcher_arc();

    let creds = Arc::new(vectispire_cp_access::credentials::CredentialService::new(
        db.clone(),
        Arc::new(vectispire_cp_access::credentials::SystemClock),
        vectispire_cp_access::credentials::SessionPolicy::default(),
        Arc::new(vectispire_cp_agents::AgentDirectoryImpl::new(db.clone())),
        vectispire_cp_access::credentials::ScimToken::default(),
    ));

    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));

    let admin = Arc::new(vectispire_cp_agents::AgentAdministrationService::new(
        db.clone(),
        creds,
        catalog,
        targets.clone(),
        audit.clone(),
        Vec::new(),
        false,
    ));

    let outbox = Arc::new(vectispire_cp_outbox::Outbox::on_database(
        db.clone(),
        vectispire_cp_app::maintenance::outbox_registry(),
        Arc::new(vectispire_cp_maintenance::SystemClock),
    ));

    let protocol = Arc::new(vectispire_cp_agents::AgentProtocolService::new(
        db.clone(),
        dispatcher.clone(),
        audit.clone(),
        outbox,
        Arc::new(vectispire_cp_scanning::ports::BundledRules),
        Arc::new(vectispire_cp_agents::NoAgentPlugins),
    ));

    let poller = Arc::new(vectispire_cp_agents::AgentJobPoller::new(dispatcher, protocol.clone()));
    let agents = Arc::new(vectispire_cp_agents::Agents::new(admin, protocol, poller));

    let scan_catalog =
        Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)));
    let inventory = Arc::new(vectispire_cp_inventory::Inventory::new(vectispire_cp_inventory::InventoryConfig {
        db: db.clone(),
        scans: scan_catalog,
        targets: targets.clone(),
        audit: audit.clone(),
    }));

    let rules = Arc::new(vectispire_cp_rules::RulesModule::new(
        db,
        Arc::new(vectispire_cp_rules::StandInInventory),
        Arc::new(vectispire_cp_rules::StandInIssues),
        audit,
    ));

    (targets, scanning, agents, rules, inventory)
}

/// The real registry, against the rules. The anonymous list is exact about what is registered; a path on it
/// that no route registers yet is excused only while the contract still lists that route as not ported.
#[tokio::test]
async fn the_registry_holds_to_the_authorization_rules() {
    let (targets, scanning, agents, rules, inventory) = stand_ins();
    let routes = descriptors(&registry::routes(targets, scanning, agents, rules, inventory));
    assert_eq!(
        routes.len(),
        76,
        "the registry composes targets (29), scanning (3), agents (17), rules (9), and inventory (18)"
    );
    let not_ported: BTreeSet<String> = Allowlist::embedded().entries().iter().map(|(_, path)| path.clone()).collect();
    let registered: BTreeSet<&str> = routes.iter().map(|route| route.path.as_str()).collect();

    let mut owed = anonymous();
    let missing: Vec<String> = owed
        .keys()
        .filter(|path| !registered.contains(path.as_str()) && !not_ported.contains(*path))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "an accepted anonymous route is neither registered nor on the contract's list of routes not yet ported: {missing:?}"
    );
    owed.retain(|path, _| registered.contains(path.as_str()));

    let violations = check(&routes, &owed, 76);
    assert!(violations.is_empty(), "the registry breaks the authorization rules:\n{}", violations.join("\n"));
}

/// The wiring, shown on registries with a route of each kind: what the builder declares is what the rules read.
#[test]
fn the_adapter_hands_the_rules_what_a_route_declared() {
    let routes = Routes::new(NoVisibility)
        .route(Route::get("/api/v1/auth/login").requires(Access::Anonymous).names_no_target().handler(handler))
        .route(Route::get("/api/v1/projects").requires(Access::Account).scoped().handler(handler))
        .route(Route::get("/api/v1/users").requires(Access::Administrator).names_no_target().handler(handler));
    let described = descriptors(&routes);

    assert_eq!(described.len(), 3);
    let by_path: BTreeMap<&str, &RouteDescriptor> =
        described.iter().map(|route| (route.path.as_str(), route)).collect();
    assert_eq!(by_path["/api/v1/auth/login"].requirement, Some(Requirement::Anonymous));
    assert!(!by_path["/api/v1/auth/login"].names_target);
    assert_eq!(by_path["/api/v1/projects"].scope, Scope::Resolved);
    assert!(by_path["/api/v1/projects"].names_target);
    assert_eq!(by_path["/api/v1/users"].requirement, Some(Requirement::Administrator));

    // Only the login is anonymous, and it is on the review's list: nothing to report.
    let accepted: BTreeMap<String, String> =
        anonymous().into_iter().filter(|(path, _)| path == "/api/v1/auth/login").collect();
    assert_eq!(check(&described, &accepted, 3), Vec::<String>::new());
}

/// …and the rules bite on what the adapter hands them: a way in the review never accepted, a list that names a
/// way in nobody registers, and a registry that read too little.
#[test]
fn the_rules_bite_on_a_registry_that_breaks_them() {
    let open = Routes::new(NoVisibility)
        .route(Route::get("/api/v1/secret-backdoor").requires(Access::Anonymous).names_no_target().handler(handler));
    let violations = check(&descriptors(&open), &BTreeMap::new(), 0);
    assert!(
        violations.iter().any(|line| line.contains("/api/v1/secret-backdoor") && line.contains("anonymous")),
        "an unlisted anonymous route went unreported: {violations:?}"
    );

    let violations = check(&descriptors(&Routes::new(NoVisibility)), &anonymous(), 0);
    assert!(
        violations.iter().any(|line| line.contains("lists /api/v1/auth/login")),
        "a listed anonymous route that nothing registers went unreported: {violations:?}"
    );

    let violations = check(&descriptors(&Routes::new(NoVisibility)), &BTreeMap::new(), 1);
    assert!(violations.iter().any(|line| line.contains("read too little")), "{violations:?}");
}
