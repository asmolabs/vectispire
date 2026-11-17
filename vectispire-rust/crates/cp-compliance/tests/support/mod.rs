//! Compliance's routes composed over a database nobody listens on: building them reads nothing. Posture's support,
//! with the compliance services over it and their two ports answered by stand-ins no route reaches here.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_posture::{NotificationsStandIn, PostureConfig, PostureModule};

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

/// The services composed over a database nobody listens on: building routes reads nothing.
pub fn services() -> Arc<vectispire_cp_compliance::Services> {
    services_on(unreachable_db(), Arc::new(vectispire_cp_targets::SystemClock))
}

/// The same over a database and a clock of the test's own.
pub fn services_on(
    db: vectispire_cp_db::Db,
    clock: Arc<dyn vectispire_cp_targets::Clock>,
) -> Arc<vectispire_cp_compliance::Services> {
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
    let targets_for_scopes = targets.clone();
    let scans = Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), clock.clone()));
    let settings = Arc::new(vectispire_cp_settings::Settings::new(db.clone()));
    let issues = Arc::new(vectispire_cp_issues::Issues::new(vectispire_cp_issues::IssuesConfig {
        db: db.clone(),
        targets: targets.clone(),
        scans: (*scans).clone(),
        settings: settings.clone(),
        audit: audit.clone(),
        events: Arc::new(vectispire_cp_outbox::NotExported),
    }));
    let rules = vectispire_cp_rules::RulesModule::new(
        db.clone(),
        Arc::new(vectispire_cp_rules::StandInInventory),
        Arc::new(vectispire_cp_rules::StandInIssues),
        audit.clone(),
    );
    let gate = vectispire_cp_gate::GateModule::new(
        db.clone(),
        issues.catalog().clone(),
        scans.clone(),
        targets.clone(),
        rules.coverage.clone(),
        audit.clone(),
        clock.clone(),
        Arc::new(vectispire_cp_outbox::NotExported),
    );
    let inventory = vectispire_cp_inventory::Inventory::new(vectispire_cp_inventory::InventoryConfig {
        db: db.clone(),
        scans: scans.clone(),
        targets: targets.clone(),
        audit: audit.clone(),
    });
    let compliance_scans = scans.clone();
    let compliance_issues = issues.catalog().clone();
    let compliance_rules = rules.coverage.clone();
    let compliance_audit = audit.clone();
    let posture = PostureModule::new(PostureConfig {
        db: db.clone(),
        gate: gate.gate.clone(),
        issues: issues.catalog().clone(),
        sla: issues.sla().clone(),
        scans,
        targets: targets.clone(),
        licences: inventory.licenses().clone(),
        apis: inventory.apis().clone(),
        settings,
        audit_log: Arc::new(vectispire_cp_audit::AuditLogQuery::new(
            (*audit).clone(),
            Arc::new(vectispire_cp_audit::SystemClock),
            Vec::new(),
        )),
        audit,
        channels: Arc::new(NotificationsStandIn),
        clock: clock.clone(),
    });
    let compliance = vectispire_cp_compliance::matrix::ComplianceService::new(
        gate.gate.clone(),
        issues.catalog().clone(),
        issues.sla().clone(),
        vectispire_cp_settings::Settings::new(db.clone()),
        Arc::new(NoPlatform),
        Arc::new(NoInventories),
        clock.clone(),
    );
    Arc::new(vectispire_cp_compliance::Services::new(
        compliance.clone(),
        vectispire_cp_compliance::scope::ScopeComplianceService::new(
            targets_for_scopes.clone(),
            compliance,
            posture.scorecards.clone(),
        ),
        db.clone(),
        targets_for_scopes,
        compliance_scans,
        compliance_issues,
        compliance_rules,
        vectispire_cp_settings::Settings::new(db),
        compliance_audit,
        clock,
    ))
}

/// A deployment with every control on and an intact chain: the governance tests read a statement, never the
/// platform's verdicts themselves.
struct NoPlatform;

impl vectispire_cp_compliance::ports::Platform for NoPlatform {
    fn posture(&self) -> BoxFuture<'_, Result<vectispire_cp_compliance::decisions::PlatformPosture, String>> {
        Box::pin(async { Ok(vectispire_cp_compliance::decisions::PlatformPosture::FULLY_ENABLED) })
    }
    fn audit_chain_valid(&self) -> BoxFuture<'_, Result<bool, String>> {
        Box::pin(async { Ok(true) })
    }
}

/// No target holds an inventory.
struct NoInventories;

impl vectispire_cp_compliance::ports::Inventories for NoInventories {
    fn targets_with_inventory(
        &self,
    ) -> BoxFuture<'_, Result<std::collections::BTreeSet<vectispire_cp_db::ScanTarget>, String>> {
        Box::pin(async { Ok(std::collections::BTreeSet::new()) })
    }
}
