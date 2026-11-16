//! The module composed over a database nobody listens on: building routes reads nothing, and a route that reads
//! before it refuses answers 500 rather than the 404 a refusal owes.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
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

/// The module composed over a database nobody listens on: building routes reads nothing.
pub fn module() -> PostureModule {
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
    PostureModule::new(PostureConfig {
        db: db.clone(),
        gate: gate.gate.clone(),
        issues: issues.catalog().clone(),
        sla: issues.sla().clone(),
        scans,
        targets,
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
        clock,
    })
}
