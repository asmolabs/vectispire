//! The maintenance tasks the binary composes, against Java's — `MaintenanceCompositionTest`, at the one level where
//! a task nobody runs is visible: the composition itself. Every slot of `MaintenanceTask.Sequence` is filled by a
//! task of `maintenance::tasks()`, or named in `cp-maintenance`'s `data/deferred.txt` with who fills it; none is both.
//! And the outbox's relay, composed, is held back while the binary's registry is not Java's.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_maintenance::SystemClock;
use vectispire_cp_maintenance::composition::{DEFERRED, check};
use vectispire_cp_outbox::{DueMessage, JavaRegistry, NotificationRelayTask, Outbox, OutboxStore, StoreFuture};

/// A store nobody calls: the composition is built, never run.
struct Unused;

impl OutboxStore for Unused {
    fn find_due(&self, _: &'static str, _: OffsetDateTime, _: u32) -> StoreFuture<'_, Vec<DueMessage>> {
        unreachable!("the composition test runs no task")
    }
    fn claim(&self, _: Uuid, _: &'static str, _: OffsetDateTime, _: OffsetDateTime) -> StoreFuture<'_, u64> {
        unreachable!("the composition test runs no task")
    }
    fn record_attempt<'a>(
        &'a self,
        _: Uuid,
        _: i32,
        _: Option<&'a str>,
        _: &'static str,
        _: Option<OffsetDateTime>,
    ) -> StoreFuture<'a, u64> {
        unreachable!("the composition test runs no task")
    }
    fn mark_sent(&self, _: Uuid, _: i32, _: &'static str, _: OffsetDateTime) -> StoreFuture<'_, u64> {
        unreachable!("the composition test runs no task")
    }
    fn delete_sent_before(&self, _: &'static str, _: OffsetDateTime) -> StoreFuture<'_, u64> {
        unreachable!("the composition test runs no task")
    }
    fn count_by_status(&self) -> StoreFuture<'_, Vec<(String, i64)>> {
        unreachable!("the composition test runs no task")
    }
}

fn outbox() -> Arc<Outbox> {
    Arc::new(Outbox::new(
        Arc::new(Unused),
        vectispire_cp_app::maintenance::outbox_registry(
            audit(),
            &siem(),
            vectispire_cp_app::checklists::answer_delivery().0,
            &notifications(),
        ),
        Arc::new(SystemClock),
    ))
}

/// The SIEM export as the binary composes it, over a pool that never connects.
fn siem() -> vectispire_cp_app::siem::Siem {
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
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    vectispire_cp_app::siem::compose(
        vectispire_cp_app::siem::SiemSetup {
            db: vectispire_cp_db::Db::connect_lazy(&settings).unwrap(),
            guard: OutboundUrlGuard::new(Vec::new()),
            trust: vectispire_tls::TlsTrust::BuiltIn,
            encryption: Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
            version: None,
        },
        Arc::new(vectispire_cp_audit::SystemClock),
    )
    .unwrap()
}

/// The notifications' channels over a pool that never connects.
fn notifications() -> vectispire_cp_notifications::Channels {
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
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    vectispire_cp_app::notifications::compose_plain(
        &vectispire_cp_db::Db::connect_lazy(&settings).unwrap(),
        Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
    )
    .1
}

/// The tickets module over a pool that never connects.
fn tickets() -> Arc<vectispire_cp_tickets::Tickets> {
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
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    vectispire_cp_app::tickets::compose(vectispire_cp_app::tickets::TicketParts {
        db: vectispire_cp_db::Db::connect_lazy(&settings).unwrap(),
        encryption: Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
        post: vectispire_cp_outbound::OutboundPost::new(
            OutboundUrlGuard::new(Vec::new()),
            PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        ),
        audit: audit(),
        alerts: Arc::new(vectispire_cp_outbox::NotTold),
        clock: Arc::new(vectispire_cp_audit::SystemClock),
    })
}

/// An audit log over a pool that never connects: the composition delivers nothing.
fn forge_encryption() -> Arc<vectispire_cp_crypto::Encryption> {
    let door = vectispire_cp_crypto::VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(vectispire_cp_crypto::Encryption::new(&vectispire_cp_crypto::EncryptionConfig::default(), door).unwrap())
}

fn audit() -> Arc<vectispire_cp_audit::AuditLog> {
    use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
    let settings = DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    };
    Arc::new(vectispire_cp_audit::AuditLog::new(
        vectispire_cp_db::Db::connect_lazy(&settings).unwrap(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ))
}

/// The targets module over a pool that never connects: the composition runs no task.
fn targets() -> Arc<vectispire_cp_targets::Targets> {
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
    Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: Arc::new(Silent),
        scans: vectispire_cp_scanning::target_scans(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins().with(vectispire_cp_scanning::purge::listeners()),
        encryption: Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        visibility: None,
    }))
}

struct Silent;

/// The scanning module over the same pool and the stand-ins the binary composes until 2.8, 2.9 and Phases 3 and 4.
fn scanning(targets: Arc<vectispire_cp_targets::Targets>) -> Arc<vectispire_cp_scanning::Scanning> {
    use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
    use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
    use vectispire_cp_scanning::ports::{AgentsStandIn, BundledRules, IngestionStandIn, NoPlugins};
    let settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(vectispire_cp_scanning::Scanning::new(vectispire_cp_scanning::ScanningConfig {
        db: vectispire_cp_db::Db::connect_lazy(&settings).unwrap(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        targets,
        encryption: Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap()),
        audit: Arc::new(Silent),
        claim_lock: Arc::new(AgentsStandIn),
        rule_sets: Arc::new(BundledRules),
        plugins: Arc::new(NoPlugins),
        ingestor: Arc::new(IngestionStandIn::default()),
        policy: vectispire_domain::scan_queue::Policy::default(),
        leader_lease: vectispire_cp_scanning::DEFAULT_LEASE,
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        image_platform: None,
        runner: None,
        scanned: Vec::new(),
    }))
}

impl vectispire_cp_targets::AuditSink for Silent {
    fn record(&self, _: vectispire_cp_audit::Record) -> vectispire_cp_http::credentials::BoxFuture<'_, ()> {
        Box::pin(async {})
    }
}

fn agents(
    targets: Arc<vectispire_cp_targets::Targets>,
    scanning: Arc<vectispire_cp_scanning::Scanning>,
    outbox: Arc<Outbox>,
) -> Arc<vectispire_cp_agents::Agents> {
    let settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&settings).unwrap();
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
        targets,
        audit.clone(),
        Vec::new(),
        false,
    ));

    let protocol = Arc::new(vectispire_cp_agents::AgentProtocolService::new(
        db,
        dispatcher.clone(),
        audit,
        outbox,
        Arc::new(vectispire_cp_scanning::ports::BundledRules),
        Arc::new(vectispire_cp_agents::NoAgentPlugins),
    ));

    let poller = Arc::new(vectispire_cp_agents::AgentJobPoller::new(dispatcher, protocol.clone()));
    Arc::new(vectispire_cp_agents::Agents::new(admin, protocol, poller))
}

fn inventory(
    targets: Arc<vectispire_cp_targets::Targets>,
    scanning: Arc<vectispire_cp_scanning::Scanning>,
) -> Arc<vectispire_cp_inventory::Inventory> {
    let settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&settings).unwrap();
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    Arc::new(vectispire_cp_inventory::Inventory::new(vectispire_cp_inventory::InventoryConfig {
        db,
        scans: Arc::new(scanning.catalog().clone()),
        targets,
        audit,
    }))
}

fn issues(
    targets: Arc<vectispire_cp_targets::Targets>,
    scanning: Arc<vectispire_cp_scanning::Scanning>,
) -> Arc<vectispire_cp_issues::Issues> {
    let settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&settings).unwrap();
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    Arc::new(vectispire_cp_issues::Issues::new(vectispire_cp_issues::IssuesConfig {
        db: db.clone(),
        targets,
        scans: scanning.catalog().clone(),
        settings: Arc::new(vectispire_cp_settings::Settings::new(db)),
        audit,
        events: Arc::new(vectispire_cp_outbox::NotExported),
    }))
}

fn gate(
    targets: Arc<vectispire_cp_targets::Targets>,
    scanning: Arc<vectispire_cp_scanning::Scanning>,
    issues: Arc<vectispire_cp_issues::Issues>,
) -> Arc<vectispire_cp_gate::GateModule> {
    let db_settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&db_settings).unwrap();
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let rules = vectispire_cp_rules::RulesModule::new(
        db.clone(),
        Arc::new(vectispire_cp_rules::StandInInventory),
        Arc::new(vectispire_cp_rules::StandInIssues),
        audit.clone(),
    );
    Arc::new(vectispire_cp_gate::GateModule::new(
        db,
        issues.catalog().clone(),
        Arc::new(scanning.catalog().clone()),
        targets,
        rules.coverage.clone(),
        audit,
        Arc::new(vectispire_cp_targets::SystemClock),
        Arc::new(vectispire_cp_outbox::NotExported),
    ))
}

/// The access module's session cleanup over a pool that never connects, as the binary composes it.
fn session_cleanup() -> Arc<dyn vectispire_cp_maintenance::MaintenanceTask> {
    let settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&settings).unwrap();
    let clock: vectispire_cp_access::throttle::SharedClock = Arc::new(vectispire_cp_access::credentials::SystemClock);
    let credentials = Arc::new(vectispire_cp_access::credentials::CredentialService::new(
        db.clone(),
        clock.clone(),
        vectispire_cp_access::credentials::SessionPolicy::default(),
        Arc::new(vectispire_cp_agents::AgentDirectoryImpl::new(db.clone())),
        vectispire_cp_access::credentials::ScimToken::default(),
    ));
    vectispire_cp_access::session_cleanup::session_cleanup_task(credentials, db, clock)
}

/// The posture module over a pool that never connects, as the binary composes it: its weekly digest fills
/// `WEEKLY_DIGEST`, its channels the notifications stand-in.
fn posture(
    targets: Arc<vectispire_cp_targets::Targets>,
    scanning: Arc<vectispire_cp_scanning::Scanning>,
    inventory: Arc<vectispire_cp_inventory::Inventory>,
    issues: Arc<vectispire_cp_issues::Issues>,
    gate: Arc<vectispire_cp_gate::GateModule>,
) -> Arc<vectispire_cp_posture::PostureModule> {
    let settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&settings).unwrap();
    let audit = audit();
    Arc::new(vectispire_cp_posture::PostureModule::new(vectispire_cp_posture::PostureConfig {
        db: db.clone(),
        gate: gate.gate.clone(),
        issues: issues.catalog().clone(),
        sla: issues.sla().clone(),
        scans: Arc::new(scanning.catalog().clone()),
        targets,
        licences: inventory.licenses().clone(),
        apis: inventory.apis().clone(),
        settings: Arc::new(vectispire_cp_settings::Settings::new(db)),
        audit_log: Arc::new(vectispire_cp_audit::AuditLogQuery::new(
            (*audit).clone(),
            Arc::new(vectispire_cp_audit::SystemClock),
            Vec::new(),
        )),
        audit,
        channels: Arc::new(vectispire_cp_posture::NotificationsStandIn),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
    }))
}

/// A deployment no task reads here: building compliance's services reads nothing.
struct NoPlatform;

impl vectispire_cp_compliance::ports::Platform for NoPlatform {
    fn posture(
        &self,
    ) -> vectispire_cp_http::credentials::BoxFuture<
        '_,
        Result<vectispire_cp_compliance::decisions::PlatformPosture, String>,
    > {
        Box::pin(async { Err("not read here".to_owned()) })
    }

    fn audit_chain_valid(&self) -> vectispire_cp_http::credentials::BoxFuture<'_, Result<bool, String>> {
        Box::pin(async { Err("not read here".to_owned()) })
    }
}

/// Compliance's services over a pool that never connects, as the binary composes them: its monthly capture fills
/// `COMPLIANCE_HISTORY` and its weekly record `OWASP_WEEKLY_COVERAGE`.
fn compliance(
    targets: Arc<vectispire_cp_targets::Targets>,
    scanning: Arc<vectispire_cp_scanning::Scanning>,
    inventory: Arc<vectispire_cp_inventory::Inventory>,
    issues: Arc<vectispire_cp_issues::Issues>,
    gate: Arc<vectispire_cp_gate::GateModule>,
    posture: Arc<vectispire_cp_posture::PostureModule>,
) -> Arc<vectispire_cp_compliance::Services> {
    let settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&settings).unwrap();
    let audit = audit();
    let clock: Arc<dyn vectispire_cp_targets::Clock> = Arc::new(vectispire_cp_targets::SystemClock);
    let rules = vectispire_cp_rules::RulesModule::new(
        db.clone(),
        Arc::new(vectispire_cp_rules::StandInInventory),
        Arc::new(vectispire_cp_rules::StandInIssues),
        audit.clone(),
    );
    let matrix = vectispire_cp_compliance::matrix::ComplianceService::new(
        gate.gate.clone(),
        issues.catalog().clone(),
        issues.sla().clone(),
        vectispire_cp_settings::Settings::new(db.clone()),
        Arc::new(NoPlatform),
        Arc::new(vectispire_cp_app::compliance::InventoryFacts(inventory.query().clone())),
        clock.clone(),
    );
    Arc::new(vectispire_cp_compliance::Services::new(
        matrix.clone(),
        vectispire_cp_compliance::scope::ScopeComplianceService::new(
            targets.clone(),
            matrix,
            posture.scorecards.clone(),
        ),
        db.clone(),
        targets,
        Arc::new(scanning.catalog().clone()),
        issues.catalog().clone(),
        issues.queries().clone(),
        rules.coverage.clone(),
        vectispire_cp_settings::Settings::new(db),
        audit,
        clock,
    ))
}

/// The checklists' accounts, never asked: the composition runs no task.
struct NoAccounts;

impl vectispire_cp_checklists::ports::AccountDirectory for NoAccounts {
    fn active<'a>(
        &'a self,
    ) -> vectispire_cp_checklists::measurer::Answer<'a, Vec<vectispire_cp_access::accounts::UserView>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn by_id<'a>(
        &'a self,
        _: i64,
    ) -> vectispire_cp_checklists::measurer::Answer<'a, Option<vectispire_cp_access::accounts::UserView>> {
        Box::pin(async { Ok(None) })
    }
    fn allowance_of<'a>(
        &'a self,
        _: &'a vectispire_cp_access::accounts::UserView,
    ) -> vectispire_cp_checklists::measurer::Answer<'a, vectispire_cp_access::visibility::Allowance> {
        Box::pin(async { Ok(vectispire_cp_access::visibility::Allowance::nothing()) })
    }
}

#[tokio::test]
async fn every_java_maintenance_task_is_composed_or_deferred_by_name() {
    let targets = targets();
    let scanning = scanning(targets.clone());
    let outbox = outbox();
    let agents = agents(targets.clone(), scanning.clone(), outbox.clone());
    let inventory = inventory(targets.clone(), scanning.clone());
    let issues = issues(targets.clone(), scanning.clone());
    let gate = gate(targets.clone(), scanning.clone(), issues.clone());
    let posture = posture(targets.clone(), scanning.clone(), inventory.clone(), issues.clone(), gate.clone());
    let compliance =
        compliance(targets.clone(), scanning.clone(), inventory.clone(), issues.clone(), gate.clone(), posture.clone());
    let db_settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&db_settings).unwrap();
    let settings = vectispire_cp_settings::Settings::new(db.clone());
    let checklist_targets = targets.clone();
    let gauges = vectispire_cp_app::gauges::Gauges::new(scanning.queue().clone(), outbox.clone(), agents.admin.clone());
    let turns = vectispire_cp_app::maintenance::turns(
        outbox,
        targets,
        scanning,
        agents,
        inventory,
        issues,
        gate,
        posture,
        compliance,
        settings,
        Arc::new(vectispire_cp_targets::SystemClock),
        session_cleanup(),
        Arc::new(vectispire_cp_checklists::ChecklistReminderTask {
            reminders: Arc::new(vectispire_cp_checklists::contact_service::ChecklistReminders::new(
                db.clone(),
                Arc::new(vectispire_cp_checklists::TargetProjects(checklist_targets.clone())),
                Arc::new(NoAccounts),
                Arc::new(vectispire_cp_settings::Settings::new(db.clone())),
                Arc::new(vectispire_cp_checklists::ports::NoMail),
                Arc::new(vectispire_cp_audit::AuditLogQuery::new(
                    (*audit()).clone(),
                    Arc::new(vectispire_cp_audit::SystemClock),
                    Vec::new(),
                )),
                audit(),
                Arc::new(vectispire_cp_targets::SystemClock),
            )),
        }),
        // The forges' two tasks and threatintel's two, as `main.rs` composes them.
        vectispire_cp_app::forges::compose(vectispire_cp_app::forges::ForgeSetup {
            db: db.clone(),
            guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
            trust: vectispire_tls::TlsTrust::BuiltIn,
            encryption: forge_encryption(),
            audit: audit(),
            clock: Arc::new(vectispire_cp_targets::SystemClock),
            targets: checklist_targets.clone(),
        })
        .services
        .tasks()
        .into_iter()
        .chain(
            vectispire_cp_app::threatintel::compose(vectispire_cp_app::threatintel::ThreatIntelSetup {
                db: db.clone(),
                guard: vectispire_cp_outbound::OutboundUrlGuard::new(Vec::new()),
                trust: vectispire_tls::TlsTrust::BuiltIn,
                locations: vectispire_cp_threatintel::sources::FeedLocations::default(),
                issues: Arc::new(vectispire_cp_issues::queries::IssueCatalog::new(db.clone())),
                targets: checklist_targets.clone(),
                clock: Arc::new(vectispire_cp_targets::SystemClock),
                events: Arc::new(vectispire_cp_outbox::NotExported),
                audit: audit(),
            })
            .tasks(),
        )
        .collect(),
        &tickets(),
        &gauges,
    )
    .unwrap();
    let problems = check(&turns.composition(), DEFERRED);
    assert!(problems.is_empty(), "the maintenance composition:\n  {}", problems.join("\n  "));
}

#[tokio::test]
async fn the_binary_s_relay_is_held_until_its_registry_is_java_s() {
    let relay = NotificationRelayTask::new(outbox(), &JavaRegistry::compiled_in().unwrap());
    assert!(relay.is_held(), "the relay would abandon Java's messages of the types this binary lacks");
    for handled in ["agent_result_audit", "siem_event"] {
        assert!(!relay.coverage().missing_handlers.contains(&handled.to_owned()), "{}", relay.coverage());
    }
}

/// Every handler a module has is registered, held relay or not: the agents' audit delivery was written, enqueued by
/// every accepted result, and missing from the registry — the relay would have opened without it. The SIEM's is the
/// second (task 4.2).
#[tokio::test]
async fn the_binary_registers_every_handler_it_has() {
    let registry = vectispire_cp_app::maintenance::outbox_registry(
        audit(),
        &siem(),
        vectispire_cp_app::checklists::answer_delivery().0,
        &notifications(),
    );
    assert_eq!(
        registry.handler_types().into_iter().collect::<Vec<_>>(),
        vec![
            "agent_result_audit".to_owned(),
            "checklist_answer".to_owned(),
            "siem_event".to_owned(),
            "token_alert".to_owned(),
            "token_alert_audit".to_owned()
        ]
    );
    // The notifications' five channels (wave 2): every channel Java relays.
    assert_eq!(
        registry.channel_types().into_iter().collect::<Vec<_>>(),
        vec!["scan_delta", "scan_delta_discord", "scan_delta_mail", "scan_delta_slack", "scan_delta_teams"]
    );
}
