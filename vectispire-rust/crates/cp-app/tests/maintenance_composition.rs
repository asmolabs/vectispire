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
    Arc::new(Outbox::new(Arc::new(Unused), vectispire_cp_app::maintenance::outbox_registry(), Arc::new(SystemClock)))
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
    }))
}

#[tokio::test]
async fn every_java_maintenance_task_is_composed_or_deferred_by_name() {
    let targets = targets();
    let scanning = scanning(targets.clone());
    let outbox = outbox();
    let agents = agents(targets.clone(), scanning.clone(), outbox.clone());
    let inventory = inventory(targets.clone(), scanning.clone());
    let issues = issues(targets.clone(), scanning.clone());
    let db_settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&db_settings).unwrap();
    let settings = vectispire_cp_settings::Settings::new(db);
    let turns = vectispire_cp_app::maintenance::turns(
        outbox,
        targets,
        scanning,
        agents,
        inventory,
        issues,
        settings,
        Arc::new(vectispire_cp_targets::SystemClock),
    )
    .unwrap();
    let problems = check(&turns.composition(), DEFERRED);
    assert!(problems.is_empty(), "the maintenance composition:\n  {}", problems.join("\n  "));
}

#[test]
fn the_binary_s_relay_is_held_until_its_registry_is_java_s() {
    let relay = NotificationRelayTask::new(outbox(), &JavaRegistry::compiled_in().unwrap());
    assert!(relay.is_held(), "the relay would abandon Java's messages of the types this binary lacks");
    assert!(relay.coverage().missing_handlers.contains(&"agent_result_audit".to_owned()), "{}", relay.coverage());
}
