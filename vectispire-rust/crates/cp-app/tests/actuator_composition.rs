//! **The actuator as the binary composes it**, on a real database: the encryption census gathered from the modules
//! that seal something, held to Java's list of stores, and the Prometheus page of the gauges `gauges.rs` registers,
//! held to the lines Java 1.0 wrote for the same meters.
//!
//! Asserted on the composition, as Java's `EncryptionCensusRoutesTest` is: each store is a module's line, and a
//! module whose line is missing makes the census say a rotation is finished while its values still need the old key —
//! which is what the procedure said for three stores out of eleven.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_audit::{AuditLog, NoMirror, SystemClock};
use vectispire_cp_crypto::{Encryption, EncryptionConfig, SigningKeys, VaultDoor};
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
use vectispire_cp_runtime::metrics::Metrics;
use vectispire_domain::secret::Secret;
use vectispire_tls::TlsTrust;

/// Java 1.0's census, every store `EncryptionCensusRoutesTest.listsEveryStore` names, sorted as the endpoint sorts them.
const JAVA_STORES: [&str; 12] = [
    "Document signing key",
    "Forge connection tokens",
    "HTTPS clone tokens",
    "Inbound tracker webhook secret",
    "Notification webhook signing secret",
    "OpenAI API key",
    "Published document signing keys",
    "SIEM authorization header",
    "SSH deploy keys",
    "TOTP backup codes",
    "TOTP secrets",
    "Tracker access token",
];

/// The stores whose Java module has no Rust counterpart answering for them yet (`cp-app/src/actuator.rs`). A module
/// ported later moves its stores out of this list and into the census in the same commit.
const NOT_PORTED: [&str; 7] = [
    "Forge connection tokens",
    "Inbound tracker webhook secret",
    "Notification webhook signing secret",
    "OpenAI API key",
    "TOTP backup codes",
    "TOTP secrets",
    "Tracker access token",
];

fn encryption() -> Arc<Encryption> {
    let config = EncryptionConfig {
        key: Some(Secret::new("actuator-composition-test-key-0123456789")),
        ..EncryptionConfig::default()
    };
    let door = VaultDoor { sender: PinnedHttpSender::new(TlsTrust::BuiltIn), guard: OutboundUrlGuard::new(Vec::new()) };
    Arc::new(Encryption::new(&config, door).unwrap())
}

fn census(db: &Db) -> vectispire_cp_crypto::EncryptionCensus {
    let encryption = encryption();
    let audit = Arc::new(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(SystemClock), Vec::new()));
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: vectispire_cp_scanning::target_scans(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins(),
        encryption: encryption.clone(),
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        visibility: None,
    }));
    let siem = vectispire_cp_app::siem::compose(
        vectispire_cp_app::siem::SiemSetup {
            db: db.clone(),
            guard: OutboundUrlGuard::new(Vec::new()),
            trust: TlsTrust::BuiltIn,
            encryption: encryption.clone(),
            version: None,
        },
        Arc::new(SystemClock),
    )
    .unwrap();
    let exporter = vectispire_cp_app::siem::service(
        &siem,
        db.clone(),
        encryption.clone(),
        (*audit).clone(),
        Arc::new(SystemClock),
    );
    let signing =
        Arc::new(SigningKeys::new("", vectispire_cp_settings::Settings::new(db.clone()), encryption).unwrap());
    vectispire_cp_app::actuator::encryption_census(signing, targets, exporter)
}

async fn the_census_lists_java_s_stores_but_those_of_modules_not_ported(engine: Engine) {
    let server = TestDatabase::start(engine).await;
    let db = server.connect().await;
    let census = census(&db);
    let stores: Vec<String> = census.take().await.unwrap().into_iter().map(|line| line.store).collect();
    let expected: Vec<&str> = JAVA_STORES.into_iter().filter(|store| !NOT_PORTED.contains(store)).collect();
    assert_eq!(stores, expected);
    let report = census.report().await.unwrap();
    assert!(
        report.starts_with("{\"rotationFinished\":true,\"stores\":[{\"store\":\"Document signing key\""),
        "{report}"
    );
    // Each line as Java's endpoint writes it: the reseal gesture, then the four counts, nothing in them yet.
    assert!(
        report.contains(
            "{\"store\":\"SIEM authorization header\",\"reseal\":\"set the header again on the SIEM settings\",\
             \"current\":0,\"previousKey\":0,\"unreadable\":0,\"clear\":0}"
        ),
        "{report}"
    );
    db.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn on_mysql() {
    if vectispire_cp_db::testing::runs_on(Engine::MySql) {
        the_census_lists_java_s_stores_but_those_of_modules_not_ported(Engine::MySql).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn on_postgresql() {
    if vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        the_census_lists_java_s_stores_but_those_of_modules_not_ported(Engine::PostgreSql).await;
    }
}

/// The page Java 1.0 answered `PrometheusScrapeTest.servesTheMetersToTheScrapeToken` (the golden recording of
/// 1.0.0-rc.2), its lines for the gauges `gauges.rs` registers, the values replaced by `V`.
const JAVA_GAUGE_LINES: &str = "\
# HELP vectispire_agents_enabled Remote agents an operator has enabled
# TYPE vectispire_agents_enabled gauge
vectispire_agents_enabled{application=\"vectispire\"} V
# HELP vectispire_agents_last_seen_age_seconds How long the least recently seen enabled agent has been silent — since its creation if it never polled; zero when none is enabled
# TYPE vectispire_agents_last_seen_age_seconds gauge
vectispire_agents_last_seen_age_seconds{application=\"vectispire\"} V
# HELP vectispire_agents_online Enabled agents heard from within the last two minutes, as the agents screen counts them
# TYPE vectispire_agents_online gauge
vectispire_agents_online{application=\"vectispire\"} V
# HELP vectispire_metrics_snapshot_age_seconds How old the figures the database gauges report are; it grows when the tick stops
# TYPE vectispire_metrics_snapshot_age_seconds gauge
vectispire_metrics_snapshot_age_seconds{application=\"vectispire\",source=\"agents\"} V
vectispire_metrics_snapshot_age_seconds{application=\"vectispire\",source=\"scans\"} V
# HELP vectispire_outbox_pending Notifications accepted but not yet delivered
# TYPE vectispire_outbox_pending gauge
vectispire_outbox_pending{application=\"vectispire\"} V
# HELP vectispire_scans_credential_unserved Waiting scans needing a credential that no executor able to be handed it can take
# TYPE vectispire_scans_credential_unserved gauge
vectispire_scans_credential_unserved{application=\"vectispire\"} V
# HELP vectispire_scans_queued Scans waiting for a worker or an agent to claim them, retry delays included
# TYPE vectispire_scans_queued gauge
vectispire_scans_queued{application=\"vectispire\",kind=\"container\"} V
vectispire_scans_queued{application=\"vectispire\",kind=\"repository\"} V
# HELP vectispire_scans_queued_oldest_age_seconds How long the oldest waiting scan has waited since it was queued; zero when none waits
# TYPE vectispire_scans_queued_oldest_age_seconds gauge
vectispire_scans_queued_oldest_age_seconds{application=\"vectispire\",kind=\"container\"} V
vectispire_scans_queued_oldest_age_seconds{application=\"vectispire\",kind=\"repository\"} V
# HELP vectispire_scans_running Scans claimed and not yet reported
# TYPE vectispire_scans_running gauge
vectispire_scans_running{application=\"vectispire\"} V
";

#[tokio::test]
async fn the_gauges_are_written_on_the_prometheus_page_as_java_wrote_them() {
    // A pool that never connects: registering reads nothing, and the page reads the snapshot, NaN before a tick.
    let settings = vectispire_cp_db::settings::DbSettings {
        url: vectispire_cp_db::settings::DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: Secret::new(""),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = vectispire_cp_db::Db::connect_lazy(&settings).unwrap();
    let audit = Arc::new(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(SystemClock), Vec::new()));
    let queue = Arc::new(vectispire_cp_scanning::ScanQueue::new(
        db.clone(),
        Arc::new(vectispire_cp_scanning::ports::AgentsStandIn),
        vectispire_domain::scan_queue::Policy::default(),
        Arc::new(vectispire_cp_targets::SystemClock),
    ));
    let outbox = Arc::new(vectispire_cp_outbox::Outbox::on_database(
        db.clone(),
        vectispire_cp_outbox::Registry::new(Vec::new(), Vec::new()),
        Arc::new(vectispire_cp_maintenance::SystemClock),
    ));
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: vectispire_cp_scanning::target_scans(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins(),
        encryption: encryption(),
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        visibility: None,
    }));
    let credentials = Arc::new(vectispire_cp_access::credentials::CredentialService::new(
        db.clone(),
        Arc::new(vectispire_cp_access::credentials::SystemClock),
        vectispire_cp_access::credentials::SessionPolicy::default(),
        Arc::new(vectispire_cp_agents::AgentDirectoryImpl::new(db.clone())),
        vectispire_cp_access::credentials::ScimToken::default(),
    ));
    let admin = Arc::new(vectispire_cp_agents::AgentAdministrationService::new(
        db.clone(),
        credentials,
        Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(vectispire_cp_targets::SystemClock))),
        targets,
        audit,
        Vec::new(),
        false,
    ));
    let metrics = Metrics::new("vectispire");
    vectispire_cp_app::gauges::Gauges::new(queue, outbox, admin).register(&metrics);

    let page = metrics.prometheus();
    let valued: String = page
        .lines()
        .map(|line| match line.rsplit_once(' ') {
            Some((series, _)) if !line.starts_with('#') => format!("{series} V\n"),
            _ => format!("{line}\n"),
        })
        .collect();
    assert_eq!(valued, JAVA_GAUGE_LINES);
    assert!(page.lines().filter(|line| !line.starts_with('#')).all(|line| line.ends_with(" NaN")), "{page}");
}
