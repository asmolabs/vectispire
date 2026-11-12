//! **The queue's and the agents' gauges, read by their tasks on a real database** — the composition exercised, since
//! a gauge whose task runs nothing reads NaN forever and passes every unit test (`AGENTS.md`, "a wiring that is not
//! exercised is not wired"). One waiting repository scan, an hour old: the repository gauge counts it and ages it,
//! the container gauge does not, and every figure is NaN before the first tick.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_app::gauges::Gauges;
use vectispire_cp_db::testing::TestDatabase;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_runtime::metrics::Metrics;

#[tokio::test(flavor = "multi_thread")]
async fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    run(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn on_postgresql() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    run(Engine::PostgreSql).await;
}

/// The `VALUE` of `name` under `tags`, as `/actuator/metrics/{name}?tag=…` reports it.
fn value(metrics: &Metrics, name: &str, tags: &[(&str, &str)]) -> f64 {
    let filters: Vec<(String, String)> = tags.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect();
    let document = metrics.metric_document(name, &filters).unwrap_or_else(|| panic!("{name} is not registered"));
    // `"measurements":[{"statistic":"VALUE","value":…}]`: the first value, NaN written as Micrometer writes it.
    let after = document.split(r#""value":"#).nth(1).unwrap_or_else(|| panic!("{document}"));
    let number: String = after.chars().take_while(|c| !matches!(c, ',' | '}')).collect();
    // `null` is how cp-runtime's JSON writes a non-finite number (`json::double`): here, "not measured yet".
    if number == "null" {
        return f64::NAN;
    }
    number.trim_matches('"').parse().unwrap_or_else(|_| panic!("{document}"))
}

fn admin(db: &Db) -> Arc<vectispire_cp_agents::AgentAdministrationService> {
    use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
    use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    let encryption = Arc::new(Encryption::new(&EncryptionConfig::default(), door).unwrap());
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: vectispire_cp_scanning::target_scans(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)),
        backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
        purge: vectispire_cp_targets::PurgeRegistry::stand_ins().with(vectispire_cp_scanning::purge::listeners()),
        encryption,
        allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        visibility: None,
    }));
    let catalog =
        Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), Arc::new(vectispire_cp_targets::SystemClock)));
    let credentials = Arc::new(vectispire_cp_access::credentials::CredentialService::new(
        db.clone(),
        Arc::new(vectispire_cp_access::credentials::SystemClock),
        vectispire_cp_access::credentials::SessionPolicy::default(),
        Arc::new(vectispire_cp_agents::AgentDirectoryImpl::new(db.clone())),
        vectispire_cp_access::credentials::ScimToken::default(),
    ));
    Arc::new(vectispire_cp_agents::AgentAdministrationService::new(
        db.clone(),
        credentials,
        catalog,
        targets,
        audit,
        Vec::new(),
        false,
    ))
}

async fn run(engine: Engine) {
    let server = TestDatabase::start(engine).await;
    let db = server.connect().await;
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
    let gauges = Gauges::new(queue, outbox, admin(&db));
    let metrics = Metrics::new("vectispire");
    gauges.register(&metrics);

    // Before the first tick, every figure is "not measured yet" — never a zero that hides it.
    assert!(value(&metrics, "vectispire.scans.queued", &[("kind", "repository")]).is_nan());
    assert!(value(&metrics, "vectispire.agents.enabled", &[]).is_nan());

    server.sql_as_admin("insert into t_repository (id, url, branch) values (1, 'https://example.org/a.git', 'main')");
    let hour_ago = match engine {
        Engine::MySql => "utc_timestamp(6) - interval 1 hour",
        Engine::PostgreSql => "(now() at time zone 'utc') - interval '1 hour'",
    };
    server.sql_as_admin(&format!(
        "insert into t_scan (id, branch, status, created_at, repo_id) values (1, 'main', 'pending', {hour_ago}, 1)"
    ));

    for task in gauges.tasks() {
        task.run().await.unwrap_or_else(|error| panic!("{:?}: {error}", task.sequence()));
    }

    assert!((value(&metrics, "vectispire.scans.queued", &[("kind", "repository")]) - 1.0).abs() < f64::EPSILON);
    assert!((value(&metrics, "vectispire.scans.queued", &[("kind", "container")]) - 0.0).abs() < f64::EPSILON);
    let oldest = value(&metrics, "vectispire.scans.queued.oldest.age", &[("kind", "repository")]);
    assert!((3_590.0..3_700.0).contains(&oldest), "the waiting scan is an hour old: {oldest}");
    assert!(
        (value(&metrics, "vectispire.scans.queued.oldest.age", &[("kind", "container")]) - 0.0).abs() < f64::EPSILON
    );
    assert!((value(&metrics, "vectispire.scans.running", &[]) - 0.0).abs() < f64::EPSILON);
    assert!((value(&metrics, "vectispire.outbox.pending", &[]) - 0.0).abs() < f64::EPSILON);
    assert!((value(&metrics, "vectispire.agents.enabled", &[]) - 0.0).abs() < f64::EPSILON);
    assert!((value(&metrics, "vectispire.agents.online", &[]) - 0.0).abs() < f64::EPSILON);
    assert!((value(&metrics, "vectispire.agents.last.seen.age", &[]) - 0.0).abs() < f64::EPSILON);
    for source in ["scans", "agents"] {
        let age = value(&metrics, "vectispire.metrics.snapshot.age", &[("source", source)]);
        assert!((0.0..60.0).contains(&age), "{source}'s snapshot was just taken: {age}");
    }
    // The time gauges say their unit, as Micrometer's TimeGauge does.
    let document = metrics.metric_document("vectispire.scans.queued.oldest.age", &[]).unwrap();
    assert!(document.contains(r#""baseUnit":"seconds""#), "{document}");
}
