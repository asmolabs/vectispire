//! The control plane binary: configuration parsing, modular composition, HTTP stack, and graceful shutdown.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_outbound::guard::OutboundUrlGuard;
use vectispire_cp_outbound::reserved;
use vectispire_cp_runtime::actuator::BuildInfo;
use vectispire_cp_runtime::settings::{ReportLine, Settings};
use vectispire_cp_runtime::shutdown::ShutdownSignal;
use vectispire_cp_runtime::telemetry::{self, LogFormat};
use vectispire_cp_runtime::{App, Service};

const USAGE: &str = "Usage: vectispire-control-plane [--check-config | --version | --help]

  (no argument)   serve the control plane
  --check-config  read the configuration, refuse what the Java control plane refuses, print every
                  setting and where its value came from (a secret as (set) or (not set)), and exit
  --version       print the version
";

/// Everything a start refuses on, read once — what `OutboundGuardConfiguration` and the property binding
/// refuse on in the Java control plane, before any request is served.
fn start_checks() -> Result<(Settings, Vec<ReportLine>, OutboundUrlGuard), String> {
    let (settings, report) = Settings::from_process().map_err(|error| error.to_string())?;
    let environment = &settings.environment;
    let mut reserved_endpoints = Vec::new();
    for reading in [
        reserved::of_docker_host(environment.docker_host.as_deref()),
        reserved::of_datasource(Some(&settings.datasource.url)),
        reserved::of_kubernetes_service(
            environment.kubernetes_service_host.as_deref(),
            environment.kubernetes_service_port.as_deref(),
        ),
    ] {
        reserved_endpoints.extend(reading.map_err(|error| error.to_string())?);
    }
    Ok((settings, report, OutboundUrlGuard::new(reserved_endpoints)))
}

/// Connects `cp-settings` to `cp-access`'s `AccessSettings` port for `target_visibility`.
struct SettingsForAccess(vectispire_cp_settings::Settings);

impl vectispire_cp_access::AccessSettings for SettingsForAccess {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, vectispire_cp_access::AccessError>> {
        Box::pin(async move {
            self.0
                .get(vectispire_cp_settings::Setting::TargetVisibility)
                .await
                .map_err(|error| vectispire_cp_access::AccessError::Port(error.to_string()))
        })
    }
}

/// Connects `cp-inventory` to `cp-rules`'s `InventoryEcosystems` port.
struct InventoryForRules(Arc<vectispire_cp_inventory::Inventory>);

impl vectispire_cp_rules::InventoryEcosystems for InventoryForRules {
    fn distinct_purls(&self) -> BoxFuture<'_, Result<Vec<String>, vectispire_cp_rules::ports::PortError>> {
        Box::pin(async move {
            self.0.distinct_purls().await.map_err(|error| Box::new(error) as vectispire_cp_rules::ports::PortError)
        })
    }

    fn distinct_purls_by_target(
        &self,
    ) -> BoxFuture<'_, Result<Vec<vectispire_cp_rules::ports::TargetPurl>, vectispire_cp_rules::ports::PortError>> {
        Box::pin(async move {
            self.0
                .distinct_purls_by_target()
                .await
                .map_err(|error| Box::new(error) as vectispire_cp_rules::ports::PortError)
        })
    }
}

/// How long the stop waits to hand the scheduler's lease back: a fraction of the 30-second grace period.
const LEASE_RELEASE: Duration = Duration::from_secs(5);

/// The composed control plane service running HTTP routing, background maintenance, and the worker.
struct ControlPlaneService {
    router: axum::Router,
    port: u16,
    turns: vectispire_cp_maintenance::Turns,
    intervals: vectispire_cp_maintenance::Intervals,
    worker: Option<vectispire_cp_scanning::ScanWorker>,
    worker_interval: Duration,
    scanning: Arc<vectispire_cp_scanning::Scanning>,
}

impl Service for ControlPlaneService {
    async fn serve(self, shutdown: ShutdownSignal) -> Result<(), String> {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(error) => {
                return Err(format!("Could not bind to {addr}: {error}"));
            }
        };

        // 1. Periodic maintenance turns in the background
        let turns_stop = shutdown.clone();
        let turns_handle = tokio::spawn(async move {
            self.turns
                .run_until(self.intervals, async move {
                    let mut stop = turns_stop;
                    stop.triggered().await;
                })
                .await;
        });

        // 2. Built-in scan worker loop in the background (if enabled)
        let worker_stop = shutdown.clone();
        let worker_handle = self.worker.map(|worker| {
            tokio::spawn(async move {
                let mut stop = worker_stop;
                loop {
                    tokio::select! {
                        () = stop.triggered() => break,
                        () = tokio::time::sleep(self.worker_interval) => {
                            worker.tick();
                        }
                    }
                }
            })
        });

        // 3. Axum HTTP server with graceful shutdown on signal
        let server_shutdown = shutdown.clone();
        let server = axum::serve(listener, self.router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .with_graceful_shutdown(async move {
                let mut stop = server_shutdown;
                stop.triggered().await;
            });

        if let Err(error) = server.await {
            tracing::error!("HTTP server ended with error: {error}");
        }

        // Wait for background loops to stop cleanly
        let _ = turns_handle.await;
        if let Some(wh) = worker_handle {
            let _ = wh.await;
        }

        // The scheduler's lease, released for the next instance — a courtesy bounded well inside the grace period. It
        // waited on the pool's 30-second acquire timeout, the whole grace, so a database that accepts connections and
        // never answers had the process abandoned (exit 1) instead of stopped. Unreleased, the lease lapses by itself.
        match tokio::time::timeout(LEASE_RELEASE, self.scanning.election().release_scheduler()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!("Could not release scheduler lease on shutdown: {error}"),
            Err(_) => tracing::warn!(
                "Could not release scheduler lease on shutdown within {} s: it lapses by itself",
                LEASE_RELEASE.as_secs()
            ),
        }

        Ok(())
    }
}

/// What the command line says on stdout. A closed pipe (`| head`) is not a failure of the command, so the
/// write's result is dropped on purpose; the print macros are denied workspace-wide (`Cargo.toml`) and a
/// binary that answers a flag is the one place that needs a way to speak.
fn out(text: &str) {
    drop(std::io::stdout().lock().write_all(text.as_bytes()));
}

/// The same on stderr, for what a refused start says before the logs exist.
fn err(text: &str) {
    drop(std::io::stderr().lock().write_all(text.as_bytes()));
}

#[tokio::main]
async fn main() -> ExitCode {
    let argument = std::env::args().nth(1);
    match argument.as_deref() {
        Some("--version") => {
            out(&format!("vectispire-control-plane {}\n", env!("CARGO_PKG_VERSION")));
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            out(USAGE);
            ExitCode::SUCCESS
        }
        Some("--check-config") => match start_checks() {
            Ok((_, report, _)) => {
                for line in report {
                    out(&format!("{} = {}  [{}]\n", line.key, line.shown, line.origin));
                }
                ExitCode::SUCCESS
            }
            Err(problem) => {
                err(&format!("{problem}\n"));
                ExitCode::FAILURE
            }
        },
        None => serve().await,
        Some(other) => {
            err(&format!("Unknown argument {other:?}\n\n{USAGE}\n"));
            ExitCode::from(2)
        }
    }
}

async fn serve() -> ExitCode {
    let format = match LogFormat::from_variable(std::env::var("VECTISPIRE_LOG_FORMAT").ok().as_deref()) {
        Ok(format) => format,
        Err(problem) => {
            err(&format!("{problem}\n"));
            return ExitCode::FAILURE;
        }
    };
    if let Err(problem) = telemetry::init(format, "vectispire") {
        err(&format!("The logs could not be set up: {problem}\n"));
        return ExitCode::FAILURE;
    }
    let (settings, _, guard) = match start_checks() {
        Ok(checked) => checked,
        Err(problem) => {
            tracing::error!("{problem}");
            return ExitCode::FAILURE;
        }
    };

    let allowed_hosts =
        match vectispire_domain::git_host_allowlist::GitHostAllowlist::parse(Some(&settings.git_allowed_hosts)) {
            Ok(hosts) => hosts,
            Err(error) => {
                tracing::error!("vectispire.git.allowed-hosts is malformed: {error}");
                return ExitCode::FAILURE;
            }
        };

    let door = vectispire_cp_crypto::VaultDoor {
        sender: vectispire_cp_outbound::PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: guard.clone(),
    };
    let enc_config = vectispire_cp_crypto::EncryptionConfig {
        key: settings.encryption.key.clone(),
        previous_keys: settings.encryption.previous_keys.clone(),
        kms_type: settings.encryption.kms_type.clone(),
        vault_endpoint: settings.encryption.vault_endpoint.clone(),
        vault_token: settings.encryption.vault_token.clone(),
        vault_key_name: settings.encryption.vault_key_name.clone(),
        vault_mount_path: settings.encryption.vault_mount_path.clone(),
    };
    let encryption = match vectispire_cp_crypto::Encryption::new(&enc_config, door) {
        Ok(enc) => Arc::new(enc),
        Err(refusal) => {
            tracing::error!("{refusal}");
            return ExitCode::FAILURE;
        }
    };

    let db_url = match vectispire_cp_db::settings::DatabaseUrl::parse(&settings.datasource.url) {
        Ok(url) => url,
        Err(error) => {
            tracing::error!("The datasource URL cannot be read: {error}");
            return ExitCode::FAILURE;
        }
    };
    let db_settings = vectispire_cp_db::settings::DbSettings {
        url: db_url,
        username: settings.datasource.username.clone(),
        password: settings.datasource.password.clone(),
        pool: vectispire_cp_db::settings::PoolSettings::default(),
        ca_pem: None,
    };
    let db = match vectispire_cp_db::Db::connect_lazy(&db_settings) {
        Ok(db) => db,
        Err(error) => {
            tracing::error!("The database pool could not be set up: {error}");
            return ExitCode::FAILURE;
        }
    };

    let configured_signing_key = settings.signing_key.as_ref().map(|s| s.expose()).unwrap_or("");
    if let Err(error) = vectispire_cp_crypto::SigningKeys::new(
        configured_signing_key,
        vectispire_cp_settings::Settings::new(db.clone()),
        encryption.clone(),
    ) {
        tracing::error!("Invalid signing key: {error}");
        return ExitCode::FAILURE;
    }

    let clock: Arc<dyn vectispire_cp_targets::Clock> = Arc::new(vectispire_cp_targets::SystemClock);

    // The SIEM export, before the audit log that takes its events as a listener (`cp-app/src/siem.rs` says why the
    // order is this one). Its collectors are reached with the runtime's trust: an unreadable bundle refuses the start.
    let trust = match vectispire_tls::TlsTrust::from_environment() {
        Ok(trust) => trust,
        Err(refusal) => {
            tracing::error!("{refusal}");
            return ExitCode::FAILURE;
        }
    };
    let siem = match vectispire_cp_app::siem::compose(
        vectispire_cp_app::siem::SiemSetup {
            db: db.clone(),
            guard: guard.clone(),
            trust,
            encryption: encryption.clone(),
            version: vectispire_cp_settings::about::product_version(
                settings.exports.tool_version.as_deref(),
                Some(env!("CARGO_PKG_VERSION")),
            ),
        },
        Arc::new(vectispire_cp_audit::SystemClock),
    ) {
        Ok(siem) => siem,
        Err(refusal) => {
            tracing::error!("The SIEM export's trust could not be read: {refusal}");
            return ExitCode::FAILURE;
        }
    };

    let mirror = vectispire_cp_app::audit_mirror::FileMirror::configured(settings.audit_mirror_path.as_deref());
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(mirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        vectispire_cp_app::siem::audit_listeners(&siem),
    ));

    let outbox = Arc::new(vectispire_cp_outbox::Outbox::on_database(
        db.clone(),
        vectispire_cp_app::maintenance::outbox_registry(audit.clone(), &siem),
        Arc::new(vectispire_cp_maintenance::SystemClock),
    ));
    let siem_service = vectispire_cp_app::siem::service(
        &siem,
        db.clone(),
        encryption.clone(),
        (*audit).clone(),
        Arc::new(vectispire_cp_audit::SystemClock),
    );

    let target_scans = vectispire_cp_scanning::target_scans(db.clone(), clock.clone());
    let purge = vectispire_cp_targets::PurgeRegistry::stand_ins()
        .with(vectispire_cp_scanning::purge::listeners())
        .with(vectispire_cp_issues::purge::listeners())
        .with(vectispire_cp_inventory::listeners())
        .with(vectispire_cp_gate::purge::listeners());
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: target_scans,
        backlog: Arc::new(vectispire_cp_issues::TargetBacklogFigures::new(db.clone())),
        purge,
        encryption: encryption.clone(),
        allowed_hosts: allowed_hosts.clone(),
        clock: clock.clone(),
        visibility: None,
    }));

    let scan_catalog = Arc::new(vectispire_cp_scanning::ScanCatalog::new(db.clone(), clock.clone()));
    let inventory = Arc::new(vectispire_cp_inventory::Inventory::new(vectispire_cp_inventory::InventoryConfig {
        db: db.clone(),
        scans: scan_catalog.clone(),
        targets: targets.clone(),
        audit: audit.clone(),
    }));

    let rules_module = Arc::new(vectispire_cp_rules::RulesModule::new(
        db.clone(),
        Arc::new(InventoryForRules(inventory.clone())),
        Arc::new(vectispire_cp_rules::StandInIssues),
        audit.clone(),
    ));
    let rule_sets = rules_module.scan_rule_sets();
    let runner: Option<Arc<dyn vectispire_cp_scanning::ports::ScanRunner>> = if settings.worker.enabled {
        let places = vectispire_runner::Places::from_lookup(|k| std::env::var(k).ok());
        let images = match vectispire_cp_app::worker::images(&settings.scanning) {
            Ok(images) => images,
            Err(refusal) => {
                tracing::error!("{refusal}");
                return ExitCode::FAILURE;
            }
        };
        match vectispire_cp_scanning::BuiltInScanRunner::new(
            rule_sets.clone(),
            images,
            places,
            settings.scanning.vulnerability_db_dir.as_ref().map(std::path::PathBuf::from),
            vectispire_tls::TlsTrust::BuiltIn,
        ) {
            Ok(runner) => Some(Arc::new(runner)),
            // Refused, as a bean that fails is in Java: a worker switched on with no runner claims nothing, and every
            // scan it was meant to take would wait without a word.
            Err(error) => {
                tracing::error!("The built-in worker is switched on and its scan runner could not be built: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let issues = Arc::new(vectispire_cp_issues::Issues::new(vectispire_cp_issues::IssuesConfig {
        db: db.clone(),
        targets: targets.clone(),
        scans: (*scan_catalog).clone(),
        settings: Arc::new(vectispire_cp_settings::Settings::new(db.clone())),
        audit: audit.clone(),
        events: siem.security_events(),
    }));

    let policy = vectispire_domain::scan_queue::Policy {
        lease: settings.queue.lease,
        retry_delays: settings.queue.retry_delays.clone(),
        ..Default::default()
    };
    let leader_lease = settings.leader_lease.max(Duration::from_secs(1));
    let ingestor = Arc::new(vectispire_cp_app::ingestion::ingestor(
        issues.backlog().clone(),
        inventory.sink(),
        vectispire_cp_settings::Settings::new(db.clone()),
        clock.clone(),
    ));
    let scanning = Arc::new(vectispire_cp_scanning::Scanning::new(vectispire_cp_scanning::ScanningConfig {
        db: db.clone(),
        clock: clock.clone(),
        targets: targets.clone(),
        encryption: encryption.clone(),
        audit: audit.clone(),
        claim_lock: Arc::new(vectispire_cp_agents::AgentRowLock),
        rule_sets: rule_sets.clone(),
        plugins: Arc::new(vectispire_cp_scanning::ports::NoPlugins),
        ingestor,
        policy,
        leader_lease,
        allowed_hosts: allowed_hosts.clone(),
        image_platform: settings.scanning.image_platform.clone(),
        runner,
        scanned: Vec::new(),
    }));

    // The access module's clock: the credentials, the session cleanup and the shared rate windows read it.
    let access_clock: vectispire_cp_access::throttle::SharedClock =
        Arc::new(vectispire_cp_access::credentials::SystemClock);
    let creds = Arc::new(vectispire_cp_access::credentials::CredentialService::new(
        db.clone(),
        access_clock.clone(),
        vectispire_cp_access::credentials::SessionPolicy {
            idle_lifetime: time::Duration::try_from(settings.session.idle_lifetime).unwrap_or(time::Duration::MAX),
            absolute_lifetime: time::Duration::try_from(settings.session.absolute_lifetime)
                .unwrap_or(time::Duration::MAX),
        },
        Arc::new(vectispire_cp_agents::AgentDirectoryImpl::new(db.clone())),
        vectispire_cp_access::credentials::ScimToken {
            enabled: settings.scim.enabled,
            token: settings.scim.token.clone(),
        },
    ));

    let built_in =
        vectispire_cp_app::worker::BuiltInWorker::of(&settings.worker, scanning.dispatcher().runs_scans_here());
    let admin = Arc::new(vectispire_cp_agents::AgentAdministrationService::new(
        db.clone(),
        creds.clone(),
        Arc::new(scanning.catalog().clone()),
        targets.clone(),
        audit.clone(),
        built_in.labels,
        built_in.runs,
    ));

    let protocol = Arc::new(vectispire_cp_agents::AgentProtocolService::new(
        db.clone(),
        scanning.dispatcher_arc(),
        audit.clone(),
        outbox.clone(),
        rule_sets.clone(),
        Arc::new(vectispire_cp_agents::NoAgentPlugins),
    ));

    let poller = Arc::new(vectispire_cp_agents::AgentJobPoller::new(scanning.dispatcher_arc(), protocol.clone()));

    let agents = Arc::new(vectispire_cp_agents::Agents::new(admin, protocol, poller));

    let gate = Arc::new(vectispire_cp_gate::GateModule::new(
        db.clone(),
        issues.catalog().clone(),
        scan_catalog.clone(),
        targets.clone(),
        rules_module.coverage.clone(),
        audit.clone(),
        clock.clone(),
        siem.security_events(),
    ));

    let turns = match vectispire_cp_app::maintenance::turns(
        outbox.clone(),
        targets.clone(),
        scanning.clone(),
        agents.clone(),
        inventory.clone(),
        issues.clone(),
        gate.clone(),
        vectispire_cp_settings::Settings::new(db.clone()),
        clock.clone(),
        vectispire_cp_access::session_cleanup::session_cleanup_task(creds.clone(), db.clone(), access_clock.clone()),
    ) {
        Ok(turns) => turns,
        Err(error) => {
            tracing::error!("The maintenance composition could not be built: {error}");
            return ExitCode::FAILURE;
        }
    };

    let intervals = vectispire_cp_maintenance::Intervals {
        relay: settings.jobs.relay_interval,
        scheduler: settings.jobs.scheduler_interval,
        maintenance: settings.jobs.maintenance_interval,
        initial_delay: Duration::from_secs(30),
    };

    let access_settings = Arc::new(SettingsForAccess(vectispire_cp_settings::Settings::new(db.clone())));
    let visibility = vectispire_cp_access::VisibilityService::new(
        db.clone(),
        access_settings,
        Arc::new(vectispire_cp_targets::TargetsForAccess(db.clone())),
    );
    let mut routes = vectispire_cp_http::routes::Routes::new(vectispire_cp_access::CallerVisibility::new(
        visibility,
        Arc::new(vectispire_cp_access::PrincipalGrounds),
    ));
    for entry in vectispire_cp_app::registry::entries(
        targets.clone(),
        scanning.clone(),
        agents.clone(),
        rules_module.clone(),
        inventory.clone(),
        issues.clone(),
        gate.clone(),
        siem_service,
    ) {
        routes = routes.route(entry);
    }

    let chain_audit = Arc::new(vectispire_cp_app::chain_entries::ChainEntries(audit.clone()));
    let trusted_proxies = match vectispire_cp_http::address::TrustedProxies::parse(&settings.security.trusted_proxies) {
        Ok(p) => p,
        Err(error) => {
            tracing::error!("vectispire.security.trusted-proxies is malformed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let chain_config = vectispire_cp_http::ChainConfig {
        trusted_proxies,
        login_attempts: u64::from(settings.security.login_attempts_per_window),
        login_window: settings.security.login_attempt_window,
        bearer_failures: u64::from(settings.security.bearer_failures_per_window),
        bearer_window: settings.security.bearer_failure_window,
        webhook_requests: u64::from(settings.security.webhook_requests_per_window),
        webhook_window: settings.security.webhook_request_window,
        api_key_requests_per_minute: u64::from(settings.security.api_key_requests_per_minute),
        anonymous_api_docs: settings.security.anonymous_api_docs,
        ..Default::default()
    };
    // The webhook's second budget, counted by every instance in `t_rate_window` (`RateWindows`): without it each
    // instance behind a load balancer kept a ceiling of its own.
    let chain = Arc::new(vectispire_cp_http::Chain::new(chain_config, creds, chain_audit).with_shared_webhook_window(
        vectispire_cp_access::rate_windows::shared_webhook_window(
            vectispire_cp_access::SqlSignInStore::new(db.clone()),
            access_clock.clone(),
        ),
    ));
    let router = match routes.build(&chain, None) {
        Ok(r) => r,
        Err(error) => {
            tracing::error!("Duplicate route registered: {error}");
            return ExitCode::FAILURE;
        }
    };

    let worker = if settings.worker.enabled {
        let worker_props = vectispire_cp_scanning::WorkerProperties {
            enabled: settings.worker.enabled,
            max_concurrent: settings.worker.max_concurrent as i32,
            labels: settings.worker.labels.clone(),
        };
        Some(vectispire_cp_scanning::ScanWorker::new(scanning.dispatcher_arc(), worker_props))
    } else {
        None
    };

    // Java's `ApplicationReadyEvent` listeners, each once, on their own: the server does not wait for them.
    let repair = Arc::new(vectispire_cp_agents::WithheldClaimRepair::new(
        db.clone(),
        scanning.catalog().clone(),
        targets.clone(),
        Arc::new(vectispire_cp_audit::AuditLogQuery::new(
            (*audit).clone(),
            Arc::new(vectispire_cp_audit::SystemClock),
            vectispire_cp_app::siem::chain_broken_listeners(&siem),
        )),
        audit.clone(),
        Arc::new(vectispire_cp_maintenance::OneShotJobs::new(
            db.clone(),
            Arc::new(vectispire_cp_maintenance::SystemClock),
        )),
    ));
    for job in vectispire_cp_app::startup::ready_jobs(targets.clone(), repair) {
        tokio::spawn(job.run());
    }

    let service = ControlPlaneService {
        router,
        port: settings.server_port,
        turns,
        intervals,
        worker,
        worker_interval: settings.worker.interval,
        scanning: scanning.clone(),
    };

    let build = BuildInfo {
        group: "vectispire".to_owned(),
        artifact: "vectispire-core".to_owned(),
        name: "vectispire-core".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        time: None,
    };
    let app = App::new(settings, "vectispire", build);
    // Before the "Started" line: a stop sent as soon as it is read must find the handlers in place.
    let stop = match vectispire_cp_runtime::shutdown::termination_handlers() {
        Ok(stop) => stop,
        Err(error) => {
            tracing::error!("The termination signals could not be installed: {error}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!("Started vectispire {} on port {}", env!("CARGO_PKG_VERSION"), app.settings.server_port);
    match app.serve_until(service, vectispire_cp_runtime::shutdown::TIMEOUT_PER_SHUTDOWN_PHASE, stop).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => {
            tracing::error!("{problem}");
            ExitCode::FAILURE
        }
    }
}
