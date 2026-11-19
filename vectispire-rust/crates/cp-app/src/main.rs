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
    /// The forges' discoveries: on every instance, whatever the built-in scan worker's switch (decision 0037 §3).
    discoveries: vectispire_cp_forges::DiscoveryWorker,
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

        // 2b. The forges' discoveries: twenty seconds after the start, then every five, as Java's schedule says.
        let discovery_stop = shutdown.clone();
        let discoveries = self.discoveries.clone();
        let discovery_handle = tokio::spawn(async move {
            let mut stop = discovery_stop;
            let mut wait = Duration::from_secs(20);
            loop {
                tokio::select! {
                    () = stop.triggered() => break,
                    () = tokio::time::sleep(wait) => {
                        discoveries.tick().await;
                        wait = Duration::from_secs(5);
                    }
                }
            }
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
        let _ = discovery_handle.await;
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

    let allowed_hosts = match vectispire_cp_app::clone_hosts::allowlist(&settings.git_allowed_hosts, &guard) {
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
    // As `SigningKeyService`'s constructor, but **needing no database**: the configured key checked and a revoked one
    // refused now; the record of published keys re-sealed, the vouched-for keys adopted and a revoked stored key
    // refused before the first key is used (`SigningKeys::start_lazily` says why). This binary starts without a
    // database, and one that does not answer must not hold the start or the stop.
    let signing = match vectispire_cp_crypto::SigningKeys::start_lazily(
        vectispire_cp_crypto::SigningConfig {
            key: configured_signing_key,
            revoked_keys: &settings.signing_revoked_keys,
            adopted_keys: &settings.signing_adopted_keys,
        },
        vectispire_cp_settings::Settings::new(db.clone()),
        encryption.clone(),
        vectispire_cp_crypto::Clock::system(),
    ) {
        Ok(signing) => Arc::new(signing),
        Err(error) => {
            tracing::error!("The document signing key is refused: {error}");
            return ExitCode::FAILURE;
        }
    };

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
            trust: trust.clone(),
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

    // The notifications (wave 2): the channels go into the outbox's registry, and the routing of a scan's delta into the
    // issues' backlog once the outbox exists. The door out is the start's guard over the runtime's trust.
    let (notifications_config, notification_channels) =
        vectispire_cp_app::notifications::compose(vectispire_cp_app::notifications::NotificationParts {
            db: db.clone(),
            encryption: encryption.clone(),
            post: vectispire_cp_outbound::OutboundPost::new(
                guard.clone(),
                vectispire_cp_outbound::PinnedHttpSender::new(trust.clone()),
            ),
            public_url: settings.exports.public_url.clone(),
            mail_host_named: settings.mail.is_some(),
            clock: Arc::new(vectispire_cp_audit::SystemClock),
        });

    // The checklists' `checklist_answer` handler, registered now and handed its service once the module is composed.
    let (checklist_delivery, checklist_slot) = vectispire_cp_app::checklists::answer_delivery();
    let outbox = Arc::new(vectispire_cp_outbox::Outbox::on_database(
        db.clone(),
        vectispire_cp_app::maintenance::outbox_registry(
            audit.clone(),
            &siem,
            checklist_delivery,
            &notification_channels,
        ),
        Arc::new(vectispire_cp_maintenance::SystemClock),
    ));
    // The tickets (wave 2): its token's alerts are told through the notifications, in the outbox.
    let tickets = vectispire_cp_app::tickets::compose(vectispire_cp_app::tickets::TicketParts {
        db: db.clone(),
        encryption: encryption.clone(),
        post: vectispire_cp_outbound::OutboundPost::new(
            guard.clone(),
            vectispire_cp_outbound::PinnedHttpSender::new(trust.clone()),
        ),
        audit: audit.clone(),
        alerts: vectispire_cp_app::notifications::token_alerts(
            &notifications_config,
            &notification_channels,
            outbox.clone(),
        ),
        clock: Arc::new(vectispire_cp_audit::SystemClock),
    });
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
        .with(vectispire_cp_gate::purge::listeners())
        .with(vectispire_cp_compliance::purge::listeners())
        .with(vectispire_cp_forges::purge::listeners())
        .with(vec![Arc::new(vectispire_cp_tickets::TicketLinkPurge)])
        .with_projects(vec![Arc::new(vectispire_cp_checklists::ChecklistPurge)]);
    let targets = Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
        db: db.clone(),
        audit: audit.clone(),
        scans: target_scans,
        backlog: Arc::new(vectispire_cp_issues::TargetBacklogFigures::new(db.clone())),
        purge,
        encryption: encryption.clone(),
        allowed_hosts: allowed_hosts.clone(),
        clock: clock.clone(),
        // The import's preview says who will see the new targets (decision 0037 §4): the visibility mode, read here.
        visibility: Some(vectispire_cp_access::VisibilityService::new(
            db.clone(),
            Arc::new(SettingsForAccess(vectispire_cp_settings::Settings::new(db.clone()))),
            Arc::new(vectispire_cp_targets::TargetsForAccess(db.clone())),
        )),
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
        match vectispire_cp_scanning::BuiltInScanRunner::new(
            rule_sets.clone(),
            vectispire_cp_app::worker::images(&settings.scanning),
            places,
            settings.scanning.vulnerability_db_dir.as_ref().map(std::path::PathBuf::from),
            // The runtime's trust, as the JVM's store is Java's: a forge behind a private authority is cloned over
            // HTTPS with the bundle the operator gave, and a public authority they removed is not trusted again.
            trust.clone(),
            vectispire_cp_app::worker::options(&settings.scanning),
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

    let issues = Arc::new(
        vectispire_cp_issues::Issues::new(vectispire_cp_issues::IssuesConfig {
            db: db.clone(),
            targets: targets.clone(),
            scans: (*scan_catalog).clone(),
            settings: Arc::new(vectispire_cp_settings::Settings::new(db.clone())),
            audit: audit.clone(),
            events: siem.security_events(),
        })
        // A scan's delta queued for the channels in the scan's transaction (`ScanDeltaNotifier`).
        // A reference attached by hand is the configured tracker's to judge.
        .with_ticket_references(tickets.references())
        .with_scan_deltas(vectispire_cp_app::notifications::scan_deltas(
            &notifications_config,
            &notification_channels,
            outbox.clone(),
            targets.clone(),
        )),
    );

    let policy = vectispire_domain::scan_queue::Policy {
        lease: settings.queue.lease,
        retry_delays: settings.queue.retry_delays.clone(),
        ..Default::default()
    };
    let leader_lease = settings.leader_lease.max(Duration::from_secs(1));
    let ingestor = Arc::new(vectispire_cp_app::ingestion::ingestor(
        issues.backlog().clone(),
        inventory.sink(),
        vectispire_cp_app::ingestion::IngestionSources {
            db: db.clone(),
            settings: vectispire_cp_settings::Settings::new(db.clone()),
            clock: clock.clone(),
            guard: guard.clone(),
            trust: trust.clone(),
        },
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
        // The checklists' `RepositoryScanned`: a `checklist_answer` message queued in the scan's transaction.
        scanned: vec![Arc::new(vectispire_cp_checklists::AnswersFromEvidence {
            outbox: outbox.clone(),
            settings: Arc::new(vectispire_cp_settings::Settings::new(db.clone())),
        })],
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

    // `vectispire.sign-in.*` in force: the derivation bound for the process, before the first request; the ceilings
    // and the known clients' retention for the sign-in and the session cleanup.
    let access = vectispire_cp_app::access::compose(&settings.sign_in, creds.clone(), db.clone(), access_clock.clone());

    let built_in =
        vectispire_cp_app::worker::BuiltInWorker::of(&settings.worker, scanning.dispatcher().runs_scans_here());
    let admin = Arc::new(
        vectispire_cp_agents::AgentAdministrationService::new(
            db.clone(),
            creds.clone(),
            Arc::new(scanning.catalog().clone()),
            targets.clone(),
            audit.clone(),
            built_in.labels,
            built_in.runs,
        )
        .with_built_in_worker(settings.worker.enabled, scanning.dispatcher_arc()),
    );

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

    // The figures of risk. The weekly report goes through the notifications module's webhook and mail.
    let posture = Arc::new(vectispire_cp_posture::PostureModule::new(vectispire_cp_posture::PostureConfig {
        db: db.clone(),
        gate: gate.gate.clone(),
        issues: issues.catalog().clone(),
        sla: issues.sla().clone(),
        scans: scan_catalog.clone(),
        targets: targets.clone(),
        licences: inventory.licenses().clone(),
        apis: inventory.apis().clone(),
        settings: Arc::new(vectispire_cp_settings::Settings::new(db.clone())),
        audit: audit.clone(),
        // Counts the digest's own entries only: it verifies no chain, so it tells no listener of a break.
        audit_log: Arc::new(vectispire_cp_audit::AuditLogQuery::new(
            (*audit).clone(),
            Arc::new(vectispire_cp_audit::SystemClock),
            Vec::new(),
        )),
        channels: Arc::new(vectispire_cp_posture::ChannelsDigest {
            config: notifications_config.clone(),
            channels: notification_channels.clone(),
        }),
        clock: clock.clone(),
    }));

    // Compliance: the matrix over the gate's posture, the issues' counts and the deployment's own controls, read
    // through the two ports the binary answers (`compliance.rs`).
    let compliance_service = vectispire_cp_compliance::matrix::ComplianceService::new(
        gate.gate.clone(),
        issues.catalog().clone(),
        issues.sla().clone(),
        vectispire_cp_settings::Settings::new(db.clone()),
        Arc::new(vectispire_cp_app::compliance::PlatformFacts {
            encryption: encryption.clone(),
            audit: audit.clone(),
            settings: vectispire_cp_settings::Settings::new(db.clone()),
            sign_in: vectispire_cp_access::sign_in::SignInMethodPolicy::new(
                settings.oidc.provider.is_some(),
                settings.oidc.password_login,
            ),
            accounts: vectispire_cp_access::SqlSignInStore::new(db.clone()),
        }),
        Arc::new(vectispire_cp_app::compliance::InventoryFacts(inventory.query().clone())),
        clock.clone(),
    );
    let compliance = Arc::new(vectispire_cp_compliance::Services::new(
        compliance_service.clone(),
        vectispire_cp_compliance::scope::ScopeComplianceService::new(
            targets.clone(),
            compliance_service,
            posture.scorecards.clone(),
        ),
        db.clone(),
        targets.clone(),
        scan_catalog.clone(),
        issues.catalog().clone(),
        issues.queries().clone(),
        rules_module.coverage.clone(),
        vectispire_cp_settings::Settings::new(db.clone()),
        audit.clone(),
        clock.clone(),
    ));

    // The checklists (wave 1): before the maintenance turns, which run their weekly reminder.
    let checklists = vectispire_cp_app::checklists::compose(vectispire_cp_app::checklists::ChecklistParts {
        db: db.clone(),
        targets: targets.clone(),
        scans: (*scan_catalog).clone(),
        issues: (**issues.catalog()).clone(),
        audit: audit.clone(),
        trail: Arc::new(vectispire_cp_audit::AuditLogQuery::new(
            (*audit).clone(),
            Arc::new(vectispire_cp_audit::SystemClock),
            vectispire_cp_app::siem::chain_broken_listeners(&siem),
        )),
        signing: signing.clone(),
        visibility: vectispire_cp_access::VisibilityService::new(
            db.clone(),
            Arc::new(SettingsForAccess(vectispire_cp_settings::Settings::new(db.clone()))),
            Arc::new(vectispire_cp_targets::TargetsForAccess(db.clone())),
        ),
        clock: clock.clone(),
        product_version: vectispire_cp_settings::about::product_version(
            settings.exports.tool_version.as_deref(),
            Some(env!("CARGO_PKG_VERSION")),
        ),
        max_workbook_bytes: i64::try_from(settings.max_body.checklist_template_import).unwrap_or(i64::MAX),
        max_file_bytes: i64::try_from(settings.max_body.checklist_evidence).unwrap_or(i64::MAX),
        mail: notification_channels.mail.clone(),
    });
    if checklist_slot.set(checklists.checklists.clone()).is_err() {
        tracing::error!("The checklists' answer delivery was handed its service twice.");
    }

    // The forges (wave 2): their routes, their discoveries' worker, their two maintenance tasks.
    let forges = vectispire_cp_app::forges::compose(vectispire_cp_app::forges::ForgeSetup {
        db: db.clone(),
        guard: guard.clone(),
        trust: trust.clone(),
        encryption: encryption.clone(),
        audit: audit.clone(),
        clock: clock.clone(),
        targets: targets.clone(),
    });

    // Threat intelligence (wave 2): its routes, and its two hourly synchronisations.
    let threatintel = vectispire_cp_app::threatintel::compose(vectispire_cp_app::threatintel::ThreatIntelSetup {
        db: db.clone(),
        guard: guard.clone(),
        trust: trust.clone(),
        locations: vectispire_cp_app::threatintel::locations(&settings.threat_intel),
        issues: issues.catalog().clone(),
        targets: targets.clone(),
        clock: clock.clone(),
        events: siem.security_events(),
        audit: audit.clone(),
    });

    let gauges = vectispire_cp_app::gauges::Gauges::new(scanning.queue().clone(), outbox.clone(), agents.admin.clone());
    let turns = match vectispire_cp_app::maintenance::turns(
        outbox.clone(),
        targets.clone(),
        scanning.clone(),
        agents.clone(),
        inventory.clone(),
        issues.clone(),
        gate.clone(),
        posture.clone(),
        compliance.clone(),
        vectispire_cp_settings::Settings::new(db.clone()),
        clock.clone(),
        access.session_cleanup.clone(),
        checklists.reminders.clone(),
        forges.services.tasks().into_iter().chain(threatintel.tasks()).collect(),
        &tickets,
        &gauges,
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

    // One reader of the trail, for the audit-log routes and the withheld-claim repair: a break it finds is told to the
    // SIEM as Java's `AuditChainBroken` event is.
    let trail = Arc::new(vectispire_cp_audit::AuditLogQuery::new(
        (*audit).clone(),
        Arc::new(vectispire_cp_audit::SystemClock),
        vectispire_cp_app::siem::chain_broken_listeners(&siem),
    ));

    // The actuator, before the router that mounts it: the pages are the runtime's, the census the modules'. Nothing of
    // either reads the database before a request does.
    let build = BuildInfo {
        group: "vectispire".to_owned(),
        artifact: "vectispire-core".to_owned(),
        name: "vectispire-core".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        time: None,
    };
    let app = App::new(settings.clone(), "vectispire", build);
    let census = vectispire_cp_app::actuator::encryption_census(
        signing.clone(),
        targets.clone(),
        siem_service.clone(),
        forges.services.connections.clone(),
        notification_channels.service.clone(),
        tickets.service.clone(),
    );
    app.actuator.serve_encryption(Arc::new(vectispire_cp_app::actuator::Census(census.clone())));

    let access_settings = Arc::new(SettingsForAccess(vectispire_cp_settings::Settings::new(db.clone())));
    let visibility = vectispire_cp_access::VisibilityService::new(
        db.clone(),
        access_settings,
        Arc::new(vectispire_cp_targets::TargetsForAccess(db.clone())),
    );
    let access_routes =
        vectispire_cp_app::access::administration_routes(vectispire_cp_app::access::AdministrationParts {
            db: db.clone(),
            audit: audit.clone(),
            credentials: creds.clone(),
            clock: access_clock.clone(),
            guard: guard.clone(),
            visibility: visibility.clone(),
            targets: Arc::new(vectispire_cp_targets::TargetsForAccess(db.clone())),
        });
    let mut access_routes = access_routes;
    access_routes.extend(vectispire_cp_app::access::sign_in_routes(vectispire_cp_app::access::SignInRoutesParts {
        db: db.clone(),
        audit: audit.clone(),
        credentials: creds.clone(),
        clock: access_clock.clone(),
        encryption: encryption.clone(),
        provider: settings.oidc.provider.as_ref().map(|provider| provider.name.clone()),
        password_login: settings.oidc.password_login,
        branding: vectispire_cp_access::Branding::of(
            Some(&settings.branding.name),
            Some(&settings.branding.gitlab_url),
        ),
        limits: access.limits,
    }));
    access_routes.extend(vectispire_cp_app::access::scim_routes(
        db.clone(),
        audit.clone(),
        access_clock.clone(),
        settings.oidc.link_privileged_accounts,
    ));
    access_routes.extend(checklists.routes);
    access_routes.extend(forges.routes);
    // Threat intelligence (wave 2): the feeds' status, the ranking, a CVE's record and the two syncs.
    access_routes.extend(vectispire_cp_threatintel::routes(threatintel.clone()));
    // The AI advisor (wave 2): the configured model, through the guard, or the product's own advice.
    access_routes.extend(vectispire_cp_ai::routes(Arc::new(vectispire_cp_ai::Services::new(
        vectispire_cp_ai::AiParts {
            settings: vectispire_cp_settings::Settings::new(db.clone()),
            integrations: Arc::new(vectispire_cp_app::registry::integrations(&db)),
            post: vectispire_cp_outbound::OutboundPost::new(
                guard.clone(),
                vectispire_cp_outbound::PinnedHttpSender::new(trust.clone()),
            ),
            encryption: encryption.clone(),
            issues: issues.catalog().clone(),
            feeds: vectispire_cp_threatintel::feeds::ThreatIntel::new(db.clone(), clock.clone()),
        },
    ))));
    access_routes.extend(vectispire_cp_app::notifications::routes(&notifications_config, &notification_channels));
    access_routes.extend(tickets.routes());
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
        posture.clone(),
        siem_service,
        vectispire_cp_app::registry::Platform {
            trail: trail.clone(),
            signing,
            integrations: vectispire_cp_app::registry::integration_administration(&db, (*audit).clone()),
            settings: vectispire_cp_app::settings_screen::compose(
                &db,
                (*audit).clone(),
                guard.clone(),
                Arc::new(vectispire_cp_app::tickets::TrackerCa(tickets.clone())),
                Arc::new(vectispire_cp_audit::SystemClock),
            ),
        },
        compliance.clone(),
        access_routes,
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
    let chain = Arc::new(
        vectispire_cp_http::Chain::new(chain_config, creds, chain_audit)
            .with_shared_webhook_window(vectispire_cp_access::rate_windows::shared_webhook_window(
                vectispire_cp_access::SqlSignInStore::new(db.clone()),
                access_clock.clone(),
            ))
            // `/actuator/prometheus` alone takes it: a Prometheus server holds no session.
            .with_scrape_token(Arc::new(vectispire_cp_app::actuator::ScrapeTokenOf(settings.metrics.clone()))),
    );
    let routes = routes.actuator(Arc::new(vectispire_cp_app::actuator::Pages(app.actuator.clone())));
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
        trail,
        audit.clone(),
        Arc::new(vectispire_cp_maintenance::OneShotJobs::new(
            db.clone(),
            Arc::new(vectispire_cp_maintenance::SystemClock),
        )),
    ));
    for job in vectispire_cp_app::startup::ready_jobs(targets.clone(), repair, census) {
        tokio::spawn(job.run());
    }

    let service = ControlPlaneService {
        router,
        port: settings.server_port,
        turns,
        intervals,
        worker,
        worker_interval: settings.worker.interval,
        discoveries: forges.services.worker.clone(),
        scanning: scanning.clone(),
    };

    // Before the first scheduling turn has run: each gauge reads NaN until its snapshot is taken.
    gauges.register(&app.metrics);
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
