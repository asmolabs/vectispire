//! Forges' services composed over a database nobody listens on: building the routes reads nothing.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use vectispire_cp_crypto::{Encryption, EncryptionConfig, VaultDoor};
use vectispire_cp_db::settings::{DatabaseUrl, DbSettings, PoolSettings};
use vectispire_cp_outbound::json::OutboundJson;
use vectispire_cp_outbound::{OutboundUrlGuard, PinnedHttpSender};

pub fn unreachable_db() -> vectispire_cp_db::Db {
    let settings = DbSettings {
        url: DatabaseUrl::parse("jdbc:mysql://127.0.0.1:9/none").unwrap(),
        username: "nobody".into(),
        password: vectispire_domain::secret::Secret::new(""),
        pool: PoolSettings::default(),
        ca_pem: None,
    };
    vectispire_cp_db::Db::connect_lazy(&settings).unwrap()
}

pub fn encryption() -> Arc<Encryption> {
    let config = EncryptionConfig {
        key: Some(vectispire_domain::secret::Secret::new("dGhyb3dhd2F5LWZvcmdlcy1rZXktMzItYnl0ZXMhISE=")),
        ..EncryptionConfig::default()
    };
    let door = VaultDoor {
        sender: PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
        guard: OutboundUrlGuard::new(Vec::new()),
    };
    Arc::new(Encryption::new(&config, door).expect("encryption"))
}

/// The services over `db`, the clock the system's.
pub fn services_on(db: vectispire_cp_db::Db) -> Arc<vectispire_cp_forges::Services> {
    let audit = Arc::new(vectispire_cp_audit::AuditLog::new(
        db.clone(),
        Arc::new(vectispire_cp_audit::NoMirror),
        Arc::new(vectispire_cp_audit::SystemClock),
        Vec::new(),
    ));
    Arc::new(vectispire_cp_forges::Services::new(vectispire_cp_forges::ForgeParts {
        db: db.clone(),
        outbound: OutboundJson::new(
            PinnedHttpSender::new(vectispire_tls::TlsTrust::BuiltIn),
            OutboundUrlGuard::new(Vec::new()),
        ),
        integrations: Arc::new(vectispire_cp_settings::Integrations::new(
            db.clone(),
            Vec::new(),
            Arc::new(time::OffsetDateTime::now_utc),
        )),
        encryption: encryption(),
        settings: vectispire_cp_settings::Settings::new(db.clone()),
        audit: audit.clone(),
        clock: Arc::new(vectispire_cp_targets::SystemClock),
        targets: Arc::new(vectispire_cp_targets::Targets::new(vectispire_cp_targets::TargetsConfig {
            db: db.clone(),
            audit,
            scans: Arc::new(vectispire_cp_targets::ScanningStandIn),
            backlog: Arc::new(vectispire_cp_targets::IssuesStandIn),
            purge: vectispire_cp_targets::PurgeRegistry::stand_ins(),
            encryption: encryption(),
            allowed_hosts: vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
            clock: Arc::new(vectispire_cp_targets::SystemClock),
            visibility: None,
        })),
        bounds: vectispire_cp_forges::DiscoveryBounds::default(),
        concurrency: 1,
        host: "test".to_owned(),
        alerts: Arc::new(NoAlerts),
        review_bounds: vectispire_cp_forges::reviews::ReviewBounds::default(),
    }))
}

/// No listener: what a test of the routes never reaches.
pub struct NoAlerts;

impl vectispire_cp_forges::TokenAlerts for NoAlerts {
    fn publish<'a>(
        &'a self,
        _: &'a mut vectispire_cp_db::Tx,
        _: &'a vectispire_domain::token_alert::TokenAlert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

pub fn services() -> Arc<vectispire_cp_forges::Services> {
    services_on(unreachable_db())
}
