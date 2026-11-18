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
        settings: vectispire_cp_settings::Settings::new(db),
        audit,
        clock: Arc::new(vectispire_cp_targets::SystemClock),
    }))
}

pub fn services() -> Arc<vectispire_cp_forges::Services> {
    services_on(unreachable_db())
}
