//! The forges module (wave 2) as the binary composes it: its connections probed through the outbound door with the
//! runtime's trust — a pinned CA per connection replacing it — the guard reserving the deployment's own endpoints, the
//! integrations' registry deciding which forges are reached, and its tokens counted in the encryption census.

use std::sync::Arc;

use vectispire_cp_db::Db;
use vectispire_cp_http::routes::RouteEntry;
use vectispire_cp_outbound::guard::OutboundUrlGuard;

/// What composing the module gives the binary.
#[allow(missing_debug_implementations)] // services and routes
pub struct Composed {
    pub routes: Vec<RouteEntry>,
    pub services: Arc<vectispire_cp_forges::Services>,
}

/// What the module is composed over.
#[allow(missing_debug_implementations)] // services and pools
pub struct ForgeSetup {
    pub db: Db,
    pub guard: OutboundUrlGuard,
    pub trust: vectispire_tls::TlsTrust,
    pub encryption: Arc<vectispire_cp_crypto::Encryption>,
    pub audit: Arc<vectispire_cp_audit::AuditLog>,
    pub clock: Arc<dyn vectispire_cp_targets::Clock>,
    pub targets: Arc<vectispire_cp_targets::Targets>,
}

/// What a discovery's claim is written under, as the scan worker names its host.
fn host_name() -> String {
    std::env::var("HOSTNAME").or_else(|_| std::env::var("HOST")).unwrap_or_else(|_| "unknown-host".to_owned())
}

/// The module, composed.
pub fn compose(setup: ForgeSetup) -> Composed {
    let ForgeSetup { db, guard, trust, encryption, audit, clock, targets } = setup;
    let audit_for_alerts = audit.clone();
    let services = Arc::new(vectispire_cp_forges::Services::new(vectispire_cp_forges::ForgeParts {
        db: db.clone(),
        outbound: vectispire_cp_outbound::json::OutboundJson::new(
            vectispire_cp_outbound::PinnedHttpSender::new(trust),
            guard,
        ),
        integrations: Arc::new(crate::registry::integrations(&db)),
        encryption,
        settings: vectispire_cp_settings::Settings::new(db),
        audit,
        clock,
        targets,
        bounds: vectispire_cp_forges::DiscoveryBounds::default(),
        concurrency: 2,
        host: host_name(),
        // `notifications` is not ported: the alert's audit entry, and through it the SIEM event, without the channels.
        alerts: Arc::new(vectispire_cp_forges::token_watch::AuditedAlerts((*audit_for_alerts).clone())),
        review_bounds: vectispire_cp_forges::reviews::ReviewBounds::default(),
    }));
    Composed { routes: vectispire_cp_forges::routes(services.clone()), services }
}
