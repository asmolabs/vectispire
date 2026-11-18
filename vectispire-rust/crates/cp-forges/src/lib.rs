//! Forges (decision 0037) — `core.forges`: read-only connections to GitHub and GitLab from which repositories are
//! discovered and imported as ordinary targets, and the change-review readings the checklists judge.
//!
//! **What it may use** (`cp-arch-tests/data/edges/forges.toml`, Java's `allowedDependencies`): `targets` for the
//! import, `checklists` for the change-review port this module implements, `access::security` for its routes. The
//! outbound door, the encryption and the audit log are the foundation's.

#![forbid(unsafe_code)]

pub mod connections;
pub mod error;
// The statements and helpers of the discoveries, the selection, the import and the readings (stages 3 and 4) are
// written and tested ahead of their services; the attribute goes when those land.
#[allow(dead_code, reason = "stages 3 and 4's statements, tested ahead of their services")]
mod internal;
#[allow(dead_code, reason = "stages 3 and 4's statements, tested ahead of their services")]
mod persistence;
pub mod token_watch;
#[allow(dead_code, reason = "the repository view of stage 3, ahead of its route")]
pub mod views;
#[allow(dead_code, reason = "stages 3 and 4's readings of a request, ahead of their routes")]
mod web;

use std::sync::Arc;

use vectispire_cp_audit::AuditLog;
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::Db;
use vectispire_cp_http::routes::RouteEntry;
use vectispire_cp_outbound::json::OutboundJson;
use vectispire_cp_settings::{Integrations, Settings};
use vectispire_cp_targets::Clock;

pub use connections::ForgeConnectionService;
pub use error::ForgeError;
pub use token_watch::{ForgeTokenWatch, TokenAlerts};

/// What the module is composed over.
#[allow(missing_debug_implementations)] // services and pools
pub struct ForgeParts {
    pub db: Db,
    pub outbound: OutboundJson,
    pub integrations: Arc<Integrations>,
    pub encryption: Arc<Encryption>,
    pub settings: Settings,
    pub audit: Arc<AuditLog>,
    pub clock: Arc<dyn Clock>,
}

/// The services a route reaches, shared.
#[derive(Debug)]
pub struct Services {
    pub connections: Arc<ForgeConnectionService>,
}

impl Services {
    pub fn new(parts: ForgeParts) -> Services {
        let ForgeParts { db, outbound, integrations, encryption, settings, audit, clock } = parts;
        let integrations = internal::integrations::ForgeIntegrations::new(integrations);
        let probes = internal::probes::ForgeProbes::new(outbound, integrations.clone());
        Services {
            connections: Arc::new(ForgeConnectionService::new(
                db,
                probes,
                integrations,
                encryption,
                settings,
                audit,
                clock,
            )),
        }
    }
}

/// The module's routes.
pub fn routes(services: Arc<Services>) -> Vec<RouteEntry> {
    web::routes(services)
}
