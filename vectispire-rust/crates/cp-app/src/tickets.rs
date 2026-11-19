//! The tickets module in the binary: the tracker client over the start's outbound door, its token alerts told
//! through the notifications, its link purge among the targets' listeners, its judgement on a reference handed to the
//! issues' attach decision, its two maintenance slots and its three routes.

use std::sync::Arc;

use vectispire_cp_outbound::OutboundPost;

/// What the module is built from.
pub struct TicketParts {
    pub db: vectispire_cp_db::Db,
    pub encryption: Arc<vectispire_cp_crypto::Encryption>,
    pub post: OutboundPost,
    pub audit: Arc<vectispire_cp_audit::AuditLog>,
    /// `notifications`' listener: a token's change of state, said on the channels and in the audit log.
    pub alerts: Arc<dyn vectispire_cp_outbox::TokenAlertSink>,
    pub clock: Arc<dyn vectispire_cp_audit::Clock>,
}

impl std::fmt::Debug for TicketParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketParts").finish_non_exhaustive()
    }
}

/// The module.
pub fn compose(parts: TicketParts) -> Arc<vectispire_cp_tickets::Tickets> {
    Arc::new(vectispire_cp_tickets::Tickets::new(vectispire_cp_tickets::TicketsConfig {
        settings: vectispire_cp_settings::Settings::new(parts.db.clone()),
        integrations: crate::registry::integrations(&parts.db),
        db: parts.db,
        encryption: parts.encryption,
        post: parts.post,
        audit: parts.audit,
        alerts: parts.alerts,
        clock: parts.clock,
    }))
}

/// The tracker's CA pinning as the settings save asks it — `TicketService.caToPin`, the tickets module's own.
#[derive(Debug, Clone)]
pub struct TrackerCa(pub Arc<vectispire_cp_tickets::Tickets>);

impl vectispire_cp_platform::Tracker for TrackerCa {
    fn refuse_ca(&self, pem: &str) -> Option<String> {
        match self.0.service.ca_to_pin(Some(pem)) {
            Ok(_) => None,
            Err(refused) => Some(refused.to_string()),
        }
    }
}
