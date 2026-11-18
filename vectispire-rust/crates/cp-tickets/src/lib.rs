//! The control plane's tickets — the Rust of `core.tickets` (wave 2).
//!
//! - **The tracker client** ([`service::TicketService`]): GitLab, GitHub, Jira and ServiceNow, through the outbound
//!   door with the CA pinned for the tracker; its token encrypted at rest and refused while the tracker is suspended
//!   (decision 0040 §3); its inbound secret; its token's health ([`token_state`]) announced once per change as a
//!   `TokenAlert` through `notifications`.
//! - **The sweep** ([`sweep::TicketSweepService`], slot `TICKET_SWEEP`): a ticket for what the gate's policy would fail
//!   a build on, claimed before the tracker is asked, closed once the issue is resolved. **The token check** (slot
//!   `TICKET_TOKEN_CHECK`).
//! - **The links attached by hand** ([`links::TicketLinkService`]), the issue's visibility first.
//! - **The tracker's webhook** ([`webhook::TicketingWebhookService`]): the only anonymous mutating route.
//! - What other modules call: `issues`' `TicketReferences`, `targets`' purge listener, the routes.

#![forbid(unsafe_code)]

mod error;
mod format;
mod internal;
pub mod links;
mod persistence;
pub mod service;
pub mod sweep;
pub mod token_state;
mod web;
pub mod webhook;

use std::sync::Arc;

use vectispire_cp_audit::{AuditLog, Clock};
use vectispire_cp_crypto::Encryption;
use vectispire_cp_db::Db;
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_outbound::OutboundPost;
use vectispire_cp_outbox::TokenAlertSink;
use vectispire_cp_settings::{Integrations, Settings};

pub use error::TicketError;
pub use internal::{TicketLinkPurge, TicketSweepTask, TicketTokenCheckTask, TrackerTicketReferences};
pub use web::routes;

/// What the module is composed over.
pub struct TicketsConfig {
    pub db: Db,
    pub settings: Settings,
    pub encryption: Arc<Encryption>,
    pub post: OutboundPost,
    pub integrations: Integrations,
    pub audit: Arc<AuditLog>,
    pub alerts: Arc<dyn TokenAlertSink>,
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for TicketsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketsConfig").finish_non_exhaustive()
    }
}

/// The module's services, composed once.
#[derive(Clone)]
pub struct Tickets {
    pub service: Arc<service::TicketService>,
    pub sweep: Arc<sweep::TicketSweepService>,
    pub links: Arc<links::TicketLinkService>,
    pub webhooks: Arc<webhook::TicketingWebhookService>,
}

impl std::fmt::Debug for Tickets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tickets").finish_non_exhaustive()
    }
}

impl Tickets {
    pub fn new(config: TicketsConfig) -> Tickets {
        let issues = vectispire_cp_issues::IssueCatalog::new(config.db.clone());
        let token_state =
            Arc::new(token_state::TrackerTokenState::new(config.db.clone(), config.settings.clone(), config.alerts));
        let service = Arc::new(service::TicketService::new(
            config.settings.clone(),
            config.encryption,
            config.post,
            config.clock.clone(),
            token_state,
            config.integrations.clone(),
        ));
        let sweep = Arc::new(sweep::TicketSweepService::new(
            config.db.clone(),
            issues.clone(),
            service.clone(),
            config.audit.clone(),
            config.clock.clone(),
        ));
        let links = Arc::new(links::TicketLinkService::new(
            config.db.clone(),
            issues.clone(),
            config.audit.clone(),
            config.clock.clone(),
            config.integrations.clone(),
        ));
        let webhooks = Arc::new(webhook::TicketingWebhookService::new(
            config.db.clone(),
            issues,
            config.audit,
            service.clone(),
            Arc::new(webhook::WebhookRefusals::default()),
            vectispire_cp_access::independence::ApproverIndependence::new(config.db, Arc::new(config.settings)),
            config.clock,
            config.integrations,
        ));
        Tickets { service, sweep, links, webhooks }
    }

    /// The two maintenance slots, `TICKET_SWEEP` and `TICKET_TOKEN_CHECK`.
    pub fn tasks(&self) -> Vec<Arc<dyn MaintenanceTask>> {
        vec![Arc::new(TicketSweepTask(self.sweep.clone())), Arc::new(TicketTokenCheckTask(self.service.clone()))]
    }

    /// The routes.
    pub fn routes(&self) -> Vec<vectispire_cp_http::routes::RouteEntry> {
        web::routes(self.links.clone(), self.webhooks.clone())
    }

    /// `issues`' judgement on a reference attached by hand.
    pub fn references(&self) -> Arc<dyn vectispire_cp_issues::TicketReferences> {
        Arc::new(TrackerTicketReferences(self.service.clone()))
    }
}
