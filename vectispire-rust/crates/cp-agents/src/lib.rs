//! The control plane's `agents` module, `core.agents` — Phase 2, task 2.9 of the port: remote agent protocol,
//! agent administration, sealing key pinning, result attestation and long polling.

#![forbid(unsafe_code)]

mod error;
mod internal;
mod persistence;
mod web;

use std::sync::Arc;

pub use error::AgentError;
pub use internal::admin_service::{
    Activity, AgentAdministrationService, AgentSummary, Change, Changed, Declaration, DeclaredAgent, PendingScan,
    PinnedKey, QueueFigures, RunningScan, Unroutable,
};
pub use internal::audit::AgentResultAuditDelivery;
pub use internal::backlog_task::{CredentialedBacklogProvider, CredentialedBacklogTask, Unserved};
pub use internal::claim_lock::AgentRowLock;
pub use internal::directory::AgentDirectoryImpl;
pub use internal::poller::AgentJobPoller;
pub use internal::protocol_service::{AgentPluginProvider, AgentProtocolService, AuthenticatedAgent, NoAgentPlugins};
pub use internal::withheld_repair::{Outcome as RepairOutcome, WithheldClaimRepair};
pub use web::routes;

/// The `Agents` facade uniting administration, protocol, and polling.
#[derive(Clone)]
pub struct Agents {
    pub admin: Arc<AgentAdministrationService>,
    pub protocol: Arc<AgentProtocolService>,
    pub poller: Arc<AgentJobPoller>,
}

impl Agents {
    pub fn new(
        admin: Arc<AgentAdministrationService>,
        protocol: Arc<AgentProtocolService>,
        poller: Arc<AgentJobPoller>,
    ) -> Self {
        Self { admin, protocol, poller }
    }
}

impl std::fmt::Debug for Agents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agents").finish()
    }
}
