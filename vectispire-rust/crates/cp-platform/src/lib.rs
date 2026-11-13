//! The control plane's platform module — the Rust of `core.platform` (plan, Phase 1 task 1.6), as far as the
//! modules it composes have been ported.
//!
//! - [`SettingsAdministration`] is `SettingsAdministrationService`'s catalog and save: what a reader may see of the
//!   catalog, what a save may change — every refusal in Java's words, the integrations it starts using enabled, the
//!   writes in one transaction holding the notification channels they configure, every save audited, the
//!   security-relevant ones signalled to the SOC — and the AI endpoint check, which names the address to an
//!   administrator only.
//! - The modules a save consults and that are not ported yet — `access`' count of approvers, `tickets`' CA pinning,
//!   `ai`'s destination guard, its acceptance record and its endpoint — are seams ([`Approvers`], [`Tracker`],
//!   [`AiDestination`], [`AiEndpoint`])
//!   that the binary fills, as `platform` in Java may use any module (decision 0029).
//!
//! - [`IntegrationAdministration`] is `IntegrationAdministrationService` (decision 0040): the registry's list and the
//!   governor's switch, audited once; [`integration_routes`] are `IntegrationsController`'s.
//! - [`routes`] are `AuditLogController`'s and `CryptoController`'s, over `cp-audit`'s `AuditLogQuery` and `cp-crypto`'s
//!   `SigningKeys`.
//!
//! Not here yet, and said so: `SettingsController`'s routes, the four credential doors that encrypt before storing,
//! each needs a module not ported yet (`README.md` says which).

#![forbid(unsafe_code)]

mod forms;
mod integrations;
mod settings;
mod web;

pub use integrations::{IntegrationAdministration, IntegrationAdministrationError};
pub use settings::{
    AI_UNAVAILABLE, AdministrationError, AiAfter, AiDestination, AiEndpoint, Applied, Approvers, Caller,
    CollaboratorError, EndpointCheck, Entry, SECURITY_SETTING_CHANGED, SettingsAdministration, SettingsParts, Tracker,
};
pub use web::{integration_routes, routes};
