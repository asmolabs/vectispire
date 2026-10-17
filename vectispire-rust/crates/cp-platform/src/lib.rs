//! The control plane's platform module — the Rust of `core.platform` (plan, Phase 1 task 1.6), as far as the
//! modules it composes have been ported.
//!
//! - [`SettingsAdministration`] is `SettingsAdministrationService`'s catalog and save: what a reader may see of the
//!   catalog, and what a save may change — every refusal in Java's words, every save audited, the security-relevant
//!   ones signalled to the SOC.
//! - The modules a save consults and that are not ported yet — `access`' count of approvers, `tickets`' CA pinning,
//!   `ai`'s destination guard and its acceptance record — are seams ([`Approvers`], [`Tracker`], [`AiDestination`])
//!   that the binary fills, as `platform` in Java may use any module (decision 0029).
//!
//! Not here yet, and said so: the routes (`SettingsController`, `AuditLogController`, `CryptoController`), the four
//! credential doors that encrypt before storing, and the AI endpoint check — each needs a module of a later phase.

#![forbid(unsafe_code)]

mod forms;
mod settings;

pub use settings::{
    AdministrationError, AiAfter, AiDestination, Applied, Approvers, Caller, CollaboratorError, Entry,
    SECURITY_SETTING_CHANGED, SettingsAdministration, Tracker,
};
