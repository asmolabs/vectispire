//! The settings screen's service as the binary composes it — `SettingsAdministrationService`, with the modules a save
//! consults behind `cp-platform`'s seams:
//!
//! - **`access`' `TriageApprovers`** ([`AccessApprovers`]): whether four-eyes could be honoured, counted from the
//!   accounts table at the save;
//! - **`tickets`' CA pinning** and **`ai`'s destination guard**: the two narrow parts `cp-platform` holds itself
//!   ([`TrackerCaPinning`], [`GuardedAiDestination`]), the latter over the guard this process built at start — the one
//!   with the reserved endpoints, which every outbound call asks;
//! - **`ai`'s endpoint**, which only `POST /api/v1/settings/ollama-test` asks and which is not served: a named stand-in
//!   ([`EndpointNotPorted`]) that fails if anything ever asks it, until `ai` lands.
//!
//! `tests/settings_composition.rs` exercises this composition on a database: a wiring that is not exercised is not
//! wired.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use vectispire_cp_access::TriageApprovers;
use vectispire_cp_audit::{AuditLog, Clock};
use vectispire_cp_db::Db;
use vectispire_cp_outbound::OutboundUrlGuard;
use vectispire_cp_platform::{
    AiEndpoint, Approvers, CollaboratorError, GuardedAiDestination, SettingsAdministration, SettingsParts,
    TrackerCaPinning,
};
use vectispire_cp_settings::Settings;

type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, CollaboratorError>> + Send + 'a>>;

/// `access`' `TriageApprovers`, as the settings save asks it.
#[derive(Clone, Debug)]
pub struct AccessApprovers(pub TriageApprovers);

impl Approvers for AccessApprovers {
    fn any_active(&self) -> Answer<'_, bool> {
        Box::pin(async move { Ok(self.0.any_active().await?) })
    }
    fn two_can_publish_templates(&self) -> Answer<'_, bool> {
        Box::pin(async move { Ok(self.0.two_can_publish_templates().await?) })
    }
    fn two_can_sign_off_checklists(&self) -> Answer<'_, bool> {
        Box::pin(async move { Ok(self.0.two_can_sign_off_checklists().await?) })
    }
}

/// What the AI endpoint check asks of `ai`, which is not ported: the check's route is not served, so nothing asks.
/// Should something, it fails as an unexpected failure — never with an invented answer.
#[derive(Clone, Copy, Debug)]
pub struct EndpointNotPorted;

/// The one answer [`EndpointNotPorted`] gives.
pub const ENDPOINT_NOT_PORTED: &str = "the AI endpoint check needs the ai module, which is not ported";

impl EndpointNotPorted {
    fn refuse<'a, T: 'a>() -> Answer<'a, T> {
        Box::pin(async { Err(ENDPOINT_NOT_PORTED.into()) })
    }
}

impl AiEndpoint for EndpointNotPorted {
    fn provider(&self) -> Answer<'_, String> {
        Self::refuse()
    }
    fn selected_model(&self) -> Answer<'_, String> {
        Self::refuse()
    }
    fn allow_remote(&self) -> Answer<'_, bool> {
        Self::refuse()
    }
    fn validated_url(&self) -> Answer<'_, Result<String, String>> {
        Self::refuse()
    }
    fn base_url(&self) -> Answer<'_, String> {
        Self::refuse()
    }
    fn has_openai_key(&self) -> Answer<'_, bool> {
        Self::refuse()
    }
    fn available_models(&self) -> Answer<'_, Option<Vec<String>>> {
        Self::refuse()
    }
}

/// The settings screen's service: `guard` is the one `main` built at start, `audit` the process' audit log.
pub fn compose(
    db: &Db,
    audit: AuditLog,
    guard: OutboundUrlGuard,
    clock: Arc<dyn Clock>,
) -> Arc<SettingsAdministration> {
    Arc::new(SettingsAdministration::new(SettingsParts {
        db: db.clone(),
        audit,
        approvers: Arc::new(AccessApprovers(TriageApprovers::new(db.clone()))),
        tracker: Arc::new(TrackerCaPinning::new(clock.clone())),
        ai: Arc::new(GuardedAiDestination::new(Settings::new(db.clone()), guard)),
        endpoint: Arc::new(EndpointNotPorted),
        // The registry the integrations' switches write: a save refuses what the governor switched off.
        integrations: crate::registry::integrations(db),
        clock,
    }))
}
