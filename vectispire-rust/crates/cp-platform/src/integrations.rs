//! The platform governor's switches over the integrations' registry (decision 0040, lot I1) —
//! `IntegrationAdministrationService`: the list a screen filters its forms with, and the gesture that switches one on or
//! off.
//!
//! **Here and not beside the registry**, as the settings' administration sits above the settings: the gesture records
//! an audit entry, and `settings`, which every module reads, may use nothing — the audit log included.
//!
//! **Each switch is a governance gesture** (0040 §4): audited as `INTEGRATION_ENABLED_CHANGED`, which the SIEM receives
//! as a security setting change (`VECTI-SEC-019`); the same state again records nothing. The entry is written after the
//! switch has committed — [`Integrations::switch_to`] opens and closes its own transaction — so it never records a
//! change that rolled back, nor holds the audit chain's lock inside one.

use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_settings::{IntegrationView, Integrations, IntegrationsError};
use vectispire_domain::integrations::Integration;

/// Why a switch was not made.
#[derive(Debug, thiserror::Error)]
pub enum IntegrationAdministrationError {
    /// `NotFoundException`: a key no integration has.
    #[error("Integration not found.")]
    NotFound,
    /// `InvalidInputException`: no state given — never read as off.
    #[error("Say whether the integration is enabled.")]
    NoState,
    /// The registry's refusal — `integration-in-use` — or its failure.
    #[error(transparent)]
    Registry(#[from] IntegrationsError),
}

/// The service.
#[derive(Debug, Clone)]
pub struct IntegrationAdministration {
    integrations: Integrations,
    audit: AuditLog,
}

impl IntegrationAdministration {
    /// `integrations` is the registry composed with every module's answer to "is it in use".
    pub fn new(integrations: Integrations, audit: AuditLog) -> IntegrationAdministration {
        IntegrationAdministration { integrations, audit }
    }

    /// Every integration with its state, for any signed-in reader: the screens that offer a forge, a tracker or a
    /// channel need to know which are on. **Who switched one is governance's trail**, shown to the roles that read
    /// governance only — an ordinary account learns what is on, not which administrator decided.
    pub async fn list(&self, reads_governance: bool) -> Result<Vec<IntegrationView>, IntegrationsError> {
        let all = self.integrations.list().await?;
        Ok(if reads_governance { all } else { all.into_iter().map(IntegrationView::without_author).collect() })
    }

    /// Switches one integration on or off, attributed to `governor`; audited once, for a change only.
    pub async fn set_enabled(
        &self,
        key: &str,
        enabled: Option<bool>,
        governor: &str,
        actor: &RequestActor,
    ) -> Result<IntegrationView, IntegrationAdministrationError> {
        let integration = Integration::by_key(key).ok_or(IntegrationAdministrationError::NotFound)?;
        let enabled = enabled.ok_or(IntegrationAdministrationError::NoState)?;
        let switched = self.integrations.switch_to(integration, enabled, governor).await?;
        if switched.changed {
            let description = format!(
                "Integration \"{}\" {}",
                integration.key(),
                if enabled {
                    "enabled: the installation may talk to it again."
                } else {
                    "disabled: the installation no longer talks to it; what uses it is kept."
                }
            );
            self.audit
                .record(actor.entry(AuditOperation::IntegrationEnabledChanged, &integration.key(), &description))
                .await;
        }
        Ok(switched.integration)
    }
}
