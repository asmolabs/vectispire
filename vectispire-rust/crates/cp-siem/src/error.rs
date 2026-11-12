//! What the module's services refuse with.

use vectispire_cp_crypto::EncryptionError;
use vectispire_cp_settings::IntegrationsError;
use vectispire_domain::integrations::Integration;

/// A refusal or a failure of the configuration's service.
#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    /// `InvalidInputException`: the sentence is the form's to show, 400.
    #[error("{0}")]
    InvalidInput(String),
    /// The header could not be encrypted — no key is configured (412), or Vault refused.
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    /// `IntegrationDisabledException`: an enabled export saved, or a test made, over a transport the platform governor
    /// switched off — 409 `integration-disabled`, naming it (decision 0040 §1).
    #[error("{}", .0.disabled_message(""))]
    IntegrationDisabled(Integration),
    /// The database refused or could not be reached.
    #[error("{0}")]
    Database(String),
}

impl From<IntegrationsError> for SiemError {
    fn from(error: IntegrationsError) -> SiemError {
        match error {
            IntegrationsError::Disabled(integration) => SiemError::IntegrationDisabled(integration),
            other => SiemError::Database(other.to_string()),
        }
    }
}

impl From<crate::persistence::DbError> for SiemError {
    fn from(error: crate::persistence::DbError) -> SiemError {
        SiemError::Database(error.to_string())
    }
}
