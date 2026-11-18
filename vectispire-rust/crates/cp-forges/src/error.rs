//! What the services refuse with, as `ApiExceptionHandler` answers each: `InvalidInputException` 400,
//! `NotFoundException` 404, `IntegrationDisabledException` and `ConflictException` 409 with their cause, anything
//! else a 500 that names a reference and nothing of the failure.

use vectispire_cp_settings::IntegrationsError;
use vectispire_domain::bounded_text::Refused;
use vectispire_domain::forges::ForgeConnectionRefusal;
use vectispire_domain::integrations::Integration;

use crate::persistence::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum ForgeError {
    /// 400, the sentence shown as it is.
    #[error("{0}")]
    InvalidInput(String),
    /// 404.
    #[error("{0}")]
    NotFound(String),
    /// 409 `integration-disabled`, the integration's key in a member of its own.
    #[error("{}", .0.disabled_message(""))]
    Disabled(Integration),
    /// 409 with a cause token and members: a discovery refused for the state the connection is in.
    #[error("{message}")]
    Conflict { cause: &'static str, message: String, members: Vec<(&'static str, serde_json::Value)> },
    /// What nobody can act on: the database, the encryption, a stored value this version cannot read.
    #[error("{0}")]
    Unexpected(String),
}

impl From<Refused> for ForgeError {
    fn from(refused: Refused) -> ForgeError {
        ForgeError::InvalidInput(refused.0)
    }
}

impl From<ForgeConnectionRefusal> for ForgeError {
    fn from(refusal: ForgeConnectionRefusal) -> ForgeError {
        ForgeError::InvalidInput(refusal.message)
    }
}

impl From<StoreError> for ForgeError {
    fn from(error: StoreError) -> ForgeError {
        ForgeError::Unexpected(error.to_string())
    }
}

impl From<IntegrationsError> for ForgeError {
    fn from(error: IntegrationsError) -> ForgeError {
        match error {
            IntegrationsError::Disabled(integration) => ForgeError::Disabled(integration),
            other => ForgeError::Unexpected(other.to_string()),
        }
    }
}

impl From<vectispire_cp_crypto::EncryptionError> for ForgeError {
    fn from(error: vectispire_cp_crypto::EncryptionError) -> ForgeError {
        ForgeError::Unexpected(error.to_string())
    }
}

impl From<vectispire_cp_settings::SettingsError> for ForgeError {
    fn from(error: vectispire_cp_settings::SettingsError) -> ForgeError {
        ForgeError::Unexpected(error.to_string())
    }
}

/// `NotFoundException("Forge connection not found.")`.
pub(crate) fn connection_not_found() -> ForgeError {
    ForgeError::NotFound("Forge connection not found.".to_owned())
}
