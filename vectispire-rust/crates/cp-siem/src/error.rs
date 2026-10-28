//! What the module's services refuse with.

use vectispire_cp_crypto::EncryptionError;

/// A refusal or a failure of the configuration's service.
#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    /// `InvalidInputException`: the sentence is the form's to show, 400.
    #[error("{0}")]
    InvalidInput(String),
    /// The header could not be encrypted — no key is configured (412), or Vault refused.
    #[error(transparent)]
    Encryption(#[from] EncryptionError),
    /// The database refused or could not be reached.
    #[error("{0}")]
    Database(String),
}

impl From<crate::persistence::DbError> for SiemError {
    fn from(error: crate::persistence::DbError) -> SiemError {
        SiemError::Database(error.to_string())
    }
}
