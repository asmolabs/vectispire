//! What the module's services refuse with, as `ApiExceptionHandler` maps it.

use crate::persistence::StoreError;
use crate::ports::PortError;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// `InvalidInputException`: 400.
    #[error("{0}")]
    Invalid(String),
    /// `NotFoundException`: 404 — one sentence for an absent row and a hidden one.
    #[error("{0}")]
    NotFound(String),
    /// Anything else: a 500 quoting a reference, never the failure's own text.
    #[error(transparent)]
    Unexpected(PortError),
}

impl ScanError {
    pub fn unexpected(failure: impl std::error::Error + Send + Sync + 'static) -> ScanError {
        ScanError::Unexpected(Box::new(failure))
    }
}

impl From<StoreError> for ScanError {
    fn from(failure: StoreError) -> ScanError {
        ScanError::Unexpected(Box::new(failure))
    }
}

impl From<vectispire_cp_access::NotFound> for ScanError {
    fn from(refused: vectispire_cp_access::NotFound) -> ScanError {
        ScanError::NotFound(refused.message.to_owned())
    }
}
