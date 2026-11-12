//! What a service of this module refuses with, and the status each refusal is answered with — the Java exceptions
//! `ApiExceptionHandler` maps, one variant each, so that a route cannot answer a refusal with the wrong status.

use crate::persistence::StoreError;

/// A refusal or a failure.
#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    /// `InvalidInputException` (and `InvalidCronExpressionException`): 400, the sentence as it is.
    #[error("{0}")]
    Invalid(String),
    /// `NotFoundException`: 404 — **one sentence for an absent row and a hidden one**, chosen by the caller from
    /// `cp_access::rows`, never worded by the check that found it.
    #[error("{0}")]
    NotFound(String),
    /// `ConflictException` and the conflicts mapped beside it: 409, typed `urn:vectispire:problem:<cause>` when a
    /// cause is named, with the members a client reads as data.
    #[error("{message}")]
    Conflict { message: String, cause: Option<&'static str>, members: Vec<(&'static str, serde_json::Value)> },
    /// `MissingEncryptionKeyException`: 412 — a secret cannot be stored without a key, and storing it in the clear
    /// is the one answer that is never right.
    #[error("{0}")]
    MissingKey(String),
    /// `UnsafeUrlException`: 422 — the guard refused the KMS's address.
    #[error("{0}")]
    UnsafeUrl(String),
    /// Anything else: the database, the KMS — answered as the unexpected failure it is, with a reference.
    #[error(transparent)]
    Unexpected(Box<dyn std::error::Error + Send + Sync>),
}

impl TargetError {
    pub fn invalid(message: impl Into<String>) -> TargetError {
        TargetError::Invalid(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> TargetError {
        TargetError::NotFound(message.into())
    }

    pub fn conflict(message: impl Into<String>, cause: &'static str) -> TargetError {
        TargetError::Conflict { message: message.into(), cause: Some(cause), members: Vec::new() }
    }

    pub fn unexpected(error: impl std::error::Error + Send + Sync + 'static) -> TargetError {
        TargetError::Unexpected(Box::new(error))
    }
}

impl From<StoreError> for TargetError {
    fn from(error: StoreError) -> TargetError {
        TargetError::Unexpected(Box::new(error))
    }
}

impl From<vectispire_domain::bounded_text::Refused> for TargetError {
    fn from(refused: vectispire_domain::bounded_text::Refused) -> TargetError {
        TargetError::Invalid(refused.0)
    }
}

impl From<vectispire_cp_access::NotFound> for TargetError {
    fn from(refused: vectispire_cp_access::NotFound) -> TargetError {
        TargetError::NotFound(refused.message.to_owned())
    }
}

impl From<vectispire_cp_crypto::EncryptionError> for TargetError {
    fn from(error: vectispire_cp_crypto::EncryptionError) -> TargetError {
        match error {
            vectispire_cp_crypto::EncryptionError::MissingKey => TargetError::MissingKey(error.to_string()),
            vectispire_cp_crypto::EncryptionError::UnsafeUrl(message) => TargetError::UnsafeUrl(message),
            other @ vectispire_cp_crypto::EncryptionError::Kms(_) => TargetError::Unexpected(Box::new(other)),
        }
    }
}
