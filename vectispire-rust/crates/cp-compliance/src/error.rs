//! What a compliance service answers instead of a figure.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use vectispire_cp_http::Problem;

#[derive(Debug, thiserror::Error)]
pub enum ComplianceError {
    /// A target or scope the caller may not see, refused as an absent one — never 403.
    #[error("{0}")]
    NotFound(String),
    /// A request refused as Java's `InvalidInputException` does — a 400 carrying the sentence.
    #[error("{0}")]
    Invalid(String),
    /// A request the state refuses, as Java's `ConflictException` — a 409 carrying the sentence.
    #[error("{0}")]
    Conflict(String),
    /// A collaborator failed. Logged, and a 500 that says nothing more.
    #[error("{0}")]
    Unexpected(String),
}

impl ComplianceError {
    pub fn unexpected(error: impl std::fmt::Display) -> ComplianceError {
        ComplianceError::Unexpected(error.to_string())
    }
}

impl From<crate::persistence::StoreError> for ComplianceError {
    fn from(error: crate::persistence::StoreError) -> ComplianceError {
        ComplianceError::unexpected(error)
    }
}

impl IntoResponse for ComplianceError {
    fn into_response(self) -> Response {
        match self {
            ComplianceError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message).into_response(),
            ComplianceError::Invalid(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
            ComplianceError::Conflict(message) => Problem::handler(StatusCode::CONFLICT, message).into_response(),
            ComplianceError::Unexpected(message) => {
                tracing::error!("A compliance answer could not be computed: {message}");
                Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "An unexpected error occurred.").into_response()
            }
        }
    }
}
