//! What a posture service answers instead of a figure.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use vectispire_cp_http::Problem;

#[derive(Debug, thiserror::Error)]
pub enum PostureError {
    /// A target the caller may not see, refused as an absent one — the guard's own sentence, never 403.
    #[error("{0}")]
    NotFound(String),
    /// A request the service refuses as Java's `InvalidInputException` does — a 400 carrying the sentence.
    #[error("{0}")]
    Invalid(String),
    /// A collaborator failed: the database, the inventory's parse. Logged, and a 500 that says nothing more.
    #[error("{0}")]
    Unexpected(String),
}

impl PostureError {
    pub fn unexpected(error: impl std::fmt::Display) -> PostureError {
        PostureError::Unexpected(error.to_string())
    }
}

impl From<vectispire_cp_access::rows::NotFound> for PostureError {
    fn from(refused: vectispire_cp_access::rows::NotFound) -> PostureError {
        PostureError::NotFound(refused.message.to_owned())
    }
}

impl IntoResponse for PostureError {
    fn into_response(self) -> Response {
        match self {
            PostureError::NotFound(message) => Problem::handler(StatusCode::NOT_FOUND, message).into_response(),
            PostureError::Invalid(message) => Problem::handler(StatusCode::BAD_REQUEST, message).into_response(),
            PostureError::Unexpected(message) => {
                tracing::error!("A posture figure could not be computed: {message}");
                Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "An unexpected error occurred.").into_response()
            }
        }
    }
}
