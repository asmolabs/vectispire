//! Gate error types.

use axum::response::{IntoResponse, Response};
use http::StatusCode;

/// Errors arising in the gate module.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("{0}")]
    InvalidInput(String),

    #[error("No {kind} with id {id}.")]
    NotFound { kind: String, id: i64 },

    #[error("{0}")]
    NotFoundMessage(String),

    #[error("the gate tables did not answer: {0}")]
    Store(#[from] crate::persistence::StoreError),

    #[error("target not found")]
    TargetNotFound,

    #[error("unauthorized")]
    Forbidden,
}

impl IntoResponse for GateError {
    fn into_response(self) -> Response {
        match self {
            GateError::InvalidInput(msg) => {
                vectispire_cp_http::Problem::handler(StatusCode::BAD_REQUEST, msg).into_response()
            }
            GateError::NotFound { kind, id } => {
                let msg = format!("No {kind} with id {id}.");
                vectispire_cp_http::Problem::handler(StatusCode::NOT_FOUND, msg).into_response()
            }
            GateError::NotFoundMessage(msg) => {
                vectispire_cp_http::Problem::handler(StatusCode::NOT_FOUND, msg).into_response()
            }
            GateError::TargetNotFound => {
                vectispire_cp_http::Problem::handler(StatusCode::NOT_FOUND, "Target not found").into_response()
            }
            GateError::Forbidden => {
                vectispire_cp_http::Problem::handler(StatusCode::FORBIDDEN, "Forbidden").into_response()
            }
            GateError::Store(err) => {
                vectispire_cp_http::Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        }
    }
}
