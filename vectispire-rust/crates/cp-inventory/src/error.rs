//! Inventory error definitions and problem mapping.

use axum::response::{IntoResponse, Response};
use http::StatusCode;
use vectispire_cp_access::NotFound;
use vectispire_cp_http::Problem;

use crate::persistence::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    #[error("Not found.")]
    NotFound(String),

    #[error("{0}")]
    Invalid(String),

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error(transparent)]
    Target(#[from] vectispire_cp_targets::TargetError),

    #[error(transparent)]
    Scan(#[from] vectispire_cp_scanning::ScanError),

    #[error(transparent)]
    ScanStore(#[from] vectispire_cp_scanning::StoreError),

    #[error(transparent)]
    Audit(#[from] vectispire_cp_audit::AuditError),

    #[error("unauthorized")]
    Unauthorized,

    #[error(transparent)]
    Unexpected(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl From<NotFound> for InventoryError {
    fn from(refusal: NotFound) -> Self {
        InventoryError::NotFound(refusal.message.to_owned())
    }
}

impl InventoryError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
}

impl IntoResponse for InventoryError {
    fn into_response(self) -> Response {
        match self {
            InventoryError::NotFound(msg) => Problem::handler(StatusCode::NOT_FOUND, msg).into_response(),
            InventoryError::Invalid(msg) => Problem::handler(StatusCode::BAD_REQUEST, msg).into_response(),
            InventoryError::Unauthorized => Problem::handler(StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
            InventoryError::Store(err) => {
                tracing::error!(error = %err, "Database store error in inventory");
                Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "A database error occurred.").into_response()
            }
            InventoryError::Target(err) => match err {
                vectispire_cp_targets::TargetError::NotFound(msg) => {
                    Problem::handler(StatusCode::NOT_FOUND, msg).into_response()
                }
                vectispire_cp_targets::TargetError::Invalid(msg) => {
                    Problem::handler(StatusCode::BAD_REQUEST, msg).into_response()
                }
                _ => {
                    tracing::error!(error = %err, "Target error in inventory");
                    Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "An unexpected target error occurred.")
                        .into_response()
                }
            },
            InventoryError::Scan(err) => match err {
                vectispire_cp_scanning::ScanError::NotFound(msg) => {
                    Problem::handler(StatusCode::NOT_FOUND, msg).into_response()
                }
                vectispire_cp_scanning::ScanError::Invalid(msg) => {
                    Problem::handler(StatusCode::BAD_REQUEST, msg).into_response()
                }
                _ => {
                    tracing::error!(error = %err, "Scan error in inventory");
                    Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "An unexpected scanning error occurred.")
                        .into_response()
                }
            },
            InventoryError::ScanStore(err) => {
                tracing::error!(error = %err, "Scan store error in inventory");
                Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "A database error occurred.").into_response()
            }
            InventoryError::Audit(err) => {
                tracing::error!(error = %err, "Audit error in inventory");
                Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "An audit error occurred.").into_response()
            }
            InventoryError::Unexpected(err) => {
                tracing::error!(error = %err, "Unexpected error in inventory");
                Problem::handler(StatusCode::INTERNAL_SERVER_ERROR, "An unexpected error occurred.").into_response()
            }
        }
    }
}
