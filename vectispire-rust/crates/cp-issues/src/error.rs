//! Error types for the issues module.

use thiserror::Error;

use crate::persistence::StoreError;

#[derive(Debug, Error)]
pub enum IssueError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    InvalidInput(String),
    #[error("{0}")]
    InvalidTriage(String),
    #[error("Issue changed meanwhile: another decision or scan modified the issue revision.")]
    ChangedMeanwhile,
    #[error("Triage approval differs: requested status was {requested_status}, but received {actual_status}.")]
    ApprovalDiffers { requested_status: String, actual_status: String },
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    Store(String),
    /// Under four-eyes, the requester administered the approver's account recently (`ApproverIndependence`).
    #[error(transparent)]
    Independence(#[from] vectispire_cp_access::accounts::IndependenceError),
}

impl From<StoreError> for IssueError {
    fn from(err: StoreError) -> Self {
        IssueError::Store(err.to_string())
    }
}

impl axum::response::IntoResponse for IssueError {
    fn into_response(self) -> axum::response::Response {
        match self {
            IssueError::NotFound(msg) => {
                vectispire_cp_http::Problem::handler(http::StatusCode::NOT_FOUND, msg).into_response()
            }
            IssueError::InvalidInput(msg) | IssueError::InvalidTriage(msg) => {
                vectispire_cp_http::Problem::handler(http::StatusCode::BAD_REQUEST, msg).into_response()
            }
            IssueError::ChangedMeanwhile => vectispire_cp_http::Problem::handler(
                http::StatusCode::CONFLICT,
                "Issue changed meanwhile: another decision or scan modified the issue revision.",
            )
            .into_response(),
            IssueError::ApprovalDiffers { requested_status, actual_status } => {
                let msg = format!(
                    "This request asks for {requested_status}: approve it as {requested_status}, or turn it down (under_review or affected) and record your own decision. It cannot be granted as {actual_status}."
                );
                vectispire_cp_http::Problem::handler(http::StatusCode::CONFLICT, msg)
                    .caused_by("triage-approval-differs")
                    .with("requestedStatus", requested_status)
                    .into_response()
            }
            // Java's `AccessDeniedException`: audited and answered by the chain, not by the handler.
            IssueError::Forbidden(msg) => vectispire_cp_http::chain::denied(msg),
            IssueError::Independence(refused) => {
                use vectispire_cp_access::accounts::IndependenceError;
                match refused {
                    IndependenceError::NotIndependent { ref sentence, gesture, window_days }
                    | IndependenceError::PasswordKnown { ref sentence, gesture, window_days } => {
                        let cause = refused.cause().unwrap_or_default();
                        vectispire_cp_http::Problem::handler(http::StatusCode::CONFLICT, sentence.clone())
                            .caused_by(cause)
                            .with("gesture", gesture.wire_name())
                            .with("windowDays", window_days)
                            .into_response()
                    }
                    IndependenceError::Failed(msg) => {
                        vectispire_cp_http::Problem::handler(http::StatusCode::INTERNAL_SERVER_ERROR, msg)
                            .into_response()
                    }
                }
            }
            IssueError::Store(msg) => {
                vectispire_cp_http::Problem::handler(http::StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
        }
    }
}
