//! Errors and refusals for the agents module.

use vectispire_cp_http::Problem;

use crate::persistence::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("{0}")]
    Invalid(String),

    #[error("{0}")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("{0}")]
    PreconditionFailed(String),

    #[error("{0}")]
    Forbidden(String),

    #[error("{0}")]
    Unauthorized(String),

    #[error(transparent)]
    Unexpected(Box<dyn std::error::Error + Send + Sync>),
}

impl AgentError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    pub fn unexpected(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Unexpected(Box::new(err))
    }
}

impl From<StoreError> for AgentError {
    fn from(err: StoreError) -> Self {
        Self::Unexpected(Box::new(err))
    }
}

impl From<vectispire_cp_targets::TargetError> for AgentError {
    fn from(err: vectispire_cp_targets::TargetError) -> Self {
        match err {
            vectispire_cp_targets::TargetError::Invalid(m) => AgentError::Invalid(m),
            vectispire_cp_targets::TargetError::NotFound(m) => AgentError::NotFound(m),
            vectispire_cp_targets::TargetError::Conflict { message, .. } => AgentError::Conflict(message),
            vectispire_cp_targets::TargetError::MissingKey(m) => AgentError::PreconditionFailed(m),
            vectispire_cp_targets::TargetError::UnsafeUrl(m) => AgentError::Invalid(m),
            vectispire_cp_targets::TargetError::Unexpected(e) => AgentError::Unexpected(e),
        }
    }
}

impl From<vectispire_domain::bounded_text::Refused> for AgentError {
    fn from(refused: vectispire_domain::bounded_text::Refused) -> Self {
        Self::Invalid(refused.0)
    }
}

impl From<AgentError> for Problem {
    fn from(err: AgentError) -> Self {
        match err {
            AgentError::Invalid(msg) => Problem::handler(http::StatusCode::BAD_REQUEST, msg),
            AgentError::NotFound(msg) => Problem::handler(http::StatusCode::NOT_FOUND, msg),
            AgentError::Conflict(msg) => Problem::handler(http::StatusCode::CONFLICT, msg),
            AgentError::PreconditionFailed(msg) => Problem::handler(http::StatusCode::PRECONDITION_FAILED, msg),
            AgentError::Forbidden(msg) => Problem::handler(http::StatusCode::FORBIDDEN, msg),
            AgentError::Unauthorized(msg) => Problem::handler(http::StatusCode::UNAUTHORIZED, msg),
            AgentError::Unexpected(failure) => {
                let reference = uuid::Uuid::new_v4().as_hyphenated().to_string();
                tracing::error!(reference = %reference, error = %failure, "Unexpected failure in agents module");
                Problem::handler(
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An unexpected error occurred. Quote reference {reference} to your administrator."),
                )
                .with("correlationId", reference)
            }
        }
    }
}
