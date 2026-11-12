//! What the sender raises when there is no answer — `OutboundJson.OutboundFailureException`.
//!
//! The messages are the Java sender's: they reach the notification log and the administrator who set
//! the URL, and they name the label of what was being sent, never what was in it.

/// Anything that is not an answer: a refusal to send unpinned, a connection that failed, an answer
/// past its ceiling, an exchange past its deadline.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct OutboundFailure {
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl OutboundFailure {
    pub fn new(message: impl Into<String>) -> OutboundFailure {
        OutboundFailure { message: message.into(), source: None }
    }

    pub fn caused_by(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> OutboundFailure {
        OutboundFailure { message: message.into(), source: Some(Box::new(source)) }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}
