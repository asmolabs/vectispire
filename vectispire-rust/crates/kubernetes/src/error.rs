//! `KubernetesException`.

/// The API server refused, failed, or could not be reached.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct KubernetesError {
    pub message: String,
    /// The HTTP status it answered, or 0 when there was no answer to read one from.
    pub status: u16,
}

impl KubernetesError {
    pub fn new(message: impl Into<String>, status: u16) -> KubernetesError {
        KubernetesError { message: message.into(), status }
    }

    /// No answer to read a status from: unreachable, broken, late.
    pub fn unanswered(message: impl Into<String>) -> KubernetesError {
        KubernetesError::new(message, 0)
    }
}
