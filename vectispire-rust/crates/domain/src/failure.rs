//! Whether another attempt could change a failure's outcome — `FailureKind` on the Java side.
//!
//! **The kind decides a scan's fate, the message only informs.** A failure report carries it to
//! the control plane, which retries a transient failure and gives up on a permanent one. A message
//! is written for a person and may be reworded; nothing may decide by reading it back.

/// What another attempt could change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// The same attempt will fail the same way until somebody changes something.
    Permanent,
    /// The next attempt may succeed. Every failure is transient when in doubt.
    Transient,
}

impl FailureKind {
    /// The spelling on the wire, as the Java enum's name is written.
    pub fn wire_name(self) -> &'static str {
        match self {
            FailureKind::Permanent => "PERMANENT",
            FailureKind::Transient => "TRANSIENT",
        }
    }
}

/// A failure that knows its kind.
pub trait Classified {
    /// Whether another attempt could succeed.
    fn failure_kind(&self) -> FailureKind;
}
