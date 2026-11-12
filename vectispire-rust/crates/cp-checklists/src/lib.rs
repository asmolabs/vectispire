//! `vectispire-cp-checklists` — the `checklists` module: the organisation's checklist templates, their versions and
//! their items, each project's checklist answered against them by people and, on its measured lines, by
//! Vectispire, and the rules that measure them (decision 0032).
//!
//! This first part is the module's vocabulary, ported from `common.domain.checklists` and held to Java's answers in
//! `reference/checklists/` (`tests/reference_set.rs`): the normalised text an item's key and content digest are
//! computed over, the rule's canonical form whose SHA-256 a measurement names, the evaluation and the evidence a
//! sign-off freezes, the reminders. The workbook reader and renderer, the services and the routes come after it.
//! What other modules build — the measurement facts, a forge's review reading — is `vectispire_domain::checklists`.

#![forbid(unsafe_code)]

pub mod allowed_component;
pub mod answer;
pub mod contacts;
pub mod coverage_scope;
pub mod decimal;
pub mod evaluation;
pub mod item;
pub mod measurement;
pub mod node;
pub mod pairing;
pub mod reminder;
pub mod rule;
pub mod source_languages;
pub mod suite_pattern;
pub mod text;
pub mod tool_scope;

pub use vectispire_domain::bounded_text::Refused;
pub use vectispire_domain::checklists::Defect;

/// What a constructor of this vocabulary refuses with: the caller's input refused in words
/// (`InvalidInputException`, a 400), or a defect (`IllegalArgumentException`, `IllegalStateException`) — a stored
/// form that does not read, an argument no caller should pass.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    #[error("{0}")]
    Refused(Refused),
    #[error("{0}")]
    Defect(Defect),
}

impl From<Refused> for Failure {
    fn from(refused: Refused) -> Failure {
        Failure::Refused(refused)
    }
}

impl From<Defect> for Failure {
    fn from(defect: Defect) -> Failure {
        Failure::Defect(defect)
    }
}

/// `InvalidInputException(message)`.
pub(crate) fn refused(message: impl Into<String>) -> Refused {
    Refused(message.into())
}

/// `Digests.sha256Hex`: SHA-256 of the UTF-8 bytes, lowercase hex.
pub(crate) fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}
