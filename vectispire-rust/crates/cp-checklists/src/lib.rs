//! `vectispire-cp-checklists` — the `checklists` module: the organisation's checklist templates, their versions and
//! their items, each project's checklist answered against them by people and, on its measured lines, by
//! Vectispire, and the rules that measure them (decision 0032).
//!
//! Its vocabulary (stage 1a) and its workbook (stage 1b), ported from `common.domain.checklists` and held to Java's
//! answers in `reference/checklists/`: the normalised text an item's key and content digest are computed over, the
//! rule's canonical form whose SHA-256 a measurement names, the evaluation and the evidence a sign-off freezes, the
//! reminders (`tests/reference_set.rs`); the `.xlsx` read as the JDK reads it, the layout proposed and confirmed, the
//! version, and the filled workbook written to the same bytes as Java's (`tests/workbook_reference_set.rs`). The
//! services, persistence and routes come after it.
//! What other modules build — the measurement facts, a forge's review reading — is `vectispire_domain::checklists`.

#![forbid(unsafe_code)]

pub mod allowed_component;
pub mod answer;
mod carried;
pub mod cell;
pub mod contact_service;
pub mod contacts;
pub mod coverage_scope;
pub mod days;
pub mod decimal;
pub mod document_zip;
pub mod documents;
pub mod error;
pub mod evaluation;
pub mod forms;
mod internal;
pub mod item;
pub mod layout;
mod links;
pub mod measurement;
pub mod measurer;
pub mod node;
pub mod pairing;
mod persistence;
pub mod ports;
pub mod project_checklists;
pub mod reminder;
pub mod renderer;
pub mod rule;
mod safe_xml;
pub mod source_languages;
pub mod statement;
pub mod suite_pattern;
pub mod templates;
pub mod text;
pub mod tool_scope;
pub mod trials;
pub mod views;
mod web;
pub mod workbook;
pub mod workbook_reader;
mod xml_cursor;
mod zip_input;

pub use internal::owners::{AccessAccounts, OwnerCatalogs, PlatformSigner, TargetProjects};
pub use internal::reactions::{
    ANSWER_MESSAGE, AnswersFromEvidence, ChecklistAnswerDelivery, ChecklistPurge, ChecklistReminderTask,
};
pub use vectispire_domain::bounded_text::Refused;
pub use vectispire_domain::checklists::Defect;
pub use web::{ChecklistServices, routes};

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
    sha256_hex_bytes(text.as_bytes())
}

/// `Digests.sha256Hex(byte[])`: SHA-256 of the bytes, lowercase hex.
pub(crate) fn sha256_hex_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}
