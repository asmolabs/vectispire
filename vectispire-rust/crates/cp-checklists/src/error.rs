//! What a checklist service refuses with — `InvalidInputException` (400), `NotFoundException` (404),
//! `ChecklistConflict` (409, its cause in the problem's `type`), `AccessDeniedException` (the chain's 403),
//! `ApproverNotIndependentException` (409), `ChecklistFileTooLargeException` (413) — or a failure (500).

use serde::Serialize;
use vectispire_cp_access::independence::IndependenceError;
use vectispire_domain::checklists::Defect;

use crate::Refused;
use crate::persistence::StoreError;
use crate::renderer::{RenderFailure, WrittenFormula};

/// `ChecklistConflict.Cause`: why a checklist write was refused for the state it found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Changed,
    LineChanged,
    NotDraft,
    NotSubmitted,
    NotSignedOff,
    NotLatest,
    Incomplete,
    FourEyes,
    VersionNotPublished,
    SameVersion,
    VersionUnrenderable,
    NothingToConfirm,
    EvidenceWithdrawn,
    MeasurementContradicted,
    MeasurementChanged,
    TemplateNotDraft,
    TemplateNoLayout,
    TemplateChanged,
    TemplateHasDraft,
    TemplateNotPublished,
    TemplateRetired,
    TemplateNothingToPair,
    TemplateUnrenderable,
}

impl Cause {
    /// What the problem's `type` ends with, after `urn:vectispire:problem:`.
    pub fn token(self) -> &'static str {
        match self {
            Cause::Changed => "checklist-changed",
            Cause::LineChanged => "checklist-line-changed",
            Cause::NotDraft => "checklist-not-draft",
            Cause::NotSubmitted => "checklist-not-submitted",
            Cause::NotSignedOff => "checklist-not-signed-off",
            Cause::NotLatest => "checklist-not-latest",
            Cause::Incomplete => "checklist-incomplete",
            Cause::FourEyes => "checklist-four-eyes",
            Cause::VersionNotPublished => "checklist-version-not-published",
            Cause::SameVersion => "checklist-same-version",
            Cause::VersionUnrenderable => "checklist-version-unrenderable",
            Cause::NothingToConfirm => "checklist-nothing-to-confirm",
            Cause::EvidenceWithdrawn => "checklist-evidence-withdrawn",
            Cause::MeasurementContradicted => "checklist-measurement-contradicted",
            Cause::MeasurementChanged => "checklist-measurement-changed",
            Cause::TemplateNotDraft => "checklist-template-not-draft",
            Cause::TemplateNoLayout => "checklist-template-no-layout",
            Cause::TemplateChanged => "checklist-template-changed",
            Cause::TemplateHasDraft => "checklist-template-has-draft",
            Cause::TemplateNotPublished => "checklist-template-not-published",
            Cause::TemplateRetired => "checklist-template-retired",
            Cause::TemplateNothingToPair => "checklist-template-nothing-to-pair",
            Cause::TemplateUnrenderable => "checklist-template-unrenderable",
        }
    }
}

/// `ChecklistConflict.IncompleteLine`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncompleteLine {
    pub item_id: i64,
    pub position: i32,
    pub problems: Vec<String>,
}

/// `ChecklistConflict.MeasuredLine`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasuredLine {
    pub item_id: i64,
    pub position: i32,
    pub answer: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub submitted_outcome: Option<String>,
    pub submitted_reason: Option<String>,
}

/// `ChecklistConflict.UnrenderableCell`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnrenderableCell {
    pub cell: String,
    pub kind: String,
    pub range: String,
}

impl UnrenderableCell {
    pub fn all(written: &WrittenFormula) -> Vec<UnrenderableCell> {
        written
            .cells
            .iter()
            .map(|cell| UnrenderableCell {
                cell: cell.cell.clone(),
                kind: cell.kind.clone(),
                range: cell.range.clone(),
            })
            .collect()
    }
}

/// The members a 409 names its lines or cells in, beside the problem's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Members {
    None,
    Incomplete(Vec<IncompleteLine>),
    Measured(Vec<MeasuredLine>),
    Cells(Vec<UnrenderableCell>),
}

/// `ChecklistConflict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub cause: Cause,
    pub message: String,
    pub members: Members,
}

/// Every refusal and failure of the module's services.
#[derive(Debug, thiserror::Error)]
pub enum ChecklistError {
    /// `InvalidInputException`: 400.
    #[error("{0}")]
    Invalid(String),
    /// `NotFoundException`: 404.
    #[error("{0}")]
    NotFound(String),
    /// `ChecklistConflict`: 409.
    #[error("{}", .0.message)]
    Conflict(Box<Conflict>),
    /// `AccessDeniedException`: the chain's 403, audited.
    #[error("{0}")]
    AccessDenied(String),
    /// `ApproverNotIndependentException`, or the independence that could not be read.
    #[error(transparent)]
    Independence(#[from] IndependenceError),
    /// `ChecklistFileTooLargeException`: 413, the ceiling in bytes.
    #[error("The request body is larger than the {0} bytes this route accepts.")]
    TooLarge(i64),
    /// A row that does not read back, a store that did not answer: 500.
    #[error("{0}")]
    Failed(String),
}

impl ChecklistError {
    pub fn conflict(cause: Cause, message: impl Into<String>) -> ChecklistError {
        ChecklistError::Conflict(Box::new(Conflict { cause, message: message.into(), members: Members::None }))
    }

    pub fn conflict_with(cause: Cause, message: impl Into<String>, members: Members) -> ChecklistError {
        ChecklistError::Conflict(Box::new(Conflict { cause, message: message.into(), members }))
    }

    pub fn invalid(message: impl Into<String>) -> ChecklistError {
        ChecklistError::Invalid(message.into())
    }

    pub fn not_found(message: impl Into<String>) -> ChecklistError {
        ChecklistError::NotFound(message.into())
    }

    /// `IllegalStateException`: a defect, answered 500.
    pub fn defect(message: impl Into<String>) -> ChecklistError {
        ChecklistError::Failed(message.into())
    }

    /// The cause token of a conflict, for a test or a log.
    pub fn cause(&self) -> Option<Cause> {
        match self {
            ChecklistError::Conflict(conflict) => Some(conflict.cause),
            _ => None,
        }
    }
}

impl From<StoreError> for ChecklistError {
    fn from(error: StoreError) -> ChecklistError {
        ChecklistError::Failed(error.to_string())
    }
}

impl From<Refused> for ChecklistError {
    fn from(refused: Refused) -> ChecklistError {
        ChecklistError::Invalid(refused.0)
    }
}

impl From<Defect> for ChecklistError {
    fn from(defect: Defect) -> ChecklistError {
        ChecklistError::Failed(defect.0)
    }
}

impl From<crate::Failure> for ChecklistError {
    fn from(failure: crate::Failure) -> ChecklistError {
        match failure {
            crate::Failure::Refused(refused) => ChecklistError::Invalid(refused.0),
            crate::Failure::Defect(defect) => ChecklistError::Failed(defect.0),
        }
    }
}

impl From<RenderFailure> for ChecklistError {
    fn from(failure: RenderFailure) -> ChecklistError {
        match failure {
            RenderFailure::Refused(refused) => ChecklistError::Invalid(refused.0),
            other => ChecklistError::Failed(other.to_string()),
        }
    }
}
