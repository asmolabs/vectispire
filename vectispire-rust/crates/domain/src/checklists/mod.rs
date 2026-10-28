//! What the checklists' rules read of a project, as the owners of the evidence hand it over (decision 0032 §6) —
//! `common.domain.checklists`' shared part: `forges` builds a [`ChangeReviewEvidence`] and the [`Look`] it was read
//! at, the checklists module asks every other owner and judges. The rules themselves are `vectispire-cp-checklists`'.

pub mod facts;
pub mod jackson;
pub mod review;

pub use facts::{Look, MeasurementFacts, Source};
pub use review::ChangeReviewEvidence;

/// A stored form that does not read back — Java's `IllegalStateException`: a defect, never the caller's input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Defect(pub String);
