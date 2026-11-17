//! What an organisation says about each control, set against what the tooling measures — Java's
//! `StatementOfApplicability`.
//!
//! **The interesting artefact is the disagreement**: a control declared implemented that the estate measures
//! non-compliant is what an assessor writes up. And Vectispire measures a slice of each control, never the whole of
//! it, so a declaration says where its evidence lives, and a control evidenced elsewhere is
//! [`Divergence::NotMeasuredHere`] — an instruction to read the other document, not a finding.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::engine::ComplianceEvaluation;
use crate::framework::{ComplianceControl, ComplianceFramework, Status};
use crate::instant_text;
use vectispire_domain::instant::Instant;
use vectispire_domain::java;

/// Applicable, or excluded from the scope of the management system (clause 6.1.3 d, with a justification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Applicability {
    Applicable,
    Excluded,
}

/// How far the control has been put in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Implementation {
    Implemented,
    PartiallyImplemented,
    Planned,
    NotImplemented,
}

/// Where the evidence for the control lives — which decides whether this product's measurement is about the
/// declaration at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSource {
    Vectispire,
    External,
    Both,
}

/// One line of the declaration, as an organisation wrote it — `Declaration`.
///
/// `framework` is a string because it genuinely is one: the OWASP Top 10 is declared here too and is no compliance
/// framework. The enums are optional because the stored row is read as Java reads it, a column it does not know
/// being null; [`reconcile`] treats them as Java's null-safe comparisons do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Declaration {
    pub framework: String,
    pub control_id: String,
    pub applicability: Option<Applicability>,
    pub justification: Option<String>,
    pub implementation: Option<Implementation>,
    pub evidence_source: Option<EvidenceSource>,
    pub external_evidence: Option<String>,
    pub owner: Option<String>,
    pub decided_by: Option<String>,
    #[serde(with = "instant_text::option")]
    pub decided_at: Option<Instant>,
    #[serde(with = "instant_text::option")]
    pub reviewed_at: Option<Instant>,
    #[serde(with = "instant_text::option")]
    pub review_due_at: Option<Instant>,
}

impl Declaration {
    /// A review is due and has not happened: strictly before `now`, as `Instant.isBefore`.
    pub fn review_overdue(&self, now: Instant) -> bool {
        self.review_due_at.is_some_and(|due| due < now)
    }
}

/// What the declaration and the measurement do to each other — **ordered worst first**, so a sort puts what an
/// assessor opens with at the top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Divergence {
    /// Declared implemented; measured non-compliant. The finding.
    Contradicted,
    /// Excluded with no justification — clause 6.1.3 d requires one.
    ExcludedWithoutJustification,
    /// The framework has this control and the declaration does not mention it.
    Undeclared,
    /// Declared implemented; measured partial.
    Overstated,
    /// Evidenced here by the declaration's own account, and nothing here has measured it yet.
    Unevidenced,
    /// Declared planned or not implemented; measured compliant: the document drifted behind the practice.
    Understated,
    /// Evidenced outside this product: the model declining to have an opinion.
    NotMeasuredHere,
    /// Excluded, with a justification.
    NotApplicable,
    /// The declaration and the measurement agree.
    Consistent,
}

impl Divergence {
    /// Whether an assessment would raise this line.
    pub fn is_finding(self) -> bool {
        matches!(self, Divergence::Contradicted | Divergence::ExcludedWithoutJustification | Divergence::Undeclared)
    }
}

/// One control's line — `Line`. `declaration` is absent when the divergence is [`Divergence::Undeclared`];
/// `measured` is absent when the engine evaluated nothing for the control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Line {
    pub control: &'static ComplianceControl,
    pub declaration: Option<Declaration>,
    pub measured: Option<Status>,
    pub divergence: Divergence,
    pub review_overdue: bool,
}

/// One framework's statement — `SoaStatement`. `title` is the standard's own name, which an assessor reads;
/// `complete` is what clause 6.1.3 d asks for: every control addressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoaStatement {
    pub framework: ComplianceFramework,
    pub title: &'static str,
    pub lines: Vec<Line>,
    pub total: i32,
    pub declared: i32,
    pub findings: i32,
    pub reviews_overdue: i32,
    pub complete: bool,
}

/// Sets one framework's declaration against its evaluation — `reconcile`.
///
/// Driven by the framework's control list, so a control nobody declared appears as [`Divergence::Undeclared`]
/// instead of vanishing; a declaration naming a control the framework does not have, or another framework, is
/// dropped. Duplicates are resolved by the last one seen, as Java's `toMap` merge keeps the second.
pub fn reconcile(evaluation: &ComplianceEvaluation, declarations: &[Declaration], now: Instant) -> SoaStatement {
    let framework = evaluation.framework;
    let mut by_control: HashMap<&str, &Declaration> = HashMap::new();
    for declaration in declarations.iter().filter(|declaration| declaration.framework == framework.name()) {
        by_control.insert(declaration.control_id.as_str(), declaration);
    }
    let mut measured: HashMap<&str, Status> = HashMap::new();
    for assessment in &evaluation.controls {
        measured.insert(assessment.control.id, assessment.status);
    }

    let lines: Vec<Line> = framework
        .controls()
        .iter()
        .map(|control| {
            let declaration = by_control.get(control.id).copied();
            let status = measured.get(control.id).copied();
            Line {
                control,
                declaration: declaration.cloned(),
                measured: status,
                divergence: diverge(declaration, status),
                review_overdue: declaration.is_some_and(|declaration| declaration.review_overdue(now)),
            }
        })
        .collect();

    let count = |keep: &dyn Fn(&Line) -> bool| {
        i32::try_from(lines.iter().filter(|line| keep(line)).count()).unwrap_or(i32::MAX)
    };
    SoaStatement {
        framework,
        title: framework.title(),
        total: i32::try_from(lines.len()).unwrap_or(i32::MAX),
        declared: count(&|line| line.declaration.is_some()),
        findings: count(&|line| line.divergence.is_finding()),
        reviews_overdue: count(&|line| line.review_overdue),
        complete: lines.iter().all(|line| line.declaration.is_some()),
        lines,
    }
}

/// **The order of the tests is the model.** Absence first; then exclusion, which ends the question; then where the
/// evidence lives, which decides whether the measurement is about this claim at all; then whether anything here
/// measured it — a claim set against nothing agrees with nothing; only then are the two compared.
fn diverge(declaration: Option<&Declaration>, measured: Option<Status>) -> Divergence {
    let Some(declaration) = declaration else {
        return Divergence::Undeclared;
    };
    if declaration.applicability == Some(Applicability::Excluded) {
        return if declaration.justification.as_deref().is_none_or(java::is_blank) {
            Divergence::ExcludedWithoutJustification
        } else {
            Divergence::NotApplicable
        };
    }
    if declaration.evidence_source == Some(EvidenceSource::External) {
        return Divergence::NotMeasuredHere;
    }
    let Some(measured) = measured.filter(|status| status.measured()) else {
        return Divergence::Unevidenced;
    };
    match declaration.implementation {
        None | Some(Implementation::PartiallyImplemented) => Divergence::Consistent,
        Some(Implementation::Implemented) => match measured {
            Status::NonCompliant => Divergence::Contradicted,
            Status::Partial => Divergence::Overstated,
            Status::Compliant => Divergence::Consistent,
            Status::NoData => Divergence::Unevidenced,
        },
        Some(Implementation::Planned | Implementation::NotImplemented) => {
            if measured == Status::Compliant {
                Divergence::Understated
            } else {
                Divergence::Consistent
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decisions::engine::ControlAssessment;

    fn evaluation(status: Status) -> ComplianceEvaluation {
        let controls = ComplianceFramework::Iso27001
            .controls()
            .iter()
            .map(|control| ControlAssessment {
                control,
                status,
                score_percentage: 0,
                details: String::new(),
                remediation_guidance: String::new(),
            })
            .collect();
        ComplianceEvaluation {
            framework: ComplianceFramework::Iso27001,
            score_percentage: 0,
            overall_status: status,
            controls,
        }
    }

    fn declared(control: &str, implementation: Implementation) -> Declaration {
        Declaration {
            framework: "ISO_27001".to_owned(),
            control_id: control.to_owned(),
            applicability: Some(Applicability::Applicable),
            justification: Some("in scope".to_owned()),
            implementation: Some(implementation),
            evidence_source: Some(EvidenceSource::Vectispire),
            external_evidence: None,
            owner: None,
            decided_by: None,
            decided_at: None,
            reviewed_at: None,
            review_due_at: None,
        }
    }

    #[test]
    fn the_contradiction_is_the_finding_and_an_unscanned_control_is_unevidenced() {
        let now = Instant::of_epoch_second(0);
        let declarations = [declared("ISO-A.8.8", Implementation::Implemented)];
        let contradicted = reconcile(&evaluation(Status::NonCompliant), &declarations, now);
        assert_eq!(contradicted.lines.first().map(|line| line.divergence), Some(Divergence::Contradicted));
        assert_eq!(contradicted.findings, 4, "the contradiction and the three undeclared controls");
        assert!(!contradicted.complete);
        let unevidenced = reconcile(&evaluation(Status::NoData), &declarations, now);
        assert_eq!(unevidenced.lines.first().map(|line| line.divergence), Some(Divergence::Unevidenced));
    }

    #[test]
    fn the_divergences_are_ordered_worst_first() {
        assert!(Divergence::Contradicted < Divergence::Undeclared);
        assert!(Divergence::Unevidenced < Divergence::Consistent);
    }
}
