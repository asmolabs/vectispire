//! The declaration of applicability — Java's `StatementOfApplicabilityService`: storage, validation and the audit
//! entry. The reconciliation itself is pure and lives in [`crate::soa`]: the rule deciding what counts as a
//! contradiction is the part somebody argues with in a meeting, and it is testable without a database.

use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use vectispire_cp_audit::{AuditLog, AuditOperation, Record};
use vectispire_cp_db::{Db, Visibility};
use vectispire_cp_targets::Clock;
use vectispire_domain::bounded_text;
use vectispire_domain::instant::Instant;
use vectispire_domain::java;

use crate::decisions::{
    Applicability, ComplianceFramework, Declaration, EvidenceSource, Implementation, SoaStatement, reconcile,
};
use crate::error::ComplianceError;
use crate::matrix::{ComplianceService, instant};
use crate::persistence::repository::DeclarationRepository;
use crate::persistence::{self, DeclarationRow};

/// The width of `control_id`.
const CONTROL_ID_LENGTH: usize = 64;
/// The width of `control_owner`.
const OWNER_LENGTH: usize = 255;
/// `Triage.MAX_REVIEW_DAYS`: the ceiling a triage's own review delay has, either side of today.
const MAX_REVIEW_DAYS: i64 = 3650;

/// What an operator submits for one control — `Submission`. `review_due_at` absent leaves the line unscheduled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub applicability: Option<Applicability>,
    pub justification: Option<String>,
    pub implementation: Option<Implementation>,
    pub evidence_source: Option<EvidenceSource>,
    pub external_evidence: Option<String>,
    pub owner: Option<String>,
    pub review_due_at: Option<Instant>,
}

#[derive(Clone)]
pub struct StatementOfApplicabilityService {
    db: Db,
    compliance: ComplianceService,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for StatementOfApplicabilityService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("StatementOfApplicabilityService").finish_non_exhaustive()
    }
}

impl StatementOfApplicabilityService {
    pub fn new(
        db: Db,
        compliance: ComplianceService,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
    ) -> StatementOfApplicabilityService {
        StatementOfApplicabilityService { db, compliance, audit, clock }
    }

    /// One framework's declaration, reconciled against its evaluation. **The allowance narrows the measurement, never
    /// the declaration**: a declaration belongs to nobody's estate, the evaluation it is set against is the caller's.
    pub async fn statement(
        &self,
        framework: ComplianceFramework,
        allowed: &Visibility,
    ) -> Result<SoaStatement, ComplianceError> {
        let evaluation = self.compliance.evaluation(framework, allowed).await?;
        let declared = self.declarations(framework.name()).await?;
        Ok(reconcile(&evaluation, &declared, instant(self.clock.now())))
    }

    /// Every framework's declaration, in the enum's order. Java reads the summary once per framework; it is read once
    /// here — the same estate, so the same six evaluations, without five more passes over it.
    pub async fn statements(&self, allowed: &Visibility) -> Result<Vec<SoaStatement>, ComplianceError> {
        let summary = self.compliance.summary(allowed).await?;
        let now = instant(self.clock.now());
        let mut statements = Vec::with_capacity(ComplianceFramework::ALL.len());
        for framework in ComplianceFramework::ALL {
            let evaluation = summary
                .evaluations
                .iter()
                .find(|evaluation| evaluation.framework == framework)
                .ok_or_else(|| ComplianceError::unexpected(format!("no evaluation of {}", framework.name())))?;
            let declared = self.declarations(framework.name()).await?;
            statements.push(reconcile(evaluation, &declared, now));
        }
        Ok(statements)
    }

    /// One framework's declarations, whatever it is: the storage key, since the OWASP Top 10 is declared here without
    /// being a compliance framework.
    pub async fn declarations(&self, framework: &str) -> Result<Vec<Declaration>, ComplianceError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = DeclarationRepository::by_framework(&mut tx, framework).await?;
        persistence::commit(tx).await?;
        rows.iter().map(to_domain).collect()
    }

    /// Lines whose review has lapsed, across every framework, the most lapsed first.
    pub async fn review_overdue(&self) -> Result<Vec<Declaration>, ComplianceError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = DeclarationRepository::review_overdue(&mut tx, self.clock.now()).await?;
        persistence::commit(tx).await?;
        rows.iter().map(to_domain).collect()
    }

    /// `declare(ComplianceFramework, …)`: **checked against the framework's catalogue** — a mistyped control was a
    /// declaration nobody would ever see again, recorded under somebody's name. A 404, since the path names a control
    /// that does not exist.
    pub async fn declare(
        &self,
        framework: ComplianceFramework,
        control_id: &str,
        submission: Submission,
        actor: Option<&str>,
    ) -> Result<Declaration, ComplianceError> {
        if !framework.controls().iter().any(|control| control.id == control_id) {
            return Err(ComplianceError::NotFound(format!("{control_id} is not a control of {}.", framework.title())));
        }
        self.declare_key(framework.name(), control_id, submission, actor).await
    }

    /// `declare(String, …)`: writes or revises one line, then says so in the audit log.
    ///
    /// **Not one transaction with the audit entry**, as Java: persist, then audit, neither wrapping the other — the
    /// unique index on (framework, control) is the arbiter of two declarations in the same instant.
    pub async fn declare_key(
        &self,
        framework: &str,
        control_id: &str,
        submission: Submission,
        actor: Option<&str>,
    ) -> Result<Declaration, ComplianceError> {
        let (Some(applicability), Some(evidence_source)) = (submission.applicability, submission.evidence_source)
        else {
            return Err(invalid(
                "A declaration says two things at minimum: whether the control applies, and where its evidence lives.",
            ));
        };
        if applicability == Applicability::Applicable && submission.implementation.is_none() {
            return Err(invalid(
                "An applicable control needs an implementation state: claiming it applies and saying nothing about \
                 whether it is in place is the omission the document exists to close.",
            ));
        }
        if applicability == Applicability::Excluded && blank(submission.justification.as_deref()) {
            return Err(invalid("An excluded control needs a justification: ISO 27001 clause 6.1.3 d requires one."));
        }
        if evidence_source != EvidenceSource::Vectispire && blank(submission.external_evidence.as_deref()) {
            return Err(invalid(
                "Evidence held outside Vectispire must say where: name the document, register or review.",
            ));
        }
        // Each against its column, before the row is read: past them the database refused the write as a 500.
        bounded(Some(control_id), CONTROL_ID_LENGTH, "The control identifier")?;
        bounded(submission.owner.as_deref(), OWNER_LENGTH, "The control owner")?;
        bounded(submission.justification.as_deref(), bounded_text::TEXT_MAX, "The justification")?;
        bounded(submission.external_evidence.as_deref(), bounded_text::TEXT_MAX, "The external evidence")?;

        let now = self.clock.now();
        // A date already past stays accepted — it files the line as overdue, which is how an imported register says a
        // review was missed — but not one centuries away, which failed at the write as a 500.
        let due = submission.review_due_at.map(offset).transpose()?;
        if let Some(due) = due {
            let span = Duration::days(MAX_REVIEW_DAYS);
            let latest = now.checked_add(span);
            let earliest = now.checked_sub(span);
            if latest.is_none_or(|latest| due > latest) || earliest.is_none_or(|earliest| due < earliest) {
                return Err(invalid(&format!(
                    "The review date is at most {MAX_REVIEW_DAYS} days from today, either way."
                )));
            }
        }

        // An excluded control has nothing to implement: an implementation left on a line switched to excluded would
        // read as a claim the organisation withdrew.
        let implementation = if applicability == Applicability::Excluded { None } else { submission.implementation };
        let mut tx = persistence::write(&self.db).await?;
        let existing = DeclarationRepository::find(&mut tx, framework, control_id).await?;
        let row = DeclarationRow {
            id: existing.as_ref().map_or_else(|| uuid::Uuid::new_v4().to_string(), |row| row.id.clone()),
            framework: framework.to_owned(),
            control_id: control_id.to_owned(),
            applicability: wire(applicability)?,
            justification: submission.justification.clone(),
            implementation: implementation.map(wire).transpose()?,
            evidence_source: wire(evidence_source)?,
            external_evidence: submission.external_evidence.clone(),
            control_owner: submission.owner.clone(),
            decided_by: actor.map(str::to_owned),
            decided_at: now,
            // Writing the line *is* confirming it holds.
            reviewed_at: Some(now),
            review_due_at: due,
        };
        if existing.is_some() {
            DeclarationRepository::update(&mut tx, &row).await?;
        } else {
            DeclarationRepository::insert(&mut tx, &row).await?;
        }
        persistence::commit(tx).await?;

        self.audit
            .record(Record::of(
                AuditOperation::ControlDeclared,
                &format!("{framework}/{control_id}"),
                &describe(title_of(framework), control_id, &submission),
                actor,
            ))
            .await;

        // The line as saved in memory, as Java answers `toDomain(saved)`: the instants as given, not as the column
        // rounded them.
        Ok(Declaration {
            framework: row.framework,
            control_id: row.control_id,
            applicability: Some(applicability),
            justification: submission.justification,
            implementation,
            evidence_source: Some(evidence_source),
            external_evidence: submission.external_evidence,
            owner: submission.owner,
            decided_by: row.decided_by,
            decided_at: Some(instant(now)),
            reviewed_at: Some(instant(now)),
            review_due_at: submission.review_due_at,
        })
    }
}

/// A framework's readable name, or the key itself when it is not one — "Excluded A04 from OWASP_2021" is read by a
/// person; an entry that failed because the key is not a framework would lose the trace.
fn title_of(framework: &str) -> &str {
    match ComplianceFramework::from_name(framework) {
        Some(known) => known.title(),
        None => framework,
    }
}

fn describe(title: &str, control_id: &str, submission: &Submission) -> String {
    if submission.applicability == Some(Applicability::Excluded) {
        format!("Excluded {control_id} from {title}: {}", submission.justification.as_deref().unwrap_or("null"))
    } else {
        format!(
            "Declared {control_id} of {title} applicable, {}, evidenced {}",
            submission.implementation.map_or(Ok("null".to_owned()), wire).unwrap_or_default(),
            submission.evidence_source.map_or(Ok("null".to_owned()), wire).unwrap_or_default(),
        )
    }
}

/// `toDomain`: an enum this build does not know throws in Java (`valueOf`), a 500 — Java's comment says such a row is
/// dropped, and it is not; the 500 is kept.
fn to_domain(row: &DeclarationRow) -> Result<Declaration, ComplianceError> {
    Ok(Declaration {
        framework: row.framework.clone(),
        control_id: row.control_id.clone(),
        applicability: Some(parse(&row.applicability)?),
        justification: row.justification.clone(),
        implementation: row.implementation.as_deref().map(parse).transpose()?,
        evidence_source: Some(parse(&row.evidence_source)?),
        external_evidence: row.external_evidence.clone(),
        owner: row.control_owner.clone(),
        decided_by: row.decided_by.clone(),
        decided_at: Some(instant(row.decided_at)),
        reviewed_at: row.reviewed_at.map(instant),
        review_due_at: row.review_due_at.map(instant),
    })
}

fn parse<T: serde::de::DeserializeOwned>(name: &str) -> Result<T, ComplianceError> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .map_err(|_| ComplianceError::unexpected(format!("No enum constant {name}")))
}

fn wire<T: serde::Serialize>(value: T) -> Result<String, ComplianceError> {
    match serde_json::to_value(value).map_err(ComplianceError::unexpected)? {
        serde_json::Value::String(name) => Ok(name),
        other => Err(ComplianceError::unexpected(format!("not an enum name: {other}"))),
    }
}

fn offset(at: Instant) -> Result<OffsetDateTime, ComplianceError> {
    OffsetDateTime::from_unix_timestamp(at.epoch_second)
        .ok()
        .and_then(|seconds| seconds.replace_nanosecond(at.nano).ok())
        .ok_or_else(|| invalid(&format!("The review date is at most {MAX_REVIEW_DAYS} days from today, either way.")))
}

fn bounded(value: Option<&str>, max: usize, what: &str) -> Result<(), ComplianceError> {
    match bounded_text::too_long(value, max, what) {
        Some(refused) => Err(ComplianceError::Invalid(refused)),
        None => Ok(()),
    }
}

fn blank(value: Option<&str>) -> bool {
    value.is_none_or(java::is_blank)
}

fn invalid(message: &str) -> ComplianceError {
    ComplianceError::Invalid(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applicable(implementation: Implementation) -> Submission {
        Submission {
            applicability: Some(Applicability::Applicable),
            justification: None,
            implementation: Some(implementation),
            evidence_source: Some(EvidenceSource::Vectispire),
            external_evidence: None,
            owner: None,
            review_due_at: None,
        }
    }

    #[test]
    fn the_audit_sentence_names_the_claim_as_java_prints_it() {
        assert_eq!(
            describe("ISO/IEC 27001:2022", "ISO-A.8.8", &applicable(Implementation::PartiallyImplemented)),
            "Declared ISO-A.8.8 of ISO/IEC 27001:2022 applicable, PARTIALLY_IMPLEMENTED, evidenced VECTISPIRE"
        );
        let excluded = Submission {
            applicability: Some(Applicability::Excluded),
            justification: Some("no such system".to_owned()),
            ..applicable(Implementation::Implemented)
        };
        assert_eq!(describe("OWASP_2021", "A04", &excluded), "Excluded A04 from OWASP_2021: no such system");
    }

    #[test]
    fn a_key_that_is_no_framework_is_its_own_title() {
        assert_eq!(title_of("OWASP_2021"), "OWASP_2021");
        assert_eq!(title_of("ISO_27001"), ComplianceFramework::Iso27001.title());
    }
}
