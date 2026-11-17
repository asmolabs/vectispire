//! `ChecklistDocumentService`: a revision's document — the organisation's workbook filled in, `checklist.json`, and,
//! once signed off, their detached signatures (decision 0032 §10).
//!
//! **Signed inside the sign-off, served as stored**: a signed-off revision's package is rendered and signed in the
//! sign-off's own transaction and served as those bytes ever after. Any other revision renders on request, unsigned,
//! its `Evidence` sheet opening with the draft banner. **The whole project, or nothing**, and a closed revision's
//! document only to a reader who sees every repository its stored measurements carry.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_access::rows::VisibleProject;
use vectispire_cp_access::visibility::Allowance;
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_db::{Db, Tx};
use vectispire_domain::bounded_text;

use crate::answer::{AnswerWords, ChecklistAnswer};
use crate::days;
use crate::document_zip::{self, Entry};
use crate::error::ChecklistError;
use crate::forms;
use crate::layout::ChecklistLayout;
use crate::measurement::{Measurement, MeasurementOutcome, Reconciliation};
use crate::measurer::Measurer;
use crate::persistence::{self as rows, ChecklistRow, DocumentRow, MeasurementRow, TemplateRow, VersionRow};
use crate::ports::{DocumentSigner, ProjectDirectory};
use crate::project_checklists::{Purpose, Status, require_whole, template_of, version_of};
use crate::renderer;
use crate::statement::{self, ChecklistStatement};
use crate::templates::Clock;
use crate::views::DocumentDownload;

pub const WORKBOOK: &str = "checklist.xlsx";
pub const STATEMENT: &str = "checklist.json";
pub const SIGNATURE: &str = ".sig";
/// Column `t_checklist_document.product_version`.
const MAX_PRODUCT_VERSION: usize = 100;

type Result<T> = std::result::Result<T, ChecklistError>;

/// The service.
pub struct Documents {
    db: Db,
    projects: Arc<dyn ProjectDirectory>,
    measurer: Measurer,
    signer: Arc<dyn DocumentSigner>,
    product_version: Option<String>,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Documents {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Documents").finish_non_exhaustive()
    }
}

/// The two parts of a document.
struct Rendered {
    workbook: Vec<u8>,
    statement: Vec<u8>,
}

impl Documents {
    pub fn new(
        db: Db,
        projects: Arc<dyn ProjectDirectory>,
        measurer: Measurer,
        signer: Arc<dyn DocumentSigner>,
        product_version: Option<String>,
        audit: Arc<AuditLog>,
        clock: Arc<dyn Clock>,
    ) -> Documents {
        Documents { db, projects, measurer, signer, product_version, audit, clock }
    }

    /// `export`: the stored, signed package of a signed-off revision, or an unsigned rendering of any other. Audited
    /// as `CHECKLIST_EXPORTED` once handed over.
    pub async fn export(
        &self,
        project_id: i64,
        revision: i32,
        allowance: &Allowance,
        actor: &RequestActor,
    ) -> Result<DocumentDownload> {
        let guarded = require_whole(self.projects.as_ref(), project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = rows::begin(&self.db, false).await?;
        let checklist = rows::checklist_revision(&mut tx, project.project_id, revision)
            .await?
            .ok_or_else(|| absent(project, revision))?;
        // A closed revision's document is its stored measurements' — and they may carry a repository the project
        // has dropped since.
        if !Status::of_stored(&checklist.status)?.is_open() {
            let stored = stored_measurements(&mut tx, &checklist).await?;
            if !crate::carried::seen_by(&crate::carried::of(stored.values()), allowance) {
                return Err(absent(project, revision));
            }
        }
        let stored = rows::document_of(&mut tx, checklist.id).await?;
        let signed = stored.is_some();
        let content = match stored {
            Some(document) => document.content,
            None => {
                let rendered =
                    self.render(&mut tx, project, &guarded.repository_ids, &checklist, false, self.clock.now()).await?;
                zip(vec![(WORKBOOK, rendered.workbook), (STATEMENT, rendered.statement)])?
            }
        };
        drop(tx);
        let sha256 = crate::sha256_hex_bytes(&content);
        self.audit
            .record(actor.entry(
                AuditOperation::ChecklistExported,
                &format!("{}/{revision}", project.project_id),
                &format!(
                    "Checklist of project \"{}\", revision {revision} ({}) downloaded: {}, SHA-256 {sha256}.",
                    project.name,
                    checklist.status,
                    if signed { "the package signed at its sign-off" } else { "rendered unsigned" }
                ),
            ))
            .await;
        Ok(DocumentDownload {
            file_name: format!("checklist-project-{}-revision-{revision}.zip", project.project_id),
            signed,
            sha256,
            content,
        })
    }

    /// Loads the signing key — or creates it, the first time — before the sign-off's transaction opens.
    pub(crate) async fn require_signing_key(&self) -> Result<()> {
        self.signer.key_id().await.map(|_| ()).map_err(ChecklistError::Failed)
    }

    /// `produceSigned`: renders, signs and stores the document **in the caller's transaction** — the sign-off's.
    /// The package's SHA-256.
    pub(crate) async fn produce_signed(
        &self,
        tx: &mut Tx,
        checklist_id: i64,
        project: &VisibleProject,
        repository_ids: &[i64],
    ) -> Result<String> {
        let checklist = rows::checklist_by_id(tx, checklist_id)
            .await?
            .ok_or_else(|| ChecklistError::defect(format!("Checklist {checklist_id} is gone.")))?;
        let Some(signed_off_at) = checklist.signed_off_at.filter(|_| checklist.status == Status::SignedOff.wire_name())
        else {
            return Err(ChecklistError::defect(format!(
                "Revision {} is {}: only a signed-off revision's document is signed.",
                checklist.revision, checklist.status
            )));
        };
        let rendered = self.render(tx, project, repository_ids, &checklist, true, signed_off_at.0).await?;
        let workbook_signature = self.signer.sign(&rendered.workbook).await.map_err(ChecklistError::Failed)?;
        let statement_signature = self.signer.sign(&rendered.statement).await.map_err(ChecklistError::Failed)?;
        let workbook_sha256 = crate::sha256_hex_bytes(&rendered.workbook);
        let statement_sha256 = crate::sha256_hex_bytes(&rendered.statement);
        // The detached signatures as cosign writes them — base64 text.
        let content = zip(vec![
            (WORKBOOK, rendered.workbook),
            (STATEMENT, rendered.statement),
            ("checklist.xlsx.sig", workbook_signature.clone().into_bytes()),
            ("checklist.json.sig", statement_signature.clone().into_bytes()),
        ])?;
        let sha256 = crate::sha256_hex_bytes(&content);
        let document = DocumentRow {
            id: 0,
            checklist_id: checklist.id,
            project_id: checklist.project_id,
            size_bytes: i64::try_from(content.len()).unwrap_or(i64::MAX),
            content,
            sha256: sha256.clone(),
            workbook_sha256,
            workbook_signature,
            statement_sha256,
            statement_signature,
            signing_key_id: self.signer.key_id().await.map_err(ChecklistError::Failed)?,
            product_version: self
                .product_version
                .as_deref()
                .and_then(|version| bounded_text::clip(Some(version), MAX_PRODUCT_VERSION))
                .map(str::to_owned),
            produced_at: signed_off_at,
        };
        rows::insert_document(tx, &document).await?;
        Ok(sha256)
    }

    async fn render(
        &self,
        tx: &mut Tx,
        project: &VisibleProject,
        repository_ids: &[i64],
        checklist: &ChecklistRow,
        signed: bool,
        now: OffsetDateTime,
    ) -> Result<Rendered> {
        let version = version_of(tx, checklist).await?;
        let template = template_of(tx, &version).await?;
        let layout = forms::layout_of(version.layout.as_deref().unwrap_or("null"))?;
        let statement =
            self.statement(tx, project, repository_ids, checklist, &version, &template, &layout, signed, now).await?;
        let source = rows::source_bytes(tx, version.id)
            .await?
            .ok_or_else(|| ChecklistError::defect(format!("Template version {} is gone.", version.id)))?;
        let workbook = renderer::render(&source, &layout, &statement)?;
        Ok(Rendered { workbook, statement: statement.to_json() })
    }

    #[allow(clippy::too_many_arguments)]
    async fn statement(
        &self,
        tx: &mut Tx,
        project: &VisibleProject,
        repository_ids: &[i64],
        checklist: &ChecklistRow,
        version: &VersionRow,
        template: &TemplateRow,
        layout: &ChecklistLayout,
        signed: bool,
        now: OffsetDateTime,
    ) -> Result<ChecklistStatement> {
        let words = layout.answers();
        let lines = rows::items_of(tx, version.id).await?;
        let mut given: HashMap<i64, Vec<statement::Answer>> = HashMap::new();
        for row in rows::answers_of(tx, checklist.id).await? {
            given.entry(row.item_id).or_default().push(answer(&row, words)?);
        }
        let mut proofs: HashMap<i64, Vec<statement::Proof>> = HashMap::new();
        for row in rows::evidence_of(tx, checklist.id).await? {
            proofs.entry(row.item_id).or_default().push(statement::Proof {
                id: row.id,
                kind: row.kind.clone(),
                link: row.link.clone(),
                file_name: row.file_name.clone(),
                media_type: row.media_type.clone(),
                size: row.file_size,
                sha256: row.file_sha256.clone(),
                performed_on: Some(days::local(days::day_of(row.performed_on.0))),
                valid_until: row.valid_until.map(|until| days::local(days::day_of(until.0))),
                added_by: Some(row.added_by.clone()),
                added_at: Some(days::instant(row.added_at.0)),
                withdrawn_by: row.withdrawn_by.clone(),
                withdrawn_at: row.withdrawn_at.map(|at| days::instant(at.0)),
            });
        }
        let measured = self.measured(tx, checklist, &lines, repository_ids, now).await?;
        let mut statement_lines = Vec::with_capacity(lines.len());
        for item in &lines {
            let history = given.remove(&item.id).unwrap_or_default();
            let current = history.last().filter(|last| !last.withdrawn).cloned();
            let measurement = measured.get(&item.id).cloned();
            let reconciliation = match &measurement {
                None => Reconciliation::NotMeasuredHere,
                Some(found) => Reconciliation::of(
                    current.as_ref().map(|answer| ChecklistAnswer::parse(Some(&answer.value))).transpose()?,
                    MeasurementOutcome::of_stored(&found.outcome),
                ),
            };
            statement_lines.push(statement::Line {
                item_id: item.id,
                key: item.item_key.clone(),
                position: item.position,
                row: item.sheet_row,
                domain: item.domain.clone(),
                objective: item.objective.clone(),
                control: item.control.clone(),
                contact: item.contact.clone(),
                kpi: item.kpi.clone(),
                content_digest: item.content_digest.clone(),
                evidence_required: item.evidence_kind.clone(),
                evidence_validity_months: item.evidence_validity_months,
                answer: current,
                history,
                measurement,
                reconciliation: Some(reconciliation.wire_name().to_owned()),
                evidence: proofs.remove(&item.id).unwrap_or_default(),
            });
        }
        // A returned revision was submitted once and is not any more: its submission is named only while it stands.
        let submission_stands = checklist
            .submitted_at
            .is_some_and(|submitted| checklist.returned_at.is_none_or(|returned| submitted.0 > returned.0));
        let act = |by: Option<&String>, at: Option<rows::StoredInstant>| {
            at.map(|at| statement::Act { by: by.cloned().unwrap_or_default(), at: days::instant(at.0) })
        };
        Ok(ChecklistStatement {
            form: statement::FORM,
            status: checklist.status.clone(),
            signed,
            project: statement::Project { id: project.project_id, name: project.name.clone() },
            revision: checklist.revision,
            template: statement::Template {
                slug: template.slug.clone(),
                name: template.name.clone(),
                version: version.ordinal,
                label: version.label.clone(),
                source_sha256: version.source_sha256.clone(),
            },
            header: statement::Header {
                product: project.name.clone(),
                author: Some(checklist.author.clone()),
                date: checklist.signed_off_at.map(|at| days::instant(at.0)),
            },
            opened: statement::Act { by: checklist.opened_by.clone(), at: days::instant(checklist.opened_at.0) },
            submitted: if submission_stands {
                act(checklist.submitted_by.as_ref(), checklist.submitted_at)
            } else {
                None
            },
            signed_off: act(checklist.signed_off_by.as_ref(), checklist.signed_off_at),
            four_eyes_required: checklist.sign_off_four_eyes,
            product_version: self.product_version.clone(),
            produced_at: days::instant(now),
            lines: statement_lines,
        })
    }

    /// Each measured line's measurement: measured now for a draft or a submitted revision, the stored one otherwise.
    async fn measured(
        &self,
        tx: &mut Tx,
        checklist: &ChecklistRow,
        lines: &[rows::ItemRow],
        repository_ids: &[i64],
        now: OffsetDateTime,
    ) -> Result<BTreeMap<i64, statement::Measured>> {
        let mut measured = BTreeMap::new();
        if matches!(Status::of_stored(&checklist.status)?, Status::Draft | Status::Submitted) {
            for line in self.measurer.measure_all(repository_ids, lines, days::instant(now)).await? {
                let found = &line.measurement;
                measured.insert(
                    line.item.id,
                    statement::Measured {
                        purpose: Purpose::Read.wire_name().to_owned(),
                        rule_kind: line.rule.kind().wire_name().to_owned(),
                        rule_digest: line.rule.digest(),
                        rule: Some(line.rule.canonical()),
                        outcome: found.outcome.wire_name().to_owned(),
                        reason: found.reason.map(|reason| reason.wire_name().to_owned()),
                        as_of: found.as_of,
                        computed_at: Some(days::instant(now)),
                        summary: found.summary.clone(),
                        evidence_digest: found.evidence_digest(),
                        evidence: Some(found.evidence_json()),
                    },
                );
            }
            return Ok(measured);
        }
        for (item_id, row) in stored_measurements(tx, checklist).await? {
            measured.insert(
                item_id,
                statement::Measured {
                    purpose: row.purpose.clone(),
                    rule_kind: row.rule_kind.clone(),
                    rule_digest: row.rule_digest.clone(),
                    rule: Some(row.bound_rule.clone()),
                    outcome: row.outcome.clone(),
                    reason: row.reason.clone(),
                    as_of: row.as_of.map(|at| days::instant(at.0)),
                    computed_at: Some(days::instant(row.computed_at.0)),
                    summary: Measurement::read(&row.evidence)?.summary,
                    evidence_digest: row.evidence_digest.clone(),
                    evidence: Some(row.evidence.clone()),
                },
            );
        }
        Ok(measured)
    }
}

/// The measurement a closed revision is rendered with, per line: its submission's, replaced by the sign-off's.
async fn stored_measurements(tx: &mut Tx, checklist: &ChecklistRow) -> Result<HashMap<i64, MeasurementRow>> {
    let mut stored = HashMap::new();
    for purpose in [Purpose::Submission, Purpose::SignOff] {
        for row in rows::measurements_of(tx, checklist.id, purpose.wire_name()).await? {
            stored.insert(row.item_id, row);
        }
    }
    Ok(stored)
}

fn answer(row: &rows::AnswerRow, words: &AnswerWords) -> Result<statement::Answer> {
    let value = ChecklistAnswer::parse(Some(&row.value))?;
    Ok(statement::Answer {
        id: row.id,
        value: row.value.clone(),
        word: words.written(value).to_owned(),
        comment: row.comment.clone(),
        answered_by: row.answered_by.clone(),
        answered_by_kind: Some(row.answered_by_kind.clone()),
        answered_at: Some(days::instant(row.answered_at.0)),
        carried_from: row.carried_from_id,
        carried_by: row.carried_by.clone(),
        carried_at: row.carried_at.map(|at| days::instant(at.0)),
        needs_confirmation: row.needs_confirmation,
        withdrawn: row.withdrawn,
    })
}

fn zip(parts: Vec<(&str, Vec<u8>)>) -> Result<Vec<u8>> {
    let entries: Vec<(String, Entry)> =
        parts.into_iter().map(|(name, bytes)| (name.to_owned(), Entry::of(bytes))).collect();
    document_zip::of(&entries).map_err(|duplicate| ChecklistError::defect(format!("duplicate entry {}", duplicate.0)))
}

/// Absent and hidden in the same words.
fn absent(project: &VisibleProject, revision: i32) -> ChecklistError {
    ChecklistError::not_found(format!("Project \"{}\" has no checklist revision {revision}.", project.name))
}
