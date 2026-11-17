//! `ProjectChecklistService`: a project's checklists, answered by people — and, on the lines a rule measures, by
//! Vectispire (decision 0032 §4, §5, §8, and the amendment "the scans answer the lines they measure").
//!
//! - **The whole project, or nothing.** Every method names a project and refuses it first, through
//!   `RowVisibility.requireWhollyVisibleProject`: absent, hidden and seen in part are all "Project not found." (404).
//! - **What a person has read is what is changed.** Every write names the edition its writer read: a line's writes
//!   are refused when *that line* changed since (`checklist-line-changed`), a revision's transitions when anything
//!   did (`checklist-changed`); each is one conditional statement on the edition this request read, read again and
//!   decided again a few times before answering 409.
//! - **Answers are never rewritten**: answering inserts a row, and moving or reopening carries answers into the new
//!   revision as new rows pointing at the ones they came from.
//! - **Sign-off and four-eyes**: an approver's act, refused 403 to any other role before anything is read; with
//!   four-eyes on, by none of the revision's authors nor an account they administered recently.
//! - **Every write is audited after its transaction commits.**

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use time::{Date, OffsetDateTime};
use vectispire_cp_access::four_eyes::{ApprovalRefusal, approval_refusal};
use vectispire_cp_access::independence::{ApproverIndependence, Author as IndependentAuthor, IndependenceError};
use vectispire_cp_access::roles::role_of;
use vectispire_cp_access::rows::{VisibleProject, require_wholly_visible_project};
use vectispire_cp_access::visibility::Allowance;
use vectispire_cp_audit::{AuditLog, AuditOperation, Record, RequestActor};
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::bounded_text;
use vectispire_domain::java;
use vectispire_domain::list_window::ListWindow;

use crate::answer::{AnswerAuthor, AnswerWords, ChecklistAnswer, GivenAnswer};
use crate::days;
use crate::documents::Documents;
use crate::error::{Cause, ChecklistError, IncompleteLine, MeasuredLine, Members};
use crate::forms;
use crate::item::EvidenceKind;
use crate::measurement::{Measurement, MeasurementOutcome, NoDataReason, Reconciliation};
use crate::measurer::{LineMeasurement, Measurer};
use crate::pairing::{Change, VersionPairing};
use crate::persistence::{
    self as rows, AnswerRow, ChecklistRow, EvidenceRow, ItemRow, MeasurementRow, NewChecklist, TemplateRow, VersionRow,
};
use crate::ports::ProjectDirectory;
use crate::templates::{self, Clock, VersionStatus};
use crate::trials::VersionTrials;
use crate::views::{
    AnswerView, AnswerWordsView, AsMeasuredAnswer, AsMeasuredSkip, AsMeasuredView, ChecklistView, EvidenceDownload,
    EvidenceView, LineHistory, LineView, MeasuredFigure, MeasuredLineView, MeasurementEvidence, MeasurementView,
    MeasurementsView, OfferedVersion, ProjectContext, RepositoryLook, RevisionSummary, Unrenderable, null, raw,
};

/// Bounded before the write, like an answer's comment (decision 0032 §2).
pub const MAX_REASON: usize = 4_000;
pub const MAX_LINK: usize = 2_000;
/// Column `t_checklist_evidence.file_name` and `media_type`.
pub const MAX_FILE_NAME: usize = 255;
pub const MAX_MEDIA_TYPE: usize = 255;
/// How many times a write reads again after another write came first, before answering 409.
const ATTEMPTS: usize = 3;

type Result<T> = std::result::Result<T, ChecklistError>;

/// `ChecklistStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Draft,
    Submitted,
    SignedOff,
    Superseded,
}

impl Status {
    pub fn wire_name(self) -> &'static str {
        match self {
            Status::Draft => "draft",
            Status::Submitted => "submitted",
            Status::SignedOff => "signed_off",
            Status::Superseded => "superseded",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Status::Draft | Status::Submitted)
    }

    /// A stored value this version does not know is a defect of the row: only this enum writes one.
    pub fn of_stored(stored: &str) -> Result<Status> {
        [Status::Draft, Status::Submitted, Status::SignedOff, Status::Superseded]
            .into_iter()
            .find(|status| status.wire_name() == stored)
            .ok_or_else(|| ChecklistError::defect(format!("A checklist has an unknown status: {stored}")))
    }
}

/// `MeasurementPurpose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Read,
    Answer,
    Submission,
    SignOff,
}

impl Purpose {
    pub fn wire_name(self) -> &'static str {
        match self {
            Purpose::Read => "read",
            Purpose::Answer => "answer",
            Purpose::Submission => "submission",
            Purpose::SignOff => "sign_off",
        }
    }
}

/// `LineProblem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineProblem {
    Unanswered,
    AwaitingConfirmation,
    MeasurementContradicted,
    CommentRequired,
    EvidenceRequired,
    EvidenceExpired,
}

impl LineProblem {
    pub fn wire_name(self) -> &'static str {
        match self {
            LineProblem::Unanswered => "unanswered",
            LineProblem::AwaitingConfirmation => "awaiting_confirmation",
            LineProblem::MeasurementContradicted => "measurement_contradicted",
            LineProblem::CommentRequired => "comment_required",
            LineProblem::EvidenceRequired => "evidence_required",
            LineProblem::EvidenceExpired => "evidence_expired",
        }
    }

    fn asked_where_no_data(self) -> bool {
        matches!(self, LineProblem::CommentRequired | LineProblem::EvidenceRequired | LineProblem::EvidenceExpired)
    }
}

/// Who is acting: the signed-in account — never a name taken from the request — and the audit's actor.
#[derive(Debug, Clone)]
pub struct Participant {
    pub account_id: i64,
    pub username: String,
    pub role: Option<String>,
    pub actor: RequestActor,
}

/// A measurement a person was shown: the line, and the `evidenceDigest` read.
#[derive(Debug, Clone, Default)]
pub struct ShownMeasurement {
    pub item_id: Option<i64>,
    pub measurement_digest: Option<String>,
}

/// A project the guard let through, and the repositories it judged it by.
#[derive(Debug, Clone)]
pub(crate) struct Guarded {
    pub project: VisibleProject,
    pub repository_ids: Vec<i64>,
}

/// Somebody who wrote a revision: the account, and the name it wrote under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Author {
    account_id: Option<i64>,
    username: String,
}

/// The service.
pub struct ProjectChecklists {
    pub(crate) db: Db,
    pub(crate) projects: Arc<dyn ProjectDirectory>,
    pub(crate) measurer: Measurer,
    pub(crate) documents: Arc<Documents>,
    pub(crate) trials: Arc<VersionTrials>,
    pub(crate) settings: Arc<Settings>,
    pub(crate) audit: Arc<AuditLog>,
    pub(crate) independence: ApproverIndependence,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) max_file_bytes: i64,
}

impl std::fmt::Debug for ProjectChecklists {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ProjectChecklists").finish_non_exhaustive()
    }
}

/// What the service is built over.
#[allow(missing_debug_implementations)] // a bag of services
pub struct ProjectChecklistsConfig {
    pub db: Db,
    pub projects: Arc<dyn ProjectDirectory>,
    pub measurer: Measurer,
    pub documents: Arc<Documents>,
    pub trials: Arc<VersionTrials>,
    pub settings: Arc<Settings>,
    pub audit: Arc<AuditLog>,
    pub independence: ApproverIndependence,
    pub clock: Arc<dyn Clock>,
    pub max_file_bytes: i64,
}

/// The guard, keeping the repositories it compared with the caller's visibility: a measurement reads exactly those.
pub(crate) async fn require_whole(
    projects: &dyn ProjectDirectory,
    project_id: i64,
    allowance: &Allowance,
) -> Result<Guarded> {
    let members = projects.members(project_id).await.map_err(ChecklistError::Failed)?;
    let repository_ids = members.as_ref().map(|members| members.repository_ids.clone()).unwrap_or_default();
    let project = require_wholly_visible_project(
        project_id,
        members.as_ref().map(|members| members.name.as_str()),
        &repository_ids,
        allowance,
    )
    .map_err(|refused| ChecklistError::NotFound(refused.to_string()))?;
    Ok(Guarded { project, repository_ids })
}

impl ProjectChecklists {
    pub fn new(config: ProjectChecklistsConfig) -> ProjectChecklists {
        let ProjectChecklistsConfig {
            db,
            projects,
            measurer,
            documents,
            trials,
            settings,
            audit,
            independence,
            clock,
            max_file_bytes,
        } = config;
        ProjectChecklists {
            db,
            projects,
            measurer,
            documents,
            trials,
            settings,
            audit,
            independence,
            clock,
            max_file_bytes,
        }
    }

    async fn read_tx(&self) -> Result<Tx> {
        Ok(rows::begin(&self.db, false).await?)
    }

    async fn write_tx(&self) -> Result<Tx> {
        Ok(rows::begin(&self.db, true).await?)
    }

    async fn guard(&self, project_id: i64, allowance: &Allowance) -> Result<Guarded> {
        require_whole(self.projects.as_ref(), project_id, allowance).await
    }

    fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    fn today(&self) -> Date {
        days::day_of(self.now())
    }

    async fn enabled(&self, setting: Setting) -> Result<bool> {
        self.settings.is_enabled(setting).await.map_err(|failure| ChecklistError::Failed(failure.to_string()))
    }

    // ------------------------------------------------------------------ reads

    /// `list`: the project's revisions, newest first, all of them or one page. The project's 404 comes first.
    pub async fn list(
        &self,
        project_id: i64,
        allowance: &Allowance,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<RevisionSummary>> {
        let guarded = self.guard(project_id, allowance).await?;
        let window = ListWindow::requested(limit, offset).map_err(ChecklistError::Invalid)?;
        let mut tx = self.read_tx().await?;
        let every = rows::checklists_of_project(&mut tx, guarded.project.project_id).await?;
        let mut revision_of: HashMap<i64, i32> = every.iter().map(|row| (row.id, row.revision)).collect();
        let page = window.map_or_else(|| every.clone(), |window| window.of(&every));
        let mut refs: HashMap<i64, VersionRef> = HashMap::new();
        let mut summaries = Vec::with_capacity(page.len());
        for row in &page {
            let reference = match refs.get(&row.template_version_id) {
                Some(found) => found.clone(),
                None => {
                    let found = version_ref(&mut tx, row.template_version_id).await?;
                    refs.insert(row.template_version_id, found.clone());
                    found
                }
            };
            summaries.push(summary(&mut tx, row, &reference, &mut revision_of).await?);
        }
        Ok(summaries)
    }

    /// `context`: the project's name and its newest revision, behind the same guard.
    pub async fn context(&self, project_id: i64, allowance: &Allowance) -> Result<ProjectContext> {
        let guarded = self.guard(project_id, allowance).await?;
        let mut tx = self.read_tx().await?;
        let latest = rows::latest_checklist(&mut tx, guarded.project.project_id).await?;
        Ok(ProjectContext {
            project_id: guarded.project.project_id,
            project_name: guarded.project.name,
            latest_revision: latest.as_ref().map(|row| row.revision),
            latest_edition: latest.as_ref().map(|row| row.edition),
        })
    }

    /// `offered`: the published versions, by template slug then number, each one no sign-off could fill in flagged.
    pub async fn offered(&self, project_id: i64, allowance: &Allowance) -> Result<Vec<OfferedVersion>> {
        self.guard(project_id, allowance).await?;
        let mut tx = self.read_tx().await?;
        let mut offered = Vec::new();
        for template in rows::templates_by_slug(&mut tx).await? {
            for row in rows::summaries_of(&mut tx, template.id).await? {
                let version = &row.version;
                if version.status != VersionStatus::Published.wire_name() {
                    continue;
                }
                let refusal = self.trials.refusal(&mut tx, version).await?;
                offered.push(OfferedVersion {
                    template_slug: template.slug.clone(),
                    template_name: template.name.clone(),
                    ordinal: version.ordinal,
                    label: version.label.clone(),
                    item_count: row.item_count,
                    offers_not_applicable: version.offers_not_applicable,
                    published_at: version.published_at.map(iso),
                    unrenderable: refusal
                        .map(|refused| Unrenderable { detail: refused.message().to_owned(), cells: refused.cells() }),
                });
            }
        }
        Ok(offered)
    }

    pub async fn read(&self, project_id: i64, revision: i32, allowance: &Allowance) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, &guarded.project, revision).await?;
        self.view(&mut tx, &guarded, &checklist).await
    }

    /// `history`: every answer and every proof of one line, oldest first.
    pub async fn history(
        &self,
        project_id: i64,
        revision: i32,
        item_id: i64,
        allowance: &Allowance,
    ) -> Result<LineHistory> {
        let guarded = self.guard(project_id, allowance).await?;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, &guarded.project, revision).await?;
        let item = require_line(&mut tx, &checklist, item_id).await?;
        let today = self.today();
        Ok(LineHistory {
            project_id: guarded.project.project_id,
            revision: checklist.revision,
            item_id: item.id,
            answers: rows::answers_of_line(&mut tx, checklist.id, item.id).await?.iter().map(answer_view).collect(),
            evidence: rows::evidence_of_line(&mut tx, checklist.id, item.id)
                .await?
                .iter()
                .map(|row| evidence_view(row, today))
                .collect(),
        })
    }

    /// `download`: an uploaded proof's bytes, withdrawn or not.
    pub async fn download(
        &self,
        project_id: i64,
        revision: i32,
        evidence_id: i64,
        allowance: &Allowance,
    ) -> Result<EvidenceDownload> {
        let guarded = self.guard(project_id, allowance).await?;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, &guarded.project, revision).await?;
        let proof = require_evidence(&mut tx, &checklist, evidence_id).await?;
        let Some(file_id) = proof.file_id else {
            return Err(ChecklistError::not_found(format!(
                "Proof {evidence_id} is a link, not a file: it has nothing to download."
            )));
        };
        let content = rows::file_content(&mut tx, file_id)
            .await?
            .ok_or_else(|| ChecklistError::defect(format!("The file of proof {evidence_id} is gone.")))?;
        Ok(EvidenceDownload {
            file_name: proof.file_name.unwrap_or_default(),
            sha256: proof.file_sha256.unwrap_or_default(),
            content,
        })
    }

    // ------------------------------------------------------------------ opening, moving, reopening

    /// `open`: the project's checklist opened on a published version, or moved to another with its answers carried.
    pub async fn open(
        &self,
        project_id: i64,
        allowance: &Allowance,
        template_slug: Option<&str>,
        version_ordinal: Option<i32>,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let (Some(slug), Some(ordinal)) = (template_slug.filter(|slug| !java::is_blank(slug)), version_ordinal) else {
            return Err(ChecklistError::invalid(
                "Name the template (\"template\", its slug) and its version (\"version\", its number) to open the \
                 checklist on.",
            ));
        };
        let mut tx = self.read_tx().await?;
        let template = rows::template_by_slug(&mut tx, java::strip(slug)).await?.ok_or_else(|| {
            ChecklistError::not_found(format!(
                "No checklist template \"{}\".",
                bounded_text::clip(Some(java::strip(slug)), 70).unwrap_or("")
            ))
        })?;
        let version = rows::version_by_ordinal(&mut tx, template.id, ordinal).await?.ok_or_else(|| {
            ChecklistError::not_found(format!("Checklist template \"{}\" has no version {ordinal}.", template.slug))
        })?;
        if VersionStatus::of_stored(&version.status)? != VersionStatus::Published {
            return Err(ChecklistError::conflict(
                Cause::VersionNotPublished,
                format!(
                    "Version {ordinal} of \"{}\" is {}: a checklist opens on a published version.",
                    template.slug, version.status
                ),
            ));
        }

        let latest = rows::latest_checklist(&mut tx, project.project_id).await?;
        match &latest {
            None => {
                if seen_edition.is_some() {
                    return Err(ChecklistError::conflict(
                        Cause::Changed,
                        "The project has no checklist any more: read it again.",
                    ));
                }
            }
            Some(previous) => {
                let Some(seen) = seen_edition else {
                    return Err(ChecklistError::conflict(
                        Cause::Changed,
                        format!(
                            "The project already has a checklist — revision {}, {}, opened since you read it. Read it \
                             again; moving it to another version names the edition you read.",
                            previous.revision, previous.status
                        ),
                    ));
                };
                require_seen(previous, seen, "moving it to another version")?;
                if previous.template_version_id == version.id {
                    let tail = if Status::of_stored(&previous.status)? == Status::SignedOff {
                        ": reopen it for a new revision on the same version."
                    } else {
                        "."
                    };
                    return Err(ChecklistError::conflict(
                        Cause::SameVersion,
                        format!(
                            "Revision {} is already on version {ordinal} of \"{}\"{tail}",
                            previous.revision, template.slug
                        ),
                    ));
                }
            }
        }

        self.require_renderable(&mut tx, &template, &version, latest.is_some()).await?;
        let carried = match &latest {
            Some(previous) => carry_onto(&mut tx, previous, &version, &template).await?,
            None => Carried::nothing(),
        };
        drop(tx);
        let opened = self.open_revision(project, &version, latest.as_ref(), carried.clone(), who).await?;

        let (operation, line) = match &latest {
            Some(previous) => (
                AuditOperation::ChecklistMovedToVersion,
                format!(
                    "Checklist of project \"{}\": revision {} opened on version {ordinal} of \"{}\", moved from \
                     revision {}{}",
                    project.name,
                    opened.revision,
                    template.slug,
                    previous.revision,
                    carried.describe()
                ),
            ),
            None => (
                AuditOperation::ChecklistOpened,
                format!(
                    "Checklist of project \"{}\" opened on version {ordinal} of \"{}\", revision {}.",
                    project.name, template.slug, opened.revision
                ),
            ),
        };
        self.audit.record(who.actor.entry(operation, &resource(project, opened.revision), &line)).await;
        self.answer_after_opening(&guarded, &opened).await;
        self.view_fresh(&guarded, opened.id).await
    }

    /// `requireRenderable`: the version moved *to* alone is tried, never the one moved from.
    async fn require_renderable(
        &self,
        tx: &mut Tx,
        template: &TemplateRow,
        version: &VersionRow,
        moving: bool,
    ) -> Result<()> {
        if let Some(refused) = self.trials.refusal(tx, version).await? {
            let (verb, instead) = if moving {
                ("moved to", "moves to that one instead.")
            } else {
                ("opened on", "opens on that one instead.")
            };
            return Err(templates::unrenderable(
                Cause::VersionUnrenderable,
                format!(
                    "Version {} of \"{}\" cannot be signed off: no sign-off could fill its workbook in, so a checklist \
                     {verb} it could never be signed. {} A published version's workbook never changes: the template's \
                     managers publish a corrected version, and the checklist {instead}",
                    version.ordinal,
                    template.slug,
                    refused.message()
                ),
                &refused,
            ));
        }
        Ok(())
    }

    /// `reopen`: the next revision of a signed-off one, on the same version, every answer and proof carried as
    /// current.
    pub async fn reopen(
        &self,
        project_id: i64,
        revision: i32,
        allowance: &Allowance,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let signed = require_revision(&mut tx, project, revision).await?;
        let seen = require_edition(seen_edition)?;
        if Status::of_stored(&signed.status)? != Status::SignedOff {
            return Err(ChecklistError::conflict(
                Cause::NotSignedOff,
                format!("Revision {revision} is {}: only a signed-off revision is reopened.", signed.status),
            ));
        }
        require_latest(&mut tx, project, &signed).await?;
        require_seen(&signed, seen, "reopening it")?;
        let version = version_of(&mut tx, &signed).await?;
        let template = template_of(&mut tx, &version).await?;
        let carried = carry_onto(&mut tx, &signed, &version, &template).await?;
        drop(tx);
        let opened = self.open_revision(project, &version, Some(&signed), carried.clone(), who).await?;

        self.audit
            .record(who.actor.entry(
                AuditOperation::ChecklistReopened,
                &resource(project, opened.revision),
                &format!(
                    "Checklist of project \"{}\": signed-off revision {revision} reopened as revision {} on the same \
                     version{}",
                    project.name,
                    opened.revision,
                    carried.describe()
                ),
            ))
            .await;
        self.answer_after_opening(&guarded, &opened).await;
        self.view_fresh(&guarded, opened.id).await
    }

    // ------------------------------------------------------------------ answering

    /// `answer`: a new row of the line's history, the principal its author; resting on the measurement the person
    /// read when they name it.
    #[allow(clippy::too_many_arguments)]
    pub async fn answer(
        &self,
        project_id: i64,
        revision: i32,
        item_id: i64,
        allowance: &Allowance,
        value: Option<&str>,
        comment: Option<&str>,
        measurement_digest: Option<&str>,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        let seen = require_edition(seen_edition)?;
        let item = require_line(&mut tx, &checklist, item_id).await?;
        let words = words_of(&mut tx, &checklist).await?;
        let given = GivenAnswer::of(ChecklistAnswer::parse(value)?, comment, &words)?;
        let now = self.now();
        let resting = self.resting_on(&mut tx, &guarded, &checklist, &item, measurement_digest, now).await?;
        drop(tx);

        let username = who.username.clone();
        let written = self
            .write_line(&checklist, item.id, seen, |tx, edition| {
                let given = given.clone();
                let resting = resting.clone();
                let who = who.clone();
                Box::pin(async move {
                    let mut row = answer_row(
                        checklist.id,
                        item.id,
                        given.value.wire_name(),
                        given.comment.as_deref(),
                        &who,
                        now,
                        None,
                        edition,
                    );
                    if let Some(measured) = &resting {
                        let stored = measurement_row(
                            checklist.id,
                            measured,
                            Purpose::Answer,
                            now,
                            &who.username,
                            None,
                            Some(given.value),
                        );
                        row.measurement_id = Some(rows::insert_measurement(tx, &stored).await?);
                    }
                    rows::insert_answer(tx, &row).await?;
                    Ok(())
                })
            })
            .await?;

        let commented = given
            .comment
            .as_deref()
            .map_or_else(String::new, |text| format!(", with a comment of {} characters", java::utf16_len(text)));
        let rested = resting.as_ref().map_or_else(String::new, |measured| {
            format!(
                ", resting on its measurement — {}{}, evidence sha256 {}",
                measured.measurement.outcome.wire_name(),
                measured.measurement.reason.map_or_else(String::new, |reason| format!(" ({})", reason.wire_name())),
                short(&measured.measurement.evidence_digest())
            )
        });
        let _ = username;
        self.audit
            .record(who.actor.entry(
                AuditOperation::ChecklistAnswered,
                &resource(project, revision),
                &format!(
                    "Checklist of project \"{}\", revision {revision}, line {} (row {}): answered {}{commented}{rested}.",
                    project.name,
                    item.position,
                    item.sheet_row,
                    given.value.wire_name()
                ),
            ))
            .await;
        self.view_fresh(&guarded, written.id).await
    }

    /// `restingOn`: the line's rule applied now, refused unless it judged the evidence the person read.
    async fn resting_on(
        &self,
        tx: &mut Tx,
        guarded: &Guarded,
        checklist: &ChecklistRow,
        item: &ItemRow,
        measurement_digest: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Option<LineMeasurement>> {
        let Some(digest) = measurement_digest.filter(|digest| !java::is_blank(digest)) else {
            return Ok(None);
        };
        if item.bound_rule.is_none() {
            return Err(ChecklistError::invalid(format!(
                "Line {} is measured by no rule: an answer cannot rest on a measurement it does not have.",
                item.position
            )));
        }
        let measured = self.measurer.measure(&guarded.repository_ids, item, days::instant(now)).await?;
        if measured.measurement.evidence_digest() != java::strip(digest) {
            let current = current_of(&rows::answers_of_line(tx, checklist.id, item.id).await?).remove(&item.id);
            return Err(ChecklistError::conflict_with(
                Cause::MeasurementChanged,
                format!(
                    "The measurement of line {} is not the one you read: it is now {}. Read it again.",
                    item.position,
                    describe(&measured.measurement)
                ),
                Members::Measured(vec![measured_line(item, current.as_ref(), &measured.measurement, None)]),
            ));
        }
        Ok(Some(measured))
    }

    /// `answerAsMeasured`: every named, unanswered, passing line whose evidence is still the one read answered yes by
    /// the caller, in one act; the others named with the reason they were left alone.
    pub async fn answer_as_measured(
        &self,
        project_id: i64,
        revision: i32,
        allowance: &Allowance,
        seen_edition: Option<i32>,
        shown: Option<&[Option<ShownMeasurement>]>,
        who: &Participant,
    ) -> Result<AsMeasuredView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        let seen_edition = require_edition(seen_edition)?;
        let lines = rows::items_of(&mut tx, checklist.template_version_id).await?;
        let seen = require_shown(shown, &lines)?;
        require_status(&checklist, Status::Draft, Cause::NotDraft, "answered")?;
        require_seen(&checklist, seen_edition, "answering its measured lines")?;
        let words = words_of(&mut tx, &checklist).await?;
        let yes = GivenAnswer::of(ChecklistAnswer::Yes, None, &words)?;
        let now = self.now();
        let measured = self.measurer.measure_all(&guarded.repository_ids, &lines, days::instant(now)).await?;
        let current = current_of(&rows::answers_of(&mut tx, checklist.id).await?);

        let mut passing: Vec<LineMeasurement> = Vec::new();
        let mut skipped = Vec::new();
        for line in measured {
            let answer = current.get(&line.item.id);
            let found = &line.measurement;
            let read = seen.get(&line.item.id);
            let digest = found.evidence_digest();
            // Answered first: a person's answer stands whatever the measurement now says. Then what the person read:
            // evidence other than theirs is a measurement they never saw, whatever it finds.
            let reason = if answer.is_some() {
                Some("already_answered")
            } else if read.is_some_and(|read| *read != digest) {
                Some("measurement_changed")
            } else {
                match found.outcome {
                    MeasurementOutcome::Pass => read.is_none().then_some("not_shown"),
                    MeasurementOutcome::Fail => Some("needs_comment"),
                    MeasurementOutcome::NoData => Some("no_data"),
                }
            };
            match reason {
                None => passing.push(line),
                Some(reason) => skipped.push(AsMeasuredSkip {
                    item_id: line.item.id,
                    position: line.item.position,
                    reason: reason.to_owned(),
                    outcome: found.outcome.wire_name().to_owned(),
                    no_data_reason: found.reason.map(|reason| reason.wire_name().to_owned()),
                    evidence_digest: digest,
                    answer: answer.map(|answer| answer.value.clone()),
                }),
            }
        }
        if passing.is_empty() {
            let view = self.view(&mut tx, &guarded, &checklist).await?;
            return Ok(AsMeasuredView { checklist: view, answered: Vec::new(), skipped });
        }
        drop(tx);

        let mut answered = Vec::with_capacity(passing.len());
        let mut tx = self.write_tx().await?;
        // One conditional statement on the edition the person read: any write since — on any line — and nothing of
        // this act is written.
        require_still(
            rows::touch_draft(&mut tx, checklist.id, seen_edition, Status::Draft.wire_name()).await?,
            &checklist,
        )?;
        let edition = seen_edition.saturating_add(1);
        for line in &passing {
            let rested =
                measurement_row(checklist.id, line, Purpose::Answer, now, &who.username, None, Some(yes.value));
            let measurement_id = rows::insert_measurement(&mut tx, &rested).await?;
            let mut row = answer_row(checklist.id, line.item.id, yes.value.wire_name(), None, who, now, None, edition);
            row.measurement_id = Some(measurement_id);
            let answer_id = rows::insert_answer(&mut tx, &row).await?;
            answered.push(AsMeasuredAnswer {
                item_id: line.item.id,
                position: line.item.position,
                value: yes.value.wire_name().to_owned(),
                answer_id,
                measurement_id,
                evidence_digest: line.measurement.evidence_digest(),
            });
        }
        rows::commit(tx).await?;

        for line in &passing {
            self.audit
                .record(who.actor.entry(
                    AuditOperation::ChecklistAnswered,
                    &resource(project, revision),
                    &format!(
                        "Checklist of project \"{}\", revision {revision}, line {} (row {}): answered {}, resting on its \
                         measurement — {}, evidence sha256 {}; one of {} measured lines answered as measured in one act.",
                        project.name,
                        line.item.position,
                        line.item.sheet_row,
                        yes.value.wire_name(),
                        describe(&line.measurement),
                        short(&line.measurement.evidence_digest()),
                        passing.len()
                    ),
                ))
                .await;
        }
        let view = self.view_fresh(&guarded, checklist.id).await?;
        Ok(AsMeasuredView { checklist: view, answered, skipped })
    }

    // ------------------------------------------------------------------ Vectispire's own answers

    /// `answerFromEvidence`: the measured lines of the draft of the project a repository is filed in, answered by
    /// Vectispire. Nothing when the setting is off, the repository is in no project, or the newest revision is not a
    /// draft. How many lines were written.
    pub async fn answer_from_evidence(&self, repository_id: i64) -> Result<usize> {
        if !self.enabled(Setting::ChecklistAutoAnswer).await? {
            return Ok(0);
        }
        let Some(project_id) = self.projects.project_of(repository_id).await.map_err(ChecklistError::Failed)? else {
            return Ok(0);
        };
        // No caller, so the system states its own allowance: everything, through the same guard.
        let guarded = match self.guard(project_id, &Allowance::everything()).await {
            Ok(guarded) => guarded,
            // Deleted between the lookup and now: nothing left to answer.
            Err(ChecklistError::NotFound(_)) => return Ok(0),
            Err(failure) => return Err(failure),
        };
        let mut tx = self.read_tx().await?;
        let latest = rows::latest_checklist(&mut tx, guarded.project.project_id).await?;
        drop(tx);
        match latest {
            Some(checklist) if Status::of_stored(&checklist.status)? == Status::Draft => {
                self.answer_automatically(&guarded, checklist).await
            }
            _ => Ok(0),
        }
    }

    /// After the opening's own commit and audit entry: a failure here is logged and leaves the lines unanswered for
    /// the next scan to answer — answering 500 would tell the person their checklist was not opened.
    async fn answer_after_opening(&self, guarded: &Guarded, opened: &ChecklistRow) {
        match self.enabled(Setting::ChecklistAutoAnswer).await {
            Ok(false) => {}
            Ok(true) => {
                let fresh = async {
                    let mut tx = self.read_tx().await?;
                    let row = reread(&mut tx, opened).await?;
                    drop(tx);
                    self.answer_automatically(guarded, row).await
                };
                if let Err(failed) = fresh.await {
                    tracing::warn!(
                        revision = opened.revision,
                        project = guarded.project.project_id,
                        error = %failed,
                        "Checklist revision was opened; answering its measured lines failed"
                    );
                }
            }
            Err(failed) => tracing::warn!(error = %failed, "The automatic answers' setting could not be read"),
        }
    }

    /// `answerAutomatically`: one transaction, one edition; read again and decided again when a person wrote first.
    async fn answer_automatically(&self, guarded: &Guarded, read: ChecklistRow) -> Result<usize> {
        let project = &guarded.project;
        let mut checklist = read.clone();
        for _ in 0..ATTEMPTS {
            if Status::of_stored(&checklist.status)? != Status::Draft {
                return Ok(0);
            }
            let edition = checklist.edition;
            let now = self.now();
            let mut tx = self.read_tx().await?;
            let items = rows::items_of(&mut tx, checklist.template_version_id).await?;
            let words = words_of(&mut tx, &checklist).await?;
            let current = current_of(&rows::answers_of(&mut tx, checklist.id).await?);
            drop(tx);
            let measured = self.measurer.measure_all(&guarded.repository_ids, &items, days::instant(now)).await?;
            let planned = plan(&current, measured, &words)?;
            if planned.is_empty() {
                return Ok(0);
            }
            let mut tx = self.write_tx().await?;
            if rows::touch_draft(&mut tx, checklist.id, edition, Status::Draft.wire_name()).await? == 1 {
                for automatic in &planned {
                    let rested = measurement_row(
                        checklist.id,
                        &automatic.line,
                        Purpose::Answer,
                        now,
                        AnswerAuthor::SYSTEM_NAME,
                        None,
                        Some(automatic.value),
                    );
                    let measurement_id = rows::insert_measurement(&mut tx, &rested).await?;
                    rows::insert_answer(
                        &mut tx,
                        &system_answer_row(checklist.id, automatic, measurement_id, now, edition.saturating_add(1)),
                    )
                    .await?;
                }
                rows::commit(tx).await?;
                for automatic in &planned {
                    self.audit
                        .record(Record::of(
                            AuditOperation::ChecklistAnswered,
                            &resource(project, checklist.revision),
                            &describe_automatic(project, checklist.revision, automatic),
                            None,
                        ))
                        .await;
                }
                return Ok(planned.len());
            }
            rows::rollback(tx).await?;
            let mut tx = self.read_tx().await?;
            checklist = reread(&mut tx, &checklist).await?;
        }
        Err(ChecklistError::conflict(
            Cause::Changed,
            format!(
                "Revision {} kept changing while Vectispire answered its measured lines; the next scan answers them.",
                read.revision
            ),
        ))
    }

    /// `confirm`: the answer carried onto a changed line still holds, under the confirmer's name.
    pub async fn confirm(
        &self,
        project_id: i64,
        revision: i32,
        item_id: i64,
        allowance: &Allowance,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        let seen = require_edition(seen_edition)?;
        let item = require_line(&mut tx, &checklist, item_id).await?;
        let words = words_of(&mut tx, &checklist).await?;
        drop(tx);
        let now = self.now();
        let confirmed: Arc<std::sync::Mutex<Option<(AnswerRow, GivenAnswer)>>> = Arc::new(std::sync::Mutex::new(None));

        let written = self
            .write_line(&checklist, item.id, seen, |tx, edition| {
                let words = words.clone();
                let who = who.clone();
                let confirmed = confirmed.clone();
                Box::pin(async move {
                    let carried = current_of(&rows::answers_of_line(tx, checklist.id, item.id).await?)
                        .remove(&item.id)
                        .filter(|answer| answer.needs_confirmation)
                        .ok_or_else(|| {
                            ChecklistError::conflict(
                                Cause::NothingToConfirm,
                                format!("Line {} has no carried answer awaiting confirmation.", item.position),
                            )
                        })?;
                    // Checked again under the new version's words: a "not applicable" it does not offer is answered
                    // again, never confirmed into the revision.
                    let given = GivenAnswer::of(
                        ChecklistAnswer::parse(Some(&carried.value))?,
                        carried.comment.as_deref(),
                        &words,
                    )?;
                    let row = answer_row(
                        checklist.id,
                        item.id,
                        given.value.wire_name(),
                        given.comment.as_deref(),
                        &who,
                        now,
                        Some(carried.id),
                        edition,
                    );
                    rows::insert_answer(tx, &row).await?;
                    if let Ok(mut slot) = confirmed.lock() {
                        *slot = Some((carried, given));
                    }
                    Ok(())
                })
            })
            .await?;

        let taken = confirmed.lock().ok().and_then(|mut slot| slot.take());
        if let Some((carried, given)) = taken {
            self.audit
                .record(who.actor.entry(
                    AuditOperation::ChecklistAnswered,
                    &resource(project, revision),
                    &format!(
                        "Checklist of project \"{}\", revision {revision}, line {} (row {}): the answer {} carried from \
                         {} confirmed.",
                        project.name,
                        item.position,
                        item.sheet_row,
                        given.value.wire_name(),
                        carried.answered_by
                    ),
                ))
                .await;
        }
        self.view_fresh(&guarded, written.id).await
    }

    // ------------------------------------------------------------------ evidence

    /// `attachLink`: an `https:` or `http:` link, and the day the work was done.
    #[allow(clippy::too_many_arguments)]
    pub async fn attach_link(
        &self,
        project_id: i64,
        revision: i32,
        item_id: i64,
        allowance: &Allowance,
        link: Option<&str>,
        performed_on: Option<&str>,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        let seen = require_edition(seen_edition)?;
        let item = require_line(&mut tx, &checklist, item_id).await?;
        drop(tx);
        let url = require_link(link)?;
        let performed = self.require_day(performed_on)?;
        let now = self.now();

        let written = self
            .write_line(&checklist, item.id, seen, |tx, edition| {
                let mut row = proof_row(&checklist, &item, performed, who, now, edition);
                row.kind = "link".to_owned();
                row.link = Some(url.clone());
                Box::pin(async move {
                    rows::insert_evidence(tx, &row).await?;
                    Ok(())
                })
            })
            .await?;

        self.audit
            .record(who.actor.entry(
                AuditOperation::ChecklistEvidenceAdded,
                &resource(project, revision),
                &format!(
                    "Checklist of project \"{}\", revision {revision}, line {}: a link attached as proof, performed on {} \
                     — {}",
                    project.name,
                    item.position,
                    days::written(performed),
                    bounded_text::clip(Some(&url), 200).unwrap_or("")
                ),
            ))
            .await;
        self.view_fresh(&guarded, written.id).await
    }

    /// `attachFile`: at most the evidence ceiling, stored apart, served back only as a download.
    #[allow(clippy::too_many_arguments)]
    pub async fn attach_file(
        &self,
        project_id: i64,
        revision: i32,
        item_id: i64,
        allowance: &Allowance,
        file_name: Option<&str>,
        media_type: Option<&str>,
        performed_on: Option<&str>,
        content: &[u8],
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        let seen = require_edition(seen_edition)?;
        let item = require_line(&mut tx, &checklist, item_id).await?;
        drop(tx);
        let name = require_file_name(file_name)?;
        let kind = match media_type.filter(|kind| !java::is_blank(kind)) {
            None => "application/octet-stream".to_owned(),
            Some(kind) => bounded_text::optional(Some(java::strip(kind)), MAX_MEDIA_TYPE, "The media type")?
                .unwrap_or_else(|| "application/octet-stream".to_owned()),
        };
        let performed = self.require_day(performed_on)?;
        if content.is_empty() {
            return Err(ChecklistError::invalid("The body is the proof's file, and it is empty."));
        }
        if i64::try_from(content.len()).unwrap_or(i64::MAX) > self.max_file_bytes {
            return Err(ChecklistError::TooLarge(self.max_file_bytes));
        }
        let sha256 = crate::sha256_hex_bytes(content);
        let now = self.now();
        let size = i64::try_from(content.len()).unwrap_or(i64::MAX);

        let written = self
            .write_line(&checklist, item.id, seen, |tx, edition| {
                let mut row = proof_row(&checklist, &item, performed, who, now, edition);
                row.kind = "file".to_owned();
                row.file_name = Some(name.clone());
                row.media_type = Some(kind.clone());
                row.file_size = Some(size);
                row.file_sha256 = Some(sha256.clone());
                let sha256 = sha256.clone();
                let project_id = project.project_id;
                let content = content.to_vec();
                Box::pin(async move {
                    row.file_id = Some(rows::insert_file(tx, project_id, &sha256, &content).await?);
                    rows::insert_evidence(tx, &row).await?;
                    Ok(())
                })
            })
            .await?;

        self.audit
            .record(who.actor.entry(
                AuditOperation::ChecklistEvidenceAdded,
                &resource(project, revision),
                &format!(
                    "Checklist of project \"{}\", revision {revision}, line {}: the file \"{}\" attached as proof, {} \
                     bytes, sha256 {sha256}, performed on {}.",
                    project.name,
                    item.position,
                    bounded_text::clip(Some(&name), 100).unwrap_or(""),
                    content.len(),
                    days::written(performed)
                ),
            ))
            .await;
        self.view_fresh(&guarded, written.id).await
    }

    /// `withdraw`: the proof stops counting; its row stays, dated and attributed.
    pub async fn withdraw(
        &self,
        project_id: i64,
        revision: i32,
        evidence_id: i64,
        allowance: &Allowance,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        let seen = require_edition(seen_edition)?;
        let proof = require_evidence(&mut tx, &checklist, evidence_id).await?;
        drop(tx);
        if let Some(at) = proof.withdrawn_at {
            return Err(ChecklistError::conflict(
                Cause::EvidenceWithdrawn,
                format!(
                    "Proof {evidence_id} was withdrawn by {} on {}.",
                    proof.withdrawn_by.as_deref().unwrap_or("null"),
                    iso(at)
                ),
            ));
        }
        let now = self.now();

        let written = self
            .write_line(&checklist, proof.item_id, seen, |tx, edition| {
                let who = who.clone();
                Box::pin(async move {
                    let done =
                        rows::withdraw_evidence(tx, proof.id, rows::at(now), &who.username, who.account_id, edition)
                            .await?;
                    if done != 1 {
                        return Err(ChecklistError::conflict(
                            Cause::EvidenceWithdrawn,
                            format!("Proof {evidence_id} was withdrawn by somebody else meanwhile."),
                        ));
                    }
                    Ok(())
                })
            })
            .await?;

        let what = match proof.file_name.as_deref() {
            Some(name) => format!("the file \"{}\"", bounded_text::clip(Some(name), 100).unwrap_or("")),
            None => "a link".to_owned(),
        };
        self.audit
            .record(who.actor.entry(
                AuditOperation::ChecklistEvidenceWithdrawn,
                &resource(project, revision),
                &format!(
                    "Checklist of project \"{}\", revision {revision}: proof {evidence_id} ({what}) withdrawn.",
                    project.name
                ),
            ))
            .await;
        self.view_fresh(&guarded, written.id).await
    }

    // ------------------------------------------------------------------ submitting, returning, signing off

    /// `submit`: a draft for sign-off, its measured lines measured again and reconciled.
    pub async fn submit(
        &self,
        project_id: i64,
        revision: i32,
        allowance: &Allowance,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        let seen = require_edition(seen_edition)?;
        require_status(&checklist, Status::Draft, Cause::NotDraft, "submitted")?;
        require_seen(&checklist, seen, "submitting it")?;
        let now = self.now();
        let items = rows::items_of(&mut tx, checklist.template_version_id).await?;
        let measured = self.measurer.measure_all(&guarded.repository_ids, &items, days::instant(now)).await?;
        // The very judgement a read makes of a draft: what readyToSubmit promised is what is refused.
        let judged = lines(&mut tx, &checklist, self.today(), &outcomes(&measured)).await?;
        require_complete(&checklist, "submitted", &judged)?;
        let current = current_of(&rows::answers_of(&mut tx, checklist.id).await?);
        drop(tx);
        let contradicted_lines = contradicted(&judged);
        let contradicted: Vec<MeasuredLine> = measured
            .iter()
            .filter(|line| contradicted_lines.contains(&line.item.id))
            .map(|line| measured_line(&line.item, current.get(&line.item.id), &line.measurement, None))
            .collect();
        if !contradicted.is_empty() {
            let named: Vec<String> = contradicted.iter().map(|line| format!("line {}", line.position)).collect();
            return Err(ChecklistError::conflict_with(
                Cause::MeasurementContradicted,
                format!(
                    "Revision {revision} cannot be submitted: {} {} answered yes where the measurement fails. Answer no \
                     with the reason, or settle the findings by triage.",
                    named.join(", "),
                    if contradicted.len() == 1 { "is" } else { "are" }
                ),
                Members::Measured(contradicted),
            ));
        }

        let mut tx = self.write_tx().await?;
        require_still(
            rows::submit_checklist(
                &mut tx,
                checklist.id,
                seen,
                Status::Draft.wire_name(),
                Status::Submitted.wire_name(),
                rows::at(now),
                &who.username,
                who.account_id,
            )
            .await?,
            &checklist,
        )?;
        store(&mut tx, &checklist, &measured, Purpose::Submission, now, who, &current).await?;
        rows::commit(tx).await?;

        self.audit
            .record(who.actor.entry(
                AuditOperation::ChecklistSubmitted,
                &resource(project, revision),
                &format!(
                    "Checklist of project \"{}\", revision {revision} submitted for sign-off at edition {seen}{}.",
                    project.name,
                    tally(&measured)
                ),
            ))
            .await;
        self.view_fresh(&guarded, checklist.id).await
    }

    /// `returnToAuthors`: a submitted revision a draft again, with the reason.
    pub async fn return_to_authors(
        &self,
        project_id: i64,
        revision: i32,
        allowance: &Allowance,
        reason: Option<&str>,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        drop(tx);
        let seen = require_edition(seen_edition)?;
        let Some(why) = bounded_text::optional(reason, MAX_REASON, "The reason")? else {
            return Err(ChecklistError::invalid("Say why the checklist is returned: its authors read the reason."));
        };
        require_status(&checklist, Status::Submitted, Cause::NotSubmitted, "returned")?;
        require_seen(&checklist, seen, "returning it")?;
        let now = self.now();

        let mut tx = self.write_tx().await?;
        require_still(
            rows::return_checklist(
                &mut tx,
                checklist.id,
                seen,
                Status::Submitted.wire_name(),
                Status::Draft.wire_name(),
                rows::at(now),
                &who.username,
                &why,
            )
            .await?,
            &checklist,
        )?;
        rows::commit(tx).await?;

        self.audit
            .record(who.actor.entry(
                AuditOperation::ChecklistReturned,
                &resource(project, revision),
                &format!(
                    "Checklist of project \"{}\", revision {revision} returned to its authors: {}",
                    project.name,
                    bounded_text::clip(Some(&why), 300).unwrap_or("")
                ),
            ))
            .await;
        self.view_fresh(&guarded, checklist.id).await
    }

    /// `signOff`: the release attestation, its measurements frozen and its document signed in the same transaction.
    pub async fn sign_off(
        &self,
        project_id: i64,
        revision: i32,
        allowance: &Allowance,
        seen_edition: Option<i32>,
        who: &Participant,
    ) -> Result<ChecklistView> {
        // An approver's decision, like a triage: refused before the project is read, so the answer depends on nothing
        // but the role.
        if let Some(refusal) = approval_refusal(role_of(who.role.as_deref())) {
            return Err(ChecklistError::AccessDenied(match refusal {
                ApprovalRefusal::Governor => "Signing a checklist off is an approval, and the platform governor takes \
                                              none: it decides the rules the others act under."
                    .to_owned(),
                ApprovalRefusal::NotAnApprover => {
                    "Signing a checklist off is an approval, which this role may not give.".to_owned()
                }
            }));
        }
        let guarded = self.guard(project_id, allowance).await?;
        let project = &guarded.project;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, project, revision).await?;
        let seen = require_edition(seen_edition)?;
        require_status(&checklist, Status::Submitted, Cause::NotSubmitted, "signed off")?;
        require_seen(&checklist, seen, "signing it off")?;

        let four_eyes = self.enabled(Setting::FourEyesApprovalRequired).await?;
        let authors = authors_of(&mut tx, &checklist).await?;
        if four_eyes && wrote(who, &authors) {
            self.audit
                .record(who.actor.entry(
                    AuditOperation::ChecklistSignOffRefused,
                    &resource(project, revision),
                    &format!(
                        "Checklist of project \"{}\", revision {revision}: sign-off refused, four-eyes is on and the \
                         signer is one of its authors ({}).",
                        project.name,
                        names(&authors)
                    ),
                ))
                .await;
            return Err(ChecklistError::conflict(
                Cause::FourEyes,
                format!(
                    "Four-eyes approval: revision {revision} was written by {}, so it is signed off by somebody else.",
                    names(&authors)
                ),
            ));
        }
        let compared: Vec<IndependentAuthor> = authors
            .iter()
            .map(|author| IndependentAuthor {
                account_id: author.account_id.unwrap_or(0),
                username: author.username.clone(),
            })
            .collect();
        if let Err(refused) =
            self.independence.require_independent_of_authors(&compared, who.account_id, four_eyes, self.now()).await
        {
            if !matches!(refused, IndependenceError::Failed(_)) {
                self.audit
                    .record(who.actor.entry(
                        AuditOperation::ChecklistSignOffRefused,
                        &resource(project, revision),
                        &format!(
                            "Checklist of project \"{}\", revision {revision}: sign-off refused, four-eyes is on and the \
                             signer and one of its authors ({}) administered one another's account within the \
                             independence window.",
                            project.name,
                            names(&authors)
                        ),
                    ))
                    .await;
            }
            return Err(refused.into());
        }
        let now = self.now();
        let items = rows::items_of(&mut tx, checklist.template_version_id).await?;
        let measured = self.measurer.measure_all(&guarded.repository_ids, &items, days::instant(now)).await?;
        let lapsed = incomplete_lines(&lines(&mut tx, &checklist, self.today(), &outcomes(&measured)).await?);
        if !lapsed.is_empty() {
            self.audit
                .record(who.actor.entry(
                    AuditOperation::ChecklistSignOffRefused,
                    &resource(project, revision),
                    &format!(
                        "Checklist of project \"{}\", revision {revision}: sign-off refused, no longer complete since \
                         its submission — {}",
                        project.name,
                        in_words(&lapsed)
                    ),
                ))
                .await;
            return Err(ChecklistError::conflict_with(
                Cause::Incomplete,
                format!("Revision {revision} cannot be signed off: {}. Return it to its authors.", in_words(&lapsed)),
                Members::Incomplete(lapsed),
            ));
        }
        let current = current_of(&rows::answers_of(&mut tx, checklist.id).await?);
        let submitted = newest_per_line(&mut tx, checklist.id, Purpose::Submission).await?;
        drop(tx);
        let mut changed = Vec::new();
        for line in &measured {
            let before = submitted.get(&line.item.id);
            let found = &line.measurement;
            // Outcome and reason, not the evidence's digest: a scan run since that finds the same is the same picture.
            let same = before.is_some_and(|before| {
                before.outcome == found.outcome.wire_name()
                    && before.reason.as_deref() == found.reason.map(NoDataReason::wire_name)
                    && before.rule_digest == line.rule.digest()
            });
            if !same {
                changed.push(measured_line(&line.item, current.get(&line.item.id), found, before));
            }
        }
        if !changed.is_empty() {
            let lines: Vec<String> = changed
                .iter()
                .map(|line| {
                    let was = match &line.submitted_outcome {
                        None => "measured nothing at the submission".to_owned(),
                        Some(outcome) => format!(
                            "was {outcome}{}",
                            line.submitted_reason.as_ref().map_or_else(String::new, |reason| format!(" ({reason})"))
                        ),
                    };
                    format!(
                        "line {} {was}, now {}{}",
                        line.position,
                        line.outcome,
                        line.reason.as_ref().map_or_else(String::new, |reason| format!(" ({reason})"))
                    )
                })
                .collect();
            let lines = lines.join("; ");
            self.audit
                .record(who.actor.entry(
                    AuditOperation::ChecklistSignOffRefused,
                    &resource(project, revision),
                    &format!(
                        "Checklist of project \"{}\", revision {revision}: sign-off refused, a measurement changed \
                         since the submission — {lines}",
                        project.name
                    ),
                ))
                .await;
            return Err(ChecklistError::conflict_with(
                Cause::MeasurementChanged,
                format!(
                    "Revision {revision} cannot be signed off: a measurement changed since its submission — {lines}. \
                     Return it to its authors."
                ),
                Members::Measured(changed),
            ));
        }

        // The document is signed in the transaction below; the key is loaded, or created, before it opens.
        self.documents.require_signing_key().await?;
        let mut tx = self.write_tx().await?;
        require_still(
            rows::sign_off_checklist(
                &mut tx,
                checklist.id,
                seen,
                Status::Submitted.wire_name(),
                Status::SignedOff.wire_name(),
                rows::at(now),
                &who.username,
                who.account_id,
                four_eyes,
            )
            .await?,
            &checklist,
        )?;
        store(&mut tx, &checklist, &measured, Purpose::SignOff, now, who, &current).await?;
        // Rendered and signed with the sign-off, from the rows it has just written: a sign-off whose document cannot
        // be produced does not happen, and a document is never signed for a sign-off that rolled back.
        let document = self.documents.produce_signed(&mut tx, checklist.id, project, &guarded.repository_ids).await?;
        rows::commit(tx).await?;

        let rule = if four_eyes {
            format!("required, and the signer is none of its authors ({})", names(&authors))
        } else {
            "not required".to_owned()
        };
        self.audit
            .record(who.actor.entry(
                AuditOperation::ChecklistSignedOff,
                &resource(project, revision),
                &format!(
                    "Checklist of project \"{}\", revision {revision} signed off, submitted by {}; four-eyes {rule}{}; \
                     signed document SHA-256 {document}.",
                    project.name,
                    checklist.submitted_by.as_deref().unwrap_or("null"),
                    tally(&measured)
                ),
            ))
            .await;
        self.view_fresh(&guarded, checklist.id).await
    }

    // ------------------------------------------------------------------ measurements (§6)

    /// `measurements`: live for a draft or a submitted revision, as frozen for a signed-off one, the last stored for
    /// a superseded one.
    pub async fn measurements(
        &self,
        project_id: i64,
        revision: i32,
        allowance: &Allowance,
        reader: &Participant,
    ) -> Result<MeasurementsView> {
        let guarded = self.guard(project_id, allowance).await?;
        let mut tx = self.read_tx().await?;
        let checklist = require_revision(&mut tx, &guarded.project, revision).await?;
        let status = Status::of_stored(&checklist.status)?;
        let bound: Vec<ItemRow> = rows::items_of(&mut tx, checklist.template_version_id)
            .await?
            .into_iter()
            .filter(|item| item.bound_rule.is_some())
            .collect();
        let current = current_of(&rows::answers_of(&mut tx, checklist.id).await?);
        let at_submission = if matches!(status, Status::Submitted | Status::SignedOff) {
            newest_per_line(&mut tx, checklist.id, Purpose::Submission).await?
        } else {
            HashMap::new()
        };
        let live = matches!(status, Status::Draft | Status::Submitted);
        let mut stored: HashMap<i64, MeasurementRow> = HashMap::new();
        if !live {
            stored.extend(newest_per_line(&mut tx, checklist.id, Purpose::Submission).await?);
            stored.extend(newest_per_line(&mut tx, checklist.id, Purpose::SignOff).await?);
        }
        // What was stored carries the repositories of its day: a reader who does not see each of them is told the
        // revision is absent, in the words an absent one gets.
        let frozen: Vec<&MeasurementRow> = at_submission.values().chain(stored.values()).collect();
        if !crate::carried::seen_by(&crate::carried::of(frozen.into_iter()), allowance) {
            return Err(ChecklistError::not_found(format!(
                "Project \"{}\" has no checklist revision {revision}.",
                guarded.project.name
            )));
        }
        let now = self.now();
        let names = self.projects.repository_names(&guarded.repository_ids).await.map_err(ChecklistError::Failed)?;
        let mut shown: HashMap<i64, MeasurementView> = HashMap::new();
        if live {
            for line in self.measurer.measure_all(&guarded.repository_ids, &bound, days::instant(now)).await? {
                let answer = current.get(&line.item.id);
                shown.insert(line.item.id, live_view(checklist.id, &line, now, reader, answer, &names)?);
            }
        } else {
            for (item_id, row) in &stored {
                shown.insert(*item_id, stored_view(row, &names)?);
            }
        }
        let mut proofs: HashMap<i64, Vec<EvidenceRow>> = HashMap::new();
        for row in rows::evidence_of(&mut tx, checklist.id).await? {
            proofs.entry(row.item_id).or_default().push(row);
        }
        let today = self.today();
        let mut lines = Vec::with_capacity(bound.len());
        for item in &bound {
            let answer = current.get(&item.id);
            let measurement = shown.remove(&item.id);
            let value = answer.map(|row| ChecklistAnswer::parse(Some(&row.value))).transpose()?;
            let outcome = measurement.as_ref().and_then(|view| MeasurementOutcome::of_stored(&view.outcome));
            let reconciled = Reconciliation::of(value, outcome);
            let declared_yes = reconciled == Reconciliation::DeclaredNotMeasured && value == Some(ChecklistAnswer::Yes);
            let problems = if live {
                problems(item, answer, proofs.get(&item.id).map_or(&[][..], Vec::as_slice), today, outcome)?
                    .into_iter()
                    .filter(|problem| {
                        *problem == LineProblem::MeasurementContradicted
                            || (declared_yes && problem.asked_where_no_data())
                    })
                    .map(|problem| problem.wire_name().to_owned())
                    .collect()
            } else {
                Vec::new()
            };
            let submitted_view = match at_submission.get(&item.id) {
                Some(row) => Some(stored_view(row, &names)?),
                None => None,
            };
            let reconciliation = if measurement.is_none() {
                Reconciliation::NotMeasuredHere.wire_name()
            } else {
                reconciled.wire_name()
            };
            lines.push(MeasuredLineView {
                item_id: item.id,
                position: item.position,
                item_key: item.item_key.clone(),
                rule: rule_raw(item.bound_rule.as_deref())?,
                answer: answer.map(|row| row.value.clone()),
                answer_id: answer.map(|row| row.id),
                measurement,
                at_submission: submitted_view,
                reconciliation: reconciliation.to_owned(),
                problems,
            });
        }
        Ok(MeasurementsView {
            project_id: guarded.project.project_id,
            revision: checklist.revision,
            status: checklist.status.clone(),
            live,
            computed_at: live.then(|| vectispire_cp_audit::iso_instant(now)),
            lines,
        })
    }

    // ------------------------------------------------------------------ writing a line

    /// `writeLine`: one write on one line of a draft, if the line is as the person read it; read again and decided
    /// again a few times when another write came first.
    async fn write_line<'s, F>(
        &'s self,
        read: &ChecklistRow,
        item_id: i64,
        seen_edition: i32,
        mut write: F,
    ) -> Result<ChecklistRow>
    where
        F: for<'t> FnMut(
            &'t mut Tx,
            i32,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 't>>,
    {
        let mut current = read.clone();
        for _ in 0..ATTEMPTS {
            require_status(&current, Status::Draft, Cause::NotDraft, "answered and proven")?;
            if seen_edition > current.edition {
                return Err(ChecklistError::conflict(
                    Cause::Changed,
                    format!(
                        "Revision {} has no edition {seen_edition} yet — it is at edition {}. Read it again.",
                        current.revision, current.edition
                    ),
                ));
            }
            let mut tx = self.read_tx().await?;
            let line_edition = line_edition(&mut tx, current.id, item_id).await?;
            drop(tx);
            if line_edition > seen_edition {
                return Err(ChecklistError::conflict(
                    Cause::LineChanged,
                    format!(
                        "This line of revision {} has changed since edition {seen_edition} — somebody wrote on it at \
                         edition {line_edition}. Read it again.",
                        current.revision
                    ),
                ));
            }
            let edition = current.edition;
            let mut tx = self.write_tx().await?;
            if rows::touch_draft(&mut tx, current.id, edition, Status::Draft.wire_name()).await? == 1 {
                write(&mut tx, edition.saturating_add(1)).await?;
                rows::commit(tx).await?;
                let mut tx = self.read_tx().await?;
                return reread(&mut tx, &current).await;
            }
            rows::rollback(tx).await?;
            let mut tx = self.read_tx().await?;
            current = reread(&mut tx, &current).await?;
        }
        Err(ChecklistError::conflict(
            Cause::Changed,
            format!("Revision {} is being changed by somebody else right now. Read it again.", read.revision),
        ))
    }

    /// `openRevision`: the previous one superseded if open, the new row, and what it carries — in one transaction.
    async fn open_revision(
        &self,
        project: &VisibleProject,
        version: &VersionRow,
        previous: Option<&ChecklistRow>,
        carried: Carried,
        who: &Participant,
    ) -> Result<ChecklistRow> {
        let now = self.now();
        let next = previous.map_or(1, |row| row.revision.saturating_add(1));
        let written: Result<i64> = async {
            let mut tx = self.write_tx().await?;
            if let Some(row) = previous
                && Status::of_stored(&row.status)?.is_open()
            {
                require_still(
                    rows::supersede_checklist(
                        &mut tx,
                        row.id,
                        row.edition,
                        Status::Superseded.wire_name(),
                        rows::at(now),
                        &who.username,
                    )
                    .await?,
                    row,
                )?;
            }
            let id = rows::insert_checklist(
                &mut tx,
                &NewChecklist {
                    project_id: project.project_id,
                    template_version_id: version.id,
                    revision: next,
                    status: Status::Draft.wire_name(),
                    author_id: who.account_id,
                    author: &who.username,
                    opened_at: rows::at(now),
                    supersedes_id: previous.map(|row| row.id),
                },
            )
            .await?;
            for answer in &carried.answers {
                let row = AnswerRow {
                    checklist_id: id,
                    carried_by: Some(who.username.clone()),
                    carried_by_id: Some(who.account_id),
                    carried_at: Some(rows::at(now)),
                    edition: 1,
                    ..answer.clone()
                };
                rows::insert_answer(&mut tx, &row).await?;
            }
            for proof in &carried.evidence {
                let row =
                    EvidenceRow { checklist_id: id, carried_by_id: Some(who.account_id), edition: 1, ..proof.clone() };
                rows::insert_evidence(&mut tx, &row).await?;
            }
            rows::commit(tx).await?;
            Ok(id)
        }
        .await;
        let id = match written {
            Ok(id) => id,
            Err(failed @ ChecklistError::Failed(_)) => {
                // Whatever failed, the transaction rolled back; only the committed rows say whether it was somebody
                // else's revision taking the number or the slot.
                let mut tx = self.read_tx().await?;
                if let Some(latest) = rows::latest_checklist(&mut tx, project.project_id).await?
                    && latest.revision >= next
                {
                    return Err(ChecklistError::conflict(
                        Cause::Changed,
                        format!(
                            "Somebody else opened revision {} of this project's checklist meanwhile. Read it again.",
                            latest.revision
                        ),
                    ));
                }
                return Err(failed);
            }
            Err(refusal) => return Err(refusal),
        };
        let mut tx = self.read_tx().await?;
        rows::checklist_by_id(&mut tx, id)
            .await?
            .ok_or_else(|| ChecklistError::defect(format!("Checklist {id} is gone.")))
    }

    // ------------------------------------------------------------------ views

    /// The view of a revision read again after a write, in a transaction of its own.
    async fn view_fresh(&self, guarded: &Guarded, checklist_id: i64) -> Result<ChecklistView> {
        let mut tx = self.read_tx().await?;
        let checklist = rows::checklist_by_id(&mut tx, checklist_id)
            .await?
            .ok_or_else(|| ChecklistError::defect(format!("Checklist {checklist_id} is gone.")))?;
        self.view(&mut tx, guarded, &checklist).await
    }

    /// `view`: a revision whole; a draft's measured lines measured for the read, so that `readyToSubmit` promises
    /// what the submission accepts.
    pub(crate) async fn view(&self, tx: &mut Tx, guarded: &Guarded, checklist: &ChecklistRow) -> Result<ChecklistView> {
        let version = version_of(tx, checklist).await?;
        let words = forms::layout_of(version.layout.as_deref().unwrap_or("null"))?.answers().clone();
        let draft = Status::of_stored(&checklist.status)? == Status::Draft;
        let measured = if draft {
            let items = rows::items_of(tx, checklist.template_version_id).await?;
            outcomes(&self.measurer.measure_all(&guarded.repository_ids, &items, days::instant(self.now())).await?)
        } else {
            HashMap::new()
        };
        let lines = lines(tx, checklist, self.today(), &measured).await?;
        let ready = draft && lines.iter().all(|line| line.problems.is_empty());
        let reference = version_ref(tx, version.id).await?;
        let mut revision_of = HashMap::new();
        let authors = authors_of(tx, checklist).await?;
        let mut names: Vec<String> = Vec::new();
        for author in authors {
            if !names.contains(&author.username) {
                names.push(author.username);
            }
        }
        Ok(ChecklistView {
            checklist: summary(tx, checklist, &reference, &mut revision_of).await?,
            project_name: guarded.project.name.clone(),
            offers_not_applicable: words.offers_not_applicable(),
            answer_words: AnswerWordsView {
                yes: words.yes().to_owned(),
                no: words.no().to_owned(),
                not_applicable: words.not_applicable().map(str::to_owned),
            },
            authors: names,
            four_eyes_required: self.enabled(Setting::FourEyesApprovalRequired).await?,
            ready_to_submit: ready,
            lines,
        })
    }

    /// A day as a person states it — `2026-09-28` — neither before 1970 nor after today.
    fn require_day(&self, value: Option<&str>) -> Result<Date> {
        let Some(value) = value.filter(|value| !java::is_blank(value)) else {
            return Err(ChecklistError::invalid("State the day the work was done — \"performedOn\", as 2026-09-28."));
        };
        let stripped = java::strip(value);
        let day = days::parse(stripped).ok_or_else(|| {
            ChecklistError::invalid(format!(
                "\"{}\" is not a day: write it as 2026-09-28.",
                bounded_text::clip(Some(stripped), 20).unwrap_or("")
            ))
        })?;
        if day > self.today() {
            return Err(ChecklistError::invalid(format!(
                "A proof is of work already done: {} is in the future.",
                days::written(day)
            )));
        }
        let earliest = Date::from_calendar_date(1970, time::Month::January, 1).unwrap_or(Date::MIN);
        if day < earliest {
            return Err(ChecklistError::invalid(format!("A proof dated {} is before 1970-01-01.", days::written(day))));
        }
        Ok(day)
    }
}

// ------------------------------------------------------------------ Vectispire's own answers

/// One line Vectispire writes: an answer resting on the measurement, or the withdrawal of its own.
#[derive(Debug, Clone)]
struct Automatic {
    line: LineMeasurement,
    value: ChecklistAnswer,
    comment: Option<String>,
    withdrawal: bool,
}

fn plan(
    current: &BTreeMap<i64, AnswerRow>,
    measured: Vec<LineMeasurement>,
    words: &AnswerWords,
) -> Result<Vec<Automatic>> {
    let mut planned = Vec::new();
    for line in measured {
        let answer = current.get(&line.item.id);
        if answer.is_some_and(|answer| !AnswerAuthor::is_system(Some(&answer.answered_by_kind))) {
            continue;
        }
        let automatic = match line.measurement.outcome {
            MeasurementOutcome::Pass => {
                let yes = GivenAnswer::of(ChecklistAnswer::Yes, None, words)?;
                Some(Automatic { value: yes.value, comment: None, withdrawal: false, line })
            }
            MeasurementOutcome::Fail => {
                let no = GivenAnswer::of(ChecklistAnswer::No, Some(&generated_comment(&line)), words)?;
                Some(Automatic { value: no.value, comment: no.comment, withdrawal: false, line })
            }
            MeasurementOutcome::NoData => match answer {
                None => None,
                Some(answer) => {
                    let comment = bounded_text::clip(
                        Some(&format!(
                            "Withdrawn by Vectispire: the measurement this answer rested on has no data any more — {}",
                            line.measurement.summary
                        )),
                        MAX_REASON,
                    )
                    .map(str::to_owned);
                    Some(Automatic {
                        value: ChecklistAnswer::parse(Some(&answer.value))?,
                        comment,
                        withdrawal: true,
                        line,
                    })
                }
            },
        };
        if let Some(automatic) = automatic
            && answer.is_none_or(|answer| !states_the_same(answer, &automatic))
        {
            planned.push(automatic);
        }
    }
    Ok(planned)
}

/// `statesTheSame`: the same value and the same generated comment, written in this revision.
fn states_the_same(answer: &AnswerRow, automatic: &Automatic) -> bool {
    answer.carried_from_id.is_none()
        && !answer.needs_confirmation
        && answer.value == automatic.value.wire_name()
        && answer.comment == automatic.comment
}

/// `generatedComment`: the rule and what the measurement found, in English, saying who measured.
pub(crate) fn generated_comment(line: &LineMeasurement) -> String {
    let text = format!("Measured by Vectispire ({}): {}", line.rule.kind().wire_name(), line.measurement.summary);
    bounded_text::clip(Some(&text), MAX_REASON).unwrap_or("").to_owned()
}

fn system_answer_row(
    checklist_id: i64,
    automatic: &Automatic,
    measurement_id: i64,
    now: OffsetDateTime,
    edition: i32,
) -> AnswerRow {
    AnswerRow {
        id: 0,
        checklist_id,
        item_id: automatic.line.item.id,
        value: automatic.value.wire_name().to_owned(),
        comment: automatic.comment.clone(),
        // No account: the kind says so, and the check constraint refuses a system row naming one.
        answered_by: AnswerAuthor::SYSTEM_NAME.to_owned(),
        answered_by_id: None,
        answered_by_kind: AnswerAuthor::System.wire_name().to_owned(),
        answered_at: rows::at(now),
        measurement_id: Some(measurement_id),
        carried_from_id: None,
        carried_by: None,
        carried_by_id: None,
        carried_at: None,
        needs_confirmation: false,
        withdrawn: automatic.withdrawal,
        edition,
    }
}

fn describe_automatic(project: &VisibleProject, revision: i32, automatic: &Automatic) -> String {
    let item = &automatic.line.item;
    let found = &automatic.line.measurement;
    let line = format!(
        "Checklist of project \"{}\", revision {revision}, line {} (row {}): ",
        project.name, item.position, item.sheet_row
    );
    if automatic.withdrawal {
        format!(
            "{line}the automatic answer {} withdrawn by Vectispire, its measurement having no data any more — {}.",
            automatic.value.wire_name(),
            describe(found)
        )
    } else {
        format!(
            "{line}answered {} automatically by Vectispire, resting on its measurement — {}, evidence sha256 {}.{}",
            automatic.value.wire_name(),
            describe(found),
            short(&found.evidence_digest()),
            if automatic.comment.is_none() { "" } else { " The comment is the measurement's summary." }
        )
    }
}

// ------------------------------------------------------------------ carrying answers (§4)

/// What a new revision receives from the one it follows.
#[derive(Debug, Clone)]
struct Carried {
    answers: Vec<AnswerRow>,
    evidence: Vec<EvidenceRow>,
    current: usize,
    to_confirm: usize,
    other_template: bool,
}

impl Carried {
    fn nothing() -> Carried {
        Carried { answers: Vec::new(), evidence: Vec::new(), current: 0, to_confirm: 0, other_template: false }
    }

    fn describe(&self) -> String {
        if self.other_template {
            return ", another template: no answer carried.".to_owned();
        }
        let plural = |count: usize, one: &str, many: &str| format!("{count} {}", if count == 1 { one } else { many });
        format!(
            ": {} carried as current, {} to be confirmed, {} carried.",
            plural(self.current, "answer", "answers"),
            self.to_confirm,
            plural(self.evidence.len(), "proof", "proofs")
        )
    }
}

/// `carryOnto`: the answers and proofs of `previous` that follow into a revision on `version`, paired by key and
/// content digest.
async fn carry_onto(
    tx: &mut Tx,
    previous: &ChecklistRow,
    version: &VersionRow,
    template: &TemplateRow,
) -> Result<Carried> {
    let from = version_of(tx, previous).await?;
    if from.template_id != template.id {
        return Ok(Carried { other_template: true, ..Carried::nothing() });
    }
    let before = rows::items_of(tx, from.id).await?;
    let after = rows::items_of(tx, version.id).await?;
    let before_by_key: HashMap<&str, &ItemRow> = before.iter().map(|item| (item.item_key.as_str(), item)).collect();
    let after_by_key: HashMap<&str, &ItemRow> = after.iter().map(|item| (item.item_key.as_str(), item)).collect();
    let offers_not_applicable = forms::layout_of(version.layout.as_deref().unwrap_or("null"))?.offers_not_applicable();

    let current_by_item = current_of(&rows::answers_of(tx, previous.id).await?);
    let mut proofs_by_item: HashMap<i64, Vec<EvidenceRow>> = HashMap::new();
    for row in rows::evidence_of(tx, previous.id).await? {
        if row.withdrawn_at.is_none() {
            proofs_by_item.entry(row.item_id).or_default().push(row);
        }
    }

    let mut carried = Carried::nothing();
    let domains = |rows: &[ItemRow]| rows.iter().map(templates::domain).collect::<Result<Vec<_>>>();
    let pairing = VersionPairing::of(&domains(&before)?, &domains(&after)?, &[])?;
    for change in &pairing.changes {
        let (was, next, changed) = match change {
            Change::Unchanged { previous, next } => (previous, next, false),
            Change::Changed { previous, next, .. } => (previous, next, true),
            Change::Added { .. } | Change::Removed { .. } => continue,
        };
        let (Some(source), Some(target)) =
            (before_by_key.get(was.key.value()).copied(), after_by_key.get(next.key.value()).copied())
        else {
            continue;
        };
        if let Some(answer) = current_by_item.get(&source.id) {
            let confirm = changed
                || answer.needs_confirmation
                || (answer.value == ChecklistAnswer::NotApplicable.wire_name() && !offers_not_applicable);
            carried.answers.push(AnswerRow {
                id: 0,
                checklist_id: 0,
                item_id: target.id,
                // The answer is the person's who gave it, then: the copy keeps their name and instant — and rests on no
                // measurement of the new revision: measurements are never carried.
                measurement_id: None,
                carried_from_id: Some(answer.id),
                carried_by: None,
                carried_by_id: None,
                carried_at: None,
                needs_confirmation: confirm,
                edition: 1,
                ..answer.clone()
            });
            if confirm {
                carried.to_confirm = carried.to_confirm.saturating_add(1);
            } else {
                carried.current = carried.current.saturating_add(1);
            }
        }
        for proof in proofs_by_item.get(&source.id).map_or(&[][..], Vec::as_slice) {
            let performed = days::day_of(proof.performed_on.0);
            carried.evidence.push(EvidenceRow {
                id: 0,
                checklist_id: 0,
                item_id: target.id,
                // Re-dated against the line it now proves.
                valid_until: valid_until(performed, target.evidence_validity_months).map(rows::at),
                carried_from_id: Some(proof.id),
                carried_by_id: None,
                edition: 1,
                withdrawn_by: None,
                withdrawn_by_id: None,
                withdrawn_at: None,
                withdrawn_edition: None,
                ..proof.clone()
            });
        }
    }
    Ok(carried)
}

// ------------------------------------------------------------------ completeness and authors

/// `problems`: what keeps a line from a submission — the one judgement a read, a submission and a sign-off make.
pub(crate) fn problems(
    item: &ItemRow,
    answer: Option<&AnswerRow>,
    proofs: &[EvidenceRow],
    today: Date,
    measured: Option<MeasurementOutcome>,
) -> Result<Vec<LineProblem>> {
    let Some(answer) = answer else {
        return Ok(vec![LineProblem::Unanswered]);
    };
    let mut problems = Vec::new();
    if answer.needs_confirmation {
        problems.push(LineProblem::AwaitingConfirmation);
    }
    let value = ChecklistAnswer::parse(Some(&answer.value))?;
    let reconciled = Reconciliation::of(Some(value), measured);
    if reconciled == Reconciliation::Contradicted {
        problems.push(LineProblem::MeasurementContradicted);
    }
    let declared_not_measured = value == ChecklistAnswer::Yes && reconciled == Reconciliation::DeclaredNotMeasured;
    if (value.requires_comment() || declared_not_measured) && answer.comment.as_deref().is_none_or(java::is_blank) {
        problems.push(LineProblem::CommentRequired);
    }
    let kind = evidence_kind(item)?;
    let asked = if declared_not_measured && kind == EvidenceKind::None { EvidenceKind::LinkOrFile } else { kind };
    if value == ChecklistAnswer::Yes && asked != EvidenceKind::None {
        let eligible: Vec<&EvidenceRow> = proofs
            .iter()
            .filter(|proof| proof.withdrawn_at.is_none())
            .filter(|proof| asked == EvidenceKind::LinkOrFile || proof.kind == "file")
            .collect();
        if eligible.is_empty() {
            problems.push(LineProblem::EvidenceRequired);
        } else if !eligible.iter().any(|proof| in_date(proof, today)) {
            problems.push(LineProblem::EvidenceExpired);
        }
    }
    Ok(problems)
}

fn incomplete_lines(judged: &[LineView]) -> Vec<IncompleteLine> {
    judged
        .iter()
        .map(|line| IncompleteLine {
            item_id: line.item_id,
            position: line.position,
            problems: line
                .problems
                .iter()
                .filter(|problem| problem.as_str() != LineProblem::MeasurementContradicted.wire_name())
                .cloned()
                .collect(),
        })
        .filter(|line| !line.problems.is_empty())
        .collect()
}

fn contradicted(judged: &[LineView]) -> BTreeSet<i64> {
    judged
        .iter()
        .filter(|line| line.problems.iter().any(|problem| problem == LineProblem::MeasurementContradicted.wire_name()))
        .map(|line| line.item_id)
        .collect()
}

/// "line 2 unanswered; line 3 evidence required".
fn in_words(lines: &[IncompleteLine]) -> String {
    lines
        .iter()
        .map(|line| format!("line {} {}", line.position, line.problems.join(", ").replace('_', " ")))
        .collect::<Vec<_>>()
        .join("; ")
}

fn require_complete(checklist: &ChecklistRow, act: &str, judged: &[LineView]) -> Result<()> {
    let incomplete = incomplete_lines(judged);
    if !incomplete.is_empty() {
        return Err(ChecklistError::conflict_with(
            Cause::Incomplete,
            format!("Revision {} cannot be {act}: {}.", checklist.revision, in_words(&incomplete)),
            Members::Incomplete(incomplete),
        ));
    }
    Ok(())
}

/// `authorsOf`: everybody who wrote what the revision says — carrying is not writing, and Vectispire is nobody.
async fn authors_of(tx: &mut Tx, checklist: &ChecklistRow) -> Result<Vec<Author>> {
    let mut authors: Vec<Author> = Vec::new();
    let mut add = |author: Author| {
        if !authors.contains(&author) {
            authors.push(author);
        }
    };
    if checklist.supersedes_id.is_none() {
        add(Author { account_id: Some(checklist.author_id), username: checklist.author.clone() });
    }
    for row in rows::answers_of(tx, checklist.id).await? {
        if !AnswerAuthor::is_system(Some(&row.answered_by_kind)) {
            add(Author { account_id: row.answered_by_id, username: row.answered_by.clone() });
        }
    }
    for row in rows::evidence_of(tx, checklist.id).await? {
        add(Author { account_id: Some(row.added_by_id), username: row.added_by.clone() });
        if let Some(by) = row.withdrawn_by_id {
            add(Author { account_id: Some(by), username: row.withdrawn_by.clone().unwrap_or_default() });
        }
    }
    if let Some(by) = checklist.submitted_by_id {
        add(Author { account_id: Some(by), username: checklist.submitted_by.clone().unwrap_or_default() });
    }
    Ok(authors)
}

/// Compared as two people, like the triage: the account, and its name — a name reused is refused too.
fn wrote(who: &Participant, authors: &[Author]) -> bool {
    let name = java::strip(&who.username);
    authors.iter().any(|author| {
        author.account_id == Some(who.account_id)
            || java::compare_ignore_case(java::strip(&author.username), name).is_eq()
    })
}

fn names(authors: &[Author]) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for author in authors {
        if !seen.contains(&author.username.as_str()) {
            seen.push(&author.username);
        }
    }
    seen.join(", ")
}

// ------------------------------------------------------------------ the rows

async fn require_revision(tx: &mut Tx, project: &VisibleProject, revision: i32) -> Result<ChecklistRow> {
    rows::checklist_revision(tx, project.project_id, revision).await?.ok_or_else(|| {
        ChecklistError::not_found(format!("Project \"{}\" has no checklist revision {revision}.", project.name))
    })
}

async fn require_line(tx: &mut Tx, checklist: &ChecklistRow, item_id: i64) -> Result<ItemRow> {
    rows::item_by_id(tx, item_id).await?.filter(|item| item.version_id == checklist.template_version_id).ok_or_else(
        || ChecklistError::not_found(format!("Checklist revision {} has no line {item_id}.", checklist.revision)),
    )
}

async fn require_evidence(tx: &mut Tx, checklist: &ChecklistRow, evidence_id: i64) -> Result<EvidenceRow> {
    rows::evidence_by_id(tx, evidence_id).await?.filter(|row| row.checklist_id == checklist.id).ok_or_else(|| {
        ChecklistError::not_found(format!("Checklist revision {} has no proof {evidence_id}.", checklist.revision))
    })
}

async fn require_latest(tx: &mut Tx, project: &VisibleProject, checklist: &ChecklistRow) -> Result<()> {
    if let Some(latest) = rows::latest_checklist(tx, project.project_id).await?
        && latest.id != checklist.id
    {
        return Err(ChecklistError::conflict(
            Cause::NotLatest,
            format!(
                "Revision {} has been followed by revision {}: act on that one.",
                checklist.revision, latest.revision
            ),
        ));
    }
    Ok(())
}

/// `requireShown`: every element a line of this revision bound to a rule, named once, with a digest.
fn require_shown(shown: Option<&[Option<ShownMeasurement>]>, lines: &[ItemRow]) -> Result<HashMap<i64, String>> {
    let Some(shown) = shown else {
        return Err(ChecklistError::invalid(
            "Name the measurements you were shown (\"lines\": each line's itemId and the measurementDigest you read): \
             only those are answered.",
        ));
    };
    let by_id: HashMap<i64, &ItemRow> = lines.iter().map(|line| (line.id, line)).collect();
    let mut seen = HashMap::new();
    for element in shown {
        let (Some(item_id), Some(digest)) = (
            element.as_ref().and_then(|element| element.item_id),
            element.as_ref().and_then(|element| element.measurement_digest.as_deref()).filter(|d| !java::is_blank(d)),
        ) else {
            return Err(ChecklistError::invalid(
                "Each shown measurement names its line (\"itemId\") and the digest you read (\"measurementDigest\").",
            ));
        };
        let Some(line) = by_id.get(&item_id) else {
            return Err(ChecklistError::invalid(format!("This revision has no line {item_id}.")));
        };
        if line.bound_rule.is_none() {
            return Err(ChecklistError::invalid(format!(
                "Line {} is measured by no rule: an answer cannot rest on a measurement it does not have.",
                line.position
            )));
        }
        if seen.insert(line.id, java::strip(digest).to_owned()).is_some() {
            return Err(ChecklistError::invalid(format!("Line {} is named twice.", line.position)));
        }
    }
    Ok(seen)
}

fn require_edition(seen: Option<i32>) -> Result<i32> {
    seen.ok_or_else(|| {
        ChecklistError::invalid(
            "State the edition you read — the checklist's \"edition\": a checklist is changed from what somebody has \
             seen.",
        )
    })
}

/// The edition the person read is the revision's now.
fn require_seen(checklist: &ChecklistRow, seen: i32, doing: &str) -> Result<()> {
    if checklist.edition != seen {
        return Err(ChecklistError::conflict(
            Cause::Changed,
            format!(
                "Revision {} has changed since edition {seen} — it is at edition {}. Read it again before {doing}.",
                checklist.revision, checklist.edition
            ),
        ));
    }
    Ok(())
}

fn require_status(checklist: &ChecklistRow, wanted: Status, cause: Cause, act: &str) -> Result<()> {
    if Status::of_stored(&checklist.status)? != wanted {
        return Err(ChecklistError::conflict(
            cause,
            format!(
                "Revision {} is {}: only a {} revision is {act}.",
                checklist.revision,
                checklist.status,
                wanted.wire_name().replace('_', " ")
            ),
        ));
    }
    Ok(())
}

/// The conditional statement's answer: nothing matched means another write came first.
fn require_still(updated: u64, checklist: &ChecklistRow) -> Result<()> {
    if updated != 1 {
        return Err(ChecklistError::conflict(
            Cause::Changed,
            format!(
                "Revision {} changed while this was being done — by somebody else. Read it again.",
                checklist.revision
            ),
        ));
    }
    Ok(())
}

async fn reread(tx: &mut Tx, checklist: &ChecklistRow) -> Result<ChecklistRow> {
    rows::checklist_by_id(tx, checklist.id)
        .await?
        .ok_or_else(|| ChecklistError::defect(format!("Checklist {} is gone.", checklist.id)))
}

/// The edition at which a line last changed: its newest answer, proof or withdrawal; 0 for none.
async fn line_edition(tx: &mut Tx, checklist_id: i64, item_id: i64) -> Result<i32> {
    let mut newest = 0;
    for row in rows::answers_of_line(tx, checklist_id, item_id).await? {
        newest = newest.max(row.edition);
    }
    for row in rows::evidence_of_line(tx, checklist_id, item_id).await? {
        newest = newest.max(row.edition).max(row.withdrawn_edition.unwrap_or(0));
    }
    Ok(newest)
}

/// `currentOf`: the newest row of each line — unless it is Vectispire withdrawing its own answer, when the line has
/// none. Every reader of "the answer" goes through here.
pub(crate) fn current_of(rows: &[AnswerRow]) -> BTreeMap<i64, AnswerRow> {
    let mut current = BTreeMap::new();
    for row in rows {
        if row.withdrawn {
            current.remove(&row.item_id);
        } else {
            current.insert(row.item_id, row.clone());
        }
    }
    current
}

#[allow(clippy::too_many_arguments)]
fn answer_row(
    checklist_id: i64,
    item_id: i64,
    value: &str,
    comment: Option<&str>,
    who: &Participant,
    now: OffsetDateTime,
    confirmed_from: Option<i64>,
    edition: i32,
) -> AnswerRow {
    AnswerRow {
        id: 0,
        checklist_id,
        item_id,
        value: value.to_owned(),
        comment: comment.map(str::to_owned),
        answered_by: who.username.clone(),
        answered_by_id: Some(who.account_id),
        answered_by_kind: AnswerAuthor::Person.wire_name().to_owned(),
        answered_at: rows::at(now),
        measurement_id: None,
        carried_from_id: confirmed_from,
        carried_by: None,
        carried_by_id: None,
        carried_at: None,
        needs_confirmation: false,
        withdrawn: false,
        edition,
    }
}

fn proof_row(
    checklist: &ChecklistRow,
    item: &ItemRow,
    performed: Date,
    who: &Participant,
    now: OffsetDateTime,
    edition: i32,
) -> EvidenceRow {
    EvidenceRow {
        id: 0,
        checklist_id: checklist.id,
        item_id: item.id,
        kind: String::new(),
        link: None,
        file_id: None,
        file_name: None,
        media_type: None,
        file_size: None,
        file_sha256: None,
        performed_on: rows::at(days::start_of(performed)),
        valid_until: valid_until(performed, item.evidence_validity_months).map(rows::at),
        added_by: who.username.clone(),
        added_by_id: who.account_id,
        added_at: rows::at(now),
        carried_from_id: None,
        carried_by_id: None,
        edition,
        withdrawn_by: None,
        withdrawn_by_id: None,
        withdrawn_at: None,
        withdrawn_edition: None,
    }
}

/// The last day a proof holds: performed on, plus the line's validity. None when the line states none.
fn valid_until(performed: Date, validity_months: Option<i32>) -> Option<OffsetDateTime> {
    validity_months.and_then(|months| days::plus_months(performed, months)).map(days::start_of)
}

fn in_date(proof: &EvidenceRow, today: Date) -> bool {
    proof.withdrawn_at.is_none() && proof.valid_until.is_none_or(|until| days::day_of(until.0) >= today)
}

fn evidence_kind(item: &ItemRow) -> Result<EvidenceKind> {
    EvidenceKind::ALL
        .into_iter()
        .find(|kind| kind.wire_name().eq_ignore_ascii_case(&item.evidence_kind))
        .ok_or_else(|| ChecklistError::defect(format!("An item asks for an unknown evidence: {}", item.evidence_kind)))
}

/// An `https:` or `http:` address with a host, as written, bounded.
fn require_link(value: Option<&str>) -> Result<String> {
    let link = java::strip(value.unwrap_or(""));
    if link.is_empty() {
        return Err(ChecklistError::invalid("A link proof names its address, \"link\"."));
    }
    let length = java::utf16_len(link);
    if length > MAX_LINK {
        return Err(ChecklistError::invalid(format!(
            "A link is at most {MAX_LINK} characters; this one has {length}."
        )));
    }
    if crate::links::has_web_host(link) {
        return Ok(link.to_owned());
    }
    Err(ChecklistError::invalid(format!(
        "A link proof is an https: or http: address with a host; \"{}\" is not one.",
        bounded_text::clip(Some(link), 60).unwrap_or("")
    )))
}

/// A file's name as the download will offer it: its last path segment, without control characters.
fn require_file_name(value: Option<&str>) -> Result<String> {
    let name = java::strip(value.unwrap_or(""));
    let last = name.rfind(['/', '\\']).map_or(name, |slash| name.get(slash.saturating_add(1)..).unwrap_or(""));
    // `\p{Cntrl}` without UNICODE_CHARACTER_CLASS: the ASCII controls and DEL.
    let cleaned: String = last.chars().filter(|c| !(*c < '\u{20}' || *c == '\u{7f}')).collect();
    let name = java::strip(&cleaned);
    if name.is_empty() || name == "." || name == ".." {
        return Err(ChecklistError::invalid("Name the file — \"name\", as it should be downloaded."));
    }
    let length = java::utf16_len(name);
    if length > MAX_FILE_NAME {
        return Err(ChecklistError::invalid(format!(
            "A file's name is at most {MAX_FILE_NAME} characters; this one has {length}."
        )));
    }
    Ok(name.to_owned())
}

fn resource(project: &VisibleProject, revision: i32) -> String {
    format!("{}/{revision}", project.project_id)
}

fn iso(at: rows::StoredInstant) -> String {
    vectispire_cp_audit::iso_instant(at.0)
}

fn short(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

// ------------------------------------------------------------------ measurements

async fn store(
    tx: &mut Tx,
    checklist: &ChecklistRow,
    measured: &[LineMeasurement],
    purpose: Purpose,
    now: OffsetDateTime,
    who: &Participant,
    current: &BTreeMap<i64, AnswerRow>,
) -> Result<()> {
    for line in measured {
        let answer = current.get(&line.item.id);
        let value = answer.map(|row| ChecklistAnswer::parse(Some(&row.value))).transpose()?;
        let row = measurement_row(checklist.id, line, purpose, now, &who.username, answer, value);
        rows::insert_measurement(tx, &row).await?;
    }
    Ok(())
}

fn measurement_row(
    checklist_id: i64,
    line: &LineMeasurement,
    purpose: Purpose,
    now: OffsetDateTime,
    computed_by: &str,
    answer: Option<&AnswerRow>,
    value: Option<ChecklistAnswer>,
) -> MeasurementRow {
    let measurement = &line.measurement;
    MeasurementRow {
        id: 0,
        checklist_id,
        item_id: line.item.id,
        purpose: purpose.wire_name().to_owned(),
        rule_kind: line.rule.kind().wire_name().to_owned(),
        rule_digest: line.rule.digest(),
        bound_rule: line.rule.canonical(),
        outcome: measurement.outcome.wire_name().to_owned(),
        reason: measurement.reason.map(|reason| reason.wire_name().to_owned()),
        as_of: measurement.as_of.map(|at| rows::at(days::offset(at))),
        computed_at: rows::at(now),
        computed_by: computed_by.to_owned(),
        answer_id: answer.map(|row| row.id),
        answer_value: value.map(|value| value.wire_name().to_owned()),
        reconciliation: Some(Reconciliation::of(value, Some(measurement.outcome)).wire_name().to_owned()),
        evidence_digest: measurement.evidence_digest(),
        evidence: measurement.evidence_json(),
    }
}

/// The newest measurement of each line stored for one purpose.
pub(crate) async fn newest_per_line(
    tx: &mut Tx,
    checklist_id: i64,
    purpose: Purpose,
) -> Result<HashMap<i64, MeasurementRow>> {
    let mut newest = HashMap::new();
    for row in rows::measurements_of(tx, checklist_id, purpose.wire_name()).await? {
        newest.insert(row.item_id, row);
    }
    Ok(newest)
}

fn outcomes(measured: &[LineMeasurement]) -> HashMap<i64, MeasurementOutcome> {
    measured.iter().map(|line| (line.item.id, line.measurement.outcome)).collect()
}

fn measured_line(
    item: &ItemRow,
    answer: Option<&AnswerRow>,
    measurement: &Measurement,
    submitted: Option<&MeasurementRow>,
) -> MeasuredLine {
    MeasuredLine {
        item_id: item.id,
        position: item.position,
        answer: answer.map(|row| row.value.clone()),
        outcome: measurement.outcome.wire_name().to_owned(),
        reason: measurement.reason.map(|reason| reason.wire_name().to_owned()),
        submitted_outcome: submitted.map(|row| row.outcome.clone()),
        submitted_reason: submitted.and_then(|row| row.reason.clone()),
    }
}

fn describe(measurement: &Measurement) -> String {
    format!(
        "{}{}",
        measurement.outcome.wire_name(),
        measurement.reason.map_or_else(String::new, |reason| format!(" ({})", reason.wire_name()))
    )
}

/// "; 3 measured lines: 2 pass, 1 no data" — nothing when no line is measured.
fn tally(measured: &[LineMeasurement]) -> String {
    if measured.is_empty() {
        return String::new();
    }
    let mut counted: Vec<(MeasurementOutcome, usize)> = Vec::new();
    for outcome in MeasurementOutcome::ALL {
        let count = measured.iter().filter(|line| line.measurement.outcome == outcome).count();
        if count > 0 {
            counted.push((outcome, count));
        }
    }
    let parts: Vec<String> =
        counted.iter().map(|(outcome, count)| format!("{count} {}", outcome.wire_name().replace('_', " "))).collect();
    format!(
        "; {} {}: {}",
        measured.len(),
        if measured.len() == 1 { "measured line" } else { "measured lines" },
        parts.join(", ")
    )
}

fn rule_raw(canonical: Option<&str>) -> Result<crate::views::Raw> {
    Ok(match canonical {
        Some(canonical) => raw(forms::rule_form_json(canonical)?),
        None => null(),
    })
}

fn live_view(
    checklist_id: i64,
    line: &LineMeasurement,
    now: OffsetDateTime,
    reader: &Participant,
    answer: Option<&AnswerRow>,
    names: &BTreeMap<i64, String>,
) -> Result<MeasurementView> {
    let measurement = &line.measurement;
    let value = answer.map(|row| ChecklistAnswer::parse(Some(&row.value))).transpose()?;
    Ok(MeasurementView {
        id: None,
        checklist_id,
        item_id: line.item.id,
        purpose: Purpose::Read.wire_name().to_owned(),
        rule_kind: line.rule.kind().wire_name().to_owned(),
        rule_digest: line.rule.digest(),
        bound_rule: rule_raw(Some(&line.rule.canonical()))?,
        outcome: measurement.outcome.wire_name().to_owned(),
        reason: measurement.reason.map(|reason| reason.wire_name().to_owned()),
        as_of: measurement.as_of.map(|at| vectispire_cp_audit::iso_instant(days::offset(at))),
        computed_at: vectispire_cp_audit::iso_instant(now),
        computed_by: reader.username.clone(),
        answer_id: answer.map(|row| row.id),
        answer_value: answer.map(|row| row.value.clone()),
        reconciliation: Some(Reconciliation::of(value, Some(measurement.outcome)).wire_name().to_owned()),
        evidence_digest: measurement.evidence_digest(),
        evidence: evidence_of(measurement, names),
    })
}

fn stored_view(row: &MeasurementRow, names: &BTreeMap<i64, String>) -> Result<MeasurementView> {
    Ok(MeasurementView {
        id: Some(row.id),
        checklist_id: row.checklist_id,
        item_id: row.item_id,
        purpose: row.purpose.clone(),
        rule_kind: row.rule_kind.clone(),
        rule_digest: row.rule_digest.clone(),
        bound_rule: rule_raw(Some(&row.bound_rule))?,
        outcome: row.outcome.clone(),
        reason: row.reason.clone(),
        as_of: row.as_of.map(iso),
        computed_at: iso(row.computed_at),
        computed_by: row.computed_by.clone(),
        answer_id: row.answer_id,
        answer_value: row.answer_value.clone(),
        reconciliation: row.reconciliation.clone(),
        evidence_digest: row.evidence_digest.clone(),
        evidence: evidence_of(&Measurement::read(&row.evidence)?, names),
    })
}

/// `ChecklistMeasurementView.evidence`: named by the guard's repositories alone.
fn evidence_of(measurement: &Measurement, names: &BTreeMap<i64, String>) -> MeasurementEvidence {
    MeasurementEvidence {
        summary: measurement.summary.clone(),
        repositories: measurement
            .repositories
            .iter()
            .map(|line| RepositoryLook {
                repository_id: line.repository_id,
                repository_name: names.get(&line.repository_id).cloned(),
                scope: line.scope.clone(),
                status: line.status.clone(),
                source: line.look.as_ref().map(|look| look.source.wire_name().to_owned()),
                source_id: line.look.as_ref().map(|look| look.id),
                at: line.look.as_ref().map(|look| vectispire_cp_audit::iso_instant(days::offset(look.at))),
                digest: line.look.as_ref().and_then(|look| look.digest.clone()),
                met: line.met,
                detail: line.detail.clone(),
            })
            .collect(),
        figures: measurement
            .figures
            .iter()
            .map(|figure| MeasuredFigure {
                scope: figure.scope.clone(),
                severity: figure.severity.clone(),
                open: figure.open,
                resolved: figure.resolved,
                met: figure.met,
                detail: figure.detail.clone(),
            })
            .collect(),
    }
}

// ------------------------------------------------------------------ views

/// A template version as a summary names it.
#[derive(Debug, Clone)]
pub(crate) struct VersionRef {
    template_slug: String,
    template_name: String,
    ordinal: i32,
    label: Option<String>,
}

pub(crate) async fn version_of(tx: &mut Tx, checklist: &ChecklistRow) -> Result<VersionRow> {
    rows::version_by_id(tx, checklist.template_version_id)
        .await?
        .ok_or_else(|| ChecklistError::defect(format!("The version of checklist {} is gone.", checklist.id)))
}

pub(crate) async fn template_of(tx: &mut Tx, version: &VersionRow) -> Result<TemplateRow> {
    rows::template_by_id(tx, version.template_id)
        .await?
        .ok_or_else(|| ChecklistError::defect(format!("Template {} is gone.", version.template_id)))
}

async fn version_ref(tx: &mut Tx, version_id: i64) -> Result<VersionRef> {
    let version = rows::version_by_id(tx, version_id)
        .await?
        .ok_or_else(|| ChecklistError::defect(format!("Template version {version_id} is gone.")))?;
    let template = template_of(tx, &version).await?;
    Ok(VersionRef {
        template_slug: template.slug,
        template_name: template.name,
        ordinal: version.ordinal,
        label: version.label,
    })
}

async fn summary(
    tx: &mut Tx,
    row: &ChecklistRow,
    version: &VersionRef,
    revision_of: &mut HashMap<i64, i32>,
) -> Result<RevisionSummary> {
    let supersedes = match row.supersedes_id {
        None => None,
        Some(id) => match revision_of.get(&id) {
            Some(revision) => Some(*revision),
            None => {
                let found = rows::checklist_by_id(tx, id).await?.map(|found| found.revision);
                if let Some(revision) = found {
                    revision_of.insert(id, revision);
                }
                found
            }
        },
    };
    Ok(RevisionSummary {
        project_id: row.project_id,
        revision: row.revision,
        status: row.status.clone(),
        edition: row.edition,
        template_slug: version.template_slug.clone(),
        template_name: version.template_name.clone(),
        version_ordinal: version.ordinal,
        version_label: version.label.clone(),
        author: row.author.clone(),
        opened_at: iso(row.opened_at),
        opened_by: row.opened_by.clone(),
        supersedes_revision: supersedes,
        submitted_at: row.submitted_at.map(iso),
        submitted_by: row.submitted_by.clone(),
        returned_at: row.returned_at.map(iso),
        returned_by: row.returned_by.clone(),
        return_reason: row.return_reason.clone(),
        signed_off_at: row.signed_off_at.map(iso),
        signed_off_by: row.signed_off_by.clone(),
        sign_off_four_eyes: row.sign_off_four_eyes,
        superseded_at: row.superseded_at.map(iso),
        superseded_by: row.superseded_by.clone(),
    })
}

/// `lines`: each line of the revision with its current answer, proofs, the edition it last changed at and its
/// problems — those of a measured line when `measured` carries its outcome.
async fn lines(
    tx: &mut Tx,
    checklist: &ChecklistRow,
    today: Date,
    measured: &HashMap<i64, MeasurementOutcome>,
) -> Result<Vec<LineView>> {
    let given = rows::answers_of(tx, checklist.id).await?;
    let current = current_of(&given);
    let mut editions: HashMap<i64, i32> = HashMap::new();
    for row in &given {
        let entry = editions.entry(row.item_id).or_insert(row.edition);
        *entry = (*entry).max(row.edition);
    }
    let mut proofs: HashMap<i64, Vec<EvidenceRow>> = HashMap::new();
    for row in rows::evidence_of(tx, checklist.id).await? {
        let newest = row.edition.max(row.withdrawn_edition.unwrap_or(row.edition));
        let entry = editions.entry(row.item_id).or_insert(newest);
        *entry = (*entry).max(newest);
        proofs.entry(row.item_id).or_default().push(row);
    }
    let mut items = rows::items_of(tx, checklist.template_version_id).await?;
    items.sort_by_key(|item| item.position);
    let mut lines = Vec::with_capacity(items.len());
    for item in items {
        let answer = current.get(&item.id);
        let attached = proofs.get(&item.id).map_or(&[][..], Vec::as_slice);
        let problems = problems(&item, answer, attached, today, measured.get(&item.id).copied())?
            .into_iter()
            .map(|problem| problem.wire_name().to_owned())
            .collect();
        lines.push(LineView {
            item_id: item.id,
            item_key: item.item_key.clone(),
            position: item.position,
            domain: item.domain.clone(),
            objective: item.objective.clone(),
            control: item.control.clone(),
            contact: item.contact.clone(),
            kpi: item.kpi.clone(),
            evidence_kind: item.evidence_kind.clone(),
            evidence_validity_months: item.evidence_validity_months,
            rule: rule_raw(item.bound_rule.as_deref())?,
            answer: answer.map(answer_view),
            evidence: attached.iter().map(|row| evidence_view(row, today)).collect(),
            edition: editions.get(&item.id).copied().unwrap_or(0),
            problems,
        });
    }
    Ok(lines)
}

pub(crate) fn answer_view(row: &AnswerRow) -> AnswerView {
    AnswerView {
        id: row.id,
        item_id: row.item_id,
        value: row.value.clone(),
        comment: row.comment.clone(),
        answered_by: row.answered_by.clone(),
        answered_by_kind: row.answered_by_kind.clone(),
        answered_at: iso(row.answered_at),
        measurement_id: row.measurement_id,
        carried_from_id: row.carried_from_id,
        carried_by: row.carried_by.clone(),
        carried_at: row.carried_at.map(iso),
        needs_confirmation: row.needs_confirmation,
        withdrawn: row.withdrawn,
        edition: row.edition,
    }
}

pub(crate) fn evidence_view(row: &EvidenceRow, today: Date) -> EvidenceView {
    EvidenceView {
        id: row.id,
        item_id: row.item_id,
        kind: row.kind.clone(),
        link: row.link.clone(),
        file_name: row.file_name.clone(),
        media_type: row.media_type.clone(),
        file_size: row.file_size,
        file_sha256: row.file_sha256.clone(),
        performed_on: days::written(days::day_of(row.performed_on.0)),
        valid_until: row.valid_until.map(|until| days::written(days::day_of(until.0))),
        added_by: row.added_by.clone(),
        added_at: iso(row.added_at),
        carried_from_id: row.carried_from_id,
        edition: row.edition,
        withdrawn_by: row.withdrawn_by.clone(),
        withdrawn_at: row.withdrawn_at.map(iso),
        in_date: in_date(row, today),
    }
}

async fn words_of(tx: &mut Tx, checklist: &ChecklistRow) -> Result<AnswerWords> {
    let version = version_of(tx, checklist).await?;
    Ok(forms::layout_of(version.layout.as_deref().unwrap_or("null"))?.answers().clone())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn at() -> rows::StoredInstant {
        rows::at(OffsetDateTime::UNIX_EPOCH)
    }

    fn answer(id: i64, item: i64, value: &str, kind: &str, withdrawn: bool) -> AnswerRow {
        AnswerRow {
            id,
            checklist_id: 1,
            item_id: item,
            value: value.to_owned(),
            comment: None,
            answered_by: "someone".to_owned(),
            answered_by_id: Some(7),
            answered_by_kind: kind.to_owned(),
            answered_at: at(),
            measurement_id: None,
            carried_from_id: None,
            carried_by: None,
            carried_by_id: None,
            carried_at: None,
            needs_confirmation: false,
            withdrawn,
            edition: 1,
        }
    }

    fn item(kind: &str) -> ItemRow {
        ItemRow {
            id: 3,
            version_id: 1,
            item_key: "text:a".to_owned(),
            position: 1,
            domain: String::new(),
            objective: String::new(),
            control: "Do it".to_owned(),
            contact: String::new(),
            kpi: String::new(),
            content_digest: String::new(),
            sheet_row: 4,
            evidence_kind: kind.to_owned(),
            evidence_validity_months: None,
            bound_rule: None,
        }
    }

    fn proof(kind: &str, valid_until: Option<OffsetDateTime>, withdrawn: bool) -> EvidenceRow {
        let mut row = proof_row(
            &ChecklistRow {
                id: 1,
                project_id: 1,
                template_version_id: 1,
                revision: 1,
                status: "draft".to_owned(),
                edition: 1,
                open_slot: Some(1),
                author_id: 7,
                author: "someone".to_owned(),
                opened_at: at(),
                opened_by: "someone".to_owned(),
                supersedes_id: None,
                submitted_at: None,
                submitted_by: None,
                submitted_by_id: None,
                returned_at: None,
                returned_by: None,
                return_reason: None,
                signed_off_at: None,
                signed_off_by: None,
                signed_off_by_id: None,
                sign_off_four_eyes: None,
                superseded_at: None,
                superseded_by: None,
            },
            &item("file"),
            Date::from_calendar_date(2026, time::Month::January, 1).unwrap(),
            &Participant { account_id: 7, username: "someone".into(), role: None, actor: RequestActor::default() },
            OffsetDateTime::UNIX_EPOCH,
            1,
        );
        row.kind = kind.to_owned();
        row.valid_until = valid_until.map(rows::at);
        if withdrawn {
            row.withdrawn_at = Some(at());
        }
        row
    }

    fn today() -> Date {
        Date::from_calendar_date(2026, time::Month::June, 1).unwrap()
    }

    #[test]
    fn a_withdrawal_of_vectispire_s_answer_leaves_the_line_unanswered() {
        let rows = [answer(1, 3, "yes", "system", false), answer(2, 3, "yes", "system", true)];
        assert!(!current_of(&rows).contains_key(&3));
        let rows = [answer(1, 3, "yes", "system", true), answer(2, 3, "no", "person", false)];
        assert_eq!(current_of(&rows).get(&3).map(|row| row.id), Some(2), "the newest row stands");
    }

    #[test]
    fn a_line_s_problems_are_the_submission_s() {
        let line = item("file");
        assert_eq!(problems(&line, None, &[], today(), None).unwrap(), vec![LineProblem::Unanswered]);
        let no = answer(1, 3, "no", "person", false);
        assert_eq!(problems(&line, Some(&no), &[], today(), None).unwrap(), vec![LineProblem::CommentRequired]);
        let yes = answer(1, 3, "yes", "person", false);
        assert_eq!(problems(&line, Some(&yes), &[], today(), None).unwrap(), vec![LineProblem::EvidenceRequired]);
        // A link does not prove a line asking for a file; a withdrawn file proves nothing.
        let link = proof("link", None, false);
        assert_eq!(problems(&line, Some(&yes), &[link], today(), None).unwrap(), vec![LineProblem::EvidenceRequired]);
        let withdrawn = proof("file", None, true);
        assert_eq!(
            problems(&line, Some(&yes), &[withdrawn], today(), None).unwrap(),
            vec![LineProblem::EvidenceRequired]
        );
        let lapsed = proof("file", Some(OffsetDateTime::UNIX_EPOCH), false);
        assert_eq!(problems(&line, Some(&yes), &[lapsed], today(), None).unwrap(), vec![LineProblem::EvidenceExpired]);
        let held = proof("file", Some(days::start_of(today())), false);
        assert!(problems(&line, Some(&yes), &[held], today(), None).unwrap().is_empty(), "valid through its last day");
        // A "yes" against a failure is contradicted; where there is no data it needs its comment and a proof.
        let free = item("none");
        let failing = problems(&free, Some(&yes), &[], today(), Some(MeasurementOutcome::Fail)).unwrap();
        assert_eq!(failing, vec![LineProblem::MeasurementContradicted]);
        let blind = problems(&free, Some(&yes), &[], today(), Some(MeasurementOutcome::NoData)).unwrap();
        assert_eq!(blind, vec![LineProblem::CommentRequired, LineProblem::EvidenceRequired]);
        let mut carried = yes.clone();
        carried.needs_confirmation = true;
        assert_eq!(
            problems(&free, Some(&carried), &[], today(), None).unwrap(),
            vec![LineProblem::AwaitingConfirmation]
        );
    }

    #[test]
    fn a_file_s_name_is_its_last_segment_without_controls() {
        assert_eq!(require_file_name(Some(" ../dir\\evil/report\u{7}.pdf ")).unwrap(), "report.pdf");
        assert!(require_file_name(Some("a/..")).is_err());
        assert!(require_file_name(Some("   ")).is_err());
        assert!(require_file_name(Some(&"x".repeat(256))).is_err());
        assert!(require_file_name(Some(&"x".repeat(255))).is_ok());
    }

    #[test]
    fn a_link_is_web_and_bounded() {
        assert_eq!(require_link(Some(" https://example.org/r ")).unwrap(), "https://example.org/r");
        assert!(require_link(Some("ftp://example.org")).is_err());
        // At most 2,000 characters: the 2,000th accepted, the 2,001st refused.
        let at_most = format!("https://example.org/{}", "a".repeat(MAX_LINK - 20));
        assert_eq!(at_most.len(), MAX_LINK);
        assert!(require_link(Some(&at_most)).is_ok());
        assert!(require_link(Some(&format!("{at_most}a"))).is_err());
        assert!(require_link(None).is_err());
    }

    #[test]
    fn the_refusal_names_each_line_and_its_problems() {
        let lines = [IncompleteLine {
            item_id: 1,
            position: 2,
            problems: vec!["evidence_required".into(), "comment_required".into()],
        }];
        assert_eq!(in_words(&lines), "line 2 evidence required, comment required");
    }

    #[test]
    fn a_tally_counts_the_outcomes_in_the_enum_s_order() {
        assert_eq!(tally(&[]), "");
    }
}
