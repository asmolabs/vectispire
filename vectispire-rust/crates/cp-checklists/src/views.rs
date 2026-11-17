//! What the services answer, as Jackson writes the Java records: every component, `null` included, in the record's
//! order, under its component name, an instant as `DateTimeFormatter.ISO_INSTANT`, a day as `yyyy-MM-dd`.
//!
//! A bound rule and a layout are written by [`crate::forms`] and carried as raw JSON: their numbers keep the digits
//! the rule was stated with, which a tree of doubles would not.

use serde::Serialize;
use serde_json::value::RawValue;

use crate::error::UnrenderableCell;

/// JSON already written, carried as it is.
pub type Raw = Box<RawValue>;

/// Raw JSON from text this crate wrote; `null` should it ever not parse, which it cannot.
pub fn raw(json: String) -> Raw {
    RawValue::from_string(json).unwrap_or_else(|_| null())
}

pub fn null() -> Raw {
    RawValue::from_string("null".to_owned()).unwrap_or_default()
}

// ------------------------------------------------------------------ templates

/// `ChecklistTemplateView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateView {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub created_at: String,
    pub created_by: String,
    pub versions: Vec<VersionSummary>,
}

/// `ChecklistVersionSummary`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionSummary {
    pub id: i64,
    pub ordinal: i32,
    pub label: Option<String>,
    pub status: String,
    pub revision: i32,
    pub source_sha256: String,
    pub source_size: i64,
    pub layout_confirmed: bool,
    pub offers_not_applicable: bool,
    pub item_count: i64,
    pub previous_ordinal: Option<i32>,
    pub derived_from_ordinal: Option<i32>,
    pub draft_authors: Vec<String>,
    pub imported_at: String,
    pub imported_by: String,
    pub published_at: Option<String>,
    pub published_by: Option<String>,
    pub retired_at: Option<String>,
    pub retired_by: Option<String>,
}

/// `ChecklistVersionView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionView {
    pub template_slug: String,
    pub template_name: String,
    pub version: VersionSummary,
    pub layout: Raw,
    pub items: Vec<ItemView>,
    pub pairs: Vec<ItemPair>,
}

/// `ChecklistItemView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemView {
    pub id: i64,
    pub version_id: i64,
    pub item_key: String,
    pub position: i32,
    pub domain: String,
    pub objective: String,
    pub control: String,
    pub contact: String,
    pub kpi: String,
    pub content_digest: String,
    pub sheet_row: i32,
    pub evidence_kind: String,
    pub evidence_validity_months: Option<i32>,
    pub bound_rule: Raw,
}

/// `ChecklistItemPair`.
#[derive(Debug, Clone, Serialize)]
pub struct ItemPair {
    pub added: String,
    pub removed: String,
}

/// `ChecklistTemplatePreview`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplatePreview {
    pub template_slug: String,
    pub version: VersionSummary,
    pub sheets: Vec<String>,
    pub sheet: String,
    pub cells: Vec<PreviewCell>,
    pub cells_truncated: bool,
    pub proposal: ProposedLayout,
    pub layout: Raw,
    pub pairing: Vec<PairingChange>,
}

/// `ChecklistTemplatePreview.PreviewCell`.
#[derive(Debug, Serialize)]
pub struct PreviewCell {
    #[serde(rename = "ref")]
    pub reference: String,
    pub row: i32,
    pub column: String,
    pub text: String,
    pub formula: bool,
}

/// `ChecklistTemplatePreview.ProposedLayout`; `columns` and `header` written by [`crate::forms`]-style writers.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposedLayout {
    pub sheet: String,
    pub column_header_row: Option<i32>,
    pub first_item_row: Option<i32>,
    pub last_item_row: Option<i32>,
    pub columns: Raw,
    pub header: Raw,
    pub answer_values: Vec<String>,
}

/// `ChecklistTemplatePreview.PairingChange`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingChange {
    pub change: String,
    pub paired_by_hand: bool,
    pub read_key: Option<String>,
    pub row: Option<i32>,
    pub control: Option<String>,
    pub previous_key: Option<String>,
    pub previous_row: Option<i32>,
    pub previous_control: Option<String>,
}

// ------------------------------------------------------------------ project checklists

/// `ChecklistRevisionSummary`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionSummary {
    pub project_id: i64,
    pub revision: i32,
    pub status: String,
    pub edition: i32,
    pub template_slug: String,
    pub template_name: String,
    pub version_ordinal: i32,
    pub version_label: Option<String>,
    pub author: String,
    pub opened_at: String,
    pub opened_by: String,
    pub supersedes_revision: Option<i32>,
    pub submitted_at: Option<String>,
    pub submitted_by: Option<String>,
    pub returned_at: Option<String>,
    pub returned_by: Option<String>,
    pub return_reason: Option<String>,
    pub signed_off_at: Option<String>,
    pub signed_off_by: Option<String>,
    pub sign_off_four_eyes: Option<bool>,
    pub superseded_at: Option<String>,
    pub superseded_by: Option<String>,
}

/// `ChecklistView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistView {
    pub checklist: RevisionSummary,
    pub project_name: String,
    pub offers_not_applicable: bool,
    pub answer_words: AnswerWordsView,
    pub authors: Vec<String>,
    pub four_eyes_required: bool,
    pub ready_to_submit: bool,
    pub lines: Vec<LineView>,
}

/// `ChecklistView.AnswerWordsView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnswerWordsView {
    pub yes: String,
    pub no: String,
    pub not_applicable: Option<String>,
}

/// `ChecklistLineView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LineView {
    pub item_id: i64,
    pub item_key: String,
    pub position: i32,
    pub domain: String,
    pub objective: String,
    pub control: String,
    pub contact: String,
    pub kpi: String,
    pub evidence_kind: String,
    pub evidence_validity_months: Option<i32>,
    pub rule: Raw,
    pub answer: Option<AnswerView>,
    pub evidence: Vec<EvidenceView>,
    pub edition: i32,
    pub problems: Vec<String>,
}

/// `ChecklistAnswerView`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnswerView {
    pub id: i64,
    pub item_id: i64,
    pub value: String,
    pub comment: Option<String>,
    pub answered_by: String,
    pub answered_by_kind: String,
    pub answered_at: String,
    pub measurement_id: Option<i64>,
    pub carried_from_id: Option<i64>,
    pub carried_by: Option<String>,
    pub carried_at: Option<String>,
    pub needs_confirmation: bool,
    pub withdrawn: bool,
    pub edition: i32,
}

/// `ChecklistEvidenceView`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceView {
    pub id: i64,
    pub item_id: i64,
    pub kind: String,
    pub link: Option<String>,
    pub file_name: Option<String>,
    pub media_type: Option<String>,
    pub file_size: Option<i64>,
    pub file_sha256: Option<String>,
    pub performed_on: String,
    pub valid_until: Option<String>,
    pub added_by: String,
    pub added_at: String,
    pub carried_from_id: Option<i64>,
    pub edition: i32,
    pub withdrawn_by: Option<String>,
    pub withdrawn_at: Option<String>,
    pub in_date: bool,
}

/// `ChecklistLineHistory`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LineHistory {
    pub project_id: i64,
    pub revision: i32,
    pub item_id: i64,
    pub answers: Vec<AnswerView>,
    pub evidence: Vec<EvidenceView>,
}

/// `ChecklistProjectContext`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectContext {
    pub project_id: i64,
    pub project_name: String,
    pub latest_revision: Option<i32>,
    pub latest_edition: Option<i32>,
}

/// `ChecklistOfferedVersion`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferedVersion {
    pub template_slug: String,
    pub template_name: String,
    pub ordinal: i32,
    pub label: Option<String>,
    pub item_count: i64,
    pub offers_not_applicable: bool,
    pub published_at: Option<String>,
    pub unrenderable: Option<Unrenderable>,
}

/// `ChecklistOfferedVersion.Unrenderable`.
#[derive(Debug, Clone, Serialize)]
pub struct Unrenderable {
    pub detail: String,
    pub cells: Vec<UnrenderableCell>,
}

/// `ChecklistAsMeasuredView`.
#[derive(Debug, Serialize)]
pub struct AsMeasuredView {
    pub checklist: ChecklistView,
    pub answered: Vec<AsMeasuredAnswer>,
    pub skipped: Vec<AsMeasuredSkip>,
}

/// `ChecklistAsMeasuredView.AsMeasuredAnswer`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsMeasuredAnswer {
    pub item_id: i64,
    pub position: i32,
    pub value: String,
    pub answer_id: i64,
    pub measurement_id: i64,
    pub evidence_digest: String,
}

/// `ChecklistAsMeasuredView.AsMeasuredSkip`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsMeasuredSkip {
    pub item_id: i64,
    pub position: i32,
    pub reason: String,
    pub outcome: String,
    pub no_data_reason: Option<String>,
    pub evidence_digest: String,
    pub answer: Option<String>,
}

/// `ChecklistMeasurementsView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasurementsView {
    pub project_id: i64,
    pub revision: i32,
    pub status: String,
    pub live: bool,
    pub computed_at: Option<String>,
    pub lines: Vec<MeasuredLineView>,
}

/// `ChecklistMeasurementsView.MeasuredLineView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasuredLineView {
    pub item_id: i64,
    pub position: i32,
    pub item_key: String,
    pub rule: Raw,
    pub answer: Option<String>,
    pub answer_id: Option<i64>,
    pub measurement: Option<MeasurementView>,
    pub at_submission: Option<MeasurementView>,
    pub reconciliation: String,
    pub problems: Vec<String>,
}

/// `ChecklistMeasurementView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasurementView {
    pub id: Option<i64>,
    pub checklist_id: i64,
    pub item_id: i64,
    pub purpose: String,
    pub rule_kind: String,
    pub rule_digest: String,
    pub bound_rule: Raw,
    pub outcome: String,
    pub reason: Option<String>,
    pub as_of: Option<String>,
    pub computed_at: String,
    pub computed_by: String,
    pub answer_id: Option<i64>,
    pub answer_value: Option<String>,
    pub reconciliation: Option<String>,
    pub evidence_digest: String,
    pub evidence: MeasurementEvidence,
}

/// `ChecklistMeasurementView.MeasurementEvidence`.
#[derive(Debug, Serialize)]
pub struct MeasurementEvidence {
    pub summary: String,
    pub repositories: Vec<RepositoryLook>,
    pub figures: Vec<MeasuredFigure>,
}

/// `ChecklistMeasurementView.RepositoryLook`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryLook {
    pub repository_id: i64,
    pub repository_name: Option<String>,
    pub scope: Option<String>,
    pub status: String,
    pub source: Option<String>,
    pub source_id: Option<i64>,
    pub at: Option<String>,
    pub digest: Option<String>,
    pub met: Option<bool>,
    pub detail: Option<String>,
}

/// `ChecklistMeasurementView.MeasuredFigure`.
#[derive(Debug, Serialize)]
pub struct MeasuredFigure {
    pub scope: String,
    pub severity: String,
    pub open: i64,
    pub resolved: i64,
    pub met: Option<bool>,
    pub detail: Option<String>,
}

// ------------------------------------------------------------------ contacts

/// `ChecklistContactsView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactsView {
    pub project_id: i64,
    pub revision: Option<i32>,
    pub draft: bool,
    pub profiles: Vec<ContactView>,
}

/// `ChecklistContactView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactView {
    pub profile: String,
    pub label: String,
    pub open_lines: usize,
    pub account_id: Option<i64>,
    pub account_name: Option<String>,
    pub warning: Option<String>,
}

/// `ChecklistContactCandidate`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactCandidate {
    pub account_id: i64,
    pub name: Option<String>,
}

// ------------------------------------------------------------------ downloads

/// `ChecklistEvidenceDownload`.
#[derive(Debug)]
pub struct EvidenceDownload {
    pub file_name: String,
    pub sha256: String,
    pub content: Vec<u8>,
}

/// `ChecklistDocumentDownload`.
#[derive(Debug)]
pub struct DocumentDownload {
    pub file_name: String,
    pub signed: bool,
    pub sha256: String,
    pub content: Vec<u8>,
}
