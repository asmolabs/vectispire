//! `ChecklistTemplateService`: the organisation's checklist templates — a workbook imported as a draft, its layout
//! confirmed by a person, its items paired with the previous version, its proofs and rules set, then published —
//! never in one step (decision 0032 §3, §4).
//!
//! **What a person has seen is what is published**: every change to a version is a conditional update on the
//! revision its writer read, and a draft changed since is refused (`checklist-template-changed`). **With four-eyes
//! on, a version is published or retired by somebody who did not write it**, and who did not administer an author's
//! account recently (`ApproverIndependence`). **Every write is audited after its transaction commits.**

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use vectispire_cp_access::independence::{ApproverIndependence, Author};
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor, Signal};
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_domain::bounded_text;
use vectispire_domain::java;
use vectispire_domain::list_window::ListWindow;

use crate::cell::{CellRef, CellValue, Field, HeaderCell};
use crate::error::{Cause, ChecklistError, Members, UnrenderableCell};
use crate::forms::{self, DraftAuthor, Writer};
use crate::item::{ChecklistColumn, ChecklistItem, EvidenceKind, EvidenceRequirement, ItemKey};
use crate::layout::{ChecklistLayout, LayoutProposal, TemplateVersion};
use crate::pairing::{Change, ManualPair, VersionPairing};
use crate::persistence::{self as rows, DraftEdit, ItemRow, NewVersion, StoreError, TemplateRow, VersionRow};
use crate::renderer::{self, RenderFailure};
use crate::rule::ChecklistRule;
use crate::views::{
    ItemPair, ItemView, PairingChange, PreviewCell, ProposedLayout, TemplatePreview, TemplateView, VersionSummary,
    VersionView, null, raw,
};
use crate::workbook::Workbook;
use crate::{answer::AnswerWords, node::Node};

/// The most cells of a sheet a preview carries; a template is a few hundred, a catalogue more.
pub const PREVIEW_CELLS: usize = 20_000;
pub const MAX_NAME: usize = 200;
pub const MAX_LABEL: usize = 200;
/// Column `t_checklist_item.item_key`.
const MAX_KEY: usize = 255;
/// The lines an evidence entry of the audit log names one by one; a whole catalogue would be a page.
const AUDITED_LINES: usize = 20;

/// `VECTI-SEC-024`: a published version retired.
const CHECKLIST_TEMPLATE_CHANGED: Signal = Signal("CHECKLIST_TEMPLATE_CHANGED");

/// `TemplateVersionStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionStatus {
    Draft,
    Published,
    Retired,
}

impl VersionStatus {
    pub fn wire_name(self) -> &'static str {
        match self {
            VersionStatus::Draft => "draft",
            VersionStatus::Published => "published",
            VersionStatus::Retired => "retired",
        }
    }

    /// A value this version does not know is a defect of the row: only this enum writes one.
    pub fn of_stored(stored: &str) -> Result<VersionStatus> {
        [VersionStatus::Draft, VersionStatus::Published, VersionStatus::Retired]
            .into_iter()
            .find(|status| status.wire_name() == stored)
            .ok_or_else(|| ChecklistError::defect(format!("A template version has an unknown status: {stored}")))
    }
}

pub use vectispire_cp_targets::Clock;

/// Who is writing: the account four-eyes compares — never a name taken from the request — and the audit's actor.
#[derive(Debug, Clone)]
pub struct Editor {
    pub account_id: i64,
    pub actor: RequestActor,
}

impl Editor {
    fn username(&self) -> String {
        self.actor.username.clone().unwrap_or_else(|| "unknown".to_owned())
    }

    /// Compared as two people, like the triage: the account, and its name — a name reused is refused too.
    fn wrote(&self, authors: &[DraftAuthor]) -> bool {
        let name = self.username();
        authors.iter().any(|author| {
            author.account_id == self.account_id
                || java::compare_ignore_case(java::strip(&author.username), java::strip(&name)).is_eq()
        })
    }
}

/// A layout as a request states it (`ChecklistLayoutForm`), each part `None` when left out.
#[derive(Debug, Clone, Default)]
pub struct LayoutForm {
    pub sheet: Option<String>,
    /// In the request's order, as Jackson's `LinkedHashMap` keeps it; a value that is no string is `None`.
    pub columns: Option<Vec<(String, Option<String>)>>,
    pub first_item_row: Option<i32>,
    pub last_item_row: Option<i32>,
    /// `None` for a member whose value is `null`.
    pub header: Option<Vec<(String, Option<HeaderCellForm>)>>,
    pub answers: Option<AnswerWordsForm>,
}

#[derive(Debug, Clone, Default)]
pub struct HeaderCellForm {
    pub label: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AnswerWordsForm {
    pub yes: Option<String>,
    pub no: Option<String>,
    pub not_applicable: Option<String>,
}

/// `ChecklistItemPair`, as a request states it; `None` for a `null` element.
#[derive(Debug, Clone, Default)]
pub struct PairForm {
    pub added: Option<String>,
    pub removed: Option<String>,
}

/// `ChecklistItemEvidence`.
#[derive(Debug, Clone, Default)]
pub struct EvidenceForm {
    pub item_key: Option<String>,
    pub evidence_kind: Option<String>,
    pub evidence_validity_months: Option<i32>,
}

/// `ChecklistItemRule`: the rule as the request's tree (`None` for a `null` rule, which unbinds the line).
#[derive(Debug, Clone, Default)]
pub struct RuleLineForm {
    pub item_key: Option<String>,
    pub rule: Option<Node>,
}

/// The service.
pub struct ChecklistTemplates {
    db: Db,
    settings: Arc<Settings>,
    audit: Arc<AuditLog>,
    independence: ApproverIndependence,
    clock: Arc<dyn Clock>,
    max_workbook_bytes: i64,
}

impl std::fmt::Debug for ChecklistTemplates {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ChecklistTemplates").finish_non_exhaustive()
    }
}

type Result<T> = std::result::Result<T, ChecklistError>;

impl ChecklistTemplates {
    pub fn new(
        db: Db,
        settings: Arc<Settings>,
        audit: Arc<AuditLog>,
        independence: ApproverIndependence,
        clock: Arc<dyn Clock>,
        max_workbook_bytes: i64,
    ) -> ChecklistTemplates {
        ChecklistTemplates { db, settings, audit, independence, clock, max_workbook_bytes }
    }

    async fn read(&self) -> Result<Tx> {
        Ok(rows::begin(&self.db, false).await?)
    }

    async fn write(&self) -> Result<Tx> {
        Ok(rows::begin(&self.db, true).await?)
    }

    // ------------------------------------------------------------------ reads

    /// `list`: the templates by slug, all of them or one page.
    pub async fn list(&self, limit: Option<i64>, offset: Option<i64>) -> Result<Vec<TemplateView>> {
        let window = ListWindow::requested(limit, offset).map_err(ChecklistError::Invalid)?;
        let mut tx = self.read().await?;
        let every = rows::templates_by_slug(&mut tx).await?;
        let page = window.map_or_else(|| every.clone(), |window| window.of(&every));
        let mut views = Vec::with_capacity(page.len());
        for template in &page {
            views.push(view(&mut tx, template).await?);
        }
        Ok(views)
    }

    pub async fn template(&self, slug: Option<&str>) -> Result<TemplateView> {
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        view(&mut tx, &template).await
    }

    pub async fn version(&self, slug: Option<&str>, ordinal: i32) -> Result<VersionView> {
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let version = require_version(&mut tx, &template, ordinal).await?;
        version_view(&mut tx, &template, version.id).await
    }

    /// `preview`: the reader's proposal, the confirmed layout, a sheet's cells and the pairing with the previous
    /// version. `sheet` blank shows the confirmed layout's sheet, else the proposal's.
    pub async fn preview(&self, slug: Option<&str>, ordinal: i32, sheet: Option<&str>) -> Result<TemplatePreview> {
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let version = require_version(&mut tx, &template, ordinal).await?;
        let workbook = self.stored(&mut tx, &version).await?;
        let proposal = LayoutProposal::of(&workbook)?;
        let layout = version.layout.as_deref().map(forms::layout_of).transpose()?;

        let shown = match sheet.filter(|name| !java::is_blank(name)) {
            Some(name) => java::strip(name).to_owned(),
            None => layout.as_ref().map_or_else(|| proposal.sheet.clone(), |layout| layout.sheet().to_owned()),
        };
        let cells = workbook.sheet(&shown).ok_or_else(|| {
            let names: Vec<String> = workbook.sheets.iter().map(|sheet| format!("\"{}\"", sheet.name)).collect();
            ChecklistError::invalid(format!(
                "The workbook has no sheet \"{}\"; it has {}.",
                bounded_text::clip(Some(&shown), 40).unwrap_or(""),
                names.join(", ")
            ))
        })?;
        let shown_cells: Vec<PreviewCell> = cells
            .cells
            .iter()
            .take(PREVIEW_CELLS)
            .map(|(cell, value)| PreviewCell {
                reference: cell.to_string(),
                row: cell.row(),
                column: cell.column_letters(),
                text: value.text().to_owned(),
                formula: matches!(value, CellValue::Formula { .. }),
            })
            .collect();

        let read_key_of = read_keys(&version)?;
        let pairing = if layout.is_some() {
            pairing_of(&mut tx, &version)
                .await?
                .changes
                .iter()
                .map(|change| pairing_change(change, &read_key_of))
                .collect()
        } else {
            Vec::new()
        };
        Ok(TemplatePreview {
            template_slug: template.slug.clone(),
            version: summary_of(&mut tx, &template, version.id).await?,
            sheets: workbook.sheets.iter().map(|sheet| sheet.name.clone()).collect(),
            sheet: cells.name.clone(),
            cells: shown_cells,
            cells_truncated: cells.cells.len() > PREVIEW_CELLS,
            proposal: proposed(&proposal),
            layout: layout.as_ref().map_or_else(null, |layout| raw(forms::layout_form_json(layout))),
            pairing,
        })
    }

    // ------------------------------------------------------------------ writes

    /// `importWorkbook`: the template's next version, a draft. The template is created when the slug is new; `name`
    /// names it then, and is not used otherwise.
    pub async fn import_workbook(
        &self,
        slug: Option<&str>,
        name: Option<&str>,
        label: Option<&str>,
        file: &[u8],
        editor: &Editor,
    ) -> Result<VersionView> {
        let template_slug = require_slug(slug)?;
        let template_name = bounded_text::optional(name, MAX_NAME, "The template's name")?;
        let version_label = bounded_text::optional(label, MAX_LABEL, "The version's label")?;
        if file.is_empty() {
            return Err(ChecklistError::invalid("The body is the template's .xlsx workbook, and it is empty."));
        }
        // Read before any transaction opens: parsing is the costly part and needs no row.
        let workbook = Workbook::read(file, self.max_workbook_bytes)?;
        let now = self.clock.now();

        let written: Result<(TemplateRow, i64, i32, bool)> = async {
            let mut tx = self.write().await?;
            let existing = rows::template_by_slug(&mut tx, &template_slug).await?;
            let created = existing.is_none();
            let template = match existing {
                Some(template) => template,
                None => {
                    let name = template_name.clone().unwrap_or_else(|| template_slug.clone());
                    let username = editor.username();
                    let id = rows::insert_template(&mut tx, &template_slug, &name, rows::at(now), &username).await?;
                    TemplateRow {
                        id,
                        slug: template_slug.clone(),
                        name,
                        created_at: rows::at(now),
                        created_by: username,
                    }
                }
            };
            require_no_draft(&mut tx, &template).await?;
            let ordinal = next_ordinal(&mut tx, template.id).await?;
            let previous = rows::published_newest_first(&mut tx, template.id).await?.first().copied();
            let authors =
                forms::authors_json(&[DraftAuthor { account_id: editor.account_id, username: editor.username() }]);
            let username = editor.username();
            let id = rows::insert_version(
                &mut tx,
                &NewVersion {
                    template_id: template.id,
                    ordinal,
                    label: version_label.as_deref(),
                    status: VersionStatus::Draft.wire_name(),
                    revision: 1,
                    source_sha256: &workbook.sha256,
                    source_size: i64::try_from(file.len()).unwrap_or(i64::MAX),
                    source_bytes: file,
                    layout: None,
                    offers_not_applicable: false,
                    previous_version_id: previous,
                    derived_from_version_id: None,
                    draft_authors: &authors,
                    imported_at: rows::at(now),
                    imported_by: &username,
                },
            )
            .await?;
            rows::commit(tx).await?;
            Ok((template, id, ordinal, created))
        }
        .await;
        let (template, version_id, ordinal, created) = self.arbitrated(&template_slug, written).await?;

        let lead = if created {
            format!("Checklist template \"{template_slug}\" created; its ")
        } else {
            format!("Checklist template \"{template_slug}\": ")
        };
        self.audit
            .record(editor.actor.entry(
                AuditOperation::ChecklistTemplateImported,
                &resource(&template, ordinal),
                &format!(
                    "{lead}version {ordinal} imported as a draft from a workbook of {} bytes, sha256 {}.",
                    file.len(),
                    workbook.sha256
                ),
            ))
            .await;
        let mut tx = self.read().await?;
        version_view(&mut tx, &template, version_id).await
    }

    /// `confirmLayout`: the draft's layout and answer words, its items read from the workbook by them; pairs made
    /// earlier are cleared, evidence requirements and bound rules kept by key.
    pub async fn confirm_layout(
        &self,
        slug: Option<&str>,
        ordinal: i32,
        seen_revision: Option<i32>,
        form: Option<&LayoutForm>,
        editor: &Editor,
    ) -> Result<VersionView> {
        let layout = parse_layout(form)?;
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let version = require_draft(require_version(&mut tx, &template, ordinal).await?, "have its layout confirmed")?;
        require_seen(&template, &version, seen_revision, "confirming its layout")?;
        let workbook = self.stored(&mut tx, &version).await?;
        let read = TemplateVersion::read(&workbook, layout.clone())?;
        let lines = keeping_evidence(&mut tx, &version, &read.items).await?;
        let authors = with_author(forms::authors_of(&version.draft_authors)?, editor);
        drop(tx);

        let mut tx = self.write().await?;
        let stored_layout = forms::layout_json(&layout);
        let authors_text = forms::authors_json(&authors);
        require_still(
            rows::edit_draft(
                &mut tx,
                version.id,
                version.revision,
                VersionStatus::Draft.wire_name(),
                DraftEdit {
                    layout: Some(&stored_layout),
                    offers_not_applicable: layout.offers_not_applicable(),
                    item_pairs: None,
                    draft_authors: &authors_text,
                },
            )
            .await?,
            &version,
        )?;
        replace_items(&mut tx, version.id, &lines).await?;
        rows::commit(tx).await?;

        let not_applicable = layout
            .answers()
            .not_applicable()
            .map_or_else(|| ", no not applicable".to_owned(), |word| format!(" / \"{word}\" (not applicable)"));
        self.audit
            .record(editor.actor.entry(
                AuditOperation::ChecklistTemplateLayoutConfirmed,
                &resource(&template, ordinal),
                &format!(
                    "Checklist template \"{}\" version {ordinal}: layout confirmed on sheet \"{}\", rows {} to {}, {} \
                     items; answers \"{}\" / \"{}\"{not_applicable}.",
                    template.slug,
                    layout.sheet(),
                    layout.first_item_row(),
                    layout.last_item_row(),
                    read.items.len(),
                    layout.answers().yes(),
                    layout.answers().no()
                ),
            ))
            .await;
        let mut tx = self.read().await?;
        version_view(&mut tx, &template, version.id).await
    }

    /// `pairItems`: the list replaces the draft's pairs; an empty one clears them.
    pub async fn pair_items(
        &self,
        slug: Option<&str>,
        ordinal: i32,
        seen_revision: Option<i32>,
        requested: Option<&[Option<PairForm>]>,
        editor: &Editor,
    ) -> Result<VersionView> {
        let pairs = parse_pairs(requested)?;
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let version = require_draft(require_version(&mut tx, &template, ordinal).await?, "have its items paired")?;
        require_seen(&template, &version, seen_revision, "pairing its items")?;
        require_layout(&version, "pairing its items")?;
        let Some(previous_id) = version.previous_version_id else {
            return Err(ChecklistError::conflict(
                Cause::TemplateNothingToPair,
                format!(
                    "Version {ordinal} of \"{}\" follows no published version: there is nothing to pair its items with.",
                    template.slug
                ),
            ));
        };
        let previous = items_of(&mut tx, previous_id).await?;
        let pairing = VersionPairing::of(&previous, &as_read(&mut tx, &version).await?, &pairs)?;
        let authors = with_author(forms::authors_of(&version.draft_authors)?, editor);
        let previous_ordinal = ordinal_of(&mut tx, previous_id).await?;
        drop(tx);

        let mut tx = self.write().await?;
        let stored_pairs = forms::pairs_json(&pairs);
        let authors_text = forms::authors_json(&authors);
        require_still(
            rows::edit_draft(
                &mut tx,
                version.id,
                version.revision,
                VersionStatus::Draft.wire_name(),
                DraftEdit {
                    layout: version.layout.as_deref(),
                    offers_not_applicable: version.offers_not_applicable,
                    item_pairs: stored_pairs.as_deref(),
                    draft_authors: &authors_text,
                },
            )
            .await?,
            &version,
        )?;
        replace_items(&mut tx, version.id, &pairing.next).await?;
        rows::commit(tx).await?;

        self.audit
            .record(editor.actor.entry(
                AuditOperation::ChecklistTemplateItemsPaired,
                &resource(&template, ordinal),
                &format!(
                    "Checklist template \"{}\" version {ordinal}: {} {} paired by hand with version {previous_ordinal}; \
                     their answers follow them, to be confirmed.",
                    template.slug,
                    pairs.len(),
                    if pairs.len() == 1 { "item" } else { "items" }
                ),
            ))
            .await;
        let mut tx = self.read().await?;
        version_view(&mut tx, &template, version.id).await
    }

    /// `setEvidence`: the lines listed change, the others keep theirs; the requirement is part of each line's digest.
    pub async fn set_evidence(
        &self,
        slug: Option<&str>,
        ordinal: i32,
        seen_revision: Option<i32>,
        requested: Option<&[Option<EvidenceForm>]>,
        editor: &Editor,
    ) -> Result<VersionView> {
        let wanted = parse_evidence(requested)?;
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let version =
            require_draft(require_version(&mut tx, &template, ordinal).await?, "have its evidence requirements set")?;
        require_seen(&template, &version, seen_revision, "setting its evidence requirements")?;
        require_layout(&version, "setting its evidence requirements")?;
        let by_key = by_key(rows::items_of(&mut tx, version.id).await?);
        let mut changed = Vec::new();
        let mut described = Vec::new();
        for (key, evidence) in &wanted {
            let Some(item) = by_key.get(key.as_str()) else {
                return Err(no_item(ordinal, &template, key));
            };
            let mut requiring = domain(item)?;
            requiring.evidence = *evidence;
            let mut row = item.clone();
            row.evidence_kind = evidence.kind.wire_name().to_owned();
            row.evidence_validity_months = evidence.validity_months;
            // The digest is what the version's view and its documents state: a requirement written without it would
            // say the line asks what it asked before.
            row.content_digest = requiring.content_digest();
            described.push(format!("line {} (row {}) {}", item.position, item.sheet_row, describe(evidence)));
            changed.push(row);
        }
        let authors = with_author(forms::authors_of(&version.draft_authors)?, editor);
        drop(tx);

        let mut tx = self.write().await?;
        let authors_text = forms::authors_json(&authors);
        require_still(
            rows::edit_draft(
                &mut tx,
                version.id,
                version.revision,
                VersionStatus::Draft.wire_name(),
                DraftEdit {
                    layout: version.layout.as_deref(),
                    offers_not_applicable: version.offers_not_applicable,
                    item_pairs: version.item_pairs.as_deref(),
                    draft_authors: &authors_text,
                },
            )
            .await?,
            &version,
        )?;
        for row in &changed {
            rows::update_item_terms(&mut tx, row).await?;
        }
        rows::commit(tx).await?;

        self.audit
            .record(editor.actor.entry(
                AuditOperation::ChecklistTemplateEvidenceSet,
                &resource(&template, ordinal),
                &format!(
                    "Checklist template \"{}\" version {ordinal}: evidence requirement set on {}.",
                    template.slug,
                    lines_described(changed.len(), &described)
                ),
            ))
            .await;
        let mut tx = self.read().await?;
        version_view(&mut tx, &template, version.id).await
    }

    /// `bindRules`: each rule read by the domain, which refuses in words; a `None` rule unbinds the line.
    pub async fn bind_rules(
        &self,
        slug: Option<&str>,
        ordinal: i32,
        seen_revision: Option<i32>,
        requested: Option<&[Option<RuleLineForm>]>,
        editor: &Editor,
    ) -> Result<VersionView> {
        let wanted = parse_rules(requested)?;
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let version = require_draft(require_version(&mut tx, &template, ordinal).await?, "have its rules bound")?;
        require_seen(&template, &version, seen_revision, "binding its rules")?;
        require_layout(&version, "binding its rules")?;
        let by_key = by_key(rows::items_of(&mut tx, version.id).await?);
        let mut changed = Vec::new();
        let mut described = Vec::new();
        for (key, rule) in &wanted {
            let Some(item) = by_key.get(key.as_str()) else {
                return Err(no_item(ordinal, &template, key));
            };
            let canonical = rule.as_ref().map(ChecklistRule::canonical);
            let mut bound = domain(item)?;
            bound.bound_rule = canonical.clone();
            let mut row = item.clone();
            row.bound_rule = canonical;
            // The digest is what the version's view and every pairing read: a binding written without it would say
            // the line asks what it asked before, and a carried answer would not wait.
            row.content_digest = bound.content_digest();
            described.push(format!(
                "line {} (row {}) {}",
                item.position,
                item.sheet_row,
                rule.as_ref().map_or_else(
                    || "unbound".to_owned(),
                    |bound| {
                        let days = bound.max_age_days();
                        format!(
                            "bound to {}, evidence at most {days} {} old, rule sha256 {}",
                            bound.kind().wire_name(),
                            if days == 1 { "day" } else { "days" },
                            bound.digest().get(..12).unwrap_or("")
                        )
                    }
                )
            ));
            changed.push(row);
        }
        let authors = with_author(forms::authors_of(&version.draft_authors)?, editor);
        drop(tx);

        let mut tx = self.write().await?;
        let authors_text = forms::authors_json(&authors);
        require_still(
            rows::edit_draft(
                &mut tx,
                version.id,
                version.revision,
                VersionStatus::Draft.wire_name(),
                DraftEdit {
                    layout: version.layout.as_deref(),
                    offers_not_applicable: version.offers_not_applicable,
                    item_pairs: version.item_pairs.as_deref(),
                    draft_authors: &authors_text,
                },
            )
            .await?,
            &version,
        )?;
        for row in &changed {
            rows::update_item_terms(&mut tx, row).await?;
        }
        rows::commit(tx).await?;

        self.audit
            .record(editor.actor.entry(
                AuditOperation::ChecklistTemplateRulesBound,
                &resource(&template, ordinal),
                &format!(
                    "Checklist template \"{}\" version {ordinal}: rules set on {}.",
                    template.slug,
                    lines_described(changed.len(), &described)
                ),
            ))
            .await;
        let mut tx = self.read().await?;
        version_view(&mut tx, &template, version.id).await
    }

    /// `derive`: a new draft from a published version — the same workbook, layout and items under the same keys.
    pub async fn derive(
        &self,
        slug: Option<&str>,
        ordinal: i32,
        label: Option<&str>,
        editor: &Editor,
    ) -> Result<VersionView> {
        let version_label = bounded_text::optional(label, MAX_LABEL, "The version's label")?;
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let source = require_version(&mut tx, &template, ordinal).await?;
        if VersionStatus::of_stored(&source.status)? != VersionStatus::Published {
            return Err(ChecklistError::conflict(
                Cause::TemplateNotPublished,
                format!(
                    "Version {ordinal} of \"{}\" is {}: a new version is derived from a published one.",
                    template.slug, source.status
                ),
            ));
        }
        let copied = rows::items_of(&mut tx, source.id).await?;
        let source_bytes = rows::source_bytes(&mut tx, source.id)
            .await?
            .ok_or_else(|| ChecklistError::defect(format!("Template version {} is gone.", source.id)))?;
        drop(tx);
        let now = self.clock.now();

        let written: Result<(i64, i32)> = async {
            let mut tx = self.write().await?;
            require_no_draft(&mut tx, &template).await?;
            let next = next_ordinal(&mut tx, template.id).await?;
            let authors =
                forms::authors_json(&[DraftAuthor { account_id: editor.account_id, username: editor.username() }]);
            let username = editor.username();
            let id = rows::insert_version(
                &mut tx,
                &NewVersion {
                    template_id: template.id,
                    ordinal: next,
                    label: version_label.as_deref(),
                    status: VersionStatus::Draft.wire_name(),
                    revision: 1,
                    source_sha256: &source.source_sha256,
                    source_size: source.source_size,
                    source_bytes: &source_bytes,
                    layout: source.layout.as_deref(),
                    offers_not_applicable: source.offers_not_applicable,
                    previous_version_id: Some(source.id),
                    derived_from_version_id: Some(source.id),
                    draft_authors: &authors,
                    imported_at: rows::at(now),
                    imported_by: &username,
                },
            )
            .await?;
            for item in &copied {
                rows::insert_item(&mut tx, &ItemRow { version_id: id, ..item.clone() }).await?;
            }
            rows::commit(tx).await?;
            Ok((id, next))
        }
        .await;
        let (derived_id, derived_ordinal) = self.arbitrated(&template.slug, written).await?;

        self.audit
            .record(editor.actor.entry(
                AuditOperation::ChecklistTemplateDerived,
                &resource(&template, derived_ordinal),
                &format!(
                    "Checklist template \"{}\": version {derived_ordinal} derived as a draft from version {ordinal}, \
                     workbook sha256 {}, {} items.",
                    template.slug,
                    source.source_sha256,
                    copied.len()
                ),
            ))
            .await;
        let mut tx = self.read().await?;
        version_view(&mut tx, &template, derived_id).await
    }

    /// `publish`: from now on, what projects open their checklists on. Immutable once done.
    pub async fn publish(
        &self,
        slug: Option<&str>,
        ordinal: i32,
        reviewed_revision: Option<i32>,
        editor: &Editor,
    ) -> Result<VersionView> {
        let Some(reviewed) = reviewed_revision else {
            return Err(ChecklistError::invalid(
                "State the revision you reviewed — the version's \"revision\": what is published is what somebody has \
                 read.",
            ));
        };
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let version = require_draft(require_version(&mut tx, &template, ordinal).await?, "be published")?;
        require_layout(&version, "publishing it")?;
        require_seen(&template, &version, Some(reviewed), "publishing it")?;
        let four_eyes = self.require_another_person(&template, &version, editor, "published").await?;
        self.require_renderable(&mut tx, &template, &version).await?;
        drop(tx);
        let now = self.clock.now();

        let mut tx = self.write().await?;
        require_still(
            rows::publish_version(
                &mut tx,
                version.id,
                reviewed,
                VersionStatus::Draft.wire_name(),
                VersionStatus::Published.wire_name(),
                rows::at(now),
                &editor.username(),
            )
            .await?,
            &version,
        )?;
        rows::commit(tx).await?;

        let rule = if four_eyes {
            format!("required, and the publisher is none of its authors ({})", author_names(&version)?)
        } else {
            "not required".to_owned()
        };
        self.audit
            .record(editor.actor.entry(
                AuditOperation::ChecklistTemplatePublished,
                &resource(&template, ordinal),
                &format!(
                    "Checklist template \"{}\" version {ordinal} published, workbook sha256 {}; four-eyes {rule}.",
                    template.slug, version.source_sha256
                ),
            ))
            .await;
        let mut tx = self.read().await?;
        version_view(&mut tx, &template, version.id).await
    }

    /// `retire`: a published version stops being offered, or a draft is set aside.
    pub async fn retire(&self, slug: Option<&str>, ordinal: i32, editor: &Editor) -> Result<VersionView> {
        let mut tx = self.read().await?;
        let template = require_template(&mut tx, slug).await?;
        let version = require_version(&mut tx, &template, ordinal).await?;
        drop(tx);
        let from = VersionStatus::of_stored(&version.status)?;
        if from == VersionStatus::Retired {
            return Err(ChecklistError::conflict(
                Cause::TemplateRetired,
                format!("Version {ordinal} of \"{}\" is already retired.", template.slug),
            ));
        }
        let published = from == VersionStatus::Published;
        let four_eyes = published && self.require_another_person(&template, &version, editor, "retired").await?;
        let now = self.clock.now();

        let mut tx = self.write().await?;
        require_still(
            rows::retire_version(
                &mut tx,
                version.id,
                version.revision,
                from.wire_name(),
                VersionStatus::Retired.wire_name(),
                rows::at(now),
                &editor.username(),
            )
            .await?,
            &version,
        )?;
        rows::commit(tx).await?;

        let description = if published {
            format!(
                "Checklist template \"{}\" version {ordinal} retired: no new checklist opens on it; four-eyes {}.",
                template.slug,
                if four_eyes { "required" } else { "not required" }
            )
        } else {
            format!("Checklist template \"{}\" version {ordinal}, a draft never published, set aside.", template.slug)
        };
        let entry =
            editor.actor.entry(AuditOperation::ChecklistTemplateRetired, &resource(&template, ordinal), &description);
        self.audit.record(if published { entry.signalling(CHECKLIST_TEMPLATE_CHANGED) } else { entry }).await;
        let mut tx = self.read().await?;
        version_view(&mut tx, &template, version.id).await
    }

    // ------------------------------------------------------------------ the trial rendering

    /// `requireRenderable`: refused when no sign-off could fill the draft's workbook in, by filling it in once with
    /// placeholder answers through the renderer the sign-off calls. Nothing of it is kept.
    async fn require_renderable(&self, tx: &mut Tx, template: &TemplateRow, version: &VersionRow) -> Result<()> {
        if let Some(refused) = trial(tx, version).await? {
            return Err(unrenderable(
                Cause::TemplateUnrenderable,
                format!(
                    "Version {} of \"{}\" cannot be published: no sign-off could fill its workbook in. {} A version's \
                     workbook never changes once imported: set this draft aside first.",
                    version.ordinal,
                    template.slug,
                    refused.message()
                ),
                &refused,
            ));
        }
        Ok(())
    }

    // ------------------------------------------------------------------ four-eyes

    /// `requireAnotherPerson`: whether the rule applied, which the audit entry states.
    async fn require_another_person(
        &self,
        template: &TemplateRow,
        version: &VersionRow,
        editor: &Editor,
        act: &str,
    ) -> Result<bool> {
        if !self.four_eyes().await? {
            return Ok(false);
        }
        let authors = forms::authors_of(&version.draft_authors)?;
        if editor.wrote(&authors) {
            return Err(ChecklistError::conflict(
                Cause::FourEyes,
                format!(
                    "Four-eyes approval: version {} of \"{}\" was written by {}, so it has to be {act} by somebody else.",
                    version.ordinal,
                    template.slug,
                    author_names(version)?
                ),
            ));
        }
        let compared: Vec<Author> = authors
            .iter()
            .map(|author| Author { account_id: author.account_id, username: author.username.clone() })
            .collect();
        self.independence.require_independent_of_authors(&compared, editor.account_id, true, self.clock.now()).await?;
        Ok(true)
    }

    async fn four_eyes(&self) -> Result<bool> {
        self.settings
            .is_enabled(Setting::FourEyesApprovalRequired)
            .await
            .map_err(|failure| ChecklistError::Failed(failure.to_string()))
    }

    // ------------------------------------------------------------------ rows

    /// The file was read under the ceiling in force when it was imported; a ceiling lowered since must not make a
    /// stored template unreadable.
    async fn stored(&self, tx: &mut Tx, version: &VersionRow) -> Result<Workbook> {
        let bytes = rows::source_bytes(tx, version.id)
            .await?
            .ok_or_else(|| ChecklistError::defect(format!("Template version {} is gone.", version.id)))?;
        let ceiling = self.max_workbook_bytes.max(i64::try_from(bytes.len()).unwrap_or(i64::MAX));
        Ok(Workbook::read(&bytes, ceiling)?)
    }

    /// `arbitrated`: a new draft's failure read as "taken" only once the committed rows say so — a key's refusal is
    /// not the only way an insert fails, and not every driver reports one as such.
    async fn arbitrated<T>(&self, slug: &str, written: Result<T>) -> Result<T> {
        match written {
            Ok(value) => Ok(value),
            Err(failed @ ChecklistError::Failed(_)) => {
                let mut tx = self.read().await?;
                if let Some(template) = rows::template_by_slug(&mut tx, slug).await? {
                    require_no_draft(&mut tx, &template).await?;
                }
                Err(failed)
            }
            Err(refusal) => Err(refusal),
        }
    }
}

// ------------------------------------------------------------------ shared with the project checklists

/// The trial's verdict on a version: what refused it, or `None` when a sign-off could fill its workbook in.
pub(crate) async fn trial(tx: &mut Tx, version: &VersionRow) -> Result<Option<Refusal>> {
    let layout = forms::layout_of(version.layout.as_deref().unwrap_or("null"))?;
    let lines = items_of(tx, version.id).await?;
    let bytes = rows::source_bytes(tx, version.id)
        .await?
        .ok_or_else(|| ChecklistError::defect(format!("Template version {} is gone.", version.id)))?;
    Ok(match renderer::trial(&bytes, &layout, &lines) {
        Ok(_) => None,
        Err(RenderFailure::Refused(refused)) => Some(Refusal::Template(refused.0)),
        Err(RenderFailure::WrittenFormula(written)) => Some(Refusal::Written(written)),
        Err(RenderFailure::Defect(defect)) => return Err(ChecklistError::Failed(defect.0)),
    })
}

/// `InvalidTemplateException`, or its `WrittenFormulaException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Refusal {
    Template(String),
    Written(crate::renderer::WrittenFormula),
}

impl Refusal {
    pub(crate) fn message(&self) -> &str {
        match self {
            Refusal::Template(message) => message,
            Refusal::Written(written) => &written.message,
        }
    }

    pub(crate) fn cells(&self) -> Vec<UnrenderableCell> {
        match self {
            Refusal::Template(_) => Vec::new(),
            Refusal::Written(written) => UnrenderableCell::all(written),
        }
    }
}

/// `ChecklistConflict.unrenderable`: the cells in a `cells` member when that is the trial's reason and there are some.
pub(crate) fn unrenderable(cause: Cause, message: String, refused: &Refusal) -> ChecklistError {
    let cells = refused.cells();
    if cells.is_empty() {
        ChecklistError::conflict(cause, message)
    } else {
        ChecklistError::conflict_with(cause, message, Members::Cells(cells))
    }
}

/// `ChecklistTemplateService.domain`: a stored item as the domain reads it.
pub(crate) fn domain(item: &ItemRow) -> Result<ChecklistItem> {
    let kind = EvidenceKind::ALL
        .into_iter()
        .find(|kind| kind.wire_name().eq_ignore_ascii_case(&item.evidence_kind))
        .ok_or_else(|| {
            ChecklistError::defect(format!("An item asks for an unknown evidence: {}", item.evidence_kind))
        })?;
    let evidence = EvidenceRequirement::new(kind, item.evidence_validity_months)
        .map_err(|refused| ChecklistError::Failed(refused.0))?;
    Ok(ChecklistItem {
        key: ItemKey::stored(&item.item_key)?,
        position: item.position,
        domain: item.domain.clone(),
        objective: item.objective.clone(),
        control: item.control.clone(),
        contact: item.contact.clone(),
        kpi: item.kpi.clone(),
        row: item.sheet_row,
        evidence,
        bound_rule: item.bound_rule.clone(),
    })
}

pub(crate) async fn items_of(tx: &mut Tx, version_id: i64) -> Result<Vec<ChecklistItem>> {
    rows::items_of(tx, version_id).await?.iter().map(domain).collect()
}

// ------------------------------------------------------------------ parsing

fn require_slug(slug: Option<&str>) -> Result<String> {
    let value = java::strip(slug.unwrap_or(""));
    if !is_slug(value) {
        return Err(ChecklistError::invalid(format!(
            "A template's slug is 1 to 64 lowercase letters, digits and inner hyphens{}",
            if value.is_empty() {
                ".".to_owned()
            } else {
                format!("; \"{}\" is not one.", bounded_text::clip(Some(value), 70).unwrap_or(""))
            }
        )));
    }
    Ok(value.to_owned())
}

/// `[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?`.
fn is_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    let edge = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let inner = |byte: &u8| edge(byte) || *byte == b'-';
    match bytes {
        [] => false,
        [one] => edge(one),
        [first, middle @ .., last] => middle.len() <= 62 && edge(first) && edge(last) && middle.iter().all(inner),
    }
}

/// `parse(ChecklistLayoutForm)`: refused in words where it cannot be a layout.
fn parse_layout(form: Option<&LayoutForm>) -> Result<ChecklistLayout> {
    let Some(form) = form else {
        return Err(ChecklistError::invalid(
            "A layout is required: the sheet, the columns, the item rows and the answer words.",
        ));
    };
    let (Some(first), Some(last)) = (form.first_item_row, form.last_item_row) else {
        return Err(ChecklistError::invalid("Name the first and the last item rows."));
    };
    let Some(answers) = &form.answers else {
        return Err(ChecklistError::invalid("Map the template's answer words to yes and no."));
    };
    let mut columns: Vec<(ChecklistColumn, Option<&str>)> = Vec::new();
    for (name, letters) in form.columns.as_deref().unwrap_or(&[]) {
        let column = named(&ChecklistColumn::ALL, |column| column.wire_name(), Some(name), "column")?;
        // An `EnumMap.put` of a column named twice keeps its first place and its last letters.
        match columns.iter_mut().find(|(present, _)| *present == column) {
            Some(entry) => entry.1 = letters.as_deref(),
            None => columns.push((column, letters.as_deref())),
        }
    }
    let mut header: Vec<(Field, HeaderCell)> = Vec::new();
    for (name, cell) in form.header.as_deref().unwrap_or(&[]) {
        let field = named(&Field::ALL, |field| field.wire_name(), Some(name), "header entry")?;
        let Some(cell) = cell else {
            return Err(ChecklistError::invalid(format!("The {} header entry names no cells.", field.wire_name())));
        };
        let built = HeaderCell::new(
            cell_of(cell.label.as_deref(), field, "label")?,
            cell_of(cell.value.as_deref(), field, "value")?,
        )?;
        match header.iter_mut().find(|(present, _)| *present == field) {
            Some(entry) => entry.1 = built,
            None => header.push((field, built)),
        }
    }
    let not_applicable = answers.not_applicable.as_deref().filter(|word| !java::is_blank(word));
    let words = AnswerWords::new(answers.yes.as_deref(), answers.no.as_deref(), not_applicable)?;
    Ok(ChecklistLayout::new(form.sheet.as_deref(), &columns, first, last, &header, words)?)
}

fn named<E: Copy>(values: &[E], wire_name: impl Fn(&E) -> &'static str, name: Option<&str>, what: &str) -> Result<E> {
    let wanted = java::to_lower_root(java::strip(name.unwrap_or("")));
    values.iter().copied().find(|value| wire_name(value) == wanted).ok_or_else(|| {
        let all: Vec<&str> = values.iter().map(&wire_name).collect();
        ChecklistError::invalid(format!(
            "\"{}\" is no {what} of a layout; one of {}.",
            bounded_text::clip(Some(name.unwrap_or("null")), 40).unwrap_or(""),
            all.join(", ")
        ))
    })
}

fn cell_of(reference: Option<&str>, field: Field, which: &str) -> Result<CellRef> {
    CellRef::parse(reference).ok_or_else(|| {
        ChecklistError::invalid(format!(
            "The {} header's {which} cell is \"{}\", which is no cell — a column's letters and a row, B3.",
            field.wire_name(),
            bounded_text::clip(Some(reference.unwrap_or("null")), 20).unwrap_or("")
        ))
    })
}

fn parse_pairs(requested: Option<&[Option<PairForm>]>) -> Result<Vec<ManualPair>> {
    let Some(requested) = requested else {
        return Err(ChecklistError::invalid("State the pairs — an empty list clears them."));
    };
    let mut pairs = Vec::with_capacity(requested.len());
    for pair in requested {
        let Some(pair) = pair else {
            return Err(ChecklistError::invalid(
                "A pair names the added item and the removed one; one of them is empty.",
            ));
        };
        pairs.push(ManualPair {
            added: key_of(pair.added.as_deref(), "added")?,
            removed: key_of(pair.removed.as_deref(), "removed")?,
        });
    }
    Ok(pairs)
}

/// A key as the preview shows it: the two forms `ItemKey` derives, and nothing a caller writes.
fn key_of(value: Option<&str>, side: &str) -> Result<ItemKey> {
    let key = java::strip(value.unwrap_or(""));
    if !(key.starts_with("id:") || key.starts_with("text:")) || java::utf16_len(key) > MAX_KEY {
        return Err(ChecklistError::invalid(format!(
            "A pair's {side} item is named by its key as the preview shows it, \"text:…\" or \"id:…\"; \"{}\" is not \
             one.",
            bounded_text::clip(Some(key), 40).unwrap_or("")
        )));
    }
    Ok(ItemKey::stored(key)?)
}

/// A line's key as a request names it.
fn line_key(key: Option<&str>) -> Result<String> {
    let Some(key) = key.filter(|key| !java::is_blank(key)) else {
        return Err(ChecklistError::invalid(
            "Each line is named by its \"itemKey\", as the version shows it; one is empty.",
        ));
    };
    let key = java::strip(key);
    if java::utf16_len(key) > MAX_KEY {
        return Err(ChecklistError::invalid(format!(
            "A line's key is at most {MAX_KEY} characters; \"{}\" is longer.",
            bounded_text::clip(Some(key), 40).unwrap_or("")
        )));
    }
    Ok(key.to_owned())
}

fn named_twice(key: &str) -> ChecklistError {
    ChecklistError::invalid(format!("The line \"{}\" is named twice.", bounded_text::clip(Some(key), 60).unwrap_or("")))
}

fn parse_evidence(requested: Option<&[Option<EvidenceForm>]>) -> Result<Vec<(String, EvidenceRequirement)>> {
    let requested = requested.filter(|list| !list.is_empty()).ok_or_else(|| {
        ChecklistError::invalid(
            "Name the lines whose evidence requirement to set — \"items\", each with its \"itemKey\" and its \
             \"evidenceKind\".",
        )
    })?;
    let mut wanted: Vec<(String, EvidenceRequirement)> = Vec::new();
    for line in requested {
        let key = line_key(line.as_ref().and_then(|line| line.item_key.as_deref()))?;
        let line = line.as_ref().map_or_else(EvidenceForm::default, Clone::clone);
        let evidence = EvidenceRequirement::new(
            EvidenceKind::parse(line.evidence_kind.as_deref())?,
            line.evidence_validity_months,
        )?;
        if wanted.iter().any(|(present, _)| *present == key) {
            return Err(named_twice(&key));
        }
        wanted.push((key, evidence));
    }
    Ok(wanted)
}

fn parse_rules(requested: Option<&[Option<RuleLineForm>]>) -> Result<Vec<(String, Option<ChecklistRule>)>> {
    let requested = requested.filter(|list| !list.is_empty()).ok_or_else(|| {
        ChecklistError::invalid(
            "Name the lines whose rule to bind — \"items\", each with its \"itemKey\" and its \"rule\", or a null rule \
             to unbind the line.",
        )
    })?;
    let mut wanted: Vec<(String, Option<ChecklistRule>)> = Vec::new();
    for line in requested {
        let key = line_key(line.as_ref().and_then(|line| line.item_key.as_deref()))?;
        let rule = match line.as_ref().and_then(|line| line.rule.as_ref()) {
            None | Some(Node::Null) => None,
            Some(node) => Some(ChecklistRule::parse(node)?),
        };
        if wanted.iter().any(|(present, _)| *present == key) {
            return Err(named_twice(&key));
        }
        wanted.push((key, rule));
    }
    Ok(wanted)
}

fn describe(evidence: &EvidenceRequirement) -> String {
    let asked = match evidence.kind {
        EvidenceKind::None => "asks for no proof",
        EvidenceKind::LinkOrFile => "asks for a link or a file",
        EvidenceKind::File => "asks for a file",
    };
    match evidence.validity_months {
        Some(months) => format!("{asked}, holding {months} {}", if months == 1 { "month" } else { "months" }),
        None => asked.to_owned(),
    }
}

/// "3 lines — line 1 (row 4) …; …; and 2 more".
fn lines_described(count: usize, described: &[String]) -> String {
    let named: Vec<&str> = described.iter().take(AUDITED_LINES).map(String::as_str).collect();
    let more = if described.len() > AUDITED_LINES {
        format!("; and {} more", described.len().saturating_sub(AUDITED_LINES))
    } else {
        String::new()
    };
    format!("{count} {} — {}{more}", if count == 1 { "line" } else { "lines" }, named.join("; "))
}

// ------------------------------------------------------------------ rows

async fn require_template(tx: &mut Tx, slug: Option<&str>) -> Result<TemplateRow> {
    rows::template_by_slug(tx, java::strip(slug.unwrap_or(""))).await?.ok_or_else(|| {
        ChecklistError::not_found(format!(
            "No checklist template \"{}\".",
            bounded_text::clip(Some(slug.unwrap_or("null")), 70).unwrap_or("")
        ))
    })
}

async fn require_version(tx: &mut Tx, template: &TemplateRow, ordinal: i32) -> Result<VersionRow> {
    rows::version_by_ordinal(tx, template.id, ordinal).await?.ok_or_else(|| {
        ChecklistError::not_found(format!("Checklist template \"{}\" has no version {ordinal}.", template.slug))
    })
}

fn require_draft(version: VersionRow, act: &str) -> Result<VersionRow> {
    if VersionStatus::of_stored(&version.status)? != VersionStatus::Draft {
        return Err(ChecklistError::conflict(
            Cause::TemplateNotDraft,
            format!(
                "Version {} is {}: only a draft can {act}. A change to a published version is a new version, derived \
                 from it.",
                version.ordinal, version.status
            ),
        ));
    }
    Ok(version)
}

fn require_layout(version: &VersionRow, act: &str) -> Result<()> {
    if version.layout.is_none() {
        return Err(ChecklistError::conflict(
            Cause::TemplateNoLayout,
            format!(
                "Version {} has no confirmed layout, so no item: confirm its layout before {act}.",
                version.ordinal
            ),
        ));
    }
    Ok(())
}

async fn require_no_draft(tx: &mut Tx, template: &TemplateRow) -> Result<()> {
    if rows::has_version_in(tx, template.id, VersionStatus::Draft.wire_name()).await? {
        return Err(ChecklistError::conflict(
            Cause::TemplateHasDraft,
            format!(
                "Checklist template \"{}\" already has a draft: publish it or set it aside before making another.",
                template.slug
            ),
        ));
    }
    Ok(())
}

/// The conditional update's answer: nothing matched means somebody else changed the version first.
fn require_still(updated: u64, version: &VersionRow) -> Result<()> {
    if updated != 1 {
        return Err(ChecklistError::conflict(
            Cause::TemplateChanged,
            format!(
                "Version {} changed while this was being done — edited, published or retired by somebody else. Read \
                 it again.",
                version.ordinal
            ),
        ));
    }
    Ok(())
}

/// The revision the writer read is the one being changed.
fn require_seen(template: &TemplateRow, version: &VersionRow, seen: Option<i32>, doing: &str) -> Result<()> {
    let Some(seen) = seen else {
        return Err(ChecklistError::invalid(
            "State the revision you read — the version's \"revision\": a draft is changed from what somebody has seen.",
        ));
    };
    if version.revision != seen {
        return Err(ChecklistError::conflict(
            Cause::TemplateChanged,
            format!(
                "Version {} of \"{}\" has changed since revision {seen} — it is at revision {}. Read it again before \
                 {doing}.",
                version.ordinal, template.slug, version.revision
            ),
        ));
    }
    Ok(())
}

async fn next_ordinal(tx: &mut Tx, template_id: i64) -> Result<i32> {
    let last = rows::last_ordinal(tx, template_id).await?;
    i32::try_from(last.saturating_add(1)).map_err(|_| ChecklistError::defect("A template has run out of numbers."))
}

fn no_item(ordinal: i32, template: &TemplateRow, key: &str) -> ChecklistError {
    ChecklistError::invalid(format!(
        "Version {ordinal} of \"{}\" has no item \"{}\"; a line is named by its key as the version shows it.",
        template.slug,
        bounded_text::clip(Some(key), 60).unwrap_or("")
    ))
}

fn by_key(items: Vec<ItemRow>) -> HashMap<String, ItemRow> {
    items.into_iter().map(|item| (item.item_key.clone(), item)).collect()
}

async fn replace_items(tx: &mut Tx, version_id: i64, read: &[ChecklistItem]) -> std::result::Result<(), StoreError> {
    rows::delete_items(tx, version_id).await?;
    for item in read {
        rows::insert_item(tx, &entity(item, version_id)).await?;
    }
    Ok(())
}

fn entity(item: &ChecklistItem, version_id: i64) -> ItemRow {
    ItemRow {
        id: 0,
        version_id,
        item_key: item.key.value().to_owned(),
        position: item.position,
        domain: item.domain.clone(),
        objective: item.objective.clone(),
        control: item.control.clone(),
        contact: item.contact.clone(),
        kpi: item.kpi.clone(),
        content_digest: item.content_digest(),
        sheet_row: item.row,
        evidence_kind: item.evidence.kind.wire_name().to_owned(),
        evidence_validity_months: item.evidence.validity_months,
        bound_rule: item.bound_rule.clone(),
    }
}

/// `keepingEvidence`: each line read keeps the proof it asked for and the rule it was bound to — the draft's own when
/// the line was read before, else the previous version's under the same key.
async fn keeping_evidence(tx: &mut Tx, version: &VersionRow, read: &[ChecklistItem]) -> Result<Vec<ChecklistItem>> {
    let mut set: HashMap<ItemKey, ChecklistItem> = HashMap::new();
    if let Some(previous) = version.previous_version_id {
        for item in items_of(tx, previous).await? {
            set.insert(item.key.clone(), item);
        }
    }
    for item in as_read(tx, version).await? {
        set.insert(item.key.clone(), item);
    }
    Ok(read
        .iter()
        .map(|item| match set.get(&item.key) {
            Some(before) => {
                ChecklistItem { evidence: before.evidence, bound_rule: before.bound_rule.clone(), ..item.clone() }
            }
            None => item.clone(),
        })
        .collect())
}

/// A draft's items as its layout read them: an item paired by hand goes back to the key it was read with.
async fn as_read(tx: &mut Tx, version: &VersionRow) -> Result<Vec<ChecklistItem>> {
    let read_key_of = read_keys(version)?;
    Ok(items_of(tx, version.id)
        .await?
        .into_iter()
        .map(|item| match read_key_of.get(&item.key) {
            Some(read) => item.with_key(read.clone()),
            None => item,
        })
        .collect())
}

/// For each key an item was stored under by a pair, the key its layout read it with.
fn read_keys(version: &VersionRow) -> Result<HashMap<ItemKey, ItemKey>> {
    Ok(forms::pairs_of(version.item_pairs.as_deref())?.into_iter().map(|pair| (pair.removed, pair.added)).collect())
}

async fn pairing_of(tx: &mut Tx, version: &VersionRow) -> Result<VersionPairing> {
    let previous = match version.previous_version_id {
        Some(previous) => items_of(tx, previous).await?,
        None => Vec::new(),
    };
    let pairs = forms::pairs_of(version.item_pairs.as_deref())?;
    Ok(VersionPairing::of(&previous, &as_read(tx, version).await?, &pairs)?)
}

async fn ordinal_of(tx: &mut Tx, version_id: i64) -> Result<i32> {
    rows::version_by_id(tx, version_id)
        .await?
        .map(|version| version.ordinal)
        .ok_or_else(|| ChecklistError::defect(format!("Template version {version_id} is gone.")))
}

fn resource(template: &TemplateRow, ordinal: i32) -> String {
    format!("{}/{ordinal}", template.slug)
}

fn with_author(mut authors: Vec<DraftAuthor>, editor: &Editor) -> Vec<DraftAuthor> {
    if !authors.iter().any(|author| author.account_id == editor.account_id) {
        authors.push(DraftAuthor { account_id: editor.account_id, username: editor.username() });
    }
    authors
}

fn author_names(version: &VersionRow) -> Result<String> {
    Ok(forms::authors_of(&version.draft_authors)?
        .into_iter()
        .map(|author| author.username)
        .collect::<Vec<_>>()
        .join(", "))
}

// ------------------------------------------------------------------ views

pub(crate) async fn view(tx: &mut Tx, template: &TemplateRow) -> Result<TemplateView> {
    let rows = rows::summaries_of(tx, template.id).await?;
    let ordinals = ordinals(&rows);
    Ok(TemplateView {
        id: template.id,
        slug: template.slug.clone(),
        name: template.name.clone(),
        created_at: vectispire_cp_audit::iso_instant(template.created_at.0),
        created_by: template.created_by.clone(),
        versions: rows.iter().map(|row| summary(row, &ordinals)).collect::<Result<_>>()?,
    })
}

async fn summary_of(tx: &mut Tx, template: &TemplateRow, version_id: i64) -> Result<VersionSummary> {
    let rows = rows::summaries_of(tx, template.id).await?;
    let ordinals = ordinals(&rows);
    rows.iter()
        .find(|row| row.version.id == version_id)
        .map(|row| summary(row, &ordinals))
        .unwrap_or_else(|| Err(ChecklistError::defect(format!("Template version {version_id} is gone."))))
}

pub(crate) async fn version_view(tx: &mut Tx, template: &TemplateRow, version_id: i64) -> Result<VersionView> {
    let summary = summary_of(tx, template, version_id).await?;
    let version = rows::version_by_id(tx, version_id)
        .await?
        .ok_or_else(|| ChecklistError::defect(format!("Template version {version_id} is gone.")))?;
    let items = rows::items_of(tx, version_id).await?.into_iter().map(item_view).collect::<Result<Vec<_>>>()?;
    let layout = match version.layout.as_deref() {
        Some(stored) => raw(forms::layout_form_json(&forms::layout_of(stored)?)),
        None => null(),
    };
    Ok(VersionView {
        template_slug: template.slug.clone(),
        template_name: template.name.clone(),
        version: summary,
        layout,
        items,
        pairs: forms::pairs_of(version.item_pairs.as_deref())?
            .into_iter()
            .map(|pair| ItemPair { added: pair.added.value().to_owned(), removed: pair.removed.value().to_owned() })
            .collect(),
    })
}

fn item_view(item: ItemRow) -> Result<ItemView> {
    let bound_rule = match item.bound_rule.as_deref() {
        Some(canonical) => raw(forms::rule_form_json(canonical)?),
        None => null(),
    };
    Ok(ItemView {
        id: item.id,
        version_id: item.version_id,
        item_key: item.item_key,
        position: item.position,
        domain: item.domain,
        objective: item.objective,
        control: item.control,
        contact: item.contact,
        kpi: item.kpi,
        content_digest: item.content_digest,
        sheet_row: item.sheet_row,
        evidence_kind: item.evidence_kind,
        evidence_validity_months: item.evidence_validity_months,
        bound_rule,
    })
}

fn ordinals(rows: &[rows::SummaryRow]) -> BTreeMap<i64, i32> {
    rows.iter().map(|row| (row.version.id, row.version.ordinal)).collect()
}

fn summary(row: &rows::SummaryRow, ordinals: &BTreeMap<i64, i32>) -> Result<VersionSummary> {
    let v = &row.version;
    Ok(VersionSummary {
        id: v.id,
        ordinal: v.ordinal,
        label: v.label.clone(),
        status: v.status.clone(),
        revision: v.revision,
        source_sha256: v.source_sha256.clone(),
        source_size: v.source_size,
        layout_confirmed: v.layout.is_some(),
        offers_not_applicable: v.offers_not_applicable,
        item_count: row.item_count,
        previous_ordinal: v.previous_version_id.and_then(|id| ordinals.get(&id).copied()),
        derived_from_ordinal: v.derived_from_version_id.and_then(|id| ordinals.get(&id).copied()),
        draft_authors: forms::authors_of(&v.draft_authors)?.into_iter().map(|author| author.username).collect(),
        imported_at: vectispire_cp_audit::iso_instant(v.imported_at.0),
        imported_by: v.imported_by.clone(),
        published_at: v.published_at.map(|at| vectispire_cp_audit::iso_instant(at.0)),
        published_by: v.published_by.clone(),
        retired_at: v.retired_at.map(|at| vectispire_cp_audit::iso_instant(at.0)),
        retired_by: v.retired_by.clone(),
    })
}

fn proposed(proposal: &LayoutProposal) -> ProposedLayout {
    let columns =
        Writer::object(proposal.columns.iter().map(|(column, letters)| (column.wire_name(), Writer::text(letters))));
    let header = Writer::object(proposal.header.iter().map(|(field, cell)| {
        (
            field.wire_name(),
            Writer::object([
                ("label", Writer::text(&cell.label().to_string())),
                ("value", Writer::text(&cell.value().to_string())),
            ]),
        )
    }));
    ProposedLayout {
        sheet: proposal.sheet.clone(),
        column_header_row: proposal.column_header_row,
        first_item_row: proposal.first_item_row,
        last_item_row: proposal.last_item_row,
        columns: raw(columns),
        header: raw(header),
        answer_values: proposal.answer_values.clone(),
    }
}

fn pairing_change(change: &Change, read_key_of: &HashMap<ItemKey, ItemKey>) -> PairingChange {
    match change {
        Change::Unchanged { previous, next } => PairingChange {
            change: "unchanged".to_owned(),
            paired_by_hand: false,
            read_key: Some(next.key.value().to_owned()),
            row: Some(next.row),
            control: Some(next.control.clone()),
            previous_key: Some(previous.key.value().to_owned()),
            previous_row: Some(previous.row),
            previous_control: Some(previous.control.clone()),
        },
        Change::Changed { previous, next, paired_by_hand } => PairingChange {
            change: "changed".to_owned(),
            paired_by_hand: *paired_by_hand,
            // Paired by hand, the item carries the old key; the pair named it by the one it was read with.
            read_key: Some(if *paired_by_hand {
                read_key_of.get(&next.key).unwrap_or(&next.key).value().to_owned()
            } else {
                next.key.value().to_owned()
            }),
            row: Some(next.row),
            control: Some(next.control.clone()),
            previous_key: Some(previous.key.value().to_owned()),
            previous_row: Some(previous.row),
            previous_control: Some(previous.control.clone()),
        },
        Change::Added { next } => PairingChange {
            change: "added".to_owned(),
            paired_by_hand: false,
            read_key: Some(next.key.value().to_owned()),
            row: Some(next.row),
            control: Some(next.control.clone()),
            previous_key: None,
            previous_row: None,
            previous_control: None,
        },
        Change::Removed { previous } => PairingChange {
            change: "removed".to_owned(),
            paired_by_hand: false,
            read_key: None,
            row: None,
            control: None,
            previous_key: Some(previous.key.value().to_owned()),
            previous_row: Some(previous.row),
            previous_control: Some(previous.control.clone()),
        },
    }
}
