//! A template version's line — its key across versions, what proof it asks for, its content digest — and the
//! columns of a checklist sheet a layout can name.

use vectispire_domain::bounded_text::clip;
use vectispire_domain::fingerprint::sha256_fields;
use vectispire_domain::java;

use crate::{Defect, Failure, Refused, refused, sha256_hex, text};

/// `ItemKey`: what identifies an item across its template's versions, so that an answer can follow it — the
/// organisation's id when the layout names an id column, otherwise the control's text. Never a row: a row moves.
///
/// **A data contract**: stored with the item, compared with the next version's. A derived key is folded to lower
/// case on top of [`text::normalize`] and the digest is not, so a control whose only change is a capital keeps its
/// key and changes its digest — paired as changed, its answer carried to be confirmed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemKey(String);

const FROM_ID: &str = "id:";
const FROM_TEXT: &str = "text:";

impl ItemKey {
    pub const MAX_ID: usize = 200;

    /// A key as stored, refused as a defect unless one of the two derivations wrote it.
    pub fn stored(value: &str) -> Result<ItemKey, Defect> {
        if !value.starts_with(FROM_ID) && !value.starts_with(FROM_TEXT) {
            return Err(Defect(format!("An item key is derived by fromId or fromControl, not written: {value}")));
        }
        Ok(ItemKey(value.to_owned()))
    }

    /// `ItemKey.fromId`: refused blank, or past [`MAX_ID`](ItemKey::MAX_ID) characters.
    pub fn from_id(id: Option<&str>) -> Result<ItemKey, Refused> {
        let normalized = text::normalize(id);
        if normalized.is_empty() {
            return Err(refused("The item's id is blank."));
        }
        if java::utf16_len(&normalized) > ItemKey::MAX_ID {
            return Err(refused(format!("The item's id is longer than {} characters.", ItemKey::MAX_ID)));
        }
        Ok(ItemKey(format!("{FROM_ID}{normalized}")))
    }

    /// `ItemKey.fromControl`: the SHA-256 of the control normalised and lowered; a blank control is not an item.
    pub fn from_control(control: Option<&str>) -> Result<ItemKey, Refused> {
        let normalized = text::normalize(control);
        if normalized.is_empty() {
            return Err(refused("The item's control is blank."));
        }
        Ok(ItemKey(format!("{FROM_TEXT}{}", sha256_hex(&java::to_lower_root(&normalized)))))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

/// What proof a line asks for before its checklist can be submitted, and for how long a proof holds. Part of the
/// item's content digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceRequirement {
    pub kind: EvidenceKind,
    pub validity_months: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    None,
    LinkOrFile,
    File,
}

impl EvidenceKind {
    pub const ALL: [EvidenceKind; 3] = [EvidenceKind::None, EvidenceKind::LinkOrFile, EvidenceKind::File];

    pub fn wire_name(self) -> &'static str {
        match self {
            EvidenceKind::None => "none",
            EvidenceKind::LinkOrFile => "link_or_file",
            EvidenceKind::File => "file",
        }
    }

    /// A kind as a request names it, refused in words.
    pub fn parse(value: Option<&str>) -> Result<EvidenceKind, Refused> {
        let wanted = java::to_lower_root(java::strip(value.unwrap_or("")));
        EvidenceKind::ALL.into_iter().find(|kind| kind.wire_name() == wanted).ok_or_else(|| {
            refused(format!(
                "A line's evidence requirement is one of none, link_or_file, file{}",
                if wanted.is_empty() {
                    "; none was given.".to_owned()
                } else {
                    format!("; \"{}\" is not one.", clip(Some(&wanted), 40).unwrap_or(""))
                }
            ))
        })
    }
}

impl EvidenceRequirement {
    /// Ten years: a proof said to hold longer is one nobody means to renew.
    pub const MAX_VALIDITY_MONTHS: i32 = 120;
    pub const NONE: EvidenceRequirement = EvidenceRequirement { kind: EvidenceKind::None, validity_months: None };

    pub fn new(kind: EvidenceKind, validity_months: Option<i32>) -> Result<EvidenceRequirement, Refused> {
        if kind == EvidenceKind::None && validity_months.is_some() {
            return Err(refused("A validity applies to a proof, and this line asks for none."));
        }
        if let Some(months) =
            validity_months.filter(|months| !(1..=EvidenceRequirement::MAX_VALIDITY_MONTHS).contains(months))
        {
            return Err(refused(format!(
                "A proof's validity is between 1 and {} months; {months} is not.",
                EvidenceRequirement::MAX_VALIDITY_MONTHS
            )));
        }
        Ok(EvidenceRequirement { kind, validity_months })
    }

    /// The form the content digest reads: the kind, and the validity when there is one.
    pub fn canonical(&self) -> String {
        match self.validity_months {
            None => self.kind.wire_name().to_owned(),
            Some(months) => format!("{}/{months}", self.kind.wire_name()),
        }
    }
}

/// One line of a template version: the template's words, as imported and shown as written, and what this version
/// asks of the line. The contact is a role, not an account, and stays out of the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecklistItem {
    pub key: ItemKey,
    /// The item's place among the version's items, from 1, in the sheet's order.
    pub position: i32,
    pub domain: String,
    pub objective: String,
    pub control: String,
    pub contact: String,
    pub kpi: String,
    /// The sheet row the item was read from, which the renderer writes into.
    pub row: i32,
    pub evidence: EvidenceRequirement,
    /// The canonical form of the rule bound to the line, when one is.
    pub bound_rule: Option<String>,
}

/// Written into the digest first, so that a change of what it covers is a new prefix, never a collision.
const DIGEST_FORM: &str = "vectispire/checklist-item/1";

/// The words of a line as a caller hands them in, before they are held to their ceilings.
#[derive(Debug, Clone, Default)]
pub struct ItemWords<'a> {
    pub domain: Option<&'a str>,
    pub objective: Option<&'a str>,
    pub control: Option<&'a str>,
    pub contact: Option<&'a str>,
    pub kpi: Option<&'a str>,
}

impl ChecklistItem {
    /// Ceilings on the template's words, refused rather than clipped: a control cut short asks something else.
    pub const MAX_LABEL: usize = 1_000;
    pub const MAX_CONTROL: usize = 4_000;
    pub const MAX_CONTACT: usize = 255;
    pub const MAX_KPI: usize = 4_000;

    pub fn new(
        key: ItemKey,
        position: i32,
        words: &ItemWords<'_>,
        row: i32,
        evidence: EvidenceRequirement,
        bound_rule: Option<String>,
    ) -> Result<ChecklistItem, Failure> {
        if position < 1 {
            return Err(Defect(format!("An item's position counts from 1: {position}")).into());
        }
        if row < 1 {
            return Err(Defect(format!("A sheet row counts from 1: {row}")).into());
        }
        let domain = bounded(words.domain, ChecklistItem::MAX_LABEL, "domain", row)?;
        let objective = bounded(words.objective, ChecklistItem::MAX_LABEL, "objective", row)?;
        let control = bounded(words.control, ChecklistItem::MAX_CONTROL, "control", row)?;
        let contact = bounded(words.contact, ChecklistItem::MAX_CONTACT, "contact", row)?;
        let kpi = bounded(words.kpi, ChecklistItem::MAX_KPI, "KPI", row)?;
        if text::normalize(Some(&control)).is_empty() {
            return Err(refused(format!("Row {row} has no control: a line that asks nothing is not an item.")).into());
        }
        Ok(ChecklistItem { key, position, domain, objective, control, contact, kpi, row, evidence, bound_rule })
    }

    /// SHA-256 over what the line asks, NUL-separated: the normalised domain, objective, control and KPI, the
    /// evidence requirement and the bound rule. Same key and same digest is *unchanged*, and an answer crosses as
    /// current; any other difference makes a carried answer wait for a person's confirmation.
    pub fn content_digest(&self) -> String {
        let domain = text::normalize(Some(&self.domain));
        let objective = text::normalize(Some(&self.objective));
        let control = text::normalize(Some(&self.control));
        let kpi = text::normalize(Some(&self.kpi));
        let evidence = self.evidence.canonical();
        let rule = self.bound_rule.as_ref().map_or_else(|| "unbound".to_owned(), |rule| format!("rule:{rule}"));
        sha256_fields(&[
            Some(DIGEST_FORM),
            Some(&domain),
            Some(&objective),
            Some(&control),
            Some(&kpi),
            Some(&evidence),
            Some(&rule),
        ])
    }

    pub fn with_key(&self, replacement: ItemKey) -> ChecklistItem {
        ChecklistItem { key: replacement, ..self.clone() }
    }
}

/// Kept as written, a blank read as empty; refused, never clipped, past its ceiling.
fn bounded(value: Option<&str>, max: usize, what: &str, row: i32) -> Result<String, Refused> {
    let kept = java::strip(value.unwrap_or(""));
    if java::utf16_len(kept) > max {
        return Err(refused(format!("Row {row}: the {what} is longer than {max} characters.")));
    }
    Ok(kept.to_owned())
}

/// The columns of a checklist sheet a layout can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChecklistColumn {
    /// The organisation's own identifier of a line, when the template has one: it becomes the key.
    Id,
    Domain,
    Objective,
    Control,
    Contact,
    Kpi,
    Answer,
    /// Required: a negative answer needs its comment, and the renderer needs a cell to write it in.
    Comment,
}

impl ChecklistColumn {
    pub const ALL: [ChecklistColumn; 8] = [
        ChecklistColumn::Id,
        ChecklistColumn::Domain,
        ChecklistColumn::Objective,
        ChecklistColumn::Control,
        ChecklistColumn::Contact,
        ChecklistColumn::Kpi,
        ChecklistColumn::Answer,
        ChecklistColumn::Comment,
    ];

    /// Without it no item can be read or no answer written.
    pub fn required(self) -> bool {
        matches!(self, ChecklistColumn::Control | ChecklistColumn::Answer | ChecklistColumn::Comment)
    }

    pub fn wire_name(self) -> &'static str {
        match self {
            ChecklistColumn::Id => "id",
            ChecklistColumn::Domain => "domain",
            ChecklistColumn::Objective => "objective",
            ChecklistColumn::Control => "control",
            ChecklistColumn::Contact => "contact",
            ChecklistColumn::Kpi => "kpi",
            ChecklistColumn::Answer => "answer",
            ChecklistColumn::Comment => "comment",
        }
    }
}
