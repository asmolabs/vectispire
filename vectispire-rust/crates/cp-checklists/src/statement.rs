//! `ChecklistStatement`: one revision of a project's checklist as a document states it — `checklist.json`, and what
//! the renderer writes into the workbook (decision 0032 §10).
//!
//! **A contract, not a view**: the input a report plugin receives. Its field names are the document's, a field is
//! added — never renamed, never repurposed — with [`FORM`] raised when a reader could misread the old shape. It
//! holds only what was recorded; a value Java holds as `null` is `None` here and written `null`, and where Java's
//! renderer concatenates one it reads `null`, as Java's string concatenation spells it.

use serde_json::{Value, json};
use vectispire_domain::instant::Instant;
use vectispire_domain::wire::write_string;

use crate::answer::AnswerAuthor;
use crate::{Defect, Failure};

/// 2 since the scans answer the lines they measure: an answer names its author's kind, and a line's history may
/// hold Vectispire withdrawing its own answer.
pub const FORM: i32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecklistStatement {
    pub form: i32,
    pub status: String,
    /// The signed-off revision's statement, rendered and signed inside its sign-off.
    pub signed: bool,
    pub project: Project,
    pub revision: i32,
    pub template: Template,
    /// What the header cells receive; the date is the sign-off instant, absent until there is one.
    pub header: Header,
    pub opened: Act,
    pub submitted: Option<Act>,
    pub signed_off: Option<Act>,
    pub four_eyes_required: Option<bool>,
    /// Absent when the build states none, not guessed.
    pub product_version: Option<String>,
    pub produced_at: Instant,
    pub lines: Vec<Line>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub slug: String,
    pub name: String,
    pub version: i32,
    pub label: Option<String>,
    /// The SHA-256 of the workbook the organisation delivered, which the document's workbook is that file patched.
    pub source_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub product: String,
    pub author: Option<String>,
    pub date: Option<Instant>,
}

/// Who did something to the revision, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Act {
    pub by: String,
    pub at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub item_id: i64,
    pub key: String,
    pub position: i32,
    /// The line's row in the checklist sheet, where its answer and comment are written.
    pub row: i32,
    pub domain: String,
    pub objective: String,
    pub control: String,
    pub contact: String,
    pub kpi: String,
    pub content_digest: String,
    pub evidence_required: String,
    pub evidence_validity_months: Option<i32>,
    pub answer: Option<Answer>,
    pub history: Vec<Answer>,
    pub measurement: Option<Measured>,
    pub reconciliation: Option<String>,
    pub evidence: Vec<Proof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub id: i64,
    pub value: String,
    pub word: String,
    pub comment: Option<String>,
    pub answered_by: String,
    pub answered_by_kind: Option<String>,
    pub answered_at: Option<Instant>,
    pub carried_from: Option<i64>,
    pub carried_by: Option<String>,
    pub carried_at: Option<Instant>,
    pub needs_confirmation: bool,
    pub withdrawn: bool,
}

impl Answer {
    /// Whether Vectispire gave it — by the kind; a kind this version does not know is a person's.
    pub fn automatic(&self) -> bool {
        AnswerAuthor::is_system(self.answered_by_kind.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measured {
    pub purpose: String,
    pub rule_kind: String,
    pub rule_digest: String,
    pub rule: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub as_of: Option<Instant>,
    pub computed_at: Option<Instant>,
    pub summary: String,
    pub evidence_digest: String,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub id: i64,
    pub kind: String,
    pub link: Option<String>,
    pub file_name: Option<String>,
    pub media_type: Option<String>,
    pub size: Option<i64>,
    pub sha256: Option<String>,
    pub performed_on: Option<LocalDate>,
    pub valid_until: Option<LocalDate>,
    pub added_by: Option<String>,
    pub added_at: Option<Instant>,
    pub withdrawn_by: Option<String>,
    pub withdrawn_at: Option<Instant>,
}

/// `LocalDate`, as `toString` and Jackson's `LocalDateSerializer` write it for the years 0000 to 9999.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalDate {
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

impl std::fmt::Display for LocalDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// `Instant.toString`; Java's own spelling beyond the year 9999 is never reached by a statement.
pub(crate) fn instant_text(instant: Instant) -> String {
    instant.to_java_string().unwrap_or_default()
}

/// What Java's `+` writes for a value that may be `null`.
pub(crate) fn or_null(value: Option<&str>) -> &str {
    value.unwrap_or("null")
}

impl ChecklistStatement {
    /// The record's check: a signed statement names its sign-off and is dated by it.
    pub fn check(self) -> Result<ChecklistStatement, Failure> {
        if self.signed && (self.signed_off.is_none() || self.header.date.is_none()) {
            return Err(Defect("A signed statement names its sign-off and is dated by it.".to_owned()).into());
        }
        Ok(self)
    }

    /// `withNames`: every person the statement names renamed — the header's author, the acts, each answer's author
    /// and carrier, each proof's adder and withdrawer. An answer Vectispire gave keeps its name: it is no account's.
    pub fn with_names(&self, name: impl Fn(&str) -> String) -> ChecklistStatement {
        let act = |given: &Act| Act { by: name(&given.by), at: given.at };
        let answer = |given: &Answer| Answer {
            answered_by: if given.automatic() { given.answered_by.clone() } else { name(&given.answered_by) },
            carried_by: given.carried_by.as_deref().map(&name),
            ..given.clone()
        };
        let lines = self
            .lines
            .iter()
            .map(|line| Line {
                answer: line.answer.as_ref().map(answer),
                history: line.history.iter().map(answer).collect(),
                evidence: line
                    .evidence
                    .iter()
                    .map(|proof| Proof {
                        added_by: proof.added_by.as_deref().map(&name),
                        withdrawn_by: proof.withdrawn_by.as_deref().map(&name),
                        ..proof.clone()
                    })
                    .collect(),
                ..line.clone()
            })
            .collect();
        ChecklistStatement {
            header: Header { author: self.header.author.as_deref().map(&name), ..self.header.clone() },
            opened: act(&self.opened),
            submitted: self.submitted.as_ref().map(act),
            signed_off: self.signed_off.as_ref().map(act),
            lines,
            ..self.clone()
        }
    }

    /// The statement as Jackson writes it, members in the record's `@JsonPropertyOrder`, nulls written, instants
    /// as `ISO_INSTANT` text.
    pub fn to_value(&self) -> Value {
        let instant = |at: Option<Instant>| at.map_or(Value::Null, |at| Value::String(instant_text(at)));
        let date = |on: Option<LocalDate>| on.map_or(Value::Null, |on| Value::String(on.to_string()));
        let act = |act: &Act| json!({ "by": act.by, "at": instant_text(act.at) });
        let answer = |answer: &Answer| {
            json!({
                "id": answer.id,
                "value": answer.value,
                "word": answer.word,
                "comment": answer.comment,
                "answeredBy": answer.answered_by,
                "answeredByKind": answer.answered_by_kind,
                "answeredAt": instant(answer.answered_at),
                "carriedFrom": answer.carried_from,
                "carriedBy": answer.carried_by,
                "carriedAt": instant(answer.carried_at),
                "needsConfirmation": answer.needs_confirmation,
                "withdrawn": answer.withdrawn,
            })
        };
        let lines: Vec<Value> = self
            .lines
            .iter()
            .map(|line| {
                json!({
                    "itemId": line.item_id,
                    "key": line.key,
                    "position": line.position,
                    "row": line.row,
                    "domain": line.domain,
                    "objective": line.objective,
                    "control": line.control,
                    "contact": line.contact,
                    "kpi": line.kpi,
                    "contentDigest": line.content_digest,
                    "evidenceRequired": line.evidence_required,
                    "evidenceValidityMonths": line.evidence_validity_months,
                    "answer": line.answer.as_ref().map_or(Value::Null, answer),
                    "history": line.history.iter().map(answer).collect::<Vec<_>>(),
                    "measurement": line.measurement.as_ref().map_or(Value::Null, |measured| json!({
                        "purpose": measured.purpose,
                        "ruleKind": measured.rule_kind,
                        "ruleDigest": measured.rule_digest,
                        "rule": measured.rule,
                        "outcome": measured.outcome,
                        "reason": measured.reason,
                        "asOf": instant(measured.as_of),
                        "computedAt": instant(measured.computed_at),
                        "summary": measured.summary,
                        "evidenceDigest": measured.evidence_digest,
                        "evidence": measured.evidence,
                    })),
                    "reconciliation": line.reconciliation,
                    "evidence": line.evidence.iter().map(|proof| json!({
                        "id": proof.id,
                        "kind": proof.kind,
                        "link": proof.link,
                        "fileName": proof.file_name,
                        "mediaType": proof.media_type,
                        "size": proof.size,
                        "sha256": proof.sha256,
                        "performedOn": date(proof.performed_on),
                        "validUntil": date(proof.valid_until),
                        "addedBy": proof.added_by,
                        "addedAt": instant(proof.added_at),
                        "withdrawnBy": proof.withdrawn_by,
                        "withdrawnAt": instant(proof.withdrawn_at),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        json!({
            "form": self.form,
            "status": self.status,
            "signed": self.signed,
            "project": { "id": self.project.id, "name": self.project.name },
            "revision": self.revision,
            "template": {
                "slug": self.template.slug,
                "name": self.template.name,
                "version": self.template.version,
                "label": self.template.label,
                "sourceSha256": self.template.source_sha256,
            },
            "header": { "product": self.header.product, "author": self.header.author, "date": instant(self.header.date) },
            "opened": act(&self.opened),
            "submitted": self.submitted.as_ref().map_or(Value::Null, act),
            "signedOff": self.signed_off.as_ref().map_or(Value::Null, act),
            "fourEyesRequired": self.four_eyes_required,
            "productVersion": self.product_version,
            "producedAt": instant_text(self.produced_at),
            "lines": lines,
        })
    }

    /// `checklist.json`: `writerWithDefaultPrettyPrinter().writeValueAsBytes(statement)`.
    pub fn to_json(&self) -> Vec<u8> {
        let mut out = String::new();
        pretty(&mut out, &self.to_value(), 0);
        out.into_bytes()
    }
}

/// Jackson 2's `DefaultPrettyPrinter`: an object's members one per line, indented two spaces per object level,
/// `" : "` after a name; an array on one line, `[ a, b ]`, its objects opening where it does; `{ }` and `[ ]` empty.
fn pretty(out: &mut String, value: &Value, level: usize) {
    match value {
        Value::Object(members) if members.is_empty() => out.push_str("{ }"),
        Value::Object(members) => {
            out.push('{');
            for (index, (name, member)) in members.iter().enumerate() {
                out.push_str(if index == 0 { "\n" } else { ",\n" });
                out.push_str(&"  ".repeat(level.saturating_add(1)));
                write_string(out, name);
                out.push_str(" : ");
                pretty(out, member, level.saturating_add(1));
            }
            out.push('\n');
            out.push_str(&"  ".repeat(level));
            out.push('}');
        }
        Value::Array(elements) if elements.is_empty() => out.push_str("[ ]"),
        Value::Array(elements) => {
            out.push_str("[ ");
            for (index, element) in elements.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                pretty(out, element, level);
            }
            out.push_str(" ]");
        }
        Value::String(text) => write_string(out, text),
        other => out.push_str(&other.to_string()),
    }
}
