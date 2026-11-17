//! `StoredForms`: the JSON a template version's row keeps — its confirmed layout, its pairs made by hand, the
//! accounts that wrote the draft — and a bound rule shown in the API's shape (`ChecklistRuleForm`).
//!
//! **Written as the Java side's `ObjectMapper` writes the records**: the components in their declared order, `null`
//! written, nothing indented. These columns are read back by Java after a switch-over, and the replay compares the
//! rows a request changed byte for byte, so the text is the contract, not only what it means.
//!
//! A row that does not read back is a defect of the row, never the caller's input ([`Defect`]).

use serde_json::Value;
use vectispire_domain::checklists::Defect;
use vectispire_domain::wire::write_string;

use crate::answer::AnswerWords;
use crate::cell::{CellRef, Field, HeaderCell};
use crate::item::{ChecklistColumn, ItemKey};
use crate::layout::ChecklistLayout;
use crate::pairing::ManualPair;
use crate::rule::{ChecklistRule, Thresholds};

/// Written into every stored layout; a new shape is a new number, and the old one still reads.
const LAYOUT_FORM: i64 = 1;

/// Somebody who wrote a draft: the account, and the name it had when it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftAuthor {
    pub account_id: i64,
    pub username: String,
}

/// JSON text built in a record's order.
#[derive(Debug, Default)]
pub(crate) struct Writer;

impl Writer {
    pub(crate) fn text(value: &str) -> String {
        let mut out = String::new();
        write_string(&mut out, value);
        out
    }

    pub(crate) fn opt_text(value: Option<&str>) -> String {
        value.map_or_else(|| "null".to_owned(), Writer::text)
    }

    /// `{"a":…,"b":…}` from members already written.
    pub(crate) fn object<'a>(members: impl IntoIterator<Item = (&'a str, String)>) -> String {
        let mut out = String::from("{");
        for (index, (name, value)) in members.into_iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            write_string(&mut out, name);
            out.push(':');
            out.push_str(&value);
        }
        out.push('}');
        out
    }

    pub(crate) fn array(values: impl IntoIterator<Item = String>) -> String {
        let mut out = String::from("[");
        for (index, value) in values.into_iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&value);
        }
        out.push(']');
        out
    }
}

// ------------------------------------------------------------------ the layout

/// `StoredForms.layout(ChecklistLayout)`: `StoredLayout`'s components in order, the columns and the header in the
/// enums' order (the `EnumMap`s the layout holds).
pub fn layout_json(layout: &ChecklistLayout) -> String {
    let columns =
        Writer::object(layout.columns().iter().map(|(column, letters)| (column.wire_name(), Writer::text(letters))));
    let header = Writer::object(layout.header().iter().map(|(field, cell)| {
        (
            field.wire_name(),
            Writer::object([
                ("label", Writer::text(&cell.label().to_string())),
                ("value", Writer::text(&cell.value().to_string())),
            ]),
        )
    }));
    Writer::object([
        ("form", LAYOUT_FORM.to_string()),
        ("sheet", Writer::text(layout.sheet())),
        ("columns", columns),
        ("firstItemRow", layout.first_item_row().to_string()),
        ("lastItemRow", layout.last_item_row().to_string()),
        ("header", header),
        ("yes", Writer::text(layout.answers().yes())),
        ("no", Writer::text(layout.answers().no())),
        ("notApplicable", Writer::opt_text(layout.answers().not_applicable())),
    ])
}

/// `StoredForms.layout(String)`.
pub fn layout_of(stored: &str) -> Result<ChecklistLayout, Defect> {
    let unreadable = || Defect("A template version's stored form is unreadable.".to_owned());
    let form: Value = serde_json::from_str(stored).map_err(|_| unreadable())?;
    let number = form.get("form").and_then(Value::as_i64).unwrap_or(0);
    if number != LAYOUT_FORM {
        return Err(Defect(format!("A stored layout is in form {number}, which this version cannot read.")));
    }
    let text = |name: &str| form.get(name).and_then(Value::as_str);
    let int = |name: &str| {
        form.get(name).and_then(Value::as_i64).and_then(|value| i32::try_from(value).ok()).ok_or_else(unreadable)
    };
    let mut columns = Vec::new();
    for (name, letters) in form.get("columns").and_then(Value::as_object).ok_or_else(unreadable)? {
        let column = ChecklistColumn::ALL
            .into_iter()
            .find(|column| column.wire_name().eq_ignore_ascii_case(name))
            .ok_or_else(|| Defect(format!("A stored layout names the column \"{name}\".")))?;
        columns.push((column, letters.as_str()));
    }
    let mut header = Vec::new();
    for (name, cell) in form.get("header").and_then(Value::as_object).ok_or_else(unreadable)? {
        let field = Field::ALL
            .into_iter()
            .find(|field| field.wire_name().eq_ignore_ascii_case(name))
            .ok_or_else(|| Defect(format!("A stored layout names the header entry \"{name}\".")))?;
        let label = stored_cell(cell.get("label").and_then(Value::as_str))?;
        let value = stored_cell(cell.get("value").and_then(Value::as_str))?;
        header.push((field, HeaderCell::new(label, value).map_err(|refused| Defect(refused.0))?));
    }
    let answers =
        AnswerWords::new(text("yes"), text("no"), text("notApplicable")).map_err(|refused| Defect(refused.0))?;
    ChecklistLayout::new(text("sheet"), &columns, int("firstItemRow")?, int("lastItemRow")?, &header, answers)
        .map_err(|refused| Defect(refused.0))
}

fn stored_cell(reference: Option<&str>) -> Result<CellRef, Defect> {
    CellRef::parse(reference)
        .ok_or_else(|| Defect(format!("A stored layout names the cell \"{}\".", reference.unwrap_or("null"))))
}

/// `ChecklistLayoutForm.of(layout)`: the layout as the API shows it.
pub fn layout_form_json(layout: &ChecklistLayout) -> String {
    let columns =
        Writer::object(layout.columns().iter().map(|(column, letters)| (column.wire_name(), Writer::text(letters))));
    let header = Writer::object(layout.header().iter().map(|(field, cell)| {
        (
            field.wire_name(),
            Writer::object([
                ("label", Writer::text(&cell.label().to_string())),
                ("value", Writer::text(&cell.value().to_string())),
            ]),
        )
    }));
    Writer::object([
        ("sheet", Writer::text(layout.sheet())),
        ("columns", columns),
        ("firstItemRow", layout.first_item_row().to_string()),
        ("lastItemRow", layout.last_item_row().to_string()),
        ("header", header),
        (
            "answers",
            Writer::object([
                ("yes", Writer::text(layout.answers().yes())),
                ("no", Writer::text(layout.answers().no())),
                ("notApplicable", Writer::opt_text(layout.answers().not_applicable())),
            ]),
        ),
    ])
}

// ------------------------------------------------------------------ pairs and authors

/// `StoredForms.pairs(List)`: `None` for none, which is how a draft without pairs stores them.
pub fn pairs_json(pairs: &[ManualPair]) -> Option<String> {
    if pairs.is_empty() {
        return None;
    }
    Some(Writer::array(pairs.iter().map(|pair| {
        Writer::object([("added", Writer::text(pair.added.value())), ("removed", Writer::text(pair.removed.value()))])
    })))
}

/// `StoredForms.pairs(String)`.
pub fn pairs_of(stored: Option<&str>) -> Result<Vec<ManualPair>, Defect> {
    let Some(stored) = stored else { return Ok(Vec::new()) };
    let unreadable = || Defect("A template version's stored form is unreadable.".to_owned());
    let pairs: Vec<Value> = serde_json::from_str(stored).map_err(|_| unreadable())?;
    pairs
        .iter()
        .map(|pair| {
            let key = |name: &str| ItemKey::stored(pair.get(name).and_then(Value::as_str).unwrap_or(""));
            Ok(ManualPair { added: key("added")?, removed: key("removed")? })
        })
        .collect()
}

/// `StoredForms.authors(List)`: `[{"accountId":…,"username":…}]`.
pub fn authors_json(authors: &[DraftAuthor]) -> String {
    Writer::array(authors.iter().map(|author| {
        Writer::object([("accountId", author.account_id.to_string()), ("username", Writer::text(&author.username))])
    }))
}

/// `StoredForms.authors(String)`.
pub fn authors_of(stored: &str) -> Result<Vec<DraftAuthor>, Defect> {
    let unreadable = || Defect("A template version's stored form is unreadable.".to_owned());
    let authors: Vec<Value> = serde_json::from_str(stored).map_err(|_| unreadable())?;
    authors
        .iter()
        .map(|author| {
            Ok(DraftAuthor {
                account_id: author.get("accountId").and_then(Value::as_i64).unwrap_or(0),
                username: author.get("username").and_then(Value::as_str).map(str::to_owned).unwrap_or_default(),
            })
        })
        .collect()
}

// ------------------------------------------------------------------ the rule's form

/// `StoredForms.ruleForm(canonical)`: the stored canonical rule read into `ChecklistRuleForm` and written back — every
/// component of the record in its order, `null` for the ones the kind does not take.
///
/// Built from the rule the canonical text reads as. The text is read through a double (`ChecklistRule::from_canonical`,
/// README "Differences from Java"): a ratio written with trailing zeros — `0.80` — comes back as `0.8`, where Java's
/// `BigDecimal` keeps its scale.
pub fn rule_form_json(canonical: &str) -> Result<String, Defect> {
    let rule = ChecklistRule::from_canonical(canonical).map_err(|failure| match failure {
        crate::Failure::Refused(refused) => Defect(refused.0),
        crate::Failure::Defect(defect) => defect,
    })?;
    Ok(rule_form(&rule))
}

fn rule_form(rule: &ChecklistRule) -> String {
    let null = || "null".to_owned();
    let mut require_schedule = null();
    let mut scopes = null();
    let mut thresholds = null();
    let mut metric = null();
    let mut minimum_ratio = null();
    let mut aggregation = null();
    let mut suite_pattern = null();
    let mut suite_patterns = null();
    let mut minimum_tests = null();
    let mut components = null();
    let mut scope = null();
    let mut minimum_approvals = null();
    let mut window_days = null();
    let mut branch = null();
    let texts = |values: &[String]| Writer::array(values.iter().map(|value| Writer::text(value)));
    match rule {
        ChecklistRule::DependencyAnalysis { require_schedule: schedule, thresholds: stated, .. } => {
            require_schedule = schedule.to_string();
            // The canonical form leaves an empty map out, and Jackson reads the absent member as null.
            if !stated.is_empty() {
                thresholds = thresholds_form(stated);
            }
        }
        ChecklistRule::FindingsThreshold { scopes: stated, thresholds: limits, .. } => {
            scopes = Writer::array(stated.iter().map(|scope| Writer::text(&scope.key())));
            thresholds = thresholds_form(limits);
        }
        ChecklistRule::CoverageThreshold { metric: m, minimum_ratio: ratio, aggregation: a, scope: s, .. } => {
            metric = Writer::text(m.wire_name());
            minimum_ratio = ratio.written();
            aggregation = Writer::text(a.wire_name());
            if let Some(stated) = s {
                // Each list only when the canonical form wrote it.
                let list = |values: &[String]| if values.is_empty() { null() } else { texts(values) };
                scope = Writer::object([("include", list(&stated.include)), ("exclude", list(&stated.exclude))]);
            }
        }
        ChecklistRule::TestSuitePassed { suite_patterns: patterns, minimum_tests: minimum, .. } => {
            match patterns.as_slice() {
                [one] => suite_pattern = Writer::text(one),
                several => suite_patterns = texts(several),
            }
            minimum_tests = minimum.to_string();
        }
        ChecklistRule::ComponentVersions { components: allowed, .. } => {
            components = Writer::array(allowed.iter().map(|component| {
                Writer::object([
                    ("purlPrefix", Writer::text(&component.purl_prefix)),
                    ("versions", texts(&component.versions)),
                ])
            }));
        }
        ChecklistRule::ComponentPresent { purl_prefixes, .. } => {
            components = Writer::array(
                purl_prefixes
                    .iter()
                    .map(|prefix| Writer::object([("purlPrefix", Writer::text(prefix)), ("versions", null())])),
            );
        }
        ChecklistRule::ChangeReview { minimum_approvals: m, window_days: w, minimum_ratio: r, branch: b, .. } => {
            minimum_approvals = m.to_string();
            window_days = w.to_string();
            minimum_ratio = r.written();
            branch = Writer::opt_text(b.as_deref());
        }
    }
    Writer::object([
        ("kind", Writer::text(rule.kind().wire_name())),
        ("maxAgeDays", rule.max_age_days().to_string()),
        ("requireSchedule", require_schedule),
        ("scopes", scopes),
        ("thresholds", thresholds),
        ("metric", metric),
        ("minimumRatio", minimum_ratio),
        ("aggregation", aggregation),
        ("suitePattern", suite_pattern),
        ("suitePatterns", suite_patterns),
        ("minimumTests", minimum_tests),
        ("components", components),
        ("scope", scope),
        ("minimumApprovals", minimum_approvals),
        ("windowDays", window_days),
        ("branch", branch),
    ])
}

/// The thresholds as Jackson reads the canonical object into a `LinkedHashMap`: in the canonical form's order, its
/// keys sorted.
fn thresholds_form(thresholds: &Thresholds) -> String {
    let mut sorted: Vec<_> = thresholds.iter().collect();
    sorted.sort_by_key(|(severity, _)| severity.wire_name());
    Writer::object(sorted.into_iter().map(|(severity, threshold)| {
        (
            severity.wire_name(),
            Writer::object([
                ("maxOpen", threshold.max_open.map_or_else(|| "null".to_owned(), |max| max.to_string())),
                (
                    "minResolvedRatio",
                    threshold.min_resolved_ratio.map_or_else(|| "null".to_owned(), |ratio| ratio.written()),
                ),
            ]),
        )
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_rule_form_names_every_component_and_its_ratio() {
        let coverage = r#"{"aggregation":"per_repository","kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.75}"#;
        let form = rule_form_json(coverage).unwrap();
        assert!(form.starts_with(r#"{"kind":"coverage_threshold","maxAgeDays":30,"requireSchedule":null,"#), "{form}");
        assert!(form.contains(r#""minimumRatio":0.75,"#), "{form}");
        assert!(form.ends_with(r#""minimumApprovals":null,"windowDays":null,"branch":null}"#), "{form}");
        let present = r#"{"components":[{"purlPrefix":"pkg:maven/a/b"}],"kind":"component_present","maxAgeDays":7}"#;
        assert!(
            rule_form_json(present)
                .unwrap()
                .contains(r#""components":[{"purlPrefix":"pkg:maven/a/b","versions":null}]"#)
        );
        assert!(rule_form_json("not json").is_err());
    }

    #[test]
    fn authors_and_pairs_read_back_what_was_written() {
        let authors = vec![DraftAuthor { account_id: 4, username: "lead".into() }];
        let written = authors_json(&authors);
        assert_eq!(written, r#"[{"accountId":4,"username":"lead"}]"#);
        assert_eq!(authors_of(&written).unwrap(), authors);
        assert_eq!(pairs_json(&[]), None, "a draft without pairs stores none");
        assert!(pairs_of(None).unwrap().is_empty());
    }
}
