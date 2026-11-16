//! The checklist workbook against `WorkbookReferenceSetTest`'s answers for `reference/checklists/workbooks.json`: the
//! reader's every refusal and every cell, merge, validation and defined name it reads; the layout proposed from a
//! workbook, a confirmed layout's refusals, the version it reads; the renderer's package **byte for byte**, the
//! trial's, `DocumentZip`'s; `checklist.json` as the control plane's mapper writes it; the date serials.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use vectispire_cp_checklists::answer::AnswerWords;
use vectispire_cp_checklists::cell::{CellRef, CellValue, Field, HeaderCell};
use vectispire_cp_checklists::document_zip::{self, Entry};
use vectispire_cp_checklists::item::ChecklistColumn;
use vectispire_cp_checklists::layout::{ChecklistLayout, LayoutProposal, TemplateVersion};
use vectispire_cp_checklists::renderer::{self, RenderFailure};
use vectispire_cp_checklists::statement::{
    Act, Answer, ChecklistStatement, Header, Line, LocalDate, Measured, Project, Proof, Template,
};
use vectispire_cp_checklists::workbook::{Limits, Workbook};
use vectispire_cp_checklists::{Failure, Refused};
use vectispire_domain::instant::Instant;

const TEN_MB: i64 = 10 * 1024 * 1024;

fn refused(refusal: &Refused) -> Value {
    json!({ "refused": refusal.0 })
}

fn failure(failure: &Failure) -> Value {
    match failure {
        Failure::Refused(refusal) => refused(refusal),
        Failure::Defect(defect) => json!({ "illegal": defect.0 }),
    }
}

fn render_failure(failure: &RenderFailure) -> Value {
    match failure {
        RenderFailure::Refused(refusal) => refused(refusal),
        RenderFailure::Defect(defect) => json!({ "illegal": defect.0 }),
        RenderFailure::WrittenFormula(written) => json!({ "writtenFormula": {
            "message": written.message,
            "cells": written.cells.iter().map(|cell| json!([cell.cell, cell.kind, cell.range])).collect::<Vec<_>>(),
        }}),
    }
}

fn s(value: &Value) -> Option<&str> {
    value.as_str()
}

fn int(value: &Value) -> i32 {
    i32::try_from(value.as_i64().unwrap()).unwrap()
}

fn limits(node: &Value) -> Limits {
    if !node.is_object() {
        return Limits::DEFAULT;
    }
    Limits {
        max_entries: int(&node["maxEntries"]),
        max_entry_bytes: node["maxEntryBytes"].as_i64().unwrap(),
        max_inflated_bytes: node["maxInflatedBytes"].as_i64().unwrap(),
        max_ratio: int(&node["maxRatio"]),
        ratio_grace_bytes: node["ratioGraceBytes"].as_i64().unwrap(),
        max_elements: node["maxElements"].as_i64().unwrap(),
        max_sheets: int(&node["maxSheets"]),
        max_cells: int(&node["maxCells"]),
        max_shared_strings: int(&node["maxSharedStrings"]),
    }
}

fn column(name: &str) -> ChecklistColumn {
    *ChecklistColumn::ALL.iter().find(|column| column.wire_name() == name).unwrap()
}

fn field(name: &str) -> Field {
    *Field::ALL.iter().find(|field| field.wire_name() == name).unwrap()
}

/// Built as the Java test builds it: the header cells, the words, then the layout.
fn layout(input: &Value) -> Result<ChecklistLayout, Refused> {
    let columns: Vec<(ChecklistColumn, Option<&str>)> =
        input["columns"].as_array().unwrap().iter().map(|pair| (column(s(&pair[0]).unwrap()), s(&pair[1]))).collect();
    let mut header: Vec<(Field, HeaderCell)> = Vec::new();
    for cell in input["header"].as_array().unwrap() {
        let parsed = HeaderCell::new(CellRef::parse(s(&cell[1])).unwrap(), CellRef::parse(s(&cell[2])).unwrap())?;
        match header.iter_mut().find(|(existing, _)| *existing == field(s(&cell[0]).unwrap())) {
            Some(slot) => slot.1 = parsed,
            None => header.push((field(s(&cell[0]).unwrap()), parsed)),
        }
    }
    let words = &input["answers"];
    let answers = AnswerWords::new(s(&words[0]), s(&words[1]), s(&words[2]))?;
    ChecklistLayout::new(
        s(&input["sheet"]),
        &columns,
        int(&input["firstItemRow"]),
        int(&input["lastItemRow"]),
        &header,
        answers,
    )
}

fn instant(value: &Value) -> Option<Instant> {
    s(value).map(|text| Instant::parse_java(text).unwrap())
}

fn date(value: &Value) -> Option<LocalDate> {
    s(value).map(|text| {
        let parts: Vec<&str> = text.split('-').collect();
        LocalDate { year: parts[0].parse().unwrap(), month: parts[1].parse().unwrap(), day: parts[2].parse().unwrap() }
    })
}

fn text(value: &Value) -> String {
    s(value).unwrap().to_owned()
}

fn opt(value: &Value) -> Option<String> {
    s(value).map(str::to_owned)
}

fn act(value: &Value) -> Option<Act> {
    value.is_object().then(|| Act { by: text(&value["by"]), at: instant(&value["at"]).unwrap() })
}

fn answer(value: &Value) -> Option<Answer> {
    value.is_object().then(|| Answer {
        id: value["id"].as_i64().unwrap(),
        value: text(&value["value"]),
        word: text(&value["word"]),
        comment: opt(&value["comment"]),
        answered_by: text(&value["answeredBy"]),
        answered_by_kind: opt(&value["answeredByKind"]),
        answered_at: instant(&value["answeredAt"]),
        carried_from: value["carriedFrom"].as_i64(),
        carried_by: opt(&value["carriedBy"]),
        carried_at: instant(&value["carriedAt"]),
        needs_confirmation: value["needsConfirmation"].as_bool().unwrap(),
        withdrawn: value["withdrawn"].as_bool().unwrap(),
    })
}

/// The statement as Jackson reads it into the record; Java's `null` comment is never reached by an input here.
fn statement(input: &Value) -> Result<ChecklistStatement, Failure> {
    let lines = input["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| Line {
            item_id: line["itemId"].as_i64().unwrap(),
            key: text(&line["key"]),
            position: int(&line["position"]),
            row: int(&line["row"]),
            domain: text(&line["domain"]),
            objective: text(&line["objective"]),
            control: text(&line["control"]),
            contact: text(&line["contact"]),
            kpi: text(&line["kpi"]),
            content_digest: text(&line["contentDigest"]),
            evidence_required: text(&line["evidenceRequired"]),
            evidence_validity_months: line["evidenceValidityMonths"]
                .as_i64()
                .map(|months| i32::try_from(months).unwrap()),
            answer: answer(&line["answer"]),
            history: line["history"].as_array().unwrap().iter().filter_map(answer).collect(),
            measurement: line["measurement"].is_object().then(|| {
                let measured = &line["measurement"];
                Measured {
                    purpose: text(&measured["purpose"]),
                    rule_kind: text(&measured["ruleKind"]),
                    rule_digest: text(&measured["ruleDigest"]),
                    rule: opt(&measured["rule"]),
                    outcome: text(&measured["outcome"]),
                    reason: opt(&measured["reason"]),
                    as_of: instant(&measured["asOf"]),
                    computed_at: instant(&measured["computedAt"]),
                    summary: text(&measured["summary"]),
                    evidence_digest: text(&measured["evidenceDigest"]),
                    evidence: opt(&measured["evidence"]),
                }
            }),
            reconciliation: opt(&line["reconciliation"]),
            evidence: line["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .map(|proof| Proof {
                    id: proof["id"].as_i64().unwrap(),
                    kind: text(&proof["kind"]),
                    link: opt(&proof["link"]),
                    file_name: opt(&proof["fileName"]),
                    media_type: opt(&proof["mediaType"]),
                    size: proof["size"].as_i64(),
                    sha256: opt(&proof["sha256"]),
                    performed_on: date(&proof["performedOn"]),
                    valid_until: date(&proof["validUntil"]),
                    added_by: opt(&proof["addedBy"]),
                    added_at: instant(&proof["addedAt"]),
                    withdrawn_by: opt(&proof["withdrawnBy"]),
                    withdrawn_at: instant(&proof["withdrawnAt"]),
                })
                .collect(),
        })
        .collect();
    ChecklistStatement {
        form: int(&input["form"]),
        status: text(&input["status"]),
        signed: input["signed"].as_bool().unwrap(),
        project: Project { id: input["project"]["id"].as_i64().unwrap(), name: text(&input["project"]["name"]) },
        revision: int(&input["revision"]),
        template: Template {
            slug: text(&input["template"]["slug"]),
            name: text(&input["template"]["name"]),
            version: int(&input["template"]["version"]),
            label: opt(&input["template"]["label"]),
            source_sha256: text(&input["template"]["sourceSha256"]),
        },
        header: Header {
            product: text(&input["header"]["product"]),
            author: opt(&input["header"]["author"]),
            date: instant(&input["header"]["date"]),
        },
        opened: act(&input["opened"]).unwrap(),
        submitted: act(&input["submitted"]),
        signed_off: act(&input["signedOff"]),
        four_eyes_required: input["fourEyesRequired"].as_bool(),
        product_version: opt(&input["productVersion"]),
        produced_at: instant(&input["producedAt"]).unwrap(),
        lines,
    }
    .check()
}

fn rendered(bytes: &[u8]) -> Value {
    use sha2::{Digest, Sha256};
    let digest: String = Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect();
    json!({ "sha256": digest, "bytes": STANDARD.encode(bytes) })
}

fn workbook_value(workbook: &Workbook) -> Value {
    let sheets: Vec<Value> = workbook
        .sheets
        .iter()
        .map(|sheet| {
            let cells: Vec<Value> = sheet
                .cells
                .iter()
                .map(|(cell, value)| match value {
                    CellValue::Text(text) => json!([cell.to_string(), "text", text]),
                    CellValue::Number(literal) => json!([cell.to_string(), "number", literal]),
                    CellValue::Bool(value) => json!([cell.to_string(), "bool", value]),
                    CellValue::Error(code) => json!([cell.to_string(), "error", code]),
                    CellValue::Formula { expression, cached } => {
                        json!([cell.to_string(), "formula", expression, cached])
                    }
                })
                .collect();
            let validations: Vec<Value> = sheet
                .validations
                .iter()
                .map(|validation| {
                    json!({
                        "ranges": validation.ranges.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "source": validation.source,
                        "fromExtension": validation.from_extension,
                        "singleColumn": validation.single_column(),
                        "cellCount": validation.cell_count(),
                        "values": workbook.list_values(validation, sheet),
                    })
                })
                .collect();
            json!({
                "name": sheet.name,
                "lastRow": sheet.last_row(),
                "cells": cells,
                "merged": sheet.merged.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "validations": validations,
            })
        })
        .collect();
    json!({
        "sha256": workbook.sha256,
        "sheets": sheets,
        "definedNames": workbook.defined_names.iter().map(|(name, formula)| json!([name, formula])).collect::<Vec<_>>(),
    })
}

fn header_value(header: &std::collections::BTreeMap<Field, HeaderCell>) -> Value {
    let mut node = serde_json::Map::new();
    for (field, cell) in header {
        node.insert(field.wire_name().to_owned(), json!([cell.label().to_string(), cell.value().to_string()]));
    }
    Value::Object(node)
}

fn columns_value(columns: &std::collections::BTreeMap<ChecklistColumn, String>) -> Value {
    let mut node = serde_json::Map::new();
    for (column, letters) in columns {
        node.insert(column.wire_name().to_owned(), json!(letters));
    }
    Value::Object(node)
}

fn proposal_value(proposal: &LayoutProposal) -> Value {
    json!({
        "sheet": proposal.sheet,
        "columnHeaderRow": proposal.column_header_row,
        "firstItemRow": proposal.first_item_row,
        "lastItemRow": proposal.last_item_row,
        "columns": columns_value(&proposal.columns),
        "header": header_value(&proposal.header),
        "answerValues": proposal.answer_values,
    })
}

fn layout_value(layout: &ChecklistLayout) -> Value {
    let mut indexes = serde_json::Map::new();
    for column in ChecklistColumn::ALL {
        if let Some(index) = layout.column(column) {
            indexes.insert(column.wire_name().to_owned(), json!(index));
        }
    }
    json!({
        "sheet": layout.sheet(),
        "columns": columns_value(layout.columns()),
        "indexes": indexes,
        "firstItemRow": layout.first_item_row(),
        "lastItemRow": layout.last_item_row(),
        "header": header_value(layout.header()),
        "offersNotApplicable": layout.offers_not_applicable(),
    })
}

struct Differences(Vec<String>);

impl Differences {
    fn check(&mut self, what: String, java: &Value, rust: &Value) {
        if java != rust {
            let (java, rust) = (java.to_string(), rust.to_string());
            let at = java.bytes().zip(rust.bytes()).position(|(a, b)| a != b).unwrap_or(java.len().min(rust.len()));
            let from = at.saturating_sub(120);
            let window = |text: &str| text.get(from..(at + 200).min(text.len())).unwrap_or(text).to_owned();
            self.0.push(format!("{what} (differs at {at}):\n  java …{}\n  rust …{}", window(&java), window(&rust)));
        }
    }
}

#[test]
fn the_checklist_workbook_answers_as_the_java_side_answers() {
    let inputs = vectispire_testkit::read_json("checklists/workbooks.json");
    let answers = vectispire_testkit::read_json("checklists/workbooks-java-answers.json");
    let mut differences = Differences(Vec::new());
    let mut each = |section: &str, rust: Vec<Value>| {
        let java = answers[section].as_array().unwrap_or_else(|| panic!("no {section} in the answers"));
        assert_eq!(java.len(), rust.len(), "{section}: as many answers as inputs");
        for (index, (java, rust)) in java.iter().zip(&rust).enumerate() {
            let name = inputs[section][index]["name"].as_str().unwrap_or("").to_owned();
            differences.check(format!("{section}[{index}] {name}"), java, rust);
        }
    };

    let files: Vec<Vec<u8>> = inputs["workbooks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| STANDARD.decode(input["xlsx"].as_str().unwrap()).unwrap())
        .collect();

    let workbooks = inputs["workbooks"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&files)
        .map(|(input, file)| {
            let max = input["maxBytes"].as_i64().unwrap_or(TEN_MB);
            match Workbook::read_with(file, max, limits(&input["limits"])) {
                Err(refusal) => failure(&refusal),
                Ok(workbook) => {
                    let mut node = workbook_value(&workbook);
                    node["proposal"] = LayoutProposal::of(&workbook)
                        .map_or_else(|refusal| refused(&refusal), |proposal| proposal_value(&proposal));
                    node
                }
            }
        })
        .collect();
    each("workbooks", workbooks);

    let layouts = inputs["layouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| layout(input).map_or_else(|refusal| refused(&refusal), |layout| layout_value(&layout)))
        .collect();
    each("layouts", layouts);

    let versions = inputs["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let file = &files[usize::try_from(input["workbook"].as_u64().unwrap()).unwrap()];
            let version = (|| -> Result<Value, Failure> {
                let workbook = Workbook::read(file, TEN_MB)?;
                let version = TemplateVersion::read(&workbook, layout(&input["layout"])?)?;
                Ok(version
                    .items
                    .iter()
                    .map(|item| {
                        json!({
                            "key": item.key.value(), "position": item.position, "domain": item.domain,
                            "objective": item.objective, "control": item.control, "contact": item.contact,
                            "kpi": item.kpi, "row": item.row, "contentDigest": item.content_digest(),
                        })
                    })
                    .collect())
            })();
            version.unwrap_or_else(|refusal| failure(&refusal))
        })
        .collect();
    each("versions", versions);

    let renders = inputs["renders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let file = &files[usize::try_from(input["workbook"].as_u64().unwrap()).unwrap()];
            let outcome = (|| -> Result<Vec<u8>, RenderFailure> {
                let layout = layout(&input["layout"])?;
                let statement = statement(&input["statement"])?;
                renderer::render(file, &layout, &statement)
            })();
            outcome.map_or_else(|failure| render_failure(&failure), |bytes| rendered(&bytes))
        })
        .collect();
    each("renders", renders);

    let trials = inputs["trials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let file = &files[usize::try_from(input["workbook"].as_u64().unwrap()).unwrap()];
            let outcome = (|| -> Result<Vec<u8>, RenderFailure> {
                let layout = layout(&input["layout"])?;
                let items = TemplateVersion::read(&Workbook::read(file, TEN_MB)?, layout.clone())?.items;
                renderer::trial(file, &layout, &items)
            })();
            outcome.map_or_else(|failure| render_failure(&failure), |bytes| rendered(&bytes))
        })
        .collect();
    each("trials", trials);

    let statements = inputs["statements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| match statement(input) {
            Err(refusal) => failure(&refusal),
            Ok(statement) => json!({
                "json": String::from_utf8(statement.to_json()).unwrap(),
                "renamed": String::from_utf8(statement.with_names(|name| format!("<{name}>")).to_json()).unwrap(),
            }),
        })
        .collect();
    each("statements", statements);

    let serials = inputs["serials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| json!(renderer::serial(instant(&input["instant"]).unwrap(), input["date1904"].as_bool().unwrap())))
        .collect();
    each("serials", serials);

    let zips = inputs["zips"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let entries: Vec<(String, Entry)> = input
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    let bytes = STANDARD.decode(entry["bytes"].as_str().unwrap()).unwrap();
                    let stored = entry["stored"].as_bool().unwrap();
                    let directory = entry["directory"].as_bool().unwrap();
                    (text(&entry["name"]), Entry { bytes, stored, directory })
                })
                .collect();
            json!(STANDARD.encode(document_zip::of(&entries).unwrap()))
        })
        .collect();
    each("zips", zips);

    assert!(
        differences.0.is_empty(),
        "{} answers differ from Java's:\n{}",
        differences.0.len(),
        differences.0.iter().take(40).cloned().collect::<Vec<_>>().join("\n")
    );
}
