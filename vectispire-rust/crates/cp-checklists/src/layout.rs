//! `ChecklistLayout`, `LayoutProposal`, `TemplateItems` and `TemplateVersion`: where a template's checklist lives in
//! its workbook — proposed from the file's structure, confirmed by a person — and the version it reads from it.

use std::collections::{BTreeMap, HashMap, HashSet};

use vectispire_domain::checklists::Defect;
use vectispire_domain::java;

use crate::answer::AnswerWords;
use crate::cell::{CellRange, CellRef, CellValue, Field, HeaderCell, ListValidation};
use crate::item::{ChecklistColumn, ChecklistItem, EvidenceRequirement, ItemKey, ItemWords};
use crate::workbook::{Sheet, Workbook};
use crate::{Failure, Refused, refused, text};

/// `ChecklistLayout`: the sheet, the column of each field (letters, upper case), the rows holding the items, the
/// header's cells and the answer words, **as the importer confirmed them** — never inferred at use (decision 0032
/// §3): a second guess made at rendering time could land on another column and write answers into the KPI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecklistLayout {
    sheet: String,
    columns: BTreeMap<ChecklistColumn, String>,
    first_item_row: i32,
    last_item_row: i32,
    header: BTreeMap<Field, HeaderCell>,
    answers: AnswerWords,
}

impl ChecklistLayout {
    /// Excel's own limit on a sheet's name.
    pub const MAX_SHEET_NAME: usize = 31;
    /// A checklist longer than this is a catalogue; nobody answers it line by line.
    pub const MAX_ITEM_ROWS: i32 = 5_000;

    /// The constructor's checks in Java's order. `columns` in the order the caller's map hands them, which decides
    /// which of two columns sharing letters a refusal names first; a letter that is none is `None` (`null`).
    pub fn new(
        sheet: Option<&str>,
        columns: &[(ChecklistColumn, Option<&str>)],
        first_item_row: i32,
        last_item_row: i32,
        header: &[(Field, HeaderCell)],
        answers: AnswerWords,
    ) -> Result<ChecklistLayout, Refused> {
        let name = sheet.unwrap_or("");
        if java::is_blank(name) || java::utf16_len(name) > ChecklistLayout::MAX_SHEET_NAME {
            return Err(refused("The layout names no sheet, or one longer than a sheet name can be."));
        }
        let columns = normalized(columns)?;
        for column in ChecklistColumn::ALL {
            if column.required() && !columns.contains_key(&column) {
                return Err(refused(format!("The layout names no {} column.", column.wire_name())));
            }
        }
        if first_item_row < 1 || last_item_row > CellRef::MAX_ROW || first_item_row > last_item_row {
            return Err(refused(format!(
                "The item rows run from {first_item_row} to {last_item_row}, which is no range of a sheet."
            )));
        }
        // Both rows are within the grid here, so the span is exact in an `i64`.
        let span = i64::from(last_item_row).saturating_sub(i64::from(first_item_row)).saturating_add(1);
        if span > i64::from(ChecklistLayout::MAX_ITEM_ROWS) {
            return Err(refused(format!("The item rows span more than {} rows.", ChecklistLayout::MAX_ITEM_ROWS)));
        }
        let fields: BTreeMap<Field, HeaderCell> = header.iter().copied().collect();
        let mut taken: HashMap<CellRef, Field> = HashMap::new();
        for (field, cell) in &fields {
            for written in [cell.label(), cell.value()] {
                // A header cell inside the item block would be overwritten by an answer, or overwrite one.
                if (first_item_row..=last_item_row).contains(&written.row()) {
                    return Err(refused(format!(
                        "The {} header cell {written} lies among the item rows.",
                        field.wire_name()
                    )));
                }
            }
            if let Some(other) = taken.get(&cell.value()) {
                return Err(refused(format!(
                    "The {} and the {} are both written into {}.",
                    other.wire_name(),
                    field.wire_name(),
                    cell.value()
                )));
            }
            taken.insert(cell.value(), *field);
        }
        Ok(ChecklistLayout { sheet: name.to_owned(), columns, first_item_row, last_item_row, header: fields, answers })
    }

    pub fn sheet(&self) -> &str {
        &self.sheet
    }

    /// Each named column's letters, upper case, in the columns' order.
    pub fn columns(&self) -> &BTreeMap<ChecklistColumn, String> {
        &self.columns
    }

    pub fn first_item_row(&self) -> i32 {
        self.first_item_row
    }

    pub fn last_item_row(&self) -> i32 {
        self.last_item_row
    }

    /// The header entries the template has, in the fields' order.
    pub fn header(&self) -> &BTreeMap<Field, HeaderCell> {
        &self.header
    }

    pub fn answers(&self) -> &AnswerWords {
        &self.answers
    }

    /// The index of a named column, from 1; `None` when the template has no such column.
    pub fn column(&self, column: ChecklistColumn) -> Option<i32> {
        self.columns.get(&column).and_then(|letters| CellRef::column_of(Some(letters)))
    }

    pub fn offers_not_applicable(&self) -> bool {
        self.answers.offers_not_applicable()
    }
}

fn normalized(given: &[(ChecklistColumn, Option<&str>)]) -> Result<BTreeMap<ChecklistColumn, String>, Refused> {
    let mut columns = BTreeMap::new();
    let mut taken: HashMap<i32, ChecklistColumn> = HashMap::new();
    for (column, letters) in given {
        let index = CellRef::column_of(*letters).ok_or_else(|| {
            refused(format!(
                "The {} column is \"{}\", which is no column's letters.",
                column.wire_name(),
                letters.unwrap_or("null")
            ))
        })?;
        if let Some(other) = taken.get(&index) {
            return Err(refused(format!(
                "The {} and the {} are both column {}.",
                other.wire_name(),
                column.wire_name(),
                CellRef::letters(index)
            )));
        }
        taken.insert(index, *column);
        columns.insert(*column, CellRef::letters(index));
    }
    Ok(columns)
}

/// `LayoutProposal`: where the reader thinks the checklist lives — to be confirmed or corrected by the importer,
/// never used as it stands (decision 0032 §3, step 1). **From the file's structure, never from its words**: the
/// answer column is the one a single-column list validation covers; the column header row the widest row of text
/// cells followed by a run of filled rows; the columns the header row's, by their place; the header cells the
/// label-and-value pairs above it. Anything it cannot find is left out rather than guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutProposal {
    pub sheet: String,
    pub column_header_row: Option<i32>,
    pub first_item_row: Option<i32>,
    pub last_item_row: Option<i32>,
    pub columns: BTreeMap<ChecklistColumn, String>,
    pub header: BTreeMap<Field, HeaderCell>,
    pub answer_values: Vec<String>,
}

/// A header row is at least this many labelled columns; fewer is a label and its value.
const MIN_HEADER_COLUMNS: usize = 3;
/// The same three, as a merged cell's width: a title across them is a heading, not a label.
const MIN_TITLE_WIDTH: i32 = 3;

/// A column header row, its columns, and the run of filled rows below it.
struct Block {
    header_row: i32,
    columns: Vec<i32>,
    first_row: i32,
    last_row: i32,
}

impl Block {
    fn length(&self) -> i32 {
        self.last_row.saturating_sub(self.first_row).saturating_add(1)
    }
}

impl LayoutProposal {
    /// `confirm`: the layout this proposal becomes once the importer has mapped the answer words.
    pub fn confirm(&self, answers: AnswerWords) -> Result<ChecklistLayout, Refused> {
        let (Some(first), Some(last)) = (self.first_item_row, self.last_item_row) else {
            return Err(refused(format!("No item rows were found on sheet \"{}\"; name them.", self.sheet)));
        };
        let columns: Vec<(ChecklistColumn, Option<&str>)> =
            self.columns.iter().map(|(column, letters)| (*column, Some(letters.as_str()))).collect();
        let header: Vec<(Field, HeaderCell)> = self.header.iter().map(|(field, cell)| (*field, *cell)).collect();
        ChecklistLayout::new(Some(&self.sheet), &columns, first, last, &header, answers)
    }

    /// `LayoutProposal.of`: a layout proposed for a workbook from its structure alone. Refused only where Java's
    /// grid check is reached past the last row of a sheet.
    pub fn of(workbook: &Workbook) -> Result<LayoutProposal, Refused> {
        let mut validated: Option<(&Sheet, &ListValidation)> = None;
        for sheet in &workbook.sheets {
            for validation in sheet.validations.iter().filter(|validation| validation.single_column()) {
                // `Stream.max` keeps the first of equals.
                if validated.is_none_or(|(_, best)| validation.cell_count() > best.cell_count()) {
                    validated = Some((sheet, validation));
                }
            }
        }
        if let Some((sheet, answers)) = validated {
            let answer_column = answers.ranges.first().map_or(0, |range| range.first().column());
            let block = best_block(sheet, Some(answers), answer_column)?;
            return propose(sheet, block, Some(answer_column), workbook.list_values(answers, sheet));
        }
        let Some(mut best) = workbook.sheets.first() else {
            return Err(refused("The workbook holds no worksheet."));
        };
        let mut best_found: Option<Block> = None;
        for sheet in &workbook.sheets {
            if let Some(block) = best_block(sheet, None, 0)?
                && best_found.as_ref().is_none_or(|found| block.length() > found.length())
            {
                best = sheet;
                best_found = Some(block);
            }
        }
        propose(best, best_found, None, Vec::new())
    }
}

/// The widest labelled row followed by a run of filled rows; among rows equally wide, the longest run, a row inside
/// a run already read being one of its items. With a validation, the header row labels the answer column and its
/// run is one the validation covers.
fn best_block(sheet: &Sheet, answers: Option<&ListValidation>, answer_column: i32) -> Result<Option<Block>, Refused> {
    let mut headings: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
    for (cell, value) in &sheet.cells {
        if let CellValue::Text(text) = value
            && !java::is_blank(text)
        {
            headings.entry(cell.row()).or_default().push(cell.column());
        }
    }
    let mut candidates: Vec<(i32, Vec<i32>)> = Vec::new();
    for (row, columns) in headings {
        let labels_answer = answers.is_none() || columns.contains(&answer_column);
        if columns.len() >= MIN_HEADER_COLUMNS
            && labels_answer
            && filled(sheet, row.saturating_add(1), &run_columns(&columns, answer_column))?
        {
            candidates.push((row, columns));
        }
    }
    let widest = candidates.iter().map(|(_, columns)| columns.len()).max().unwrap_or(0);
    let mut best: Option<Block> = None;
    let mut read_through = 0;
    for (row, columns) in candidates {
        if columns.len() < widest || row <= read_through {
            continue;
        }
        let filled_by = run_columns(&columns, answer_column);
        let first_row = row.saturating_add(1);
        let mut last = first_row;
        while last < CellRef::MAX_ROW
            && last.saturating_sub(row) < ChecklistLayout::MAX_ITEM_ROWS
            && filled(sheet, last.saturating_add(1), &filled_by)?
        {
            last = last.saturating_add(1);
        }
        let block = Block { header_row: row, columns, first_row, last_row: last };
        read_through = last;
        if let Some(answers) = answers
            && !covers(answers, &block)
        {
            continue;
        }
        if best.as_ref().is_none_or(|found| block.length() > found.length()) {
            best = Some(block);
        }
    }
    Ok(best)
}

/// The answer column is blank in a template, so a run is read in the other columns.
fn run_columns(headings: &[i32], answer_column: i32) -> Vec<i32> {
    headings.iter().copied().filter(|column| *column != answer_column).collect()
}

fn filled(sheet: &Sheet, row: i32, columns: &[i32]) -> Result<bool, Refused> {
    for column in columns {
        if !sheet.blank(CellRef::new(*column, row)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn covers(validation: &ListValidation, block: &Block) -> bool {
    validation.ranges.iter().any(|range| range.first().row() <= block.last_row && range.last().row() >= block.first_row)
}

fn propose(
    sheet: &Sheet,
    found: Option<Block>,
    answer: Option<i32>,
    values: Vec<String>,
) -> Result<LayoutProposal, Refused> {
    let mut columns = BTreeMap::new();
    let mut header = BTreeMap::new();
    if let Some(column) = answer {
        columns.insert(ChecklistColumn::Answer, CellRef::letters(column));
    }
    let Some(block) = found else {
        return Ok(LayoutProposal {
            sheet: sheet.name.clone(),
            column_header_row: None,
            first_item_row: None,
            last_item_row: None,
            columns,
            header,
            answer_values: values,
        });
    };
    let left: Vec<i32> =
        block.columns.iter().copied().filter(|column| answer.is_none_or(|answer| *column < answer)).collect();
    if let Some(answer) = answer
        && let Some(comment) = block.columns.iter().find(|heading| **heading > answer)
    {
        columns.insert(ChecklistColumn::Comment, CellRef::letters(*comment));
    }
    // A template that adds an identifier column in front of its domain read as control = the identifier, contact =
    // the domain, KPI = the objective. Only that shape is stepped over — one column, identifier-like, a grouped one
    // after it — since a template with no domain may well start with its control.
    let step_over = match (left.first(), left.get(1)) {
        (Some(&identifier), Some(&after)) => {
            identifier_like(sheet, identifier, &block)? && grouped(sheet, after, &block)?
        }
        _ => false,
    };
    let mut rest = left.iter().copied().skip(usize::from(step_over)).peekable();
    for column in [ChecklistColumn::Domain, ChecklistColumn::Objective] {
        match rest.peek() {
            Some(&next) if grouped(sheet, next, &block)? => {
                columns.insert(column, CellRef::letters(next));
                rest.next();
            }
            _ => break,
        }
    }
    for column in [ChecklistColumn::Control, ChecklistColumn::Contact, ChecklistColumn::Kpi] {
        if let Some(next) = rest.next() {
            columns.insert(column, CellRef::letters(next));
        }
    }
    header_cells(sheet, block.header_row, &mut header)?;
    Ok(LayoutProposal {
        sheet: sheet.name.clone(),
        column_header_row: Some(block.header_row),
        first_item_row: Some(block.first_row),
        last_item_row: Some(block.last_row),
        columns,
        header,
        answer_values: values,
    })
}

/// Written on every item row, and never twice the same: the shape of a line's identifier.
fn identifier_like(sheet: &Sheet, column: i32, block: &Block) -> Result<bool, Refused> {
    let mut seen: HashSet<&str> = HashSet::new();
    for row in block.first_row..=block.last_row {
        let cell = CellRef::new(column, row)?;
        if sheet.blank(cell) || !seen.insert(sheet.text(cell)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Written on the first item row, and left blank on some row below: the fill-down shape.
fn grouped(sheet: &Sheet, column: i32, block: &Block) -> Result<bool, Refused> {
    if sheet.blank(CellRef::new(column, block.first_row)?) {
        return Ok(false);
    }
    for row in block.first_row.saturating_add(1)..=block.last_row {
        if sheet.blank(CellRef::new(column, row)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn header_cells(sheet: &Sheet, header_row: i32, header: &mut BTreeMap<Field, HeaderCell>) -> Result<(), Refused> {
    let mut pairs: Vec<HeaderCell> = Vec::new();
    let mut dated: Vec<HeaderCell> = Vec::new();
    for row in 1..header_row {
        let mut skip_until = 0;
        for (label, value) in sheet.row(row) {
            let CellValue::Text(text) = value else {
                continue;
            };
            if label.column() <= skip_until || java::is_blank(text) {
                continue;
            }
            let merge = sheet.merged_at(*label);
            if merge.is_some_and(|range| range.width() >= MIN_TITLE_WIDTH) {
                // A title across the sheet is a heading, not a label.
                continue;
            }
            let value_column = merge.map_or(label.column(), |range: CellRange| range.last().column()).saturating_add(1);
            if value_column > CellRef::MAX_COLUMN {
                continue;
            }
            let value_cell = CellRef::new(value_column, row)?;
            let pair = HeaderCell::new(*label, value_cell)?;
            let is_date = matches!(sheet.value(value_cell), Some(CellValue::Formula { .. } | CellValue::Number(_)));
            if is_date {
                dated.push(pair);
            } else {
                pairs.push(pair);
            }
            skip_until = sheet.merged_at(value_cell).map_or(value_column, |range| range.last().column());
        }
    }
    if let Some(date) = dated.first() {
        header.insert(Field::Date, *date);
    }
    for (field, pair) in [Field::Product, Field::Author].into_iter().zip(pairs) {
        header.insert(field, pair);
    }
    Ok(())
}

/// `TemplateItems.read`: the items a confirmed layout reads from its sheet (decision 0032 §3, step 2). **Filled
/// down, as the sheet means it**: a row's blank domain is the last domain written above it within the item rows,
/// likewise its objective, and a new domain stops the objective carried from the previous one. A row whose control
/// is empty is not an item, but a domain or objective written on it still carries down.
pub fn template_items(workbook: &Workbook, layout: &ChecklistLayout) -> Result<Vec<ChecklistItem>, Failure> {
    let sheet = workbook.sheet(layout.sheet()).ok_or_else(|| {
        refused(format!("The layout names sheet \"{}\", which the workbook does not have.", layout.sheet()))
    })?;
    let id = layout.column(ChecklistColumn::Id);
    let domain_column = layout.column(ChecklistColumn::Domain);
    let objective_column = layout.column(ChecklistColumn::Objective);
    let control = layout
        .column(ChecklistColumn::Control)
        .ok_or_else(|| Defect("A layout names its control column.".to_owned()))?;
    let contact = layout.column(ChecklistColumn::Contact);
    let kpi = layout.column(ChecklistColumn::Kpi);

    let mut items: Vec<ChecklistItem> = Vec::new();
    let mut domain = String::new();
    let mut objective = String::new();
    for row in layout.first_item_row()..=layout.last_item_row() {
        let written_domain = stripped(sheet, domain_column, row)?;
        if !java::is_blank(&written_domain) && written_domain != domain {
            domain = written_domain;
            objective.clear();
        }
        let written_objective = stripped(sheet, objective_column, row)?;
        if !java::is_blank(&written_objective) {
            objective = written_objective;
        }
        let control_text = sheet.text(CellRef::new(control, row)?);
        if text::normalize(Some(control_text)).is_empty() {
            continue;
        }
        let key = match id {
            Some(id) => key_from_id(sheet.text(CellRef::new(id, row)?), row)?,
            None => ItemKey::from_control(Some(control_text))?,
        };
        let contact_text = stripped(sheet, contact, row)?;
        let kpi_text = stripped(sheet, kpi, row)?;
        let words = ItemWords {
            domain: Some(&domain),
            objective: Some(&objective),
            control: Some(control_text),
            contact: Some(&contact_text),
            kpi: Some(&kpi_text),
        };
        let position = i32::try_from(items.len()).map_or(i32::MAX, |count| count.saturating_add(1));
        items.push(ChecklistItem::new(key, position, &words, row, EvidenceRequirement::NONE, None)?);
    }
    Ok(items)
}

fn key_from_id(id: &str, row: i32) -> Result<ItemKey, Refused> {
    let normalized = text::normalize(Some(id));
    if normalized.is_empty() {
        return Err(refused(format!(
            "Row {row} has a control and no id, and the layout says the id column identifies the items."
        )));
    }
    if java::utf16_len(&normalized) > ItemKey::MAX_ID {
        return Err(refused(format!("Row {row}: the id is longer than {} characters.", ItemKey::MAX_ID)));
    }
    ItemKey::from_id(Some(id))
}

fn stripped(sheet: &Sheet, column: Option<i32>, row: i32) -> Result<String, Refused> {
    match column {
        Some(index) => Ok(java::strip(sheet.text(CellRef::new(index, row)?)).to_owned()),
        None => Ok(String::new()),
    }
}

/// `TemplateVersion`: the file a version came from (its SHA-256, which the renderer writes into and an auditor
/// compares a delivered document with), where its checklist lives in it, and its items in the sheet's order —
/// every key unique, every item on a row of the layout's item block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateVersion {
    pub source_sha256: String,
    pub layout: ChecklistLayout,
    pub items: Vec<ChecklistItem>,
}

impl TemplateVersion {
    pub fn new(
        source_sha256: &str,
        layout: ChecklistLayout,
        items: Vec<ChecklistItem>,
    ) -> Result<TemplateVersion, Failure> {
        if source_sha256.len() != 64 || !source_sha256.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(Defect(format!("A source digest is 64 lowercase hex digits: {source_sha256}")).into());
        }
        if items.is_empty() {
            // A version of nothing would be a checklist every project passes by answering nothing.
            return Err(refused(format!(
                "The item rows {} to {} of sheet \"{}\" hold no control: the template has no item.",
                layout.first_item_row(),
                layout.last_item_row(),
                layout.sheet()
            ))
            .into());
        }
        let mut by_key: HashMap<&ItemKey, &ChecklistItem> = HashMap::new();
        let mut by_row: HashSet<i32> = HashSet::new();
        for (index, item) in items.iter().enumerate() {
            let expected = i32::try_from(index).map_or(i32::MAX, |index| index.saturating_add(1));
            if item.position != expected {
                return Err(Defect(format!("Item {expected} is numbered {}", item.position)).into());
            }
            if item.row < layout.first_item_row() || item.row > layout.last_item_row() {
                return Err(refused(format!(
                    "Row {} holds an item outside the item rows {} to {}.",
                    item.row,
                    layout.first_item_row(),
                    layout.last_item_row()
                ))
                .into());
            }
            if !by_row.insert(item.row) {
                return Err(refused(format!("Row {} holds two items.", item.row)).into());
            }
            if let Some(same) = by_key.get(&item.key) {
                let why = if layout.column(ChecklistColumn::Id).is_some() {
                    ": they carry the same id."
                } else {
                    ": their controls say the same thing. Name an id column to tell them apart, or reword one of them."
                };
                return Err(refused(format!("Rows {} and {} read as the same item{why}", same.row, item.row)).into());
            }
            by_key.insert(&item.key, item);
        }
        Ok(TemplateVersion { source_sha256: source_sha256.to_owned(), layout, items })
    }

    /// `TemplateVersion.read`: the version a confirmed layout reads from a workbook.
    pub fn read(workbook: &Workbook, layout: ChecklistLayout) -> Result<TemplateVersion, Failure> {
        let items = template_items(workbook, &layout)?;
        TemplateVersion::new(&workbook.sha256, layout, items)
    }
}
