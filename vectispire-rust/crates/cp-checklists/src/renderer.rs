//! `ChecklistRenderer` and `EvidenceSheet`: the organisation's workbook, filled in — the template's own package with
//! a handful of cells written and one sheet added (decision 0032 §10). A pure function: the template's bytes, the
//! confirmed layout and the statement in; the package's bytes out, **the same bytes Java writes**.
//!
//! Every entry is copied byte for byte except the checklist sheet's part — its item rows' answer and comment cells
//! and its header's value cells — and, only as far as adding a sheet asks, the workbook part, its relationships and
//! the content types. Inside the sheet part only the cells written change, replaced in the text of the part
//! ([`xml_cursor`]); answers, comments and the header's words are inline strings, so the shared strings are never
//! renumbered. The date is the sign-off instant as a value; a formula there is removed, and the calculation chain
//! with it. The added sheet says what each answer rests on and who stands behind the revision.

use std::collections::BTreeMap;

use vectispire_domain::bounded_text::clip;
use vectispire_domain::checklists::Defect;
use vectispire_domain::instant::Instant;
use vectispire_domain::java;

use crate::answer::{AnswerAuthor, AnswerWords, ChecklistAnswer};
use crate::cell::{CellRange, CellRef, Field};
use crate::document_zip::{self, Entry};
use crate::item::{ChecklistColumn, ChecklistItem};
use crate::layout::ChecklistLayout;
use crate::measurement::Reconciliation;
use crate::statement::{self, Act, Answer, ChecklistStatement, Header, Line, Measured, Project, Proof, Template};
use crate::workbook::{Limits, Workbook};
use crate::workbook_reader::{self, MAX_CELL_TEXT, PackageEntry, normalized_name, relationships_of, resolve};
use crate::xml_cursor::{self, Kind, Tag, XmlCursor, escape_attribute, escape_text};
use crate::{Failure, Refused, refused, sha256_hex_bytes};

pub const EVIDENCE_SHEET: &str = "Evidence";
/// The first line of a document nobody has signed: a draft, a submitted or a superseded revision.
pub const DRAFT_BANNER: &str = "Draft — not signed off";
/// The words a trial writes: never seen, but the length of real ones.
pub const TRIAL_TEXT: &str = "Trial rendering";

const WORKSHEET_CONTENT_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";
const MAIN_NAMESPACE: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// What rendering refuses: the template, in the importer's words; a template whose written cells carry a formula
/// others depend on, every such cell named; or a defect — rows given that do not belong together.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderFailure {
    #[error("{0}")]
    Refused(Refused),
    #[error("{}", .0.message)]
    WrittenFormula(WrittenFormula),
    #[error("{0}")]
    Defect(Defect),
}

impl From<Refused> for RenderFailure {
    fn from(refusal: Refused) -> RenderFailure {
        RenderFailure::Refused(refusal)
    }
}

impl From<Defect> for RenderFailure {
    fn from(defect: Defect) -> RenderFailure {
        RenderFailure::Defect(defect)
    }
}

impl From<Failure> for RenderFailure {
    fn from(failure: Failure) -> RenderFailure {
        match failure {
            Failure::Refused(refusal) => RenderFailure::Refused(refusal),
            Failure::Defect(defect) => RenderFailure::Defect(defect),
        }
    }
}

/// `WrittenFormulaException`: the cells the renderer writes that carry a formula other cells depend on — the
/// master of a shared formula, or an array formula over several cells — every one named, not only the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFormula {
    pub message: String,
    pub cells: Vec<WrittenCell>,
}

/// One written cell carrying a formula others depend on: the cell, `shared` or `array`, and the range depending on
/// it as the workbook names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenCell {
    pub cell: String,
    pub kind: String,
    pub range: String,
}

impl WrittenCell {
    fn in_words(&self) -> String {
        if self.kind == "array" {
            format!("{} (an array formula over {})", self.cell, self.range)
        } else {
            format!("{} (the master of a formula shared across {})", self.cell, self.range)
        }
    }
}

/// The most cells the sentence names one by one; the list carries them all.
const NAMED: usize = 10;

impl WrittenFormula {
    fn of(cells: Vec<WrittenCell>) -> WrittenFormula {
        let mut named = String::new();
        for (index, cell) in cells.iter().take(NAMED).enumerate() {
            if index > 0 {
                named.push_str(", ");
            }
            named.push_str(&cell.in_words());
        }
        if cells.len() > NAMED {
            named.push_str(&format!(" and {} more", cells.len().saturating_sub(NAMED)));
        }
        let one = cells.len() == 1;
        let message = format!(
            "{}{named} of the checklist sheet {} Vectispire writes, and {} other cells depend on: writing an answer, a \
             comment or a header value there would leave them pointing at a formula that is gone. Un-share the \
             formula in the workbook — give each cell its own formula, or move it out of the cells the layout writes \
             — and import the workbook again.",
            if one { "Cell " } else { "Cells " },
            if one { "is a cell" } else { "are cells" },
            if one { "it holds a formula" } else { "each holds a formula" },
        );
        WrittenFormula { message, cells }
    }
}

/// `trial`: the workbook filled in as a sign-off would, with placeholder answers — every line answered and
/// commented, the header dated — through [`render`] itself, so that a template the renderer cannot write into is
/// refused at publication rather than at the first sign-off. Pure computation; nobody keeps what it returns.
pub fn trial(template: &[u8], layout: &ChecklistLayout, items: &[ChecklistItem]) -> Result<Vec<u8>, RenderFailure> {
    let at = document_entry_instant();
    let given = ChecklistAnswer::Yes;
    let lines = items
        .iter()
        .map(|item| {
            let answer = Answer {
                id: i64::from(item.position),
                value: given.wire_name().to_owned(),
                word: layout.answers().written(given).to_owned(),
                comment: Some(TRIAL_TEXT.to_owned()),
                answered_by: TRIAL_TEXT.to_owned(),
                answered_by_kind: Some(AnswerAuthor::Person.wire_name().to_owned()),
                answered_at: Some(at),
                carried_from: None,
                carried_by: None,
                carried_at: None,
                needs_confirmation: false,
                withdrawn: false,
            };
            Line {
                item_id: i64::from(item.position),
                key: item.key.value().to_owned(),
                position: item.position,
                row: item.row,
                domain: item.domain.clone(),
                objective: item.objective.clone(),
                control: item.control.clone(),
                contact: item.contact.clone(),
                kpi: item.kpi.clone(),
                content_digest: item.content_digest(),
                evidence_required: item.evidence.kind.wire_name().to_owned(),
                evidence_validity_months: item.evidence.validity_months,
                answer: Some(answer.clone()),
                history: vec![answer],
                measurement: None,
                reconciliation: Some(Reconciliation::NotMeasuredHere.wire_name().to_owned()),
                evidence: Vec::new(),
            }
        })
        .collect();
    let act = Act { by: TRIAL_TEXT.to_owned(), at };
    let statement = ChecklistStatement {
        form: statement::FORM,
        status: "signed_off".to_owned(),
        signed: true,
        project: Project { id: 0, name: TRIAL_TEXT.to_owned() },
        revision: 1,
        template: Template {
            slug: TRIAL_TEXT.to_owned(),
            name: TRIAL_TEXT.to_owned(),
            version: 1,
            label: None,
            source_sha256: sha256_hex_bytes(template),
        },
        header: Header { product: TRIAL_TEXT.to_owned(), author: Some(TRIAL_TEXT.to_owned()), date: Some(at) },
        opened: act.clone(),
        submitted: Some(act.clone()),
        signed_off: Some(act),
        four_eyes_required: Some(false),
        product_version: None,
        produced_at: at,
        lines,
    };
    render(template, layout, &statement)
}

/// `DocumentZip.ENTRY_TIME` read as UTC: 1980-02-01T00:00:00Z.
fn document_entry_instant() -> Instant {
    Instant::of_utc(1980, 2, 1, 0, 0, 0).unwrap_or(Instant::of_epoch_second(318_211_200))
}

/// `render`: the filled workbook. A defect when the template does not hash to the statement's source SHA-256 or a
/// line names a row outside the layout's items; refused past the reader's guards; [`WrittenFormula`] for a cell
/// the renderer cannot replace without breaking others.
pub fn render(
    template: &[u8],
    layout: &ChecklistLayout,
    statement: &ChecklistStatement,
) -> Result<Vec<u8>, RenderFailure> {
    if statement.signed && (statement.signed_off.is_none() || statement.header.date.is_none()) {
        return Err(Defect("A signed statement names its sign-off and is dated by it.".to_owned()).into());
    }
    if sha256_hex_bytes(template) != statement.template.source_sha256 {
        return Err(Defect(
            "The template's bytes do not hash to the version's source SHA-256: the document would claim to follow a \
             workbook it was not written into."
                .to_owned(),
        )
        .into());
    }
    let length = i64::try_from(template.len()).unwrap_or(i64::MAX);
    // Read as an import reads it — every guard, every part parsed by the hardened parser — before a byte is spliced.
    let workbook = Workbook::read(template, length)?;
    if workbook.sheet(layout.sheet()).is_none() {
        return Err(
            refused(format!("The workbook has no sheet \"{}\", which its layout names.", layout.sheet())).into()
        );
    }
    let mut parts = Package::new(workbook_reader::entries(template, length, Limits::DEFAULT)?);

    let workbook_part = parts.main_part()?;
    let workbook_rels_part = relationships_of(&workbook_part);
    let book = WorkbookParts::read(&parts.text(&workbook_part)?)?;
    let links = read_relationships(&parts.text(&workbook_rels_part)?, &workbook_part)?;
    let checklist_sheet = book
        .sheets
        .iter()
        .find(|sheet| sheet.name == layout.sheet())
        .ok_or_else(|| refused(format!("The workbook part lists no sheet \"{}\".", layout.sheet())))?;
    let sheet_link = links
        .iter()
        .find(|link| link.id == checklist_sheet.relationship)
        .ok_or_else(|| refused(format!("Sheet \"{}\" points at no part.", layout.sheet())))?;
    let sheet_part = sheet_link.target.clone();

    let sheet_text = parts.text(&sheet_part)?;
    let patch = Patcher::run(&sheet_text, writes(layout, statement, book.date1904)?)?;
    parts.replace(&sheet_part, &patch.xml)?;

    let mut content_types = parts.text("[content_types].xml")?;
    let mut workbook_rels = parts.text(&workbook_rels_part)?;
    if patch.formula_removed {
        for chain in links.iter().filter(|link| link.kind.ends_with("/calcChain")) {
            parts.drop(&chain.target);
            workbook_rels = remove_element(&workbook_rels, "Relationship", "Id", &chain.id)?;
            content_types = remove_override(&content_types, &chain.target)?;
        }
    }

    // The added sheet, beside the template's: its part in the workbook's folder, the next free number.
    let original = parts.original_name(&workbook_part)?;
    let folder = original.rsplit_once('/').map_or_else(String::new, |(folder, _)| format!("{folder}/"));
    let mut number = book.sheets.len().saturating_add(1);
    while parts.has(&normalized_name(&format!("{folder}worksheets/sheet{number}.xml"))) {
        number = number.saturating_add(1);
    }
    let evidence_file = format!("worksheets/sheet{number}.xml");
    let evidence_part = format!("{folder}{evidence_file}");
    let relationship_id = free_id(&links);
    let sheet_name = free_name(&book.sheets);
    let worksheet_type =
        override_type(&content_types, &sheet_part)?.unwrap_or_else(|| WORKSHEET_CONTENT_TYPE.to_owned());

    content_types = insert_before_end(&content_types, "Types", |prefix| {
        format!(
            "<{prefix}Override PartName=\"/{}\" ContentType=\"{}\"/>",
            escape_attribute(&evidence_part),
            escape_attribute(&worksheet_type)
        )
    })?;
    workbook_rels = insert_before_end(&workbook_rels, "Relationships", |prefix| {
        format!(
            "<{prefix}Relationship Id=\"{relationship_id}\" Type=\"{}\" Target=\"{evidence_file}\"/>",
            escape_attribute(&sheet_link.kind)
        )
    })?;
    let sheet_element = format!("{}sheet", checklist_sheet.tag.prefix());
    let id_attribute = &checklist_sheet.id_attribute;
    let declaration = checklist_sheet.id_declaration.as_ref().map_or_else(String::new, |uri| {
        let prefix = id_attribute.split_once(':').map_or("", |(prefix, _)| prefix);
        format!(" xmlns:{prefix}=\"{}\"", escape_attribute(uri))
    });
    let book_xml = insert_before_end(&parts.text(&workbook_part)?, "sheets", |_| {
        format!(
            "<{sheet_element}{declaration} name=\"{}\" sheetId=\"{}\" {id_attribute}=\"{relationship_id}\"/>",
            escape_attribute(&sheet_name),
            book.next_sheet_id
        )
    })?;

    parts.replace("[content_types].xml", &content_types)?;
    parts.replace(&workbook_rels_part, &workbook_rels)?;
    parts.replace(&workbook_part, &book_xml)?;
    parts.add(&evidence_part, &evidence_sheet(statement, layout, &patch.namespace)?);
    parts.write()
}

// ------------------------------------------------------------------ the cells

/// What a cell receives.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CellWrite {
    Text(String),
    Number(String),
    /// Emptied: the cell stays, with its style, and holds nothing.
    Blank,
}

type Writes = BTreeMap<i32, BTreeMap<i32, CellWrite>>;

/// Each cell the statement writes, row by row.
fn writes(layout: &ChecklistLayout, statement: &ChecklistStatement, date1904: bool) -> Result<Writes, RenderFailure> {
    let mut rows: Writes = BTreeMap::new();
    let answer_column = layout.column(ChecklistColumn::Answer).ok_or_else(|| Defect("No answer column.".to_owned()))?;
    let comment_column =
        layout.column(ChecklistColumn::Comment).ok_or_else(|| Defect("No comment column.".to_owned()))?;
    for line in &statement.lines {
        if line.row < layout.first_item_row() || line.row > layout.last_item_row() {
            return Err(Defect(format!(
                "Line {} names row {}, outside the layout's items ({} to {}).",
                line.position,
                line.row,
                layout.first_item_row(),
                layout.last_item_row()
            ))
            .into());
        }
        let answer = match &line.answer {
            Some(given) => CellWrite::Text(word(layout.answers(), given)?.to_owned()),
            None => CellWrite::Blank,
        };
        let comment = match &line.answer {
            Some(Answer { comment: Some(comment), .. }) if !java::is_blank(comment) => CellWrite::Text(comment.clone()),
            _ => CellWrite::Blank,
        };
        let cells = rows.entry(line.row).or_default();
        cells.insert(answer_column, answer);
        cells.insert(comment_column, comment);
    }
    for (field, cell) in layout.header() {
        let write = match field {
            Field::Product => CellWrite::Text(statement.header.product.clone()),
            Field::Author => CellWrite::Text(
                statement.header.author.clone().ok_or_else(|| Defect("The header names no author.".to_owned()))?,
            ),
            Field::Date => {
                statement.header.date.map_or(CellWrite::Blank, |date| CellWrite::Number(serial(date, date1904)))
            }
        };
        rows.entry(cell.value().row()).or_default().insert(cell.value().column(), write);
    }
    Ok(rows)
}

/// The template's word for an answer, as `AnswerWords.written` gives it.
fn word<'w>(words: &'w AnswerWords, answer: &Answer) -> Result<&'w str, Refused> {
    Ok(words.written(ChecklistAnswer::parse(Some(&answer.value))?))
}

/// An instant as a spreadsheet date: days since the workbook's epoch, the time of day as the fraction, in UTC, to
/// the second, rounded half-even to ten places and written without trailing zeros. The 1900 system counts from
/// 1899-12-30, which absorbs the leap day 1900 never had — right for every date after February 1900.
pub fn serial(instant: Instant, date1904: bool) -> String {
    const EPOCH_1900: i64 = -25_569; // 1899-12-30, in days from 1970-01-01
    const EPOCH_1904: i64 = -24_107; // 1904-01-01
    let day = instant.epoch_second.div_euclid(Instant::SECONDS_PER_DAY);
    let second = instant.epoch_second.rem_euclid(Instant::SECONDS_PER_DAY);
    // In an `i128`, days of an `i64` of seconds times ten digits never reach its bounds: nothing saturates.
    let days = i128::from(day).saturating_sub(i128::from(if date1904 { EPOCH_1904 } else { EPOCH_1900 }));
    let scaled = i128::from(second).saturating_mul(10_000_000_000);
    let (quotient, remainder) = (scaled.div_euclid(86_400), scaled.rem_euclid(86_400));
    let fraction = match remainder.saturating_mul(2).cmp(&86_400) {
        std::cmp::Ordering::Less => quotient,
        std::cmp::Ordering::Greater => quotient.saturating_add(1),
        std::cmp::Ordering::Equal => quotient.saturating_add(quotient & 1),
    };
    let total = days.saturating_mul(10_000_000_000).saturating_add(fraction);
    let magnitude = total.unsigned_abs();
    let whole = magnitude / 10_000_000_000;
    let decimals = format!("{:010}", magnitude % 10_000_000_000);
    let decimals = decimals.trim_end_matches('0');
    let sign = if total < 0 { "-" } else { "" };
    if decimals.is_empty() { format!("{sign}{whole}") } else { format!("{sign}{whole}.{decimals}") }
}

fn free_id(links: &[Relationship]) -> String {
    let mut n = links.len().saturating_add(1);
    while links.iter().any(|link| link.id == format!("rId{n}")) {
        n = n.saturating_add(1);
    }
    format!("rId{n}")
}

/// `Evidence`, or `Evidence (2)` when the template already has a sheet of that name.
fn free_name(sheets: &[SheetEntry]) -> String {
    let taken: Vec<String> = sheets.iter().map(|sheet| java::to_lower_root(&sheet.name)).collect();
    let mut name = EVIDENCE_SHEET.to_owned();
    let mut n: u32 = 2;
    while taken.contains(&java::to_lower_root(&name)) {
        name = format!("{EVIDENCE_SHEET} ({n})");
        n = n.saturating_add(1);
    }
    name
}

// ------------------------------------------------------------------ the package

/// The package's entries by normalised name, and what is replaced, dropped and added.
struct Package {
    entries: Vec<PackageEntry>,
    index: Vec<(String, usize)>,
    replaced: BTreeMap<usize, Vec<u8>>,
    dropped: Vec<usize>,
    added: Vec<(String, Vec<u8>)>,
}

impl Package {
    fn new(entries: Vec<PackageEntry>) -> Package {
        let mut index: Vec<(String, usize)> = Vec::new();
        for (at, entry) in entries.iter().enumerate() {
            if !entry.directory {
                let key = normalized_name(&entry.name);
                match index.iter_mut().find(|(name, _)| *name == key) {
                    Some(slot) => slot.1 = at,
                    None => index.push((key, at)),
                }
            }
        }
        Package { entries, index, replaced: BTreeMap::new(), dropped: Vec::new(), added: Vec::new() }
    }

    fn at(&self, part: &str) -> Option<usize> {
        self.index.iter().find(|(name, _)| name == part).map(|(_, at)| *at)
    }

    /// An entry by the index `at` answered, which is always one of them.
    fn entry(&self, at: usize) -> &PackageEntry {
        self.entries.get(at).unwrap_or(&NO_ENTRY)
    }

    fn has(&self, part: &str) -> bool {
        self.at(part).is_some()
    }

    fn required(&self, part: &str) -> Result<usize, Refused> {
        self.at(part).ok_or_else(|| {
            refused(format!(
                "The workbook refers to part {}, which the package does not hold.",
                clip(Some(part), 120).unwrap_or("")
            ))
        })
    }

    fn original_name(&self, part: &str) -> Result<String, Refused> {
        Ok(self.entry(self.required(part)?).name.clone())
    }

    fn main_part(&self) -> Result<String, Refused> {
        read_relationships(&self.text("_rels/.rels")?, "")?
            .into_iter()
            .find(|link| link.kind.ends_with("/officeDocument"))
            .map(|link| link.target)
            .ok_or_else(|| refused("The package holds no workbook part."))
    }

    /// A part's text. UTF-8 only — what Office writes, and what the reader accepted; a part declared in another
    /// encoding would be spliced as the wrong characters. Undecodable bytes read as U+FFFD, as `new String` reads
    /// them.
    fn text(&self, part: &str) -> Result<String, Refused> {
        let at = self.required(part)?;
        let bytes = self.replaced.get(&at).unwrap_or(&self.entry(at).bytes);
        let body = bytes.strip_prefix(&UTF8_BOM).unwrap_or(bytes);
        if bytes.starts_with(&[0xFE, 0xFF]) || bytes.starts_with(&[0xFF, 0xFE]) {
            return Err(refused(format!("Part {part} is written in UTF-16, which the renderer does not write into.")));
        }
        let text = String::from_utf8_lossy(body).into_owned();
        if text.starts_with("<?xml")
            && let Some(declared) = declared_encoding(&text)
            && !declared.eq_ignore_ascii_case("UTF-8")
        {
            return Err(refused(format!(
                "Part {part} is written in {}, which the renderer does not write into.",
                clip(Some(&declared), 20).unwrap_or("")
            )));
        }
        Ok(text)
    }

    fn replace(&mut self, part: &str, text: &str) -> Result<(), Refused> {
        let at = self.required(part)?;
        let mut encoded = Vec::with_capacity(text.len().saturating_add(3));
        if self.entry(at).bytes.starts_with(&UTF8_BOM) {
            encoded.extend_from_slice(&UTF8_BOM);
        }
        encoded.extend_from_slice(text.as_bytes());
        self.replaced.insert(at, encoded);
        Ok(())
    }

    fn drop(&mut self, part: &str) {
        if let Some(at) = self.at(part) {
            self.dropped.push(at);
        }
    }

    fn add(&mut self, name: &str, text: &str) {
        self.added.push((name.to_owned(), text.as_bytes().to_vec()));
    }

    fn write(&self) -> Result<Vec<u8>, RenderFailure> {
        let mut written: Vec<(String, Entry)> = Vec::new();
        let mut put = |name: &str, entry: Entry| match written.iter_mut().find(|(existing, _)| existing == name) {
            Some(slot) => slot.1 = entry,
            None => written.push((name.to_owned(), entry)),
        };
        for (at, entry) in self.entries.iter().enumerate() {
            if self.dropped.contains(&at) {
                continue;
            }
            let bytes = self.replaced.get(&at).unwrap_or(&entry.bytes).clone();
            put(&entry.name, Entry { bytes, stored: entry.stored, directory: entry.directory });
        }
        for (name, bytes) in &self.added {
            put(name, Entry::of(bytes.clone()));
        }
        document_zip::of(&written).map_err(|duplicate| Defect(duplicate.to_string()).into())
    }
}

static NO_ENTRY: PackageEntry =
    PackageEntry { name: String::new(), bytes: Vec::new(), directory: false, stored: false };

/// `encoding\s*=\s*["']([^"']+)["']`, found in the first 200 UTF-16 units of the text.
fn declared_encoding(text: &str) -> Option<String> {
    let mut units = 0usize;
    let end = text
        .char_indices()
        .find(|(_, c)| {
            units = units.saturating_add(c.len_utf16());
            units > 200
        })
        .map_or(text.len(), |(at, _)| at);
    let mut head = text.get(..end).unwrap_or(text);
    let space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r');
    // Each "encoding" in turn, as the regex's search moves along: the first that reads as the whole pattern.
    while let Some((_, after)) = head.split_once("encoding") {
        head = after;
        let Some(rest) = after.trim_start_matches(space).strip_prefix('=') else {
            continue;
        };
        let Some(rest) = rest.trim_start_matches(space).strip_prefix(['"', '\'']) else {
            continue;
        };
        match rest.split_once(['"', '\'']) {
            Some((value, _)) if !value.is_empty() => return Some(value.to_owned()),
            _ => continue,
        }
    }
    None
}

/// A relationship of a part, its target resolved to a part name.
#[derive(Debug, Clone)]
struct Relationship {
    id: String,
    kind: String,
    target: String,
}

fn read_relationships(xml: &str, source: &str) -> Result<Vec<Relationship>, Refused> {
    let mut found = Vec::new();
    let mut cursor = XmlCursor::new(xml);
    while let Some(tag) = cursor.next()? {
        if tag.opens()
            && tag.local() == "Relationship"
            && let (Some(target), Some(kind)) = (tag.attribute("Target"), tag.attribute("Type"))
        {
            found.push(Relationship {
                id: tag.attribute("Id").unwrap_or_default(),
                kind: java::strip(&kind).to_owned(),
                target: resolve(source, java::strip(&target)),
            });
        }
    }
    Ok(found)
}

/// A sheet the workbook part lists: `id_attribute` the relationship attribute as the workbook spells it (`r:id`),
/// `id_declaration` the namespace of its prefix when the element declared it itself.
struct SheetEntry {
    name: String,
    relationship: String,
    id_attribute: String,
    id_declaration: Option<String>,
    tag: Tag,
}

struct WorkbookParts {
    sheets: Vec<SheetEntry>,
    date1904: bool,
    next_sheet_id: i32,
}

impl WorkbookParts {
    fn read(xml: &str) -> Result<WorkbookParts, Refused> {
        let mut sheets = Vec::new();
        let mut date1904 = false;
        let mut max_id: i32 = 0;
        let mut cursor = XmlCursor::new(xml);
        while let Some(tag) = cursor.next()? {
            if !tag.opens() {
                continue;
            }
            if tag.local() == "workbookPr" {
                let value = tag.attribute("date1904").unwrap_or_else(|| "0".to_owned());
                let value = java::strip(&value);
                date1904 = value == "1" || value.eq_ignore_ascii_case("true");
            } else if tag.local() == "sheet" {
                let id = tag
                    .attributes
                    .iter()
                    .find(|attribute| {
                        attribute.prefixed() && attribute.local() == "id" && !attribute.name.starts_with("xmlns:")
                    })
                    .ok_or_else(|| refused("The workbook lists a sheet without a part."))?;
                let prefix = id.name.split_once(':').map_or("", |(prefix, _)| prefix);
                let entry = SheetEntry {
                    name: tag.attribute("name").unwrap_or_default(),
                    relationship: id.value(),
                    id_attribute: id.name.clone(),
                    id_declaration: tag.attribute(&format!("xmlns:{prefix}")),
                    tag: tag.clone(),
                };
                sheets.push(entry);
                // The added sheet takes a number past every one that reads as a number.
                if let Ok(id) = java::read_int(java::strip(&tag.attribute("sheetId").unwrap_or_else(|| "0".to_owned())))
                {
                    max_id = max_id.max(id);
                }
            }
        }
        // `maxId + 1` in an `int`, which wraps.
        Ok(WorkbookParts { sheets, date1904, next_sheet_id: max_id.wrapping_add(1) })
    }
}

// ------------------------------------------------------------------ splicing the small parts

/// `element` written just before the end tag of `parent`, with the parent's prefix.
fn insert_before_end(xml: &str, parent: &str, element: impl Fn(&str) -> String) -> Result<String, Refused> {
    let mut cursor = XmlCursor::new(xml);
    while let Some(tag) = cursor.next()? {
        if tag.local() == parent && tag.kind == Kind::End {
            return Ok(format!(
                "{}{}{}",
                xml.get(..tag.start).unwrap_or_default(),
                element(tag.prefix()),
                xml.get(tag.start..).unwrap_or_default()
            ));
        }
        if tag.local() == parent && tag.kind == Kind::Empty {
            return Ok(format!(
                "{}{}{}</{}>{}",
                xml.get(..tag.start).unwrap_or_default(),
                xml_cursor::rewrite(&tag, &[], &[], true),
                element(tag.prefix()),
                tag.name,
                xml.get(tag.end..).unwrap_or_default()
            ));
        }
    }
    Err(refused(format!("A part of the workbook has no {parent} element to add to.")))
}

/// Removes the `element` whose `attribute` is `value`, with its content if it has one.
fn remove_element(xml: &str, element: &str, attribute: &str, value: &str) -> Result<String, Refused> {
    let mut cursor = XmlCursor::new(xml);
    while let Some(tag) = cursor.next()? {
        if tag.opens() && tag.local() == element && tag.attribute(attribute).as_deref() == Some(value) {
            let mut end = tag.end;
            if tag.kind == Kind::Start {
                while let Some(inner) = cursor.next()? {
                    if inner.kind == Kind::End && inner.local() == element {
                        end = inner.end;
                        break;
                    }
                }
            }
            return Ok(format!("{}{}", xml.get(..tag.start).unwrap_or_default(), xml.get(end..).unwrap_or_default()));
        }
    }
    Ok(xml.to_owned())
}

fn override_of(content_types: &str, part: &str) -> Result<Option<Tag>, Refused> {
    let mut cursor = XmlCursor::new(content_types);
    while let Some(tag) = cursor.next()? {
        if tag.opens()
            && tag.local() == "Override"
            && tag.attribute("PartName").is_some_and(|name| normalized_name(&name) == part)
        {
            return Ok(Some(tag));
        }
    }
    Ok(None)
}

fn remove_override(content_types: &str, part: &str) -> Result<String, Refused> {
    match override_of(content_types, part)?.and_then(|tag| tag.attribute("PartName")) {
        Some(name) => remove_element(content_types, "Override", "PartName", &name),
        None => Ok(content_types.to_owned()),
    }
}

fn override_type(content_types: &str, part: &str) -> Result<Option<String>, Refused> {
    Ok(override_of(content_types, part)?
        .and_then(|tag| tag.attribute("ContentType"))
        .map(|kind| java::strip(&kind).to_owned()))
}

// ------------------------------------------------------------------ the checklist sheet

/// The checklist sheet with its cells written; `namespace` the one its root binds its elements to.
struct SheetPatch {
    xml: String,
    formula_removed: bool,
    namespace: String,
}

/// Walks the sheet's tags once, copying the text between the places it writes. A row the template does not have is
/// created in row order, a cell likewise in column order; a cell it has is replaced whole, keeping its reference
/// and its style.
struct Patcher<'a> {
    xml: &'a str,
    writes: Writes,
    pending: Writes,
    cursor: XmlCursor<'a>,
    out: String,
    copied: usize,
    formula_removed: bool,
    depended_on: Vec<WrittenCell>,
    prefix: String,
    namespace: String,
}

impl<'a> Patcher<'a> {
    fn run(xml: &'a str, writes: Writes) -> Result<SheetPatch, RenderFailure> {
        let mut patcher = Patcher {
            xml,
            pending: writes.clone(),
            writes,
            cursor: XmlCursor::new(xml),
            out: String::with_capacity(xml.len().saturating_add(4096)),
            copied: 0,
            formula_removed: false,
            depended_on: Vec::new(),
            prefix: String::new(),
            namespace: MAIN_NAMESPACE.to_owned(),
        };
        patcher.walk()?;
        if let Some(first) = patcher.pending.keys().next() {
            return Err(refused(format!("The checklist sheet has no sheetData to write rows {first} to.")).into());
        }
        // Every such cell named at once, after the whole sheet was walked.
        if !patcher.depended_on.is_empty() {
            return Err(RenderFailure::WrittenFormula(WrittenFormula::of(std::mem::take(&mut patcher.depended_on))));
        }
        patcher.out.push_str(xml.get(patcher.copied..).unwrap_or_default());
        Ok(SheetPatch { xml: patcher.out, formula_removed: patcher.formula_removed, namespace: patcher.namespace })
    }

    fn walk(&mut self) -> Result<(), RenderFailure> {
        let mut in_sheet_data = false;
        let mut seen_root = false;
        let mut last_row = 0i32;
        while let Some(tag) = self.cursor.next()? {
            let local = tag.local().to_owned();
            if !seen_root && tag.opens() {
                seen_root = true;
                let root_prefix = tag.prefix();
                let declaration = if root_prefix.is_empty() {
                    "xmlns".to_owned()
                } else {
                    format!("xmlns:{}", root_prefix.strip_suffix(':').unwrap_or(root_prefix))
                };
                self.namespace = tag.attribute(&declaration).unwrap_or_else(|| MAIN_NAMESPACE.to_owned());
            }
            if !in_sheet_data {
                if local == "dimension" && tag.opens() {
                    self.widen_dimension(&tag)?;
                } else if local == "sheetData" && tag.opens() {
                    self.prefix = tag.prefix().to_owned();
                    if tag.kind == Kind::Empty {
                        self.copy_to(tag.start);
                        self.out.push_str(&xml_cursor::rewrite(&tag, &[], &[], true));
                        self.append_rows_before(i32::MAX)?;
                        self.out.push_str(&format!("</{}>", tag.name));
                        self.copied = tag.end;
                    } else {
                        in_sheet_data = true;
                    }
                }
                continue;
            }
            if local == "sheetData" && tag.kind == Kind::End {
                self.copy_to(tag.start);
                self.append_rows_before(i32::MAX)?;
                in_sheet_data = false;
            } else if local == "row" && tag.opens() {
                let r = tag.attribute("r");
                let number = match &r {
                    Some(value) => row_number(value)?,
                    None => last_row.saturating_add(1),
                };
                let inserted = self.pending.range(..number).next().is_some();
                if inserted {
                    self.copy_to(tag.start);
                    self.append_rows_before(number)?;
                }
                last_row = number;
                let cells = self.pending.remove(&number);
                // A row placed by its order alone follows the one before it: after a row inserted before it, it
                // states its number, or it would take the inserted row's.
                let fix_number = inserted && r.is_none();
                match cells {
                    None => {
                        if fix_number {
                            self.retag(&tag, &[("r", number.to_string())], &[], false);
                        }
                    }
                    Some(cells) => self.edit_row(&tag, number, cells, fix_number)?,
                }
            }
        }
        Ok(())
    }

    fn edit_row(
        &mut self,
        row: &Tag,
        number: i32,
        cells: BTreeMap<i32, CellWrite>,
        fix_number: bool,
    ) -> Result<(), RenderFailure> {
        let mut set: Vec<(&str, String)> = Vec::new();
        let mut remove: Vec<&str> = Vec::new();
        if fix_number {
            set.push(("r", number.to_string()));
        }
        // `spans` names the columns a row's cells lie in; a cell written outside it would make the hint a lie.
        if let Some(spans) = row.attribute("spans")
            && !cells.keys().all(|column| within(&spans, *column))
        {
            remove.push("spans");
        }
        if row.kind == Kind::Empty {
            self.copy_to(row.start);
            self.out.push_str(&xml_cursor::rewrite(row, &set, &remove, true));
            for (column, write) in &cells {
                let cell = self.cell(CellRef::new(*column, number)?, None, write);
                self.out.push_str(&cell);
            }
            self.out.push_str(&format!("</{}>", row.name));
            self.copied = row.end;
            return Ok(());
        }
        if !set.is_empty() || !remove.is_empty() {
            self.retag(row, &set, &remove, false);
        }
        let mut remaining = cells;
        let mut last_column = 0i32;
        while let Some(tag) = self.cursor.next()? {
            if tag.local() == "row" && tag.kind == Kind::End {
                self.copy_to(tag.start);
                for (column, write) in &remaining {
                    let cell = self.cell(CellRef::new(*column, number)?, None, write);
                    self.out.push_str(&cell);
                }
                return Ok(());
            }
            if tag.local() != "c" || !tag.opens() {
                continue;
            }
            let r = tag.attribute("r");
            let column = r
                .as_deref()
                .and_then(|r| CellRef::parse(Some(r)))
                .map_or(last_column.saturating_add(1), CellRef::column);
            let before: Vec<i32> = remaining.range(..column).map(|(column, _)| *column).collect();
            let inserted = !before.is_empty();
            if inserted {
                self.copy_to(tag.start);
                for earlier in before {
                    if let Some(write) = remaining.remove(&earlier) {
                        let cell = self.cell(CellRef::new(earlier, number)?, None, &write);
                        self.out.push_str(&cell);
                    }
                }
            }
            last_column = column;
            if let Some(write) = remaining.remove(&column) {
                let reference = CellRef::new(column, number)?;
                let end = self.cell_end(&tag, reference)?;
                self.copy_to(tag.start);
                let style = raw_style(&tag);
                let cell = self.cell(reference, style.as_deref(), &write);
                self.out.push_str(&cell);
                self.copied = end;
            } else if inserted && r.is_none() {
                let reference = CellRef::new(column, number)?;
                self.retag(&tag, &[("r", reference.to_string())], &[], false);
            }
        }
        Err(refused(format!("Row {number} of the checklist sheet does not end.")).into())
    }

    /// Where a cell's element ends, noting a formula it held and naming one others depend on.
    fn cell_end(&mut self, cell: &Tag, reference: CellRef) -> Result<usize, Refused> {
        if cell.kind == Kind::Empty {
            return Ok(cell.end);
        }
        while let Some(tag) = self.cursor.next()? {
            if tag.local() == "f" && tag.opens() {
                self.formula_removed = true;
                let range = tag.attribute("ref");
                let kind = tag.attribute("t").unwrap_or_else(|| "normal".to_owned());
                if let Some(range) = range
                    && (kind == "shared" || kind == "array")
                    && !CellRange::parse(Some(&range)).is_some_and(|parsed| parsed.first() == parsed.last())
                {
                    self.depended_on.push(WrittenCell {
                        cell: reference.to_string(),
                        kind,
                        range: clip(Some(java::strip(&range)), 30).unwrap_or("").to_owned(),
                    });
                }
            }
            if tag.local() == "c" && tag.kind == Kind::End {
                return Ok(tag.end);
            }
        }
        Err(refused(format!("Cell {reference} of the checklist sheet does not end.")))
    }

    fn append_rows_before(&mut self, limit: i32) -> Result<(), Refused> {
        let numbers: Vec<i32> = self.pending.range(..limit).map(|(number, _)| *number).collect();
        for number in numbers {
            let Some(cells) = self.pending.remove(&number) else {
                continue;
            };
            let mut row = format!("<{}row r=\"{number}\">", self.prefix);
            for (column, write) in &cells {
                row.push_str(&self.cell(CellRef::new(*column, number)?, None, write));
            }
            row.push_str(&format!("</{}row>", self.prefix));
            self.out.push_str(&row);
        }
        Ok(())
    }

    fn cell(&self, reference: CellRef, raw_style: Option<&str>, write: &CellWrite) -> String {
        let p = &self.prefix;
        let mut cell = format!("<{p}c r=\"{reference}\"");
        if let Some(style) = raw_style {
            cell.push_str(&format!(" s=\"{style}\""));
        }
        match write {
            CellWrite::Text(text) => cell.push_str(&format!(
                " t=\"inlineStr\"><{p}is><{p}t xml:space=\"preserve\">{}</{p}t></{p}is></{p}c>",
                escape_text(clip(Some(text), MAX_CELL_TEXT).unwrap_or(""))
            )),
            CellWrite::Number(literal) => cell.push_str(&format!("><{p}v>{literal}</{p}v></{p}c>")),
            CellWrite::Blank => cell.push_str("/>"),
        }
        cell
    }

    fn widen_dimension(&mut self, tag: &Tag) -> Result<(), Refused> {
        let Some(written) = tag.attribute("ref") else {
            return Ok(());
        };
        let Some(range) = CellRange::parse(Some(&written)) else {
            return Ok(());
        };
        let (Some(first_written), Some(last_written)) = (self.writes.keys().next(), self.writes.keys().next_back())
        else {
            return Ok(());
        };
        let first_row = range.first().row().min(*first_written);
        let last_row = range.last().row().max(*last_written);
        let mut first_column = range.first().column();
        let mut last_column = range.last().column();
        for cells in self.writes.values() {
            if let (Some(first), Some(last)) = (cells.keys().next(), cells.keys().next_back()) {
                first_column = first_column.min(*first);
                last_column = last_column.max(*last);
            }
        }
        let first = CellRef::new(first_column, first_row)?;
        let last = CellRef::new(last_column, last_row)?;
        let widened = if first == last { first.to_string() } else { format!("{first}:{last}") };
        if widened != written {
            self.retag(tag, &[("ref", widened)], &[], false);
        }
        Ok(())
    }

    fn retag(&mut self, tag: &Tag, set: &[(&str, String)], remove: &[&str], open: bool) {
        self.copy_to(tag.start);
        self.out.push_str(&xml_cursor::rewrite(tag, set, remove, open));
        self.copied = tag.end;
    }

    fn copy_to(&mut self, offset: usize) {
        self.out.push_str(self.xml.get(self.copied..offset).unwrap_or_default());
        self.copied = offset;
    }
}

/// The style attribute exactly as written, which the replacement keeps: the cell looks as it did.
fn raw_style(cell: &Tag) -> Option<String> {
    cell.attributes.iter().find(|attribute| attribute.name == "s").map(|attribute| attribute.raw.clone())
}

fn row_number(value: &str) -> Result<i32, Refused> {
    java::read_int(java::strip(value))
        .map_err(|_| refused(format!("The checklist sheet numbers a row \"{}\".", clip(Some(value), 20).unwrap_or(""))))
}

/// Whether a column lies within a row's `spans`, `1:7` or several such, separated by whitespace.
fn within(spans: &str, column: i32) -> bool {
    let stripped = java::strip(spans);
    let tokens: Vec<&str> = if stripped.is_empty() {
        vec![""]
    } else {
        stripped.split([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']).filter(|token| !token.is_empty()).collect()
    };
    for span in tokens {
        let bounds = crate::workbook::split_java(span, ':');
        let (Some(first), Some(last)) = (bounds.first(), bounds.last()) else {
            // `"".split(":")` is one empty string, and `":".split(":")` none: `bounds[0]` then throws.
            return false;
        };
        match (java::read_int(first), java::read_int(last)) {
            (Ok(from), Ok(to)) => {
                if column >= from && column <= to {
                    return true;
                }
            }
            _ => return false,
        }
    }
    false
}

// ------------------------------------------------------------------ the evidence sheet

/// The columns of the added sheet, in English whatever the template's language.
pub const EVIDENCE_COLUMNS: [&str; 10] = [
    "Line",
    "Control",
    "Answer",
    "Answered by",
    "Answered at",
    "Measurement",
    "As of",
    "Answer and measurement",
    "Measurement evidence",
    "Proofs",
];

const WIDTHS: [i32; 10] = [6, 48, 14, 20, 22, 22, 22, 24, 60, 70];

enum Value {
    Number(i64),
    Text(String),
}

/// `EvidenceSheet.xml`: one row per line, then who stands behind the revision; every instant UTC, ISO 8601, as text.
fn evidence_sheet(
    statement: &ChecklistStatement,
    layout: &ChecklistLayout,
    namespace: &str,
) -> Result<String, RenderFailure> {
    let text = |value: &str| Value::Text(value.to_owned());
    let mut rows: Vec<Vec<Value>> = vec![vec![Value::Text(banner(statement))], Vec::new()];
    rows.push(EVIDENCE_COLUMNS.iter().map(|column| text(column)).collect());
    for line in &statement.lines {
        let answer = line.answer.as_ref();
        let measured = line.measurement.as_ref();
        let word = match answer {
            Some(given) => word(layout.answers(), given)?.to_owned(),
            None => "unanswered".to_owned(),
        };
        rows.push(vec![
            Value::Number(i64::from(line.position)),
            text(&line.control),
            Value::Text(word),
            Value::Text(answer.map(answered_by).unwrap_or_default()),
            Value::Text(answer.and_then(|given| given.answered_at).map(statement::instant_text).unwrap_or_default()),
            Value::Text(measured.map_or_else(|| "not measured here".to_owned(), outcome)),
            Value::Text(measured.and_then(|measured| measured.as_of).map(statement::instant_text).unwrap_or_default()),
            Value::Text(reconciliation(line.reconciliation.as_deref())),
            Value::Text(measured.map(evidence).unwrap_or_default()),
            Value::Text(proofs(&line.evidence)),
        ]);
    }
    rows.push(Vec::new());
    rows.push(vec![text("Project"), Value::Text(format!("{} ({})", statement.project.name, statement.project.id))]);
    rows.push(vec![text("Revision"), Value::Number(i64::from(statement.revision))]);
    let template = &statement.template;
    let label = match template.label.as_deref() {
        Some(label) if !java::is_blank(label) => format!(" ({label})"),
        _ => String::new(),
    };
    rows.push(vec![
        text("Template"),
        Value::Text(format!("{} — {}, version {}{label}", template.slug, template.name, template.version)),
    ]);
    rows.push(vec![text("Template source SHA-256"), text(&template.source_sha256)]);
    rows.push(vec![text("Opened by"), Value::Text(act(&statement.opened))]);
    rows.push(vec![
        text("Submitted by"),
        Value::Text(statement.submitted.as_ref().map_or_else(|| "not submitted".to_owned(), act)),
    ]);
    rows.push(vec![
        text("Signed off by"),
        Value::Text(statement.signed_off.as_ref().map_or_else(|| "not signed off".to_owned(), act)),
    ]);
    rows.push(vec![text("Four-eyes rule"), text(four_eyes(statement.four_eyes_required))]);
    rows.push(vec![
        text("Produced by"),
        Value::Text(format!(
            "Vectispire {} at {}",
            statement.product_version.as_deref().unwrap_or("(version not stated by the build)"),
            statement::instant_text(statement.produced_at)
        )),
    ]);
    rows.push(vec![text("Instants"), text("UTC, ISO 8601")]);

    let mut sheet = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<worksheet xmlns=\"{}\"><cols>",
        escape_attribute(namespace)
    );
    for (index, width) in WIDTHS.iter().enumerate() {
        let column = index.saturating_add(1);
        sheet.push_str(&format!("<col min=\"{column}\" max=\"{column}\" width=\"{width}\" customWidth=\"1\"/>"));
    }
    sheet.push_str("</cols><sheetData>");
    for (r, row) in rows.iter().enumerate() {
        if row.is_empty() {
            continue;
        }
        let number = i32::try_from(r.saturating_add(1)).unwrap_or(i32::MAX);
        sheet.push_str(&format!("<row r=\"{number}\">"));
        for (c, value) in row.iter().enumerate() {
            let reference = CellRef::new(i32::try_from(c.saturating_add(1)).unwrap_or(i32::MAX), number)?;
            match value {
                Value::Number(number) => sheet.push_str(&format!("<c r=\"{reference}\"><v>{number}</v></c>")),
                Value::Text(text) if !text.is_empty() => sheet.push_str(&format!(
                    "<c r=\"{reference}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
                    escape_text(clip(Some(text), MAX_CELL_TEXT).unwrap_or(""))
                )),
                Value::Text(_) => {}
            }
        }
        sheet.push_str("</row>");
    }
    sheet.push_str("</sheetData></worksheet>");
    Ok(sheet)
}

/// The first line: whether anybody signed what follows.
pub fn banner(statement: &ChecklistStatement) -> String {
    match &statement.signed_off {
        Some(signed_off) if statement.signed => format!(
            "Signed off by {} at {} — this document was produced and signed with the sign-off.",
            signed_off.by,
            statement::instant_text(signed_off.at)
        ),
        // Signed off before documents were signed: the revision is, the document is not.
        Some(signed_off) => format!(
            "Signed off by {} at {} — but no signed document was produced then: this rendering is not signed.",
            signed_off.by,
            statement::instant_text(signed_off.at)
        ),
        None => DRAFT_BANNER.to_owned(),
    }
}

fn answered_by(answer: &Answer) -> String {
    // By the kind, never the name: an account called "Vectispire" is a person, and says so.
    let mut by = if answer.automatic() {
        format!("{} (automatic, from its measurement)", AnswerAuthor::SYSTEM_NAME)
    } else {
        answer.answered_by.clone()
    };
    if let Some(carrier) = &answer.carried_by {
        by.push_str(&format!(" (carried by {carrier})"));
    }
    if answer.needs_confirmation { format!("{by} — awaiting confirmation") } else { by }
}

fn outcome(measured: &Measured) -> String {
    let outcome = measured.outcome.replace('_', " ");
    match &measured.reason {
        None => outcome,
        Some(reason) => format!("{outcome} ({})", reason.replace('_', " ")),
    }
}

fn evidence(measured: &Measured) -> String {
    format!(
        "{} — evidence SHA-256 {}{}",
        measured.summary,
        measured.evidence_digest,
        if measured.purpose == "read" { "; computed for this rendering" } else { "" }
    )
}

/// The reconciliation in the words the screen and the ADR use (§6).
pub fn reconciliation(wire_name: Option<&str>) -> String {
    match wire_name {
        None => String::new(),
        Some("declared_not_measured") => "declared, not measured".to_owned(),
        Some("excluded") => "excluded (not applicable)".to_owned(),
        Some(other) => other.replace('_', " "),
    }
}

fn proofs(proofs: &[Proof]) -> String {
    let date = |on: Option<statement::LocalDate>| on.map_or_else(|| "null".to_owned(), |on| on.to_string());
    proofs
        .iter()
        .filter(|proof| proof.withdrawn_at.is_none())
        .map(|proof| {
            let what = if proof.kind == "file" {
                format!(
                    "file {} SHA-256 {}",
                    statement::or_null(proof.file_name.as_deref()),
                    statement::or_null(proof.sha256.as_deref())
                )
            } else {
                format!("link {}", statement::or_null(proof.link.as_deref()))
            };
            let until = proof.valid_until.map_or_else(String::new, |until| format!(", valid until {until}"));
            format!("{what}, performed on {}{until}", date(proof.performed_on))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn four_eyes(required: Option<bool>) -> &'static str {
    match required {
        None => "not signed off: no rule has applied yet",
        Some(true) => "required — the signer is none of the revision's authors",
        Some(false) => "not required — the platform's four-eyes setting was off at the sign-off",
    }
}

fn act(act: &Act) -> String {
    format!("{} at {}", act.by, statement::instant_text(act.at))
}
