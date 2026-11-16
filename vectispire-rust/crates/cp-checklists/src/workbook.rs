//! `Workbook` and `Sheet`: a template workbook as read from its `.xlsx` — its worksheets in the workbook's order and
//! the names it defines. What this model does not carry (styles, comments, drawings, extensions other than a list
//! validation) is not lost: the renderer copies every part of the source byte for byte and rewrites a few cells.

use std::collections::BTreeMap;

use vectispire_domain::java;

use crate::Failure as ReadFailure;
use crate::cell::{CellRange, CellRef, CellValue, ListValidation};
use crate::workbook_reader;

/// `Sheet`: one worksheet as the reader found it — the cells that hold something, the merged ranges, the list
/// validations. Blank cells are absent: a styled empty cell holds nothing to read.
#[derive(Clone, PartialEq, Eq)]
pub struct Sheet {
    pub name: String,
    pub cells: BTreeMap<CellRef, CellValue>,
    pub merged: Vec<CellRange>,
    pub validations: Vec<ListValidation>,
}

impl Sheet {
    pub fn value(&self, cell: CellRef) -> Option<&CellValue> {
        self.cells.get(&cell)
    }

    /// The cell's text as a reader sees it; empty for a blank cell.
    pub fn text(&self, cell: CellRef) -> &str {
        self.cells.get(&cell).map_or("", CellValue::text)
    }

    /// Blank as a person sees it, and holding no formula.
    pub fn blank(&self, cell: CellRef) -> bool {
        java::is_blank(self.text(cell)) && !matches!(self.cells.get(&cell), Some(CellValue::Formula { .. }))
    }

    /// The cells of one row, left to right.
    pub fn row(&self, row: i32) -> impl Iterator<Item = (&CellRef, &CellValue)> {
        let first = CellRef::new(1, row).ok();
        let last = CellRef::new(CellRef::MAX_COLUMN, row).ok();
        first.zip(last).into_iter().flat_map(move |(first, last)| self.cells.range(first..=last))
    }

    /// The merged range a cell lies in, when it lies in one — the first the sheet lists.
    pub fn merged_at(&self, cell: CellRef) -> Option<CellRange> {
        self.merged.iter().copied().find(|range| range.contains(cell))
    }

    pub fn last_row(&self) -> i32 {
        self.cells.keys().next_back().map_or(0, |cell| cell.row())
    }
}

/// Its name and size: a sheet's cells are the organisation's text, and have no place in a log line.
impl std::fmt::Debug for Sheet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sheet[{}, {} cells]", self.name, self.cells.len())
    }
}

/// `Workbook.Limits`: the ceilings the reader holds a file to, each checked as the bytes are read rather than taken
/// from what the file says of itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Entries in the zip; a workbook of three sheets has about fifteen.
    pub max_entries: i32,
    /// One entry inflated.
    pub max_entry_bytes: i64,
    /// Every entry inflated, together (decision 0032 §3: 50 MB).
    pub max_inflated_bytes: i64,
    /// How much larger than its compressed bytes an entry may inflate (§3: 100 to one).
    pub max_ratio: i32,
    /// How much an entry inflates before its ratio is judged: a small part compresses far better than 100 to one.
    pub ratio_grace_bytes: i64,
    /// XML elements, across every part read.
    pub max_elements: i64,
    pub max_sheets: i32,
    /// Cells holding a value, across every sheet.
    pub max_cells: i32,
    pub max_shared_strings: i32,
}

impl Limits {
    pub const DEFAULT: Limits = Limits {
        max_entries: 200,
        max_entry_bytes: 20 * 1024 * 1024,
        max_inflated_bytes: 50 * 1024 * 1024,
        max_ratio: 100,
        ratio_grace_bytes: 100 * 1024,
        max_elements: 5_000_000,
        max_sheets: 64,
        max_cells: 1_000_000,
        max_shared_strings: 1_000_000,
    };
}

/// `Workbook`: the file's SHA-256 (lowercase hex), its worksheets in order, and its workbook-scoped defined names
/// with their formulas, without a leading `=` — in the order the workbook first names them, a repeat replacing the
/// value in place, as `LinkedHashMap.put` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workbook {
    pub sha256: String,
    pub sheets: Vec<Sheet>,
    pub defined_names: Vec<(String, String)>,
}

impl Workbook {
    /// `Workbook.read(file, maxBytes)` under the default limits.
    pub fn read(file: &[u8], max_bytes: i64) -> Result<Workbook, ReadFailure> {
        Workbook::read_with(file, max_bytes, Limits::DEFAULT)
    }

    /// `Workbook.read(file, maxBytes, limits)`: refused past a guard, not an `.xlsx`, a legacy, OpenDocument,
    /// binary or macro-enabled workbook, an external relationship, a DOCTYPE, malformed XML.
    pub fn read_with(file: &[u8], max_bytes: i64, limits: Limits) -> Result<Workbook, ReadFailure> {
        workbook_reader::read(file, max_bytes, limits)
    }

    pub fn sheet(&self, name: &str) -> Option<&Sheet> {
        self.sheets.iter().find(|sheet| sheet.name == name)
    }

    pub fn defined_name(&self, name: &str) -> Option<&str> {
        self.defined_names.iter().find(|(defined, _)| defined == name).map(|(_, formula)| formula.as_str())
    }

    /// The values a list validation allows, in the list's order, blanks and repeats left out — what the preview
    /// offers the importer to map to yes, no and not applicable. Empty when the formula is not one this reads: a
    /// literal list, a range on a sheet of this workbook, or a defined name standing for one. Formulas are not
    /// evaluated. `on` is the sheet a range without a sheet is read against.
    pub fn list_values(&self, validation: &ListValidation, on: &Sheet) -> Vec<String> {
        self.values(java::strip(&validation.source), on, 0)
    }

    fn values(&self, formula: &str, on: &Sheet, indirections: u32) -> Vec<String> {
        let source = formula.strip_prefix('=').map_or(formula, java::strip);
        if let Some(inner) = quoted(source, '"') {
            let mut words: Vec<String> = Vec::new();
            for word in split_java(&inner.replace("\"\"", "\""), ',') {
                if !java::is_blank(word) {
                    push_once(&mut words, java::strip(word));
                }
            }
            return words;
        }
        if let Some(name) = self.defined_name(source) {
            // A name standing for a name is legal; one standing for itself would never end.
            return if indirections < 3 { self.values(name, on, indirections.saturating_add(1)) } else { Vec::new() };
        }
        let mut target = on;
        let mut range = source;
        if let Some((sheet_name, after)) = source.rsplit_once('!') {
            let sheet_name =
                quoted(sheet_name, '\'').map_or_else(|| sheet_name.to_owned(), |inner| inner.replace("''", "'"));
            let Some(named) = self.sheet(&sheet_name) else {
                return Vec::new();
            };
            target = named;
            range = after;
        }
        let Some(area) = CellRange::parse(Some(range)) else {
            return Vec::new();
        };
        let mut words: Vec<String> = Vec::new();
        // Walked over the cells the sheet holds, not over the range's grid: A1:A1048576 is a legal list.
        for (cell, value) in target.cells.range(area.first()..=area.last()) {
            if area.contains(*cell) && !java::is_blank(value.text()) {
                push_once(&mut words, java::strip(value.text()));
            }
        }
        words
    }
}

/// What lies between a leading and a trailing `quote`, when the text is at least two characters long and has both.
fn quoted(text: &str, quote: char) -> Option<&str> {
    text.strip_prefix(quote)?.strip_suffix(quote)
}

/// `LinkedHashSet.add`: kept at its first place.
fn push_once(words: &mut Vec<String>, word: &str) {
    if !words.iter().any(|kept| kept == word) {
        words.push(word.to_owned());
    }
}

/// `String.split(String.valueOf(separator))`: trailing empty strings removed, as Java removes them.
pub(crate) fn split_java(text: &str, separator: char) -> Vec<&str> {
    let mut parts: Vec<&str> = text.split(separator).collect();
    while parts.len() > 1 && parts.last().is_some_and(|part| part.is_empty()) {
        parts.pop();
    }
    if parts.len() == 1 && parts.first().is_some_and(|part| part.is_empty()) && !text.is_empty() {
        parts.clear();
    }
    parts
}
