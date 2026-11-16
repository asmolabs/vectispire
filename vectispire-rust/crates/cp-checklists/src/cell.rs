//! A sheet's grid as the workbook states it: `CellRef`, `CellRange`, `CellValue`, `ListValidation` and `HeaderCell`.

use std::cmp::Ordering;
use std::fmt;

use vectispire_domain::java;

use crate::{Refused, refused};

/// `CellRef`: a cell by column and row, both from 1 — `B12` is column 2, row 12. Ordered row by row, then left to
/// right: the order a sheet is read in, and the order a worksheet part lists its cells in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CellRef {
    column: i32,
    row: i32,
}

impl CellRef {
    /// The grid of the file format itself: column `XFD`, row 1,048,576.
    pub const MAX_COLUMN: i32 = 16_384;
    pub const MAX_ROW: i32 = 1_048_576;

    /// `new CellRef(column, row)`, refused outside the grid in Java's sentence.
    pub fn new(column: i32, row: i32) -> Result<CellRef, Refused> {
        if !(1..=CellRef::MAX_COLUMN).contains(&column) || !(1..=CellRef::MAX_ROW).contains(&row) {
            return Err(refused(format!("Column {column}, row {row} is outside a sheet.")));
        }
        Ok(CellRef { column, row })
    }

    pub fn column(self) -> i32 {
        self.column
    }

    pub fn row(self) -> i32 {
        self.row
    }

    /// `B12`, `$B$12`; `None` for anything else, a whole column or row included.
    pub fn parse(reference: Option<&str>) -> Option<CellRef> {
        let text = java::strip(reference?).replace('$', "");
        let split = text.bytes().take_while(u8::is_ascii_alphabetic).count();
        // The letters are ASCII, so `split` is a char boundary; what follows must be ASCII digits, so a byte
        // count past it agrees with Java's UTF-16 length wherever the answer is not "none".
        let (letters, rest) = text.split_at_checked(split)?;
        if split == 0 || split > 3 || rest.is_empty() || rest.len() > 7 {
            return None;
        }
        let mut row = 0i32;
        for byte in rest.bytes() {
            if !byte.is_ascii_digit() {
                return None;
            }
            row = row.checked_mul(10)?.checked_add(i32::from(byte.checked_sub(b'0')?))?;
        }
        let column = column_index(letters);
        if !(1..=CellRef::MAX_ROW).contains(&row) || column > CellRef::MAX_COLUMN {
            return None;
        }
        Some(CellRef { column, row })
    }

    /// `CellRef.column(letters)`: a column's letters as a person types them (`f` or `F`); `None` otherwise.
    pub fn column_of(letters: Option<&str>) -> Option<i32> {
        let text = java::strip(letters.unwrap_or(""));
        if text.is_empty() || java::utf16_len(text) > 3 || !text.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return None;
        }
        let column = column_index(text);
        (column <= CellRef::MAX_COLUMN).then_some(column)
    }

    /// `CellRef.letters`: `1` is `A`, `27` is `AA`; empty for a column below 1.
    pub fn letters(column: i32) -> String {
        let mut letters = Vec::new();
        let mut n = column;
        while let Some(below) = n.checked_sub(1).filter(|_| n > 0) {
            let offset = u8::try_from(below.rem_euclid(26)).unwrap_or(0);
            letters.push(char::from(b'A'.saturating_add(offset)));
            n = below.div_euclid(26);
        }
        letters.iter().rev().collect()
    }

    pub fn column_letters(self) -> String {
        CellRef::letters(self.column)
    }
}

/// Upper-cased ASCII letters to a column index; at most three, so it never saturates.
fn column_index(letters: &str) -> i32 {
    letters.bytes().fold(0i32, |column, byte| {
        let digit = i32::from(byte.to_ascii_uppercase().saturating_sub(b'A')).saturating_add(1);
        column.saturating_mul(26).saturating_add(digit)
    })
}

impl Ord for CellRef {
    fn cmp(&self, other: &CellRef) -> Ordering {
        self.row.cmp(&other.row).then(self.column.cmp(&other.column))
    }
}

impl PartialOrd for CellRef {
    fn partial_cmp(&self, other: &CellRef) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for CellRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.column_letters(), self.row)
    }
}

/// `CellRange`: a rectangle of cells, its corners included — a merged cell, a validation's range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CellRange {
    first: CellRef,
    last: CellRef,
}

impl CellRange {
    /// Two corners in any order, held as the top left and the bottom right.
    pub fn new(first: CellRef, last: CellRef) -> CellRange {
        if first.column > last.column || first.row > last.row {
            let top_left = CellRef { column: first.column.min(last.column), row: first.row.min(last.row) };
            let bottom_right = CellRef { column: first.column.max(last.column), row: first.row.max(last.row) };
            return CellRange { first: top_left, last: bottom_right };
        }
        CellRange { first, last }
    }

    pub fn first(self) -> CellRef {
        self.first
    }

    pub fn last(self) -> CellRef {
        self.last
    }

    /// `A1:G1`, or a single cell as a range of one; `None` for anything else.
    pub fn parse(reference: Option<&str>) -> Option<CellRange> {
        let corners: Vec<&str> = java::strip(reference?).split(':').collect();
        match corners.as_slice() {
            [single] => CellRef::parse(Some(single)).map(|cell| CellRange::new(cell, cell)),
            [first, last] => Some(CellRange::new(CellRef::parse(Some(first))?, CellRef::parse(Some(last))?)),
            _ => None,
        }
    }

    /// A list of ranges separated by whitespace, as a validation's `sqref` holds them; unreadable ones left out.
    /// `split("\\s+")` splits on ASCII whitespace only, after `strip`.
    pub fn parse_list(references: Option<&str>) -> Vec<CellRange> {
        let Some(references) = references else {
            return Vec::new();
        };
        java::strip(references)
            .split([' ', '\t', '\n', '\u{b}', '\u{c}', '\r'])
            .filter_map(|reference| CellRange::parse(Some(reference)))
            .collect()
    }

    pub fn contains(self, cell: CellRef) -> bool {
        (self.first.column..=self.last.column).contains(&cell.column)
            && (self.first.row..=self.last.row).contains(&cell.row)
    }

    pub fn width(self) -> i32 {
        self.last.column.saturating_sub(self.first.column).saturating_add(1)
    }

    pub fn height(self) -> i32 {
        self.last.row.saturating_sub(self.first.row).saturating_add(1)
    }
}

impl fmt::Display for CellRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last { write!(f, "{}", self.first) } else { write!(f, "{}:{}", self.first, self.last) }
    }
}

/// `CellValue`: what a cell holds, as the file states it. **A formula is a formula**: its expression and the value
/// the last program to save the file cached beside it, never evaluated (decision 0032 §11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellValue {
    /// A string, shared or inline.
    Text(String),
    /// A number as written in the file — a date too, as the serial the sheet stores. Never parsed.
    Number(String),
    Bool(bool),
    /// An error value the sheet stored, `#N/A` or `#REF!`.
    Error(String),
    /// `expression` without its leading `=` (empty for a cell sharing another's formula); `cached` the result the
    /// saving program stored, when it stored one.
    Formula {
        expression: String,
        cached: Option<String>,
    },
}

impl CellValue {
    /// The value as a person reading the sheet sees it; a formula shows its cached result, or nothing.
    pub fn text(&self) -> &str {
        match self {
            CellValue::Text(text) | CellValue::Number(text) | CellValue::Error(text) => text,
            CellValue::Bool(true) => "TRUE",
            CellValue::Bool(false) => "FALSE",
            CellValue::Formula { cached, .. } => cached.as_deref().unwrap_or(""),
        }
    }
}

/// `ListValidation`: a list data validation of a sheet — the cells it covers, and the formula naming the allowed
/// values (`source`, without a leading `=`). `from_extension` when read from the `x14` extension, where Excel writes
/// a list pointing at another sheet and a mainstream reader drops it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListValidation {
    pub ranges: Vec<CellRange>,
    pub source: String,
    pub from_extension: bool,
}

impl ListValidation {
    /// It covers exactly one column: the answer column's shape.
    pub fn single_column(&self) -> bool {
        let Some(first) = self.ranges.first() else {
            return false;
        };
        self.ranges.iter().all(|range| range.width() == 1 && range.first.column == first.first.column)
    }

    /// The cells it covers, summed over its ranges as Java sums them — in an `int`, which wraps.
    pub fn cell_count(&self) -> i32 {
        self.ranges.iter().fold(0i32, |sum, range| sum.wrapping_add(range.width().wrapping_mul(range.height())))
    }
}

/// `HeaderCell.Field`: the three entries a checklist's header carries (decision 0032 §2), in Java's enum order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field {
    /// In a document, the sign-off instant written as a value — never "now", never a formula.
    Date,
    /// The project's name.
    Product,
    /// The account responsible for the checklist.
    Author,
}

impl Field {
    pub const ALL: [Field; 3] = [Field::Date, Field::Product, Field::Author];

    pub fn wire_name(self) -> &'static str {
        match self {
            Field::Date => "date",
            Field::Product => "product",
            Field::Author => "author",
        }
    }
}

/// `HeaderCell`: a header entry's label cell, which the renderer leaves alone, and the value cell it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderCell {
    label: CellRef,
    value: CellRef,
}

impl HeaderCell {
    pub fn new(label: CellRef, value: CellRef) -> Result<HeaderCell, Refused> {
        if label == value {
            return Err(refused(format!("A header's value cell cannot be its label cell, {label}.")));
        }
        Ok(HeaderCell { label, value })
    }

    pub fn label(self) -> CellRef {
        self.label
    }

    pub fn value(self) -> CellRef {
        self.value
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn letters_count_from_a_as_one() {
        assert_eq!(CellRef::letters(1), "A");
        assert_eq!(CellRef::letters(26), "Z");
        assert_eq!(CellRef::letters(27), "AA");
        assert_eq!(CellRef::letters(16_384), "XFD");
        assert_eq!(CellRef::parse(Some(" $b$12 ")), Some(CellRef::new(2, 12).unwrap()));
        assert_eq!(CellRef::parse(Some("XFE1")), None);
        assert_eq!(CellRef::parse(Some("A0")), None);
        assert_eq!(CellRef::parse(Some("A")), None);
    }
}
