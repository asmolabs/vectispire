#!/usr/bin/env python3
"""Mutation check of wave 1, checklists stage 1b: the workbook in crates/cp-checklists — the zip read as Java's stream
reads it and its guards, the hardened XML reader, the workbook reader, the layout, its proposal and the template
version, the renderer and its evidence sheet, DocumentZip, the statement and checklist.json. See README.md.
"""
import sys

import _runner

W = ["-p", "vectispire-cp-checklists", "--test", "workbook_reference_set"]
L = ["-p", "vectispire-cp-checklists", "--lib"]
WL = [W, L]
C = "crates/cp-checklists/src/"
R = C + "workbook_reader.rs"
Z = C + "zip_input.rs"
X = C + "safe_xml.rs"
Y = C + "layout.rs"
N = C + "renderer.rs"

# Equivalent, and removed: the rounding of a serial's tenth decimal on a tie — a second of the day over 86,400 never
# falls half-way at ten places (2^3·5^8·s/27), so half-even and half-up never differ; the order the sheets' ids are
# kept in (the largest wins whatever came first); a cell counted once when written twice, below any ceiling the set
# reaches; the objective cleared by a new domain, which every version of the set writes again; a row (or a cell)
# placed by its order alone numbered after an insert — it is numbered last + 1, and every pending row below that was
# flushed at the row before it, so the renderer's `inserted && r.is_none()` (Java's too) is never true.
MUTANTS = [
    # The zip, as the stream reads it.
    ("zip a non-local header ends it", Z, "if u32_at(header, 0) != LOCSIG {", "if false {", W),
    ("zip encrypted refused", Z, "if flag & 1 == 1 {\n            return Err(ZipError::Malformed);", "if false {\n            return Err(ZipError::Malformed);", W),
    ("zip descriptor only deflated", Z, "if method != DEFLATED {\n                return Err(ZipError::Malformed);", "if false {\n                return Err(ZipError::Malformed);", W),
    ("zip stored crc", Z, "if self.remaining == 0 && entry.crc != i64::from(self.crc.sum()) {", "if false {", W),
    ("zip deflated crc", Z, "if entry.size != written || entry.csize != read || entry.crc != i64::from(self.crc.sum()) {", "if entry.size != written || entry.csize != read {", W),
    ("zip unsigned descriptor pushed back", Z, "entry.size = i64::from(u32_at(descriptor, 8));\n                    self.pos = self.pos.saturating_sub(4);", "entry.size = i64::from(u32_at(descriptor, 8));", W),
    ("zip header ceiling", Z, "if CENHDR.saturating_add(name_units) > MAX_COMBINED_CEN_HEADER_SIZE {", "if false {", W),
    ("zip extra ceiling", Z, "if CENHDR.saturating_add(name_units).saturating_add(extra.len()) > MAX_COMBINED_CEN_HEADER_SIZE {", "if false {", W),
    ("zip zip64 sizes", Z, "        if tag == EXTID_ZIP64 && zip64 && size >= 16 {", "        if false {", W),
    # The reader's guards.
    ("reader entries ceiling", R, "if entries > i64::from(self.limits.max_entries) {", "if entries > i64::from(self.limits.max_entries) + 1 {", W),
    ("reader a name held twice", R, "if !seen.insert(key.clone()) {", "if false && !seen.insert(key.clone()) {", W),
    ("reader nested by name", R, "if ARCHIVE_SUFFIXES.iter().any(|suffix| key.ends_with(suffix)) {", "if false {", W),
    ("reader nested by head", R, "if head == b\"PK\\x03\\x04\" {", "if false {", W),
    ("reader entry ceiling", R, "if read > self.limits.max_entry_bytes {", "if false {", W),
    ("reader total ceiling", R, "if *inflated > self.limits.max_inflated_bytes {", "if false {", W),
    ("reader ratio grace", R, "&& read > self.limits.ratio_grace_bytes", "&& read >= self.limits.ratio_grace_bytes", W),
    ("reader ratio counted", R, "i64::from(self.limits.max_ratio).saturating_mul(compressed)", "i64::from(self.limits.max_ratio).saturating_mul(compressed).saturating_mul(1000)", W),
    ("reader macros by their part", R, "java::to_lower_root(&part.name).ends_with(\"vbaproject.bin\")", "false", W),
    ("reader external in any case", R, "java::strip(element.attribute(\"TargetMode\").unwrap_or(\"null\")).eq_ignore_ascii_case(\"external\")", "java::strip(element.attribute(\"TargetMode\").unwrap_or(\"null\")) == \"external\"", W),
    ("reader templates accepted", R, "if workbook_type != MAIN_SHEET && workbook_type != MAIN_TEMPLATE {", "if workbook_type != MAIN_SHEET {", W),
    ("reader sheets ceiling", R, "== i64::from(self.limits.max_sheets)", "> i64::from(self.limits.max_sheets)", W),
    ("reader strings ceiling", R, "== i64::from(self.max)", "== -1", W),
    ("reader phonetic reading left out", R, " && !self.open.iter().any(|name| name == \"rPh\")", "", W),
    ("reader cells ceiling", R, "if *self.cell_count > self.max_cells {", "if false {", W),
    ("reader implied cell follows", R, "None => implied(self.row, self.column.saturating_add(1), &self.what)?,", "None => implied(self.row, self.column, &self.what)?,", W),
    ("reader implied row follows", R, "None => self.row.saturating_add(1),", "None => self.row,", W),
    ("reader text ceiling", R, "if java::utf16_len(into).saturating_add(java::utf16_len(characters)) > MAX_CELL_TEXT {", "if java::utf16_len(into).saturating_add(java::utf16_len(characters)) >= MAX_CELL_TEXT {", W),
    ("reader true in any case", R, "stripped == \"1\" || stripped.eq_ignore_ascii_case(\"true\")", "stripped == \"1\" || stripped == \"true\"", W),
    ("reader cached boolean", R, "if self.kind.as_deref() == Some(\"b\") { bool_of(literal)", "if self.kind.as_deref() == Some(\"x\") { bool_of(literal)", W),
    ("reader workbook names only", R, "                            Some(_) => None,", "                            Some(_) => element.attribute(\"name\").map(str::to_owned),", W),
    ("reader percent escapes", R, "if let ('%', (Some(high), Some(low))) = (c, pair) {", "if let ('#', (Some(high), Some(low))) = (c, pair) {", WL),
    ("reader dot dot", R, "            \"..\" => {\n                segments.pop();\n            }", "            \"..\" => {}", WL),
    ("reader owner of rels", R, "Some((before, after)) => format!(\"{before}/{after}\"),", "Some(_) => without.to_owned(),", WL),
    ("reader hash map order", R, "    ordered.sort_by_key(|(bucket, index, _)| (*bucket, *index));\n", "", W),
    # The XML.
    ("xml doctype refused", X, "} else if self.rest().starts_with(\"<!DOCTYPE\") {", "} else if self.rest().starts_with(\"<!DOCTYPEX\") {", W),
    ("xml entities named", X, "            _ => Reference::Entity(name),", "            _ => Reference::Character('?'),", W),
    ("xml depth", X, "if depth > MAX_DEPTH {", "if depth > MAX_DEPTH + 10 {", W),
    ("xml attributes ceiling", X, "if attributes.len() > MAX_ATTRIBUTES {", "if attributes.len() > MAX_ATTRIBUTES + 1 {", W),
    ("xml declarations are no attributes", X, "if attribute == \"xmlns\" || attribute.starts_with(\"xmlns:\") {\n                continue;", "if false {\n                continue;", W),
    ("xml element budget", X, "if !budget.spend() {", "if false && !budget.spend() {", W),
    ("xml characters it carries", X, "'\\t' | '\\n' | '\\r' | '\\u{20}'..='\\u{D7FF}'", "'\\t' | '\\n' | '\\r' | '\\u{1}'..='\\u{D7FF}'", WL),
    ("xml ]]> in text", X, "if let Some(at) = run.find(\"]]>\") {", "if let Some(at) = run.find(\"]]]>\") {", W),
    ("xml unbound prefix", X, "if prefixed(&name) && self.namespace(&name).is_none() {", "if false {", W),
    ("xml repeated attribute", X, "if raw.iter().take(index).any(|(seen, _)| seen == attribute) {", "if false {", WL),
    ("xml repeated expanded name", X, "if !uri.is_empty() && expanded.iter().any(", "if false && expanded.iter().any(", W),
    ("xml repeated declaration", X, "if raw.iter().any(|(seen, _)| *seen == attribute) {", "if false {", W),
    ("xml reserved prefixes", X, "|| (prefix == \"xml\") != (value == XML_NAMESPACE)", "|| false", W),
    ("xml attribute whitespace", X, "                '\\t' | '\\n' => {\n                    value.push(' ');", "                '\\t' | '\\n' => {\n                    value.push(c);", W),
    ("xml line ends", X, "let normalize = |text: String| text.replace(\"\\r\\n\", \"\\n\").replace('\\r', \"\\n\");", "let normalize = |text: String| text;", W),
    ("xml utf-16 little endian", X, "} else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {\n        utf16(rest, u16::from_le_bytes)", "} else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {\n        utf16(rest, u16::from_be_bytes)", W),
    ("xml windows-1252", X, "\"WINDOWS-1252\" =>", "\"WINDOWS-1253\" =>", W),
    ("xml version 1.1", X, "1 => value == \"1.0\" || value == \"1.1\",", "1 => value == \"1.0\",", W),
    ("xml colon first is no prefix", X, "    name.find(':').is_some_and(|colon| colon > 0)", "    name.contains(':')", W),
    ("xml second colon", X, "if let Some(second) = name.match_indices(':').nth(1).map(|(at, _)| at) {", "if let Some(second) = name.match_indices(':').nth(2).map(|(at, _)| at) {", W),
    ("xml decode stops on the last good character", X, "position(&before, before.char_indices().next_back().map_or(0, |(at, _)| at))", "position(&before, before.len())", W),
    # The layout, its proposal, the version.
    ("layout header among the items", Y, "if (first_item_row..=last_item_row).contains(&written.row()) {", "if false {", W),
    ("layout rows ceiling", Y, "> i64::from(ChecklistLayout::MAX_ITEM_ROWS)", "> i64::from(ChecklistLayout::MAX_ITEM_ROWS) + 1", W),
    ("layout one column per letter", Y, "if let Some(other) = taken.get(&index) {", "if let Some(other) = taken.get(&index).filter(|_| false) {", W),
    ("layout one header per cell", Y, "if let Some(other) = taken.get(&cell.value()) {", "if let Some(other) = taken.get(&cell.value()).filter(|_| false) {", W),
    ("proposal widest rows", Y, "if columns.len() < widest || row <= read_through {", "if row <= read_through {", W),
    ("proposal identifier stepped over", Y, "            identifier_like(sheet, identifier, &block)? && grouped(sheet, after, &block)?\n", "            false\n", W),
    ("proposal title is no label", Y, "if merge.is_some_and(|range| range.width() >= MIN_TITLE_WIDTH) {", "if false {", W),
    ("proposal first of equals", Y, "if validated.is_none_or(|(_, best)| validation.cell_count() > best.cell_count()) {", "if validated.is_none_or(|(_, best)| validation.cell_count() >= best.cell_count()) {", W),
    ("version same key refused", Y, "if let Some(same) = by_key.get(&item.key) {", "if let Some(same) = by_key.get(&item.key).filter(|_| false) {", W),
    ("version id required", Y, "    if normalized.is_empty() {\n        return Err(refused(format!(\n            \"Row {row} has a control and no id", "    if false {\n        return Err(refused(format!(\n            \"Row {row} has a control and no id", W),
    # The renderer.
    ("render template hashed", N, "if sha256_hex_bytes(template) != statement.template.source_sha256 {", "if false {", W),
    ("render rows of the items only", N, "if line.row < layout.first_item_row() || line.row > layout.last_item_row() {", "if false {", W),
    ("render blank comment left out", N, "Some(Answer { comment: Some(comment), .. }) if !java::is_blank(comment) =>", "Some(Answer { comment: Some(comment), .. }) =>", W),
    ("render the workbook's epoch", N, "writes(layout, statement, book.date1904)?", "writes(layout, statement, false)?", W),
    ("render serial rounded", N, "std::cmp::Ordering::Greater => quotient.saturating_add(1),", "std::cmp::Ordering::Greater => quotient,", W),
    ("render chain dropped with its formula", N, "    if patch.formula_removed {", "    if false {", W),
    ("render a single-cell array writable", N, "&& !CellRange::parse(Some(&range)).is_some_and(|parsed| parsed.first() == parsed.last())", "", W),
    ("render formulas others depend on", N, "if !patcher.depended_on.is_empty() {", "if false {", W),
    ("render spans dropped", N, "            remove.push(\"spans\");\n", "", W),
    ("render dimension widened", N, "        if widened != written {", "        if false {", W),
    ("render style kept", N, "let style = raw_style(&tag);", "let style: Option<String> = None;", W),
    ("render byte order mark kept", N, "if self.entry(at).bytes.starts_with(&UTF8_BOM) {", "if false {", W),
    ("render utf-16 refused", N, "if bytes.starts_with(&[0xFE, 0xFF]) || bytes.starts_with(&[0xFF, 0xFE]) {", "if false {", W),
    ("render evidence name free in any case", N, "while taken.contains(&java::to_lower_root(&name)) {", "while taken.contains(&name) {", W),
    ("render sheet number", N, "let mut number = book.sheets.len().saturating_add(1);", "let mut number = book.sheets.len().saturating_add(2);", W),
    ("render sheet id wraps", N, "next_sheet_id: max_id.wrapping_add(1)", "next_sheet_id: max_id.saturating_add(1)", W),
    ("render sheet declares its prefix", N, "format!(\" xmlns:{prefix}=\\\"{}\\\"\", escape_attribute(uri))", "String::new()", W),
    ("evidence automatic by kind", N, "    let mut by = if answer.automatic() {", "    let mut by = if false {", W),
    ("evidence withdrawn proofs left out", N, "        .filter(|proof| proof.withdrawn_at.is_none())\n", "", W),
    ("evidence blank label left out", N, "Some(label) if !java::is_blank(label) => format!(\" ({label})\"),", "Some(label) => format!(\" ({label})\"),", W),
    # The text written, the archive, the statement.
    ("cursor what XML cannot carry dropped", C + "xml_cursor.rs", "            c if allowed(c) => escaped.push(c),\n            _ => {}", "            c => escaped.push(c),", WL),
    ("zip names flagged UTF-8", C + "document_zip.rs", "const USE_UTF8: u16 = 0x800;", "const USE_UTF8: u16 = 0;", W),
    ("zip deflated with a descriptor", C + "document_zip.rs", "(20, USE_UTF8 | 8, 8)", "(20, USE_UTF8, 8)", W),
    ("zip directories deflated", C + "document_zip.rs", "let stored = entry.stored && !entry.directory;", "let stored = entry.stored;", W),
    ("zip entry date", C + "document_zip.rs", "const ENTRY_DOS_TIME: u32 = (2 << 21) | (1 << 16);", "const ENTRY_DOS_TIME: u32 = (1 << 21) | (1 << 16);", W),
    ("statement arrays on one line", C + "statement.rs", "                    out.push_str(\", \");", "                    out.push_str(\",\");", W),
    ("statement Vectispire keeps its name", C + "statement.rs", "answered_by: if given.automatic() { given.answered_by.clone() } else { name(&given.answered_by) },", "answered_by: name(&given.answered_by),", W),
    ("list blank words left out", C + "workbook.rs", "                if !java::is_blank(word) {", "                if true {", W),
    ("list names followed", C + "workbook.rs", "return if indirections < 3 {", "return if indirections > 3 {", W),
    ("cell columns up to XFD", C + "cell.rs", "if !(1..=CellRef::MAX_ROW).contains(&row) || column > CellRef::MAX_COLUMN {", "if !(1..=CellRef::MAX_ROW).contains(&row) {", WL),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
