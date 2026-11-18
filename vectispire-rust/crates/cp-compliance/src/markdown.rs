//! The model's Markdown read once into blocks — Java's `OwaspMarkdown`, held to `reference/compliance/markdown.json`.
//!
//! **Blocks carry no markup.** The text is model prose derived from findings the audited repository wrote; a client
//! handed Markdown to render would interpret it, and one handed blocks places text into elements it chose. What is
//! not recognised becomes a paragraph rather than disappearing.
//!
//! **Java's regexes are reproduced by hand**, not translated: the emphasis rule looks behind, which the `regex` crate
//! cannot, and every pattern leans on two Java definitions Rust's do not share — `\s` is ASCII's six spaces, and `.`
//! refuses `\r`, U+0085, U+2028 and U+2029 as well as `\n`. A line holding one of those mid-text is a paragraph in
//! Java, not a bullet, and so it is here.

use serde::Serialize;
use vectispire_domain::{java, owasp_coverage};

/// What a block is. Deliberately few: this is a report, not a document format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Kind {
    Heading,
    /// A heading naming one of the Top 10 — what a reader scans the document for.
    Category,
    Paragraph,
    Bullet,
    Numbered,
    Blockquote,
    Table,
}

/// `OwaspMarkdown.Block`, every member written, a null included, in the record's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Block {
    pub kind: Kind,
    pub level: i32,
    pub marker: Option<String>,
    pub text: String,
    pub headers: Option<Vec<String>>,
    pub rows: Option<Vec<Vec<String>>>,
    pub category: Option<String>,
}

impl Block {
    fn plain(kind: Kind, marker: Option<String>, text: String) -> Block {
        Block { kind, level: 0, marker, text, headers: None, rows: None, category: None }
    }
}

/// `OwaspMarkdown.parse`.
pub fn parse(markdown: Option<&str>) -> Vec<Block> {
    let Some(markdown) = markdown.filter(|text| !java::is_blank(text)) else {
        return Vec::new();
    };
    let mut reader = Reader::default();
    // `split("\n", -1)`: the trailing empty lines kept, which only ever flush.
    for raw in markdown.split('\n') {
        reader.line(raw.trim_end_matches(java::is_whitespace));
    }
    reader.flush_paragraph();
    reader.flush_blockquote();
    reader.flush_table();
    reader.blocks
}

#[derive(Default)]
struct Reader {
    blocks: Vec<Block>,
    paragraph: String,
    blockquote: String,
    table: Vec<String>,
    /// Reset only by a blank line and by a line closing a table that has rows — a separator read with no row before it
    /// stays seen across prose, as Java's flag does.
    separator_seen: bool,
}

impl Reader {
    fn line(&mut self, line: &str) {
        if java::is_blank(line) {
            self.flush_paragraph();
            self.flush_blockquote();
            self.flush_table();
            self.separator_seen = false;
            return;
        }
        if is_table_row(line) {
            self.flush_paragraph();
            self.flush_blockquote();
            if is_table_separator(line) {
                self.separator_seen = true;
            } else {
                self.table.push(line.to_owned());
            }
            return;
        } else if !self.table.is_empty() {
            self.flush_table();
            self.separator_seen = false;
        }

        if let Some(quoted) = blockquote(line) {
            self.flush_paragraph();
            if !self.blockquote.is_empty() {
                self.blockquote.push(' ');
            }
            self.blockquote.push_str(java::strip(quoted));
            return;
        } else if !self.blockquote.is_empty() {
            self.flush_blockquote();
        }

        if let Some((level, text)) = heading(java::strip(line)) {
            self.flush_paragraph();
            let text = strip(text);
            let category = category_of(&text);
            self.blocks.push(Block {
                kind: if category.is_some() { Kind::Category } else { Kind::Heading },
                level,
                marker: None,
                text,
                headers: None,
                rows: None,
                category,
            });
            return;
        }
        if let Some(item) = bullet(line) {
            self.flush_paragraph();
            self.blocks.push(Block::plain(Kind::Bullet, None, strip(item)));
            return;
        }
        if let Some((number, item)) = numbered(line) {
            self.flush_paragraph();
            self.blocks.push(Block::plain(Kind::Numbered, Some(number.to_owned()), strip(item)));
            return;
        }
        // Consecutive lines are one paragraph, Markdown's own rule: a model hard-wraps its prose.
        if !self.paragraph.is_empty() {
            self.paragraph.push(' ');
        }
        self.paragraph.push_str(java::strip(line));
    }

    fn flush_paragraph(&mut self) {
        if !self.paragraph.is_empty() {
            let text = strip(&std::mem::take(&mut self.paragraph));
            self.blocks.push(Block::plain(Kind::Paragraph, None, text));
        }
    }

    fn flush_blockquote(&mut self) {
        if !self.blockquote.is_empty() {
            let text = strip(&std::mem::take(&mut self.blockquote));
            self.blocks.push(Block::plain(Kind::Blockquote, None, text));
        }
    }

    fn flush_table(&mut self) {
        let lines = std::mem::take(&mut self.table);
        let mut lines = lines.into_iter();
        let Some(first) = lines.next() else {
            return;
        };
        if self.separator_seen {
            self.blocks.push(Block {
                kind: Kind::Table,
                level: 0,
                marker: None,
                text: String::new(),
                headers: Some(cells(&first)),
                rows: Some(lines.map(|line| cells(&line)).collect()),
                category: None,
            });
        } else {
            for line in std::iter::once(first).chain(lines) {
                self.blocks.push(Block::plain(Kind::Paragraph, None, strip(&line)));
            }
        }
    }
}

/// Java's `\s`: six ASCII characters, not Unicode's spaces.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
}

/// What Java's `.` refuses without `DOTALL`.
fn is_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// `(.*)$` under `matches()`: the rest of the line, when `.` can read all of it.
fn dotted(rest: &str) -> Option<&str> {
    (!rest.chars().any(is_terminator)).then_some(rest)
}

/// `^(#{1,4})\s+(.*)$`, matched against the stripped line.
fn heading(line: &str) -> Option<(i32, &str)> {
    let after = line.trim_start_matches('#');
    let hashes = line.len().checked_sub(after.len())?;
    if !(1..=4).contains(&hashes) || !after.starts_with(is_space) {
        return None;
    }
    let level = i32::try_from(hashes).ok()?;
    dotted(after.trim_start_matches(is_space)).map(|text| (level, text))
}

/// `^\s*[-*+]\s+(.*)$`.
fn bullet(line: &str) -> Option<&str> {
    let after = line.trim_start_matches(is_space).strip_prefix(['-', '*', '+'])?;
    if !after.starts_with(is_space) {
        return None;
    }
    dotted(after.trim_start_matches(is_space))
}

/// `^\s*(\d+)[.)]\s+(.*)$`, `\d` being ASCII's ten digits.
fn numbered(line: &str) -> Option<(&str, &str)> {
    let start = line.trim_start_matches(is_space);
    let after_digits = start.trim_start_matches(|c: char| c.is_ascii_digit());
    let number = start.get(..start.len().checked_sub(after_digits.len())?)?;
    if number.is_empty() {
        return None;
    }
    let after = after_digits.strip_prefix(['.', ')'])?;
    if !after.starts_with(is_space) {
        return None;
    }
    dotted(after.trim_start_matches(is_space)).map(|item| (number, item))
}

/// `^\s*>\s?(.*)$`: the optional space is taken whenever it is there — a `\r` after the marker included, which `.`
/// could not have read.
fn blockquote(line: &str) -> Option<&str> {
    let after = line.trim_start_matches(is_space).strip_prefix('>')?;
    let mut chars = after.chars();
    let rest = match chars.next() {
        Some(c) if is_space(c) => chars.as_str(),
        _ => after,
    };
    dotted(rest)
}

/// `isTableRow`: between pipes once trimmed, and longer than two UTF-16 units.
fn is_table_row(line: &str) -> bool {
    let trimmed = java::trim(line);
    trimmed.starts_with('|') && trimmed.ends_with('|') && java::utf16_len(trimmed) > 2
}

/// `^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?$` on the trimmed line: two cells at least, each dashes with an optional colon
/// either side and spaces around, and one optional pipe at each end. A cell cannot begin or end with a pipe, so the
/// optional ones are exactly a pipe at either end — which makes `|---|`, one cell, no separator.
fn is_table_separator(line: &str) -> bool {
    let trimmed = java::trim(line);
    let body = trimmed.strip_prefix('|').unwrap_or(trimmed);
    let body = body.strip_suffix('|').unwrap_or(body);
    let mut cells = 0usize;
    for cell in body.split('|') {
        let inner = cell.trim_matches(is_space);
        let inner = inner.strip_prefix(':').unwrap_or(inner);
        let inner = inner.strip_suffix(':').unwrap_or(inner);
        if inner.is_empty() || !inner.chars().all(|c| c == '-') {
            return false;
        }
        cells = cells.saturating_add(1);
    }
    cells >= 2
}

/// `parseCells`: one pipe off each end of the trimmed line, then every cell between pipes, the empty ones kept.
fn cells(line: &str) -> Vec<String> {
    let trimmed = java::trim(line);
    let body = trimmed.strip_prefix('|').unwrap_or(trimmed);
    let body = body.strip_suffix('|').unwrap_or(body);
    body.split('|').map(|part| strip(java::trim(part))).collect()
}

/// `categoryOf`: the Top 10:2021 code the heading opens with — `A01` to `A10` not followed by a digit — or none.
pub fn category_of(heading: &str) -> Option<String> {
    let upper = java::to_upper_root(java::strip(heading));
    let mut chars = upper.chars();
    let code = match (chars.next(), chars.next(), chars.next()) {
        (Some('A'), Some('0'), Some(digit @ '1'..='9')) => format!("A0{digit}"),
        (Some('A'), Some('1'), Some('0')) => "A10".to_owned(),
        _ => return None,
    };
    if chars.next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    owasp_coverage::is_category(&code).then_some(code)
}

/// `OwaspMarkdown.strip`: bold, then italics, then code spans removed — each pass Java's `replaceAll` over the
/// previous one's result — and the whole stripped.
pub fn strip(value: &str) -> String {
    let bold = replace_all(value, bold_at);
    let italic = replace_all(&bold, italic_at);
    let code = replace_all(&italic, code_at);
    java::strip(&code).to_owned()
}

/// A match found at a position: the text that replaces it, and where the scan resumes.
type Found = Option<(String, usize)>;

/// `replaceAll` with a single group as the replacement: tried at each position left to right, resuming after a match.
fn replace_all(value: &str, at: fn(&[char], usize) -> Found) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::with_capacity(value.len());
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        match at(&chars, i) {
            Some((group, next)) => {
                out.push_str(&group);
                i = next;
            }
            None => {
                out.push(c);
                i = i.saturating_add(1);
            }
        }
    }
    out
}

fn collect(chars: &[char], from: usize, to: usize) -> String {
    chars.get(from..to).map(|run| run.iter().collect()).unwrap_or_default()
}

fn is(chars: &[char], at: usize, wanted: char) -> bool {
    chars.get(at) == Some(&wanted)
}

/// `\*\*(.+?)\*\*`.
fn bold_at(chars: &[char], i: usize) -> Found {
    if !is(chars, i, '*') || !is(chars, i.checked_add(1)?, '*') {
        return None;
    }
    let from = i.checked_add(2)?;
    lazily(chars, from, |k| is(chars, k, '*') && is(chars, k.saturating_add(1), '*'))
        .map(|end| (collect(chars, from, end), end.saturating_add(2)))
}

/// `(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)`: a lone star either side, the lookbehinds reading the input as it stands.
fn italic_at(chars: &[char], i: usize) -> Found {
    let lone = |k: usize| {
        is(chars, k, '*')
            && !k.checked_sub(1).is_some_and(|before| is(chars, before, '*'))
            && !is(chars, k.saturating_add(1), '*')
    };
    if !lone(i) {
        return None;
    }
    let from = i.checked_add(1)?;
    lazily(chars, from, lone).map(|end| (collect(chars, from, end), end.saturating_add(1)))
}

/// ``` `([^`]+)` ```: the class reads line terminators, so the span runs to the next backtick whatever lies between.
fn code_at(chars: &[char], i: usize) -> Found {
    if !is(chars, i, '`') {
        return None;
    }
    let from = i.checked_add(1)?;
    let length = chars.get(from..)?.iter().position(|&c| c == '`')?;
    if length == 0 {
        return None;
    }
    let end = from.checked_add(length)?;
    Some((collect(chars, from, end), end.saturating_add(1)))
}

/// `(.+?)` followed by a closing test: the first position past at least one readable character where `closes` holds,
/// every character before it one `.` reads.
fn lazily(chars: &[char], from: usize, closes: impl Fn(usize) -> bool) -> Option<usize> {
    let mut k = from;
    loop {
        if k > from && closes(k) {
            return Some(k);
        }
        let c = *chars.get(k)?;
        if is_terminator(c) {
            return None;
        }
        k = k.checked_add(1)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emphasis_is_removed_as_java_removes_it() {
        assert_eq!(strip("**bold** and *it* and `code`"), "bold and it and code");
        assert_eq!(strip("a*b*c"), "abc");
        assert_eq!(strip("**unclosed"), "**unclosed");
        assert_eq!(strip("``"), "``");
    }

    #[test]
    fn a_category_is_a_code_not_followed_by_a_digit() {
        assert_eq!(category_of("a01 lower").as_deref(), Some("A01"));
        assert_eq!(category_of("A10:2021 – SSRF").as_deref(), Some("A10"));
        assert_eq!(category_of("A100"), None);
        assert_eq!(category_of("A011"), None);
        assert_eq!(category_of("A00"), None);
    }
}
