//! `XmlCursor`: the tags of an XML part one after the other, each with where it starts and ends in the text — what
//! the renderer needs to replace a few cells and leave every other byte of the part where it was.
//!
//! Only on parts the reader has already parsed through the hardened parser: this splits what is known to be
//! well-formed and resolves nothing but the five predefined entities and character references. Text between tags
//! is never tokenised. Offsets are byte offsets into the `&str`, where Java's are UTF-16 offsets into its string —
//! each side slices its own text with them, so what is written is the same.

use std::fmt::Write as _;

use vectispire_domain::java;

use crate::workbook_reader;
use crate::{Refused, refused};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Start,
    End,
    /// A self-closing tag: `<c r="A1"/>`.
    Empty,
}

/// An attribute as written: its qualified name, its value undecoded, and the quote around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attribute {
    pub(crate) name: String,
    pub(crate) raw: String,
    pub(crate) quote: char,
}

impl Attribute {
    pub(crate) fn value(&self) -> String {
        decode(&self.raw)
    }

    pub(crate) fn local(&self) -> &str {
        self.name.split_once(':').map_or(&self.name, |(_, local)| local)
    }

    /// A colon past the first character: `r:id`, not `:id`.
    pub(crate) fn prefixed(&self) -> bool {
        self.name.find(':').is_some_and(|colon| colon > 0)
    }
}

/// A tag of the part: `start` the offset of its `<`, `end` the offset just after its `>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tag {
    pub(crate) kind: Kind,
    pub(crate) name: String,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) attributes: Vec<Attribute>,
}

impl Tag {
    pub(crate) fn local(&self) -> &str {
        self.name.split_once(':').map_or(&self.name, |(_, local)| local)
    }

    /// The prefix with its colon — `x:` — or nothing: what a sibling written beside it uses.
    pub(crate) fn prefix(&self) -> &str {
        self.name.find(':').and_then(|colon| self.name.get(..=colon)).unwrap_or_default()
    }

    pub(crate) fn attribute(&self, qualified_name: &str) -> Option<String> {
        self.attributes.iter().find(|attribute| attribute.name == qualified_name).map(Attribute::value)
    }

    pub(crate) fn opens(&self) -> bool {
        self.kind != Kind::End
    }
}

pub(crate) struct XmlCursor<'a> {
    xml: &'a str,
    position: usize,
}

impl<'a> XmlCursor<'a> {
    pub(crate) fn new(xml: &'a str) -> XmlCursor<'a> {
        XmlCursor { xml, position: 0 }
    }

    /// The text between two offsets this cursor found; empty where they would not be char boundaries.
    fn slice(&self, from: usize, to: usize) -> &'a str {
        self.xml.get(from..to).unwrap_or_default()
    }

    fn from(&self, at: usize) -> &'a str {
        self.xml.get(at..).unwrap_or_default()
    }

    /// The next tag, comments, processing instructions and CDATA sections skipped; `None` at the end.
    pub(crate) fn next(&mut self) -> Result<Option<Tag>, Refused> {
        loop {
            let Some(found) = self.from(self.position).find('<') else {
                self.position = self.xml.len();
                return Ok(None);
            };
            let open = self.position.saturating_add(found);
            let rest = self.from(open);
            if rest.starts_with("<!--") {
                self.position = self.after(open, "-->")?;
            } else if rest.starts_with("<![CDATA[") {
                self.position = self.after(open, "]]>")?;
            } else if rest.starts_with("<?") {
                self.position = self.after(open, "?>")?;
            } else if rest.starts_with("<!") {
                return Err(refused("A part of the workbook carries a declaration the renderer does not read."));
            } else if let Some(tail) = rest.strip_prefix("</") {
                let Some((name, _)) = tail.split_once('>') else {
                    return Err(truncated());
                };
                // `</` and `>` around the name.
                let end = open.saturating_add(name.len()).saturating_add(3);
                self.position = end;
                return Ok(Some(Tag {
                    kind: Kind::End,
                    name: java::strip(name).to_owned(),
                    start: open,
                    end,
                    attributes: Vec::new(),
                }));
            } else {
                return self.start_tag(open).map(Some);
            }
        }
    }

    fn char_at(&self, i: usize) -> Option<char> {
        self.from(i).chars().next()
    }

    /// The offset past the characters from `i` that `keep` accepts.
    fn past(&self, i: usize, keep: impl Fn(char) -> bool) -> usize {
        let rest = self.from(i);
        i.saturating_add(rest.find(|c: char| !keep(c)).unwrap_or(rest.len()))
    }

    fn skip_whitespace(&self, i: usize) -> usize {
        self.past(i, java::is_whitespace)
    }

    fn start_tag(&mut self, open: usize) -> Result<Tag, Refused> {
        let name_start = open.saturating_add(1);
        let mut i = self.past(name_start, |c| !java::is_whitespace(c) && c != '/' && c != '>');
        let name = self.slice(name_start, i).to_owned();
        let mut attributes = Vec::new();
        loop {
            i = self.skip_whitespace(i);
            let Some(c) = self.char_at(i) else {
                return Err(truncated());
            };
            if c == '>' {
                self.position = i.saturating_add(1);
                return Ok(Tag { kind: Kind::Start, name, start: open, end: self.position, attributes });
            }
            if c == '/' && self.char_at(i.saturating_add(1)) == Some('>') {
                self.position = i.saturating_add(2);
                return Ok(Tag { kind: Kind::Empty, name, start: open, end: self.position, attributes });
            }
            let attribute_start = i;
            i = self.past(i, |c| c != '=' && !java::is_whitespace(c));
            let attribute = self.slice(attribute_start, i).to_owned();
            i = self.skip_whitespace(i);
            if self.char_at(i) != Some('=') {
                return Err(truncated());
            }
            i = self.skip_whitespace(i.saturating_add(1));
            let quote = match self.char_at(i) {
                Some(quote @ ('"' | '\'')) => quote,
                _ => return Err(truncated()),
            };
            let value_start = i.saturating_add(1);
            let Some((raw, _)) = self.from(value_start).split_once(quote) else {
                return Err(truncated());
            };
            attributes.push(Attribute { name: attribute, raw: raw.to_owned(), quote });
            i = value_start.saturating_add(raw.len()).saturating_add(1);
        }
    }

    fn after(&self, from: usize, terminator: &str) -> Result<usize, Refused> {
        self.from(from)
            .find(terminator)
            .map(|found| from.saturating_add(found).saturating_add(terminator.len()))
            .ok_or_else(truncated)
    }
}

fn truncated() -> Refused {
    refused("A part of the workbook ends inside a tag.")
}

/// A tag written again with some attributes set or removed and the others exactly as they were — their order,
/// their quotes, their escapes. `set` holds qualified names and new values, unescaped, appended when the tag lacked
/// them; `open` writes a self-closing tag as a start tag.
pub(crate) fn rewrite(tag: &Tag, set: &[(&str, String)], remove: &[&str], open: bool) -> String {
    let mut written = format!("<{}", tag.name);
    let mut done: Vec<&str> = Vec::new();
    for attribute in &tag.attributes {
        if remove.contains(&attribute.name.as_str()) {
            continue;
        }
        match set.iter().find(|(name, _)| *name == attribute.name) {
            Some((name, value)) => {
                let _ = write!(written, " {}=\"{}\"", attribute.name, escape_attribute(value));
                done.push(name);
            }
            None => {
                let _ = write!(written, " {}={}{}{}", attribute.name, attribute.quote, attribute.raw, attribute.quote);
            }
        }
    }
    for (name, value) in set {
        if !done.contains(name) {
            let _ = write!(written, " {name}=\"{}\"", escape_attribute(value));
        }
    }
    written.push_str(if tag.kind == Kind::Empty && !open { "/>" } else { ">" });
    written
}

/// The five predefined entities and character references; anything else is left as written.
pub(crate) fn decode(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_owned();
    }
    let mut decoded = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(c) = rest.chars().next() {
        let after = rest.get(c.len_utf8()..).unwrap_or_default();
        let reference = if c == '&' { after.split_once(';') } else { None };
        let replacement = reference.and_then(|(entity, beyond)| {
            let character = match entity {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => character_reference(entity),
            };
            character.map(|character| (character, beyond))
        });
        match replacement {
            Some((character, beyond)) => {
                decoded.push(character);
                rest = beyond;
            }
            None => {
                decoded.push(c);
                rest = after;
            }
        }
    }
    decoded
}

/// `Character.toString(Integer.parseInt(…))`: a sign is read and every digit `Character.digit` knows, as Java reads
/// them. A surrogate code point, which Java would write as a lone surrogate, is left as written: no Rust string
/// holds one, and the reader has refused a part carrying one already.
fn character_reference(entity: &str) -> Option<char> {
    let (digits, radix) = if let Some(hex) = entity.strip_prefix("#x").or_else(|| entity.strip_prefix("#X")) {
        (hex, 16)
    } else {
        (entity.strip_prefix('#')?, 10)
    };
    let value = parse_int(digits, radix)?;
    u32::try_from(value).ok().and_then(char::from_u32)
}

/// `Integer.parseInt(text, radix)`, `None` where Java throws.
fn parse_int(text: &str, radix: u32) -> Option<i32> {
    let (negative, digits) = if let Some(digits) = text.strip_prefix('-') {
        (true, digits)
    } else {
        (false, text.strip_prefix('+').unwrap_or(text))
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    for c in digits.chars() {
        let digit = if radix == 16 { workbook_reader::hex(c)? } else { java::digit(c)? };
        value = value.checked_mul(i64::from(radix))?.checked_add(i64::from(digit))?;
        if value > i64::from(i32::MAX).saturating_add(1) {
            return None;
        }
    }
    i32::try_from(if negative { value.checked_neg()? } else { value }).ok()
}

/// Text as an element's content: escaped, and without the characters XML 1.0 cannot carry at all — a control
/// character typed into a comment would otherwise make the whole part unreadable.
pub(crate) fn escape_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            c if allowed(c) => escaped.push(c),
            _ => {}
        }
    }
    escaped
}

pub(crate) fn escape_attribute(value: &str) -> String {
    escape_text(value).replace('"', "&quot;")
}

fn allowed(c: char) -> bool {
    matches!(c, '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn rewrites_a_tag_keeping_what_it_does_not_set() {
        let mut cursor = XmlCursor::new("<?xml version='1.0'?><!-- x --><x:row r='3' spans=\"1:2\" s=\"&amp;\"/>");
        let tag = cursor.next().unwrap().unwrap();
        assert_eq!((tag.kind, tag.local(), tag.prefix()), (Kind::Empty, "row", "x:"));
        assert_eq!(tag.attribute("s").as_deref(), Some("&"));
        assert_eq!(
            rewrite(&tag, &[("r", "4".to_owned()), ("t", "a\"<".to_owned())], &["spans"], true),
            "<x:row r=\"4\" s=\"&amp;\" t=\"a&quot;&lt;\">"
        );
        assert_eq!(decode("&#65;&#x42;&#+67;&bogus;&"), "ABC&bogus;&");
    }
}
