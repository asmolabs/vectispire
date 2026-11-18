//! `SafeXml` as the workbook reader uses it (`Doctype.REFUSED`): a part read as a stream of elements, resolving
//! nothing, every refusal an `InvalidTemplateException` in the reader's words.
//!
//! **Hand-written, strict, and the JDK's parser is the reference.** The Java side reads through the JDK's StAX
//! parser with DTD support off; this is a non-validating XML 1.0 parser with namespaces that refuses what that
//! parser refuses — a DOCTYPE outright, an entity other than the five predefined ones, a character XML cannot
//! carry, a name, prefix or attribute that is not well-formed — and hands the handler the same events: an
//! element's local name and its attributes (namespace declarations are not attributes, as in StAX), the end of an
//! element, and its character data with line ends and attribute whitespace normalised as XML requires. The
//! sentences are SafeXml's; where a malformed part is refused, the position named is this parser's (README).

use vectispire_domain::java;

use crate::{Refused, refused};

pub(crate) const MAX_DEPTH: usize = 64;
pub(crate) const MAX_ATTRIBUTES: usize = 64;

const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

/// `SafeXml.Budget`: how many elements an upload may still hold, whatever the number of documents in it.
pub(crate) struct Budget {
    max: i64,
    whole: &'static str,
    left: i64,
}

impl Budget {
    pub(crate) fn new(max: i64, whole: &'static str) -> Budget {
        Budget { max, whole, left: max }
    }

    fn spend(&mut self) -> bool {
        self.left = self.left.saturating_sub(1);
        self.left >= 0
    }
}

/// An attribute as the handler sees it: its qualified name, local name and normalised value.
pub(crate) struct Attribute {
    pub(crate) local: String,
    pub(crate) value: String,
}

/// An element as it starts.
pub(crate) struct Element<'a> {
    pub(crate) name: &'a str,
    pub(crate) attributes: &'a [Attribute],
}

impl Element<'_> {
    /// `getAttributeValue(null, name)`: the first attribute of that local name, in any namespace.
    pub(crate) fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|attribute| attribute.local == name).map(|attribute| attribute.value.as_str())
    }
}

pub(crate) trait Handler {
    fn start(&mut self, element: &Element<'_>) -> Result<(), Refused>;

    fn end(&mut self, _name: &str) -> Result<(), Refused> {
        Ok(())
    }

    /// Character data inside an element, possibly in several chunks.
    fn text(&mut self, _characters: &str) -> Result<(), Refused> {
        Ok(())
    }
}

/// Reads one document to its end, calling the handler on every element.
pub(crate) fn read(bytes: &[u8], what: &str, budget: &mut Budget, handler: &mut dyn Handler) -> Result<(), Refused> {
    let text = decode(bytes).map_err(|undecodable| {
        let (line, column) = match undecodable {
            // The JDK's reader hands over what it decoded before the bad bytes and fails on the next read, which
            // its scanner makes when one character is left: it stops on the last good character, not past it.
            Undecodable::After(before) => position(&before, before.char_indices().next_back().map_or(0, |(at, _)| at)),
            // An encoding it does not read is refused once the declaration naming it is read.
            Undecodable::Declared(declaration) => position(&declaration, declaration.len()),
        };
        refused(format!("{what} is not well-formed XML (line {line}, column {column})."))
    })?;
    let mut parser = Parser { text: &text, pos: 0, what, scopes: Vec::new(), open: Vec::new() };
    match parser.document(budget, handler) {
        Ok(()) => Ok(()),
        Err(Stop::Refused(refusal)) => Err(refusal),
        Err(Stop::Malformed(offset)) => Err(malformed_at(what, &text, offset)),
    }
}

/// `SafeXml.malformed`: where the parser stopped, never its message.
fn malformed_at(what: &str, text: &str, offset: usize) -> Refused {
    let (line, column) = position(text, offset);
    refused(format!("{what} is not well-formed XML (line {line}, column {column})."))
}

/// Line and column of a byte offset, both from 1, the column in UTF-16 units as the JDK counts them.
fn position(text: &str, offset: usize) -> (usize, usize) {
    let before = text.get(..offset).unwrap_or(text);
    let current = before.rsplit_once('\n').map_or(before, |(_, current)| current);
    let line = before.matches('\n').count().saturating_add(1);
    (line, java::utf16_len(current).saturating_add(1))
}

/// Why a part's bytes do not decode: a byte the encoding cannot read, after these characters; or an encoding the
/// reader does not read, named by this declaration.
enum Undecodable {
    After(String),
    Declared(String),
}

/// The part's characters, line ends normalised (`\r\n` and a lone `\r` read as `\n`, as XML requires before
/// anything else). UTF-8, with or without its BOM, is what Office writes; UTF-16 by its BOM or its first bytes,
/// ISO-8859-1, US-ASCII and windows-1252 by the declaration are read as the JDK reads them; any other declared encoding
/// — and UTF-16 declared without its mark — is refused once the declaration is read. The JDK reads every encoding
/// its runtime knows; Office writes none of the others (README).
fn decode(bytes: &[u8]) -> Result<String, Undecodable> {
    let decoded = if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        utf8(rest)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, u16::from_be_bytes)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, u16::from_le_bytes)
    } else if bytes.starts_with(&[0x00, 0x3C, 0x00, 0x3F]) {
        utf16(bytes, u16::from_be_bytes)
    } else if bytes.starts_with(&[0x3C, 0x00, 0x3F, 0x00]) {
        utf16(bytes, u16::from_le_bytes)
    } else {
        match declared_encoding(bytes) {
            None => utf8(bytes),
            Some((name, declaration)) => match name.to_ascii_uppercase().as_str() {
                "UTF-8" => utf8(bytes),
                "ISO-8859-1" => Ok(bytes.iter().map(|&byte| char::from(byte)).collect()),
                "WINDOWS-1252" => Ok(bytes.iter().map(|&byte| windows_1252(byte)).collect()),
                "US-ASCII" | "ASCII" => {
                    let valid = bytes.iter().position(|byte| !byte.is_ascii()).unwrap_or(bytes.len());
                    let text: String = bytes.iter().take(valid).map(|&byte| char::from(byte)).collect();
                    if valid < bytes.len() { Err(text) } else { Ok(text) }
                }
                _ => return Err(Undecodable::Declared(declaration)),
            },
        }
    };
    let normalize = |text: String| text.replace("\r\n", "\n").replace('\r', "\n");
    decoded.map(normalize).map_err(|before| Undecodable::After(normalize(before)))
}

fn utf8(bytes: &[u8]) -> Result<String, String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| String::from_utf8_lossy(bytes.get(..error.valid_up_to()).unwrap_or_default()).into_owned())
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<String, String> {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|pair| unit(*pair)).collect();
    let mut text = String::new();
    for decoded in char::decode_utf16(units.iter().copied()) {
        match decoded {
            Ok(c) => text.push(c),
            Err(_) => return Err(text),
        }
    }
    if bytes.len().is_multiple_of(2) { Ok(text) } else { Err(text) }
}

/// windows-1252: Latin-1 but for 0x80–0x9F, five of which it leaves undefined and Java reads as U+FFFD.
fn windows_1252(byte: u8) -> char {
    const HIGH: [u16; 32] = [
        0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFD,
        0x017D, 0xFFFD, 0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A,
        0x0153, 0xFFFD, 0x017E, 0x0178,
    ];
    match byte {
        0x80..=0x9F => HIGH
            .get(usize::from(byte.saturating_sub(0x80)))
            .and_then(|&unit| char::from_u32(u32::from(unit)))
            .unwrap_or('\u{FFFD}'),
        _ => char::from(byte),
    }
}

/// The `encoding` pseudo-attribute of an XML declaration written in ASCII, and the declaration up to its `?>`.
fn declared_encoding(bytes: &[u8]) -> Option<(String, String)> {
    let head = bytes.get(..bytes.len().min(200))?;
    let head: String = head.iter().take_while(|byte| byte.is_ascii()).map(|&byte| char::from(byte)).collect();
    let body = head.strip_prefix("<?xml")?;
    let (declaration, _) = body.split_once("?>")?;
    let (_, rest) = declaration.split_once("encoding")?;
    let rest = rest.trim_start_matches([' ', '\t', '\n', '\r']);
    let rest = rest.strip_prefix('=')?.trim_start_matches([' ', '\t', '\n', '\r']);
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let (value, _) = rest.strip_prefix(quote)?.split_once(quote)?;
    let whole = format!("<?xml{declaration}?>").replace("\r\n", "\n").replace('\r', "\n");
    Some((value.to_owned(), whole))
}

enum Stop {
    /// A refusal in the caller's words, raised by a bound or the handler.
    Refused(Refused),
    /// Not well-formed at this byte offset.
    Malformed(usize),
}

impl From<Refused> for Stop {
    fn from(refusal: Refused) -> Stop {
        Stop::Refused(refusal)
    }
}

type Step<T> = Result<T, Stop>;

struct Parser<'t> {
    text: &'t str,
    pos: usize,
    what: &'t str,
    /// The namespace bindings in force, innermost last, each with the depth that declared it.
    scopes: Vec<(usize, String, String)>,
    /// The qualified names of the open elements.
    open: Vec<String>,
}

impl<'t> Parser<'t> {
    fn rest(&self) -> &'t str {
        self.slice(self.pos, self.text.len())
    }

    /// The text between two offsets of this parser; empty where they are not char boundaries, which they always are.
    fn slice(&self, from: usize, to: usize) -> &'t str {
        self.text.get(from..to).unwrap_or_default()
    }

    fn advance(&mut self, by: usize) {
        self.pos = self.pos.saturating_add(by).min(self.text.len());
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn malformed<T>(&self) -> Step<T> {
        Err(Stop::Malformed(self.pos))
    }

    fn eat(&mut self, literal: &str) -> bool {
        if self.rest().starts_with(literal) {
            self.advance(literal.len());
            true
        } else {
            false
        }
    }

    fn expect(&mut self, literal: &str) -> Step<()> {
        if self.eat(literal) { Ok(()) } else { self.malformed() }
    }

    /// `S`: XML's four whitespace characters; whether any was read.
    fn whitespace(&mut self) -> bool {
        let start = self.pos;
        while let Some(c) = self.peek().filter(|c| matches!(c, ' ' | '\t' | '\n')) {
            self.advance(c.len_utf8());
        }
        self.pos > start
    }

    fn document(&mut self, budget: &mut Budget, handler: &mut dyn Handler) -> Step<()> {
        if self.rest().starts_with("<?xml")
            && self.rest().get(5..).unwrap_or_default().starts_with([' ', '\t', '\n', '?'])
        {
            self.declaration()?;
        }
        // The prolog: whitespace, comments and processing instructions; a DOCTYPE is refused where it is met.
        loop {
            self.whitespace();
            if self.rest().starts_with("<!--") {
                self.comment()?;
            } else if self.rest().starts_with("<?") {
                self.processing_instruction()?;
            } else if self.rest().starts_with("<!DOCTYPE") {
                return Err(refused(format!(
                    "{} carries a DOCTYPE declaration, which this format never needs; it is not read.",
                    self.what
                ))
                .into());
            } else if self.rest().starts_with('<') && !self.rest().starts_with("<!") {
                break;
            } else {
                return self.malformed();
            }
        }
        self.content(budget, handler)?;
        // After the root: whitespace, comments and processing instructions only.
        loop {
            self.whitespace();
            if self.pos == self.text.len() {
                return Ok(());
            }
            if self.rest().starts_with("<!--") {
                self.comment()?;
            } else if self.rest().starts_with("<?") {
                self.processing_instruction()?;
            } else {
                // Markup after the root is read as far as `<` or `<!` before the JDK refuses it.
                self.advance(if self.rest().starts_with("<!") { 2 } else { usize::from(self.rest().starts_with('<')) });
                return self.malformed();
            }
        }
    }

    /// `<?xml version="1.0" encoding="…" standalone="…"?>`, its pseudo-attributes in that order.
    fn declaration(&mut self) -> Step<()> {
        self.advance("<?xml".len());
        let mut seen = 0;
        loop {
            let spaced = self.whitespace();
            if self.eat("?>") {
                return if seen == 0 { self.malformed() } else { Ok(()) };
            }
            if !spaced {
                return self.malformed();
            }
            let name = self.name()?;
            // A pseudo-attribute out of place is judged once its value is read, where the JDK stops.
            let order = match name {
                "version" if seen == 0 => 1,
                "encoding" if (1..2).contains(&seen) => 2,
                "standalone" if (1..3).contains(&seen) => 3,
                _ => 0,
            };
            self.whitespace();
            self.expect("=")?;
            self.whitespace();
            let quote = match self.peek() {
                Some(quote @ ('"' | '\'')) => quote,
                _ => return self.malformed(),
            };
            self.advance(1);
            let Some(end) = self.rest().find(quote) else {
                return self.malformed();
            };
            let value = self.slice(self.pos, self.pos.saturating_add(end));
            self.advance(end.saturating_add(1));
            let valid = match order {
                0 => false,
                1 => value == "1.0" || value == "1.1",
                2 => {
                    value.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
                        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                }
                _ => value == "yes" || value == "no",
            };
            if !valid {
                return self.malformed();
            }
            seen = order;
        }
    }

    fn comment(&mut self) -> Step<()> {
        self.advance("<!--".len());
        let Some(end) = self.rest().find("--") else {
            self.pos = self.text.len();
            return self.malformed();
        };
        self.characters(end)?;
        self.advance(end.saturating_add(2));
        if !self.eat(">") {
            return self.malformed();
        }
        Ok(())
    }

    fn processing_instruction(&mut self) -> Step<()> {
        self.advance("<?".len());
        let target = self.name()?;
        if target.contains(':') || target.eq_ignore_ascii_case("xml") {
            return self.malformed();
        }
        if self.eat("?>") {
            return Ok(());
        }
        if !self.whitespace() {
            return self.malformed();
        }
        let Some(end) = self.rest().find("?>") else {
            self.pos = self.text.len();
            return self.malformed();
        };
        self.characters(end)?;
        self.advance(end.saturating_add(2));
        Ok(())
    }

    /// The next `length` bytes are characters XML can carry, or the parser stops at the first that is not.
    fn characters(&mut self, length: usize) -> Step<()> {
        let span = self.slice(self.pos, self.pos.saturating_add(length));
        if let Some((offset, _)) = span.char_indices().find(|(_, c)| !is_char(*c)) {
            self.advance(offset);
            return self.malformed();
        }
        Ok(())
    }

    /// A `Name`: where it starts must be a name's first character.
    fn name(&mut self) -> Step<&'t str> {
        let start = self.pos;
        match self.peek() {
            Some(c) if is_name_start(c) => self.advance(c.len_utf8()),
            _ => return self.malformed(),
        }
        while let Some(c) = self.peek().filter(|c| is_name_char(*c)) {
            self.advance(c.len_utf8());
        }
        Ok(self.slice(start, self.pos))
    }

    /// A `QName` as the JDK's scanner reads one: it stops at a second colon, which is then where it refuses the
    /// tag; a name ending with its colon has no local part.
    fn qualified_name(&mut self) -> Step<String> {
        let start = self.pos;
        let name = self.name()?;
        if let Some(second) = name.match_indices(':').nth(1).map(|(at, _)| at) {
            self.pos = start.saturating_add(second);
            return self.malformed();
        }
        if !qualified(name) {
            return self.malformed();
        }
        Ok(name.to_owned())
    }

    /// The root element and everything in it.
    fn content(&mut self, budget: &mut Budget, handler: &mut dyn Handler) -> Step<()> {
        let mut text = String::new();
        loop {
            let Some(c) = self.peek() else {
                return self.malformed();
            };
            if c != '<' && c != '&' {
                let end = self.rest().find(['<', '&']).unwrap_or(self.rest().len());
                let run = self.slice(self.pos, self.pos.saturating_add(end));
                if let Some(at) = run.find("]]>") {
                    // The JDK stops past the `]]>`, unless a character it cannot carry comes first.
                    self.characters(at)?;
                    self.advance(at.saturating_add(3));
                    return self.malformed();
                }
                self.characters(end)?;
                text.push_str(run);
                self.advance(end);
                continue;
            }
            if c == '&' {
                let reference = self.reference()?;
                match reference {
                    Reference::Character(character) => text.push(character),
                    Reference::Entity(name) => {
                        return Err(refused(format!(
                            "{} refers to the entity &{name}; — entities are not expanded.",
                            self.what
                        ))
                        .into());
                    }
                }
                continue;
            }
            if self.rest().starts_with("<![CDATA[") {
                self.advance("<![CDATA[".len());
                let Some(end) = self.rest().find("]]>") else {
                    self.pos = self.text.len();
                    return self.malformed();
                };
                self.characters(end)?;
                text.push_str(self.slice(self.pos, self.pos.saturating_add(end)));
                self.advance(end.saturating_add(3));
                continue;
            }
            self.flush(&mut text, handler)?;
            if self.rest().starts_with("<!--") {
                self.comment()?;
            } else if self.rest().starts_with("<?") {
                self.processing_instruction()?;
            } else if self.rest().starts_with("<!") {
                self.advance(2);
                return self.malformed();
            } else if self.rest().starts_with("</") {
                self.end_tag(handler)?;
                if self.open.is_empty() {
                    return Ok(());
                }
            } else if self.start_tag(budget, handler)? && self.open.is_empty() {
                return Ok(());
            }
        }
    }

    fn flush(&self, text: &mut String, handler: &mut dyn Handler) -> Step<()> {
        if !text.is_empty() {
            handler.text(text)?;
            text.clear();
        }
        Ok(())
    }

    /// `&…;` in text: a character reference read, a predefined entity replaced, any other entity named.
    fn reference(&mut self) -> Step<Reference> {
        self.advance(1);
        if self.eat("#") {
            let hex = self.eat("x");
            let start = self.pos;
            let digits =
                self.rest().bytes().take_while(|b| if hex { b.is_ascii_hexdigit() } else { b.is_ascii_digit() });
            let length = digits.count();
            let value = u32::from_str_radix(self.slice(start, start.saturating_add(length)), if hex { 16 } else { 10 });
            self.advance(length);
            if length == 0 {
                return self.malformed();
            }
            self.expect(";")?;
            // The JDK judges the character past the semicolon.
            let Some(character) = value.ok().and_then(char::from_u32).filter(|c| is_char(*c)) else {
                return self.malformed();
            };
            return Ok(Reference::Character(character));
        }
        let name = self.name()?.to_owned();
        self.expect(";")?;
        Ok(match name.as_str() {
            "lt" => Reference::Character('<'),
            "gt" => Reference::Character('>'),
            "amp" => Reference::Character('&'),
            "quot" => Reference::Character('"'),
            "apos" => Reference::Character('\''),
            _ => Reference::Entity(name),
        })
    }

    /// A start tag; true when it was empty (`<c/>`), its end already reported.
    fn start_tag(&mut self, budget: &mut Budget, handler: &mut dyn Handler) -> Step<bool> {
        self.advance(1);
        let name = self.qualified_name()?;
        let mut raw: Vec<(String, String)> = Vec::new();
        let empty = loop {
            let spaced = self.whitespace();
            if self.eat("/>") {
                break true;
            }
            if self.eat(">") {
                break false;
            }
            if !spaced {
                return self.malformed();
            }
            let attribute = self.qualified_name()?;
            self.whitespace();
            self.expect("=")?;
            self.whitespace();
            let value = self.attribute_value()?;
            // A declaration is judged as it is read, where the JDK stops; a repeated name once the tag is read.
            if let Some(prefix) = declared_prefix(&attribute) {
                if raw.iter().any(|(seen, _)| *seen == attribute) {
                    return self.malformed();
                }
                let reserved = prefix.is_empty() && attribute != "xmlns"
                    || prefix.contains(':')
                    || prefix == "xmlns"
                    || (prefix == "xml") != (value == XML_NAMESPACE)
                    || value == XMLNS_NAMESPACE
                    || (!prefix.is_empty() && value.is_empty());
                if reserved {
                    return self.malformed();
                }
            }
            raw.push((attribute, value));
        };
        for (index, (attribute, _)) in raw.iter().enumerate() {
            if raw.iter().take(index).any(|(seen, _)| seen == attribute) {
                return self.malformed();
            }
        }
        let depth = self.open.len().saturating_add(1);
        // Namespace declarations first: they bind the element's own prefix and its attributes'.
        for (attribute, value) in &raw {
            if let Some(prefix) = declared_prefix(attribute) {
                self.scopes.push((depth, prefix.to_owned(), value.clone()));
            }
        }
        if prefixed(&name) && self.namespace(&name).is_none() {
            return self.malformed();
        }
        let mut attributes: Vec<Attribute> = Vec::new();
        let mut expanded: Vec<(String, String)> = Vec::new();
        for (attribute, value) in raw {
            if attribute == "xmlns" || attribute.starts_with("xmlns:") {
                continue;
            }
            let (local, uri) = match attribute.split_once(':') {
                Some((_, local)) if prefixed(&attribute) => match self.namespace(&attribute) {
                    Some(uri) => (local.to_owned(), uri),
                    None => return self.malformed(),
                },
                Some((_, local)) => (local.to_owned(), String::new()),
                None => (attribute.clone(), String::new()),
            };
            if !uri.is_empty() && expanded.iter().any(|(seen_uri, seen_local)| *seen_uri == uri && *seen_local == local)
            {
                return self.malformed();
            }
            expanded.push((uri, local.clone()));
            attributes.push(Attribute { local, value });
        }
        if depth > MAX_DEPTH {
            return Err(refused(format!("{} nests elements deeper than {MAX_DEPTH}.", self.what)).into());
        }
        if attributes.len() > MAX_ATTRIBUTES {
            return Err(
                refused(format!("{} has an element with more than {MAX_ATTRIBUTES} attributes.", self.what)).into()
            );
        }
        if !budget.spend() {
            return Err(refused(format!("{} holds more than {} XML elements.", budget.whole, budget.max)).into());
        }
        let local = local_of(&name).to_owned();
        handler.start(&Element { name: &local, attributes: &attributes })?;
        self.open.push(name);
        if empty {
            self.close(handler)?;
        }
        Ok(empty)
    }

    /// An attribute's value, quoted, its references read and its whitespace characters each one space.
    fn attribute_value(&mut self) -> Step<String> {
        let quote = match self.peek() {
            Some(quote @ ('"' | '\'')) => quote,
            _ => return self.malformed(),
        };
        self.advance(1);
        let mut value = String::new();
        loop {
            let Some(c) = self.peek() else {
                return self.malformed();
            };
            if c == quote {
                self.advance(1);
                return Ok(value);
            }
            match c {
                '<' => return self.malformed(),
                '&' => match self.reference()? {
                    Reference::Character(character) => value.push(character),
                    // No entity is declared, so a reference to one is undeclared: not well-formed, the JDK
                    // stopping past its semicolon.
                    Reference::Entity(_) => return self.malformed(),
                },
                '\t' | '\n' => {
                    value.push(' ');
                    self.advance(1);
                }
                _ if !is_char(c) => return self.malformed(),
                _ => {
                    value.push(c);
                    self.advance(c.len_utf8());
                }
            }
        }
    }

    fn end_tag(&mut self, handler: &mut dyn Handler) -> Step<()> {
        self.advance(2);
        let start = self.pos;
        let name = self.name()?;
        if self.open.last().map(String::as_str) != Some(name) {
            self.pos = start;
            return self.malformed();
        }
        self.whitespace();
        self.expect(">")?;
        self.close(handler)
    }

    fn close(&mut self, handler: &mut dyn Handler) -> Step<()> {
        let depth = self.open.len();
        if let Some(name) = self.open.pop() {
            handler.end(local_of(&name))?;
        }
        self.scopes.retain(|(declared, _, _)| *declared < depth);
        Ok(())
    }

    /// The namespace a prefixed name's prefix is bound to; `None` when it is bound to none.
    fn namespace(&self, name: &str) -> Option<String> {
        let (prefix, _) = name.split_once(':')?;
        if prefix == "xml" {
            return Some(XML_NAMESPACE.to_owned());
        }
        self.scopes.iter().rev().find(|(_, bound, _)| bound == prefix).map(|(_, _, uri)| uri.clone())
    }
}

enum Reference {
    Character(char),
    Entity(String),
}

/// The prefix a namespace declaration binds — empty for the default namespace — or `None` for an attribute.
fn declared_prefix(attribute: &str) -> Option<&str> {
    if attribute == "xmlns" { Some("") } else { attribute.strip_prefix("xmlns:") }
}

fn local_of(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, local)| local)
}

/// A `QName` as the JDK's scanner splits it: one colon at most, a local part after it. A colon first is no prefix
/// at all — `<:a>` is the element `a` — which the scanner accepts.
fn qualified(name: &str) -> bool {
    match name.split_once(':') {
        None => true,
        Some((_, local)) => {
            !local.is_empty() && !local.contains(':') && local.chars().next().is_some_and(is_name_start)
        }
    }
}

/// A prefix before the colon, which must be bound.
fn prefixed(name: &str) -> bool {
    name.find(':').is_some_and(|colon| colon > 0)
}

/// `Char` of XML 1.0: a Rust `char` is never a surrogate, so what is left out is the C0 controls but tab, line feed
/// and carriage return, and U+FFFE and U+FFFF.
fn is_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

fn is_name_start(c: char) -> bool {
    matches!(c, ':' | 'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}'
        | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}'
        | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start(c) || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[derive(Default)]
    struct Events(Vec<String>);

    impl Handler for Events {
        fn start(&mut self, element: &Element<'_>) -> Result<(), Refused> {
            let attributes: Vec<String> =
                element.attributes.iter().map(|attribute| format!("{}={}", attribute.local, attribute.value)).collect();
            self.0.push(format!("<{} {}>", element.name, attributes.join(" ")));
            Ok(())
        }

        fn end(&mut self, name: &str) -> Result<(), Refused> {
            self.0.push(format!("</{name}>"));
            Ok(())
        }

        fn text(&mut self, characters: &str) -> Result<(), Refused> {
            self.0.push(characters.to_owned());
            Ok(())
        }
    }

    fn events(xml: &str) -> Result<Vec<String>, Refused> {
        let mut events = Events::default();
        read(xml.as_bytes(), "Part p", &mut Budget::new(100, "The workbook"), &mut events)?;
        Ok(events.0)
    }

    #[test]
    fn reads_elements_attributes_and_text() {
        assert_eq!(
            events("<?xml version=\"1.0\"?>\n<a xmlns:r=\"u\" r:id=\"x\tz\"><b/>t&amp;&#65;<![CDATA[<c>]]></a>")
                .unwrap(),
            vec!["<a id=x z>", "<b >", "</b>", "t&A<c>", "</a>"]
        );
    }

    #[test]
    fn refuses_what_is_not_well_formed() {
        for xml in ["<a><b></a>", "<a", "", "<a/><b/>", "<p:a/>", "<a x='1' x='2'/>", "<a>&#1;</a>", "x<a/>"] {
            let refusal = events(xml).unwrap_err();
            assert!(refusal.0.starts_with("Part p is not well-formed XML (line "), "{xml}: {refusal}");
        }
        assert!(events("<!DOCTYPE a><a/>").unwrap_err().0.contains("DOCTYPE"));
        assert!(events("<a>&e;</a>").unwrap_err().0.contains("&e;"));
    }
}
