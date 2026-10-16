//! JSON as Jackson serves it: **key order and number text kept**, which `serde_json::Value` loses.
//!
//! The control plane's responses are compared with what the Java application served, and two
//! things that a `Value` comparison forgets are part of that contract: the order of an object's
//! keys (the generated client reads them in document order, a CSV export and a signed document are
//! byte-exact) and the text of a number (`1` and `1.0` are two answers). This module parses into a
//! tree that keeps both and compares two trees, reporting where they differ.
//!
//! It is strict where Jackson is strict (no trailing content, no raw control character in a string,
//! no leading zero) and keeps a duplicated key as two entries, since Jackson's default is to accept
//! it and the last one wins in a tree.

use std::fmt;

/// The nesting a document may have before it is refused — the limit `serde_json` applies too, so
/// that a hostile body is refused the same way by both readers.
pub const MAX_DEPTH: usize = 128;

/// A JSON document with its key order and number spelling kept.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// The number as written: `1`, `1.0` and `1e0` are three values.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    /// Entries in document order; a duplicated key is two entries.
    Obj(Vec<(String, Json)>),
}

/// Why a text is not a JSON document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not JSON at byte {offset}: {message}")]
pub struct ParseError {
    pub offset: usize,
    pub message: &'static str,
}

impl Json {
    /// Reads one document; anything after it, whitespace aside, is an error.
    pub fn parse(text: &str) -> Result<Json, ParseError> {
        let mut reader = Reader { bytes: text.as_bytes(), at: 0 };
        reader.skip_whitespace();
        let value = reader.value(0)?;
        reader.skip_whitespace();
        if reader.at != reader.bytes.len() {
            return Err(reader.fail("content after the document"));
        }
        Ok(value)
    }

    /// The value of `key` in an object — the last entry of that name, as a Jackson tree keeps it.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(entries) => entries.iter().rev().find(|(name, _)| name == key).map(|(_, value)| value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(entries) => Some(entries),
            _ => None,
        }
    }

    /// The same document as text, compact, in the order it holds — for a message or a body to send.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
            Json::Num(text) => out.push_str(text),
            Json::Str(text) => write_string(text, out),
            Json::Arr(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(entries) => {
                out.push('{');
                for (index, (name, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_string(name, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Json::Null => "null",
            Json::Bool(_) => "boolean",
            Json::Num(_) => "number",
            Json::Str(_) => "string",
            Json::Arr(_) => "array",
            Json::Obj(_) => "object",
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                // Jackson writes the hexadecimal digits of an escape in upper case.
                out.push_str(&format!("\\u{:04X}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn fail(&self, message: &'static str) -> ParseError {
        ParseError { offset: self.at, message }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.at) == Some(&expected) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn keyword(&mut self, word: &'static str, value: Json) -> Result<Json, ParseError> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(self.fail("not a JSON value"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.fail("nested too deep"));
        }
        match self.bytes.get(self.at) {
            None => Err(self.fail("the document ends early")),
            Some(b'n') => self.keyword("null", Json::Null),
            Some(b't') => self.keyword("true", Json::Bool(true)),
            Some(b'f') => self.keyword("false", Json::Bool(false)),
            Some(b'"') => self.string().map(Json::Str),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.fail("not a JSON value")),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.at += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.eat(b']') {
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b']') {
                return Ok(Json::Arr(items));
            }
            return Err(self.fail("expected a comma or the end of the array"));
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.at += 1;
        let mut entries = Vec::new();
        self.skip_whitespace();
        if self.eat(b'}') {
            return Ok(Json::Obj(entries));
        }
        loop {
            self.skip_whitespace();
            if self.bytes.get(self.at) != Some(&b'"') {
                return Err(self.fail("expected a key"));
            }
            let name = self.string()?;
            self.skip_whitespace();
            if !self.eat(b':') {
                return Err(self.fail("expected a colon"));
            }
            self.skip_whitespace();
            entries.push((name, self.value(depth + 1)?));
            self.skip_whitespace();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b'}') {
                return Ok(Json::Obj(entries));
            }
            return Err(self.fail("expected a comma or the end of the object"));
        }
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.at;
        self.eat(b'-');
        match self.bytes.get(self.at) {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.fail("a number needs a digit")),
        }
        if self.eat(b'.') {
            if !matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                return Err(self.fail("a fraction needs a digit"));
            }
            self.digits();
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                return Err(self.fail("an exponent needs a digit"));
            }
            self.digits();
        }
        // The slice is ASCII digits and signs only, so it is valid UTF-8.
        let text = String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned();
        Ok(Json::Num(text))
    }

    fn digits(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
            self.at += 1;
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let Some(&byte) = self.bytes.get(self.at) else {
                return Err(self.fail("the string never ends"));
            };
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    out.push(self.escape()?);
                }
                0..=0x1F => return Err(self.fail("a raw control character in a string")),
                _ => {
                    // Copy the whole UTF-8 sequence: the input is a `&str`, so it is well formed.
                    let rest = &self.bytes[self.at..];
                    let width = utf8_width(byte);
                    let end = width.min(rest.len());
                    out.push_str(&String::from_utf8_lossy(&rest[..end]));
                    self.at += end;
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, ParseError> {
        let Some(&byte) = self.bytes.get(self.at) else {
            return Err(self.fail("the string never ends"));
        };
        self.at += 1;
        Ok(match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let high = self.hex4()?;
                if (0xD800..0xDC00).contains(&high) {
                    // A pair needs its second half; a lone half is kept as the replacement
                    // character, which is what a Rust `String` can hold (Jackson would keep the
                    // half itself — a difference no response of the control plane produces).
                    if self.bytes[self.at..].starts_with(b"\\u") {
                        let saved = self.at;
                        self.at += 2;
                        let low = self.hex4()?;
                        if (0xDC00..0xE000).contains(&low) {
                            let code = 0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                            return Ok(char::from_u32(code).unwrap_or('\u{FFFD}'));
                        }
                        self.at = saved;
                    }
                    '\u{FFFD}'
                } else {
                    char::from_u32(high).unwrap_or('\u{FFFD}')
                }
            }
            _ => {
                self.at -= 1;
                return Err(self.fail("an escape JSON does not have"));
            }
        })
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let Some(digits) = self.bytes.get(self.at..self.at + 4) else {
            return Err(self.fail("a \\u escape needs four digits"));
        };
        let mut code = 0u32;
        for digit in digits {
            let Some(value) = (*digit as char).to_digit(16) else {
                return Err(self.fail("a \\u escape needs four hexadecimal digits"));
            };
            code = code * 16 + value;
        }
        self.at += 4;
        Ok(code)
    }
}

fn utf8_width(first: u8) -> usize {
    match first {
        0xF0..=0xFF => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    }
}

/// How two documents are compared.
#[derive(Clone, Copy, Debug)]
pub struct Compare {
    /// The order of an object's keys is part of the answer.
    pub key_order: bool,
    /// How two numbers are equal.
    pub numbers: Numbers,
}

impl Default for Compare {
    fn default() -> Self {
        Compare { key_order: true, numbers: Numbers::Text }
    }
}

/// When two numbers are the same number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Numbers {
    /// Only when written alike: `1` and `1.0` differ, as they do on the wire.
    Text,
    /// When they have the same value: `1` and `1.0` agree. For a test that does not pin the format.
    Value,
}

/// One place where two documents differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Difference {
    /// A JSON Pointer to the place, `""` for the root.
    pub pointer: String,
    pub kind: DifferenceKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DifferenceKind {
    /// The expected document has it and the actual one does not.
    Missing,
    /// The actual document has it and the expected one does not.
    Extra,
    /// Not the same kind of value.
    Type { expected: &'static str, actual: &'static str },
    /// The same kind of value, not the same value.
    Value { expected: String, actual: String },
    /// An array of another length.
    Length { expected: usize, actual: usize },
    /// The same keys in another order.
    KeyOrder { expected: Vec<String>, actual: Vec<String> },
}

impl fmt::Display for Difference {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let at = if self.pointer.is_empty() { "the document" } else { &self.pointer };
        match &self.kind {
            DifferenceKind::Missing => write!(out, "{at}: expected, absent"),
            DifferenceKind::Extra => write!(out, "{at}: present, not expected"),
            DifferenceKind::Type { expected, actual } => write!(out, "{at}: a {actual}, expected a {expected}"),
            DifferenceKind::Value { expected, actual } => write!(out, "{at}: {actual}, expected {expected}"),
            DifferenceKind::Length { expected, actual } => {
                write!(out, "{at}: {actual} elements, expected {expected}")
            }
            DifferenceKind::KeyOrder { expected, actual } => {
                write!(out, "{at}: keys in the order {actual:?}, expected {expected:?}")
            }
        }
    }
}

/// Every place where `actual` is not `expected`, in document order. Empty means identical under
/// `how`.
#[must_use]
pub fn compare(expected: &Json, actual: &Json, how: Compare) -> Vec<Difference> {
    let mut found = Vec::new();
    walk(expected, actual, how, &mut String::new(), &mut found);
    found
}

fn walk(expected: &Json, actual: &Json, how: Compare, pointer: &mut String, found: &mut Vec<Difference>) {
    let here = |kind| Difference { pointer: pointer.clone(), kind };
    match (expected, actual) {
        (Json::Null, Json::Null) => {}
        (Json::Bool(left), Json::Bool(right)) if left == right => {}
        (Json::Str(left), Json::Str(right)) if left == right => {}
        (Json::Num(left), Json::Num(right)) => {
            let same = match how.numbers {
                Numbers::Text => left == right,
                Numbers::Value => same_number(left, right),
            };
            if !same {
                found.push(here(DifferenceKind::Value { expected: left.clone(), actual: right.clone() }));
            }
        }
        (Json::Bool(left), Json::Bool(right)) => {
            found.push(here(DifferenceKind::Value { expected: left.to_string(), actual: right.to_string() }));
        }
        (Json::Str(left), Json::Str(right)) => {
            found.push(here(DifferenceKind::Value { expected: format!("{left:?}"), actual: format!("{right:?}") }));
        }
        (Json::Arr(left), Json::Arr(right)) => {
            if left.len() != right.len() {
                found.push(here(DifferenceKind::Length { expected: left.len(), actual: right.len() }));
            }
            for (index, (one, other)) in left.iter().zip(right).enumerate() {
                let mark = pointer.len();
                pointer.push_str(&format!("/{index}"));
                walk(one, other, how, pointer, found);
                pointer.truncate(mark);
            }
        }
        (Json::Obj(left), Json::Obj(right)) => object(left, right, how, pointer, found),
        (left, right) => {
            found.push(here(DifferenceKind::Type { expected: left.kind(), actual: right.kind() }));
        }
    }
}

fn object(
    expected: &[(String, Json)],
    actual: &[(String, Json)],
    how: Compare,
    pointer: &mut String,
    found: &mut Vec<Difference>,
) {
    let names = |entries: &[(String, Json)]| {
        let mut seen: Vec<String> = Vec::new();
        for (name, _) in entries {
            if !seen.contains(name) {
                seen.push(name.clone());
            }
        }
        seen
    };
    let expected_names = names(expected);
    let actual_names = names(actual);
    let last = |entries: &'_ [(String, Json)], key: &str| -> Option<Json> {
        entries.iter().rev().find(|(name, _)| name == key).map(|(_, value)| value.clone())
    };
    let mut keys_agree = true;
    for name in &expected_names {
        let mark = pointer.len();
        pointer.push('/');
        pointer.push_str(&escape_pointer(name));
        match (last(expected, name), last(actual, name)) {
            (Some(one), Some(other)) => walk(&one, &other, how, pointer, found),
            (Some(_), None) => {
                keys_agree = false;
                found.push(Difference { pointer: pointer.clone(), kind: DifferenceKind::Missing });
            }
            _ => {}
        }
        pointer.truncate(mark);
    }
    for name in &actual_names {
        if !expected_names.contains(name) {
            keys_agree = false;
            let mark = pointer.len();
            pointer.push('/');
            pointer.push_str(&escape_pointer(name));
            found.push(Difference { pointer: pointer.clone(), kind: DifferenceKind::Extra });
            pointer.truncate(mark);
        }
    }
    if how.key_order && keys_agree && expected_names != actual_names {
        found.push(Difference {
            pointer: pointer.clone(),
            kind: DifferenceKind::KeyOrder { expected: expected_names, actual: actual_names },
        });
    }
}

fn escape_pointer(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

fn same_number(left: &str, right: &str) -> bool {
    match (left.parse::<i128>(), right.parse::<i128>()) {
        (Ok(one), Ok(other)) => one == other,
        _ => match (left.parse::<f64>(), right.parse::<f64>()) {
            (Ok(one), Ok(other)) => one == other,
            _ => false,
        },
    }
}
