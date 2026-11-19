//! `ObjectMapper.readTree` as Jackson 2 reads it, for JSON the audited repository wrote: a `package.json`, an
//! OpenAPI document.
//!
//! **Not `serde_json`, on purpose.** What these files say reaches the inventory — a contract's format, title and
//! version, its paths, an operation's summary — and serde_json disagrees with Jackson on inputs a repository can
//! hold: a 400-digit number (serde_json refuses it, Jackson holds a `BigInteger`), `\ud800` (serde_json refuses a
//! lone surrogate, Jackson keeps it), an array nested 200 deep (serde_json stops at 128, Jackson at 1,000), and a
//! number's text (`1e2` is `100.0` to Jackson). Each of those turned a contract the Java agent inventories into
//! one the Rust agent drops. So this is Jackson's grammar and limits, as measured against 2.22 and pinned by
//! `reference/workspace/`:
//!
//! - the first value only — **trailing content ignored**, except that a number at the root must be followed by
//!   white space; nothing at all is no value (`MissingNode`), not an error;
//! - nesting deeper than **1,000**, a number of more than **1,000 digits** (sign, point and exponent letter not
//!   counted), a name longer than **50,000** — UTF-8 bytes when the input is bytes, UTF-16 units when it is
//!   text — refused;
//! - a duplicate name replaces the value where the first one stood;
//! - from bytes: a UTF-8 byte-order mark skipped, UTF-16 and UTF-32 detected as Jackson's bootstrapper detects
//!   them, and **Jackson's own UTF-8 decoding** — an overlong form is decoded rather than refused, an encoded
//!   surrogate is refused, a four-byte form past U+10FFFF becomes the units Jackson's arithmetic makes;
//! - a string is UTF-16 units, so a lone surrogate survives the parse; it leaves as `?`, as the Java agent's
//!   `String` reaches the wire through `getBytes(UTF_8)`.
//!
//! **Iterative**: the nesting a document's author chose is a vector here, never the stack.

use std::collections::HashMap;

/// The deepest nesting Jackson reads (`StreamReadConstraints.DEFAULT_MAX_DEPTH`).
pub const MAX_DEPTH: usize = 1000;
/// The most digits in one number (`DEFAULT_MAX_NUM_LEN`).
pub const MAX_NUMBER_DIGITS: usize = 1000;
/// The longest name (`DEFAULT_MAX_NAME_LEN`).
pub const MAX_NAME_LENGTH: usize = 50_000;

/// A `JsonNode`.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Null,
    Bool(bool),
    /// As written: what `asText` makes of it depends on its form.
    Number(String),
    Text(String),
    Array(Vec<Node>),
    Object(Object),
}

/// An `ObjectNode`: its members in the order their names first appeared.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Object {
    members: Vec<(String, Node)>,
    index: HashMap<String, usize>,
}

impl Object {
    fn insert(&mut self, name: String, value: Node) {
        match self.index.get(&name).and_then(|&at| self.members.get_mut(at)) {
            Some(member) => member.1 = value,
            None => {
                self.index.insert(name.clone(), self.members.len());
                self.members.push((name, value));
            }
        }
    }

    /// `get(name)`.
    pub fn get(&self, name: &str) -> Option<&Node> {
        self.index.get(name).and_then(|&at| self.members.get(at)).map(|(_, value)| value)
    }

    /// `fields()`, in order.
    pub fn members(&self) -> impl Iterator<Item = (&str, &Node)> {
        self.members.iter().map(|(name, value)| (name.as_str(), value))
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

impl Node {
    /// `has(name)`: a member of an object, `null` included; nothing for anything else.
    pub fn get(&self, name: &str) -> Option<&Node> {
        match self {
            Node::Object(object) => object.get(name),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Node::Object(object) => Some(object),
            _ => None,
        }
    }

    /// `asText()`: a scalar's text — `"null"` for null, Jackson's number text — and `""` for a container.
    pub fn as_text(&self) -> String {
        match self {
            Node::Null => "null".to_owned(),
            Node::Bool(flag) => flag.to_string(),
            Node::Number(raw) => number_text(raw),
            Node::Text(text) => text.clone(),
            Node::Array(_) | Node::Object(_) => String::new(),
        }
    }

    /// `isEmpty()` of an array or object.
    pub fn is_empty_container(&self) -> bool {
        match self {
            Node::Array(items) => items.is_empty(),
            Node::Object(object) => object.is_empty(),
            _ => false,
        }
    }
}

/// A number's `asText`: an integer as `BigInteger` writes it (`-0` is `0`), anything with a point or an exponent
/// through `Double.toString`.
fn number_text(raw: &str) -> String {
    if raw.contains(['.', 'e', 'E']) {
        return raw.parse::<f64>().map_or_else(|_| raw.to_owned(), crate::jackson::java_double_to_string);
    }
    if raw == "-0" { "0".to_owned() } else { raw.to_owned() }
}

/// `readTree(String)`: `Ok(None)` for a text with no value in it, `Err` where Jackson throws.
pub fn read_text(content: &str) -> Result<Option<Node>, Refused> {
    Parser { input: content.as_bytes(), at: 0, names_in_bytes: false }.root()
}

/// `readTree(byte[])`: the encoding detected, a UTF-8 byte-order mark skipped.
pub fn read_bytes(content: &[u8]) -> Result<Option<Node>, Refused> {
    match detect(content)? {
        Source::Utf8(rest) => Parser { input: rest, at: 0, names_in_bytes: true }.root(),
        Source::Decoded(text) => read_text(&text),
    }
}

/// Why Jackson would have thrown — kept short: the readers only need to know that it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused(pub &'static str);

enum Source<'a> {
    Utf8(&'a [u8]),
    Decoded(String),
}

/// `ByteSourceJsonBootstrapper.detectEncoding`: a byte-order mark first, then the zero bytes of the first four.
fn detect(bytes: &[u8]) -> Result<Source<'_>, Refused> {
    let byte = |at: usize| bytes.get(at).copied();
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return Ok(Source::Utf8(rest));
    }
    let utf32 = |rest: &[u8], big: bool| -> Result<Source<'_>, Refused> {
        rest.chunks(4)
            .map(|chunk| {
                let unit: [u8; 4] = chunk.try_into().map_err(|_| Refused("a truncated UTF-32 unit"))?;
                let value = if big { u32::from_be_bytes(unit) } else { u32::from_le_bytes(unit) };
                char::from_u32(value).ok_or(Refused("an invalid UTF-32 character"))
            })
            .collect::<Result<String, _>>()
            .map(Source::Decoded)
    };
    let utf16 = |rest: &[u8], big: bool| -> Source<'_> {
        let units = rest.chunks(2).map(|pair| match pair {
            [a, b] if big => u16::from_be_bytes([*a, *b]),
            [a, b] => u16::from_le_bytes([*a, *b]),
            // A last odd byte: the decoder's replacement.
            _ => 0xFFFD,
        });
        Source::Decoded(char::decode_utf16(units).map(|unit| unit.unwrap_or('\u{FFFD}')).collect())
    };
    match (byte(0), byte(1), byte(2), byte(3)) {
        (Some(0), Some(0), Some(0xFE), Some(0xFF)) => return utf32(bytes.get(4..).unwrap_or_default(), true),
        (Some(0xFF), Some(0xFE), Some(0), Some(0)) => return utf32(bytes.get(4..).unwrap_or_default(), false),
        (Some(0xFE), Some(0xFF), _, _) => return Ok(utf16(bytes.get(2..).unwrap_or_default(), true)),
        (Some(0xFF), Some(0xFE), _, _) => return Ok(utf16(bytes.get(2..).unwrap_or_default(), false)),
        (Some(0), Some(0), Some(0), Some(_)) => return utf32(bytes, true),
        (Some(_), Some(0), Some(0), Some(0)) => return utf32(bytes, false),
        (Some(0), Some(_), Some(0), Some(0)) | (Some(0), Some(0), Some(_), Some(0)) => {
            return Err(Refused("an unsupported UCS-4 byte order"));
        }
        (Some(0), Some(_), _, _) => return Ok(utf16(bytes, true)),
        (Some(_), Some(0), _, _) => return Ok(utf16(bytes, false)),
        _ => {}
    }
    Ok(Source::Utf8(bytes))
}

enum Frame {
    Array(Vec<Node>),
    Object(Object, String),
}

struct Parser<'a> {
    input: &'a [u8],
    at: usize,
    /// The unit a name's length is counted in: UTF-8 bytes when Jackson reads bytes, UTF-16 units for a string.
    names_in_bytes: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    fn bump(&mut self) {
        self.at = self.at.saturating_add(1);
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek();
        self.bump();
        byte
    }

    /// Only the four white spaces JSON knows; any other control character is an error, as in Jackson.
    fn skip_white_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn expect(&mut self, byte: u8, refusal: &'static str) -> Result<(), Refused> {
        if self.next_byte() == Some(byte) { Ok(()) } else { Err(Refused(refusal)) }
    }

    fn root(mut self) -> Result<Option<Node>, Refused> {
        self.skip_white_space();
        if self.peek().is_none() {
            return Ok(None);
        }
        let root = self.value()?;
        // `_verifyRootSpace`: a number at the root ends at white space or at the end, nothing else.
        if matches!(root, Node::Number(_)) && !matches!(self.peek(), None | Some(b' ' | b'\t' | b'\n' | b'\r')) {
            return Err(Refused("no space after a root-level number"));
        }
        Ok(Some(root))
    }

    fn value(&mut self) -> Result<Node, Refused> {
        let mut stack: Vec<Frame> = Vec::new();
        'values: loop {
            self.skip_white_space();
            let mut value = match self.peek() {
                Some(open @ (b'{' | b'[')) => {
                    self.bump();
                    if stack.len() >= MAX_DEPTH {
                        return Err(Refused("nested deeper than Jackson reads"));
                    }
                    self.skip_white_space();
                    if open == b'[' {
                        if self.peek() == Some(b']') {
                            self.bump();
                            Node::Array(Vec::new())
                        } else {
                            stack.push(Frame::Array(Vec::new()));
                            continue 'values;
                        }
                    } else if self.peek() == Some(b'}') {
                        self.bump();
                        Node::Object(Object::default())
                    } else {
                        let name = self.name()?;
                        stack.push(Frame::Object(Object::default(), name));
                        continue 'values;
                    }
                }
                Some(b'"') => {
                    self.bump();
                    Node::Text(self.string(false)?)
                }
                Some(b'-' | b'0'..=b'9') => Node::Number(self.number()?),
                Some(b't') => self.keyword("true", Node::Bool(true))?,
                Some(b'f') => self.keyword("false", Node::Bool(false))?,
                Some(b'n') => self.keyword("null", Node::Null)?,
                _ => return Err(Refused("not a value")),
            };
            // A complete value: hand it to its container, closing every container it completes.
            loop {
                match stack.last_mut() {
                    None => return Ok(value),
                    Some(Frame::Array(items)) => {
                        items.push(value);
                        self.skip_white_space();
                        match self.next_byte() {
                            Some(b',') => continue 'values,
                            Some(b']') => {}
                            _ => return Err(Refused("an array not separated by commas")),
                        }
                    }
                    Some(Frame::Object(object, name)) => {
                        object.insert(std::mem::take(name), value);
                        self.skip_white_space();
                        match self.next_byte() {
                            Some(b',') => {
                                self.skip_white_space();
                                *name = self.name()?;
                                continue 'values;
                            }
                            Some(b'}') => {}
                            _ => return Err(Refused("an object not separated by commas")),
                        }
                    }
                }
                value = match stack.pop() {
                    Some(Frame::Array(items)) => Node::Array(items),
                    Some(Frame::Object(object, _)) => Node::Object(object),
                    None => return Err(Refused("a container closed twice")),
                };
            }
        }
    }

    /// A member's name, its colon read.
    fn name(&mut self) -> Result<String, Refused> {
        self.expect(b'"', "a name not in double quotes")?;
        let name = self.string(true)?;
        self.skip_white_space();
        self.expect(b':', "a name not followed by a colon")?;
        Ok(name)
    }

    fn keyword(&mut self, word: &'static str, node: Node) -> Result<Node, Refused> {
        let end = self.at.saturating_add(word.len());
        if self.input.get(self.at..end) != Some(word.as_bytes()) {
            return Err(Refused("an unrecognized token"));
        }
        self.at = end;
        // `_checkMatchEnd`: `nullx` is one unrecognized token, not `null` and garbage.
        if self.peek().is_some_and(|next| next.is_ascii_alphanumeric() || next == b'_' || next == b'$' || next >= 0x80)
        {
            return Err(Refused("an unrecognized token"));
        }
        Ok(node)
    }

    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`, at most [`MAX_NUMBER_DIGITS`] digits in all.
    fn number(&mut self) -> Result<String, Refused> {
        let start = self.at;
        let mut digits = 0usize;
        let mut run = |parser: &mut Parser<'_>| {
            let mut count = 0usize;
            while parser.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                parser.bump();
                count = count.saturating_add(1);
            }
            digits = digits.saturating_add(count);
            count
        };
        if self.peek() == Some(b'-') {
            self.bump();
        }
        let leading_zero = self.peek() == Some(b'0');
        let integer = run(self);
        if integer == 0 {
            return Err(Refused("a minus sign not followed by a digit"));
        }
        if leading_zero && integer > 1 {
            return Err(Refused("leading zeroes"));
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if run(self) == 0 {
                return Err(Refused("a decimal point not followed by a digit"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if run(self) == 0 {
                return Err(Refused("an exponent not followed by a digit"));
            }
        }
        if digits > MAX_NUMBER_DIGITS {
            return Err(Refused("a number longer than Jackson reads"));
        }
        let raw = self.input.get(start..self.at).ok_or(Refused("a number past the end"))?;
        Ok(String::from_utf8_lossy(raw).into_owned())
    }

    /// The rest of a string, its opening quote read: escapes resolved, Jackson's UTF-8 decoding, as UTF-16 units.
    fn string(&mut self, is_name: bool) -> Result<String, Refused> {
        let start = self.at;
        let mut units: Vec<u16> = Vec::new();
        loop {
            let byte = self.next_byte().ok_or(Refused("a string not closed"))?;
            match byte {
                b'"' => break,
                b'\\' => {
                    let unit = match self.next_byte() {
                        Some(b'"') => u16::from(b'"'),
                        Some(b'\\') => u16::from(b'\\'),
                        Some(b'/') => u16::from(b'/'),
                        Some(b'b') => 0x08,
                        Some(b'f') => 0x0C,
                        Some(b'n') => u16::from(b'\n'),
                        Some(b'r') => u16::from(b'\r'),
                        Some(b't') => u16::from(b'\t'),
                        Some(b'u') => {
                            let mut value = 0u16;
                            for _ in 0..4 {
                                let digit = self
                                    .next_byte()
                                    .and_then(|hex| char::from(hex).to_digit(16))
                                    .and_then(|digit| u16::try_from(digit).ok())
                                    .ok_or(Refused("a \\u escape without four hex digits"))?;
                                value = value.wrapping_shl(4) | digit;
                            }
                            value
                        }
                        _ => return Err(Refused("an unrecognized escape")),
                    };
                    units.push(unit);
                }
                0x00..=0x1F => return Err(Refused("a control character in a string")),
                0x20..=0x7F => units.push(u16::from(byte)),
                lead => units.extend(self.utf8_sequence(lead)?),
            }
        }
        if is_name {
            let length =
                if self.names_in_bytes { self.at.saturating_sub(start).saturating_sub(1) } else { units.len() };
            if length > MAX_NAME_LENGTH {
                return Err(Refused("a name longer than Jackson reads"));
            }
        }
        Ok(vectispire_domain::java::from_utf16(&units))
    }

    /// `UTF8StreamJsonParser._decodeUtf8_2/3/4`: continuation bytes checked, overlong forms not, surrogates refused,
    /// the four-byte forms past U+10FFFF folded into the units Jackson's `int` arithmetic gives.
    fn utf8_sequence(&mut self, lead: u8) -> Result<Vec<u16>, Refused> {
        let (length, initial) = match lead {
            0xC0..=0xDF => (2, i32::from(lead & 0x1F)),
            0xE0..=0xEF => (3, i32::from(lead & 0x0F)),
            0xF0..=0xF7 => (4, i32::from(lead & 0x07)),
            _ => return Err(Refused("an invalid UTF-8 start byte")),
        };
        let mut value = initial;
        for _ in 1..length {
            let next = self.peek().filter(|byte| byte & 0xC0 == 0x80).ok_or(Refused("an invalid UTF-8 middle byte"))?;
            self.bump();
            value = value.wrapping_shl(6) | i32::from(next & 0x3F);
        }
        match length {
            2 => Ok(vec![unit(value)]),
            3 if (0xD800..=0xDFFF).contains(&value) => Err(Refused("an encoded surrogate")),
            3 => Ok(vec![unit(value)]),
            _ => {
                let offset = value.wrapping_sub(0x10000);
                Ok(vec![unit(0xD800 | offset.wrapping_shr(10)), unit(0xDC00 | (offset & 0x3FF))])
            }
        }
    }
}

/// Java's `(char) value`: the low sixteen bits.
fn unit(value: i32) -> u16 {
    u16::try_from(value & 0xFFFF).unwrap_or(0xFFFD)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(content: &str) -> Option<String> {
        read_text(content).ok().flatten().and_then(|node| node.get("v").map(Node::as_text))
    }

    fn bytes_of(content: &[u8]) -> Result<String, Refused> {
        let mut document = b"{\"v\":\"".to_vec();
        document.extend_from_slice(content);
        document.extend_from_slice(b"\"}");
        read_bytes(&document).map(|node| node.and_then(|node| node.get("v").map(Node::as_text)).unwrap_or_default())
    }

    #[test]
    fn numbers_read_as_jackson_writes_them_back() {
        for (raw, text) in [
            ("-0", "0"),
            ("-0.0", "-0.0"),
            ("1E400", "Infinity"),
            ("-1e400", "-Infinity"),
            ("1e-400", "0.0"),
            ("1e2", "100.0"),
            ("12345678901234567890", "12345678901234567890"),
            ("123456789.0", "1.23456789E8"),
            ("1e7", "1.0E7"),
            ("0.00001", "1.0E-5"),
            ("1e-3", "0.001"),
        ] {
            assert_eq!(text_of(&format!("{{\"v\":{raw}}}")).as_deref(), Some(text), "{raw}");
        }
        assert!(text_of(&format!("{{\"v\":-{}}}", "1".repeat(1000))).is_some(), "the sign is not a digit");
        assert!(text_of(&format!("{{\"v\":{}}}", "1".repeat(1001))).is_none());
        assert!(text_of(&format!("{{\"v\":-1.{}e10}}", "5".repeat(997))).is_some(), "1,000 digits in three runs");
        assert!(text_of(&format!("{{\"v\":1.{}e+10}}", "5".repeat(998))).is_none());
        for refused in ["01", "-", "1.", ".5", "+1", "-01", "1.e5", "1e"] {
            assert!(text_of(&format!("{{\"v\":{refused}}}")).is_none(), "{refused}");
        }
    }

    #[test]
    fn documents_are_read_as_jackson_reads_them() {
        assert_eq!(read_text(""), Ok(None));
        assert_eq!(read_text(" \t\n"), Ok(None));
        assert!(read_text("1x").is_err(), "a root number needs a space after it");
        assert!(read_text("1 x").is_ok());
        assert!(read_text("[1x]").is_err());
        assert!(read_text("{\"a\":1}x").is_ok(), "trailing content is ignored");
        assert!(read_text("null x").is_ok());
        assert!(read_text("nullx").is_err());
        assert!(read_text("\u{b}{}").is_err());
        assert!(read_text("\u{feff}{}").is_err(), "a byte-order mark in a string is a character");
        for refused in
            ["{'a':1}", "{a:1}", "{\"a\":1,}", "[1,]", "{\"a\":\"\\x\"}", "{\"a\":\"\\u00G0\"}", "/* c */{}", "#\n{}"]
        {
            assert!(read_text(refused).is_err(), "{refused}");
        }
        assert_eq!(text_of("{\"v\":\"\\uD800\\uDC00\"}").as_deref(), Some("\u{10000}"));
        assert_eq!(text_of("{\"v\":\"\\uDC00\\uD800\"}").as_deref(), Some("??"), "lone surrogates leave as `?`");
        assert_eq!(text_of("{\"v\":\"\\/\"}").as_deref(), Some("/"));
        assert_eq!(text_of("{\"v\":1,\"v\":2,\"w\":3}").as_deref(), Some("2"));
        let deep = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert!(read_text(&deep(1000)).is_ok());
        assert!(read_text(&deep(1001)).is_err());
    }

    #[test]
    fn bytes_are_decoded_as_jackson_decodes_them() {
        assert_eq!(bytes_of(b"\xc0\xaf").as_deref(), Ok("/"), "an overlong form is decoded");
        assert_eq!(bytes_of(b"\xe0\x80\x80").as_deref(), Ok("\0"));
        assert!(bytes_of(b"\xed\xa0\x80").is_err(), "an encoded surrogate is refused");
        assert_eq!(bytes_of(b"\xf0\x90\x80\x80").as_deref(), Ok("\u{10000}"));
        assert_eq!(bytes_of(b"\xf4\x90\x80\x80").as_deref(), Ok("??"), "past U+10FFFF: two low surrogates");
        assert_eq!(bytes_of(b"\xf0\x80\x80\x80").as_deref(), Ok("\u{ffc0}?"));
        for refused in [&b"\xf8\x88\x80\x80\x80"[..], b"\xfe", b"\x80", b"\xc2", b"\xc2A", b"\xe2\x82", b"\x1f"] {
            assert!(bytes_of(refused).is_err(), "{refused:?}");
        }
        assert_eq!(bytes_of(b"\x7f").as_deref(), Ok("\u{7f}"));
        assert!(read_bytes(b"\xef\xbb\xbf{}").is_ok(), "a UTF-8 byte-order mark is skipped");
        let utf16: Vec<u8> = "{\"v\":\"x\"}".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(read_bytes(&utf16).unwrap().unwrap().get("v").map(Node::as_text).as_deref(), Some("x"));
        let long = |name: &str| format!("{{\"{name}\":1}}");
        assert!(read_bytes(long(&"é".repeat(25_000)).as_bytes()).is_ok());
        assert!(read_bytes(long(&"é".repeat(25_001)).as_bytes()).is_err(), "bytes count from bytes");
        assert!(read_text(&long(&"é".repeat(25_001))).is_ok(), "units count from a string");
        assert!(read_text(&long(&"\u{1F600}".repeat(25_001))).is_err());
    }
}
