//! JSON read as the control plane's Jackson reads it, before `serde_json` sees a byte of it.
//!
//! **Why a pass of its own.** The control plane's mappers accept bodies `serde_json` refuses, and refuse
//! some it accepts; a result one side ingests and the other answers 400 to is a scan whose findings
//! exist on one control plane and not on the other. Every difference below was measured against Java
//! (`reference/artifacts/java-read.json`, written by `AgentWireReferenceSetTest`), none reasoned out:
//!
//! - **the encoding is detected**, as `ByteSourceJsonBootstrapper` does: a UTF-8 byte-order mark is
//!   passed over, and UTF-16 and UTF-32 bodies, with or without a mark, are read;
//! - **only the first document is read**: what follows it — another document, garbage, invalid bytes — is
//!   never looked at by the result's mapper (`FAIL_ON_TRAILING_TOKENS` is off in Jackson 2), and refused by
//!   Spring MVC's (Jackson 3 turns it on);
//! - **an unpaired surrogate escape is a character**, `\uD800`: Jackson keeps it in the string and the
//!   string's UTF-8 bytes — what the fingerprint hashes, what the database stores — carry it as `?`. So it
//!   is written `?` here, where `serde_json` would refuse the whole body. In a *field name* Jackson is
//!   strict, and so is this pass;
//! - **Jackson's UTF-8 decoder is lenient** where the standard is not: overlong forms (`C0 AF` is `/`),
//!   four-byte forms past U+10FFFF (two low surrogates). They are rewritten as the characters Jackson
//!   decodes them to; an encoded surrogate (`ED A0 80`), a stray continuation byte or a bad middle byte is
//!   refused, as Jackson refuses it;
//! - **`StreamReadConstraints`' defaults apply**: for the result's Jackson 2, nesting deeper than 1,000, a
//!   number of more than 1,000 digits, a string of more than 20,000,000 UTF-16 units — even one in a field
//!   nobody reads — and a field name of more than 50,000 are refused; Spring MVC's Jackson 3 nests 500 deep
//!   and reads strings up to 100,000,000. `serde_json`'s own limit of 128 levels is lifted in their place.
//!
//! The pass refuses nothing Jackson accepts and lets through nothing it refuses for these reasons; what
//! remains — the grammar itself — is `serde_json`'s, which agrees with Jackson's defaults on it (no
//! comments, no single quotes, no trailing commas, no `NaN`, no leading zeros, no raw control
//! characters). The output is the first document alone, borrowed from the body unless a string had to
//! be rewritten.

use std::borrow::Cow;

/// `StreamReadConstraints.DEFAULT_MAX_NUM_LEN`, both Jacksons, in digits: an integer's, or a decimal's
/// integer, fraction and exponent digits together.
pub const MAX_NUMBER_LENGTH: usize = 1_000;
/// `StreamReadConstraints.DEFAULT_MAX_NAME_LEN`, both Jacksons.
pub const MAX_NAME_LENGTH: usize = 50_000;

/// One of the control plane's two mappers, as far as reading a body goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mapper {
    /// Whether what follows the first document refuses the body.
    pub trailing: Trailing,
    /// `StreamReadConstraints`' nesting depth, the root being level one.
    pub depth: usize,
    /// `StreamReadConstraints`' string length, in UTF-16 units of the decoded text.
    pub string: usize,
}

/// `CoreConfiguration`'s Jackson 2 bean, which reads the result and the failure report from their bytes.
pub(crate) const CONTROL_PLANE: Mapper = Mapper { trailing: Trailing::Ignored, depth: 1_000, string: 20_000_000 };

/// Spring Boot 4's auto-configured Jackson 3, which Spring MVC binds every other request body with.
pub(crate) const SPRING_MVC: Mapper = Mapper { trailing: Trailing::Refused, depth: 500, string: 100_000_000 };

/// What follows the first document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trailing {
    /// Never read — Jackson 2's `FAIL_ON_TRAILING_TOKENS` is off.
    Ignored,
    /// Anything but whitespace refuses the body — Jackson 3 turns it on.
    Refused,
}

/// A body Jackson would not read, with the reason in Jackson's terms. The routes do not echo it; it is for
/// the log and the tests.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refused(pub String);

fn refused<T>(reason: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(reason.into()))
}

/// The first document of `body`, as UTF-8 that `serde_json` reads to what Jackson reads.
pub(crate) fn prepare(body: &[u8], mapper: Mapper) -> Result<Cow<'_, [u8]>, Refused> {
    match decode(body)? {
        Cow::Borrowed(text) => Lexer::new(text, mapper).run(),
        Cow::Owned(text) => Lexer::new(&text, mapper).run().map(|document| Cow::Owned(document.into_owned())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf8 { skip: usize },
    Utf16 { big_endian: bool, skip: usize },
    Utf32 { big_endian: bool, skip: usize },
}

/// `ByteSourceJsonBootstrapper.detectEncoding`: a mark first, then the zero bytes ASCII text leaves.
fn encoding(body: &[u8]) -> Result<Encoding, Refused> {
    let unusual = || refused("Unsupported UCS-4 endianness (2143 or 3412) detected");
    let Some(&[b0, b1, b2, b3]) = body.first_chunk::<4>() else {
        return Ok(match body.first_chunk::<2>() {
            Some(&[b0, b1]) => utf16_without_mark(u16::from_be_bytes([b0, b1])),
            None => Encoding::Utf8 { skip: 0 },
        });
    };
    let quad = u32::from_be_bytes([b0, b1, b2, b3]);
    match quad {
        0x0000_FEFF => return Ok(Encoding::Utf32 { big_endian: true, skip: 4 }),
        0xFFFE_0000 => return Ok(Encoding::Utf32 { big_endian: false, skip: 4 }),
        0x0000_FFFE | 0xFEFF_0000 => return unusual(),
        _ => {}
    }
    match quad >> 16 {
        0xFEFF => return Ok(Encoding::Utf16 { big_endian: true, skip: 2 }),
        0xFFFE => return Ok(Encoding::Utf16 { big_endian: false, skip: 2 }),
        _ if quad >> 8 == 0x00EF_BBBF => return Ok(Encoding::Utf8 { skip: 3 }),
        _ => {}
    }
    if quad >> 8 == 0 {
        Ok(Encoding::Utf32 { big_endian: true, skip: 0 })
    } else if quad & 0x00FF_FFFF == 0 {
        Ok(Encoding::Utf32 { big_endian: false, skip: 0 })
    } else if quad & 0xFF00_FFFF == 0 || quad & 0xFFFF_00FF == 0 {
        unusual()
    } else {
        Ok(utf16_without_mark(u16::try_from(quad >> 16).unwrap_or_default()))
    }
}

fn utf16_without_mark(first: u16) -> Encoding {
    if first & 0xFF00 == 0 {
        Encoding::Utf16 { big_endian: true, skip: 0 }
    } else if first & 0x00FF == 0 {
        Encoding::Utf16 { big_endian: false, skip: 0 }
    } else {
        Encoding::Utf8 { skip: 0 }
    }
}

fn decode(body: &[u8]) -> Result<Cow<'_, [u8]>, Refused> {
    Ok(match encoding(body)? {
        Encoding::Utf8 { skip } => Cow::Borrowed(body.get(skip..).unwrap_or_default()),
        Encoding::Utf16 { big_endian, skip } => Cow::Owned(utf16(body.get(skip..).unwrap_or_default(), big_endian)),
        Encoding::Utf32 { big_endian, skip } => Cow::Owned(utf32(body.get(skip..).unwrap_or_default(), big_endian)?),
    })
}

/// UTF-16 as the JDK's decoder behind Jackson's `InputStreamReader` reads it: a malformed sequence is
/// U+FFFD, and a high surrogate followed by anything but a low one swallows that unit with it — which is
/// how a closing quote after a stray surrogate goes missing and the body ends inside a string.
fn utf16(bytes: &[u8], big_endian: bool) -> Vec<u8> {
    let unit = |pair: &[u8]| match pair {
        [a, b] if big_endian => u16::from_be_bytes([*a, *b]),
        [a, b] => u16::from_le_bytes([*a, *b]),
        _ => 0xFFFD,
    };
    let units: Vec<u16> = bytes.chunks(2).map(unit).collect();
    let mut text = String::with_capacity(units.len());
    let mut index = 0;
    while let Some(&first) = units.get(index) {
        index = index.saturating_add(1);
        let c = match first {
            // The reversed mark is malformed to this decoder.
            0xFFFE => '\u{FFFD}',
            0xD800..=0xDBFF => match units.get(index) {
                Some(&second @ 0xDC00..=0xDFFF) => {
                    index = index.saturating_add(1);
                    char::decode_utf16([first, second]).next().and_then(Result::ok).unwrap_or('\u{FFFD}')
                }
                Some(_) => {
                    index = index.saturating_add(1);
                    '\u{FFFD}'
                }
                None => '\u{FFFD}',
            },
            0xDC00..=0xDFFF => '\u{FFFD}',
            other => char::from_u32(u32::from(other)).unwrap_or('\u{FFFD}'),
        };
        text.push(c);
    }
    if bytes.len() % 2 == 1 {
        text.push('\u{FFFD}');
    }
    text.into_bytes()
}

/// UTF-32 as Jackson's own `UTF32Reader` reads it: past U+10FFFF or cut short is refused; a surrogate code
/// point passes as a lone surrogate, which reaches the text as `?`.
fn utf32(bytes: &[u8], big_endian: bool) -> Result<Vec<u8>, Refused> {
    let mut text = String::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks(4) {
        let Ok(quad) = <[u8; 4]>::try_from(chunk) else {
            return refused("Unexpected EOF in the middle of a 4-byte UTF-32 char");
        };
        let code = if big_endian { u32::from_be_bytes(quad) } else { u32::from_le_bytes(quad) };
        if code > 0x10_FFFF {
            return refused(format!("Invalid UTF-32 character 0x{code:x} (above 0x0010ffff)"));
        }
        text.push(char::from_u32(code).unwrap_or('?'));
    }
    Ok(text.into_bytes())
}

struct Lexer<'a> {
    input: &'a [u8],
    mapper: Mapper,
    pos: usize,
    depth: usize,
    /// The rewritten document, from the first string that needed it; `None` while the input stands.
    out: Option<Vec<u8>>,
    /// How much of the input `out` already holds.
    copied: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a [u8], mapper: Mapper) -> Lexer<'a> {
        Lexer { input, mapper, pos: 0, depth: 0, out: None, copied: 0 }
    }

    fn run(mut self) -> Result<Cow<'a, [u8]>, Refused> {
        self.whitespace();
        if self.pos == self.input.len() {
            return refused("No content to map due to end-of-input");
        }
        let start = self.pos;
        self.copied = start;
        self.value(true)?;
        let end = self.pos;
        if self.mapper.trailing == Trailing::Refused {
            self.whitespace();
            if self.pos != self.input.len() {
                return refused("Trailing token found after value: not allowed as per FAIL_ON_TRAILING_TOKENS");
            }
        }
        Ok(match self.out {
            None => Cow::Borrowed(self.input.get(start..end).unwrap_or_default()),
            Some(mut out) => {
                out.extend_from_slice(self.input.get(self.copied..end).unwrap_or_default());
                Cow::Owned(out)
            }
        })
    }

    /// Positions are bounded by the input's length; saturating rather than panicking all the same.
    fn advance(&mut self, by: usize) {
        self.pos = self.pos.saturating_add(by);
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Result<u8, Refused> {
        let byte = self.peek().ok_or_else(|| Refused("Unexpected end-of-input".into()))?;
        self.advance(1);
        Ok(byte)
    }

    /// Jackson's white space, and JSON's: a space, a tab, a line feed, a carriage return.
    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.advance(1);
        }
    }

    fn value(&mut self, root: bool) -> Result<(), Refused> {
        match self.peek() {
            Some(b'{') => self.container(b'}', true),
            Some(b'[') => self.container(b']', false),
            Some(b'"') => {
                self.advance(1);
                self.string(false)
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => self.literal(b"true", root),
            Some(b'f') => self.literal(b"false", root),
            Some(b'n') => self.literal(b"null", root),
            Some(other) => refused(format!("Unexpected character (code {other}): expected a valid value")),
            None => refused("Unexpected end-of-input: expected a value"),
        }
    }

    /// An object or an array, one level deeper — counted as Jackson counts, the root being level one.
    fn container(&mut self, close: u8, object: bool) -> Result<(), Refused> {
        self.advance(1);
        self.depth = self.depth.saturating_add(1);
        if self.depth > self.mapper.depth {
            return refused(format!(
                "Document nesting depth ({}) exceeds the maximum allowed ({})",
                self.depth, self.mapper.depth
            ));
        }
        self.whitespace();
        if self.peek() == Some(close) {
            self.advance(1);
        } else {
            loop {
                if object {
                    if self.next()? != b'"' {
                        return refused("Unexpected character: was expecting double-quote to start field name");
                    }
                    self.string(true)?;
                    self.whitespace();
                    if self.next()? != b':' {
                        return refused("Unexpected character: was expecting a colon to separate field name and value");
                    }
                    self.whitespace();
                }
                self.value(false)?;
                self.whitespace();
                match self.next()? {
                    b',' => self.whitespace(),
                    byte if byte == close => break,
                    _ => return refused("Unexpected character: was expecting comma to separate entries"),
                }
            }
        }
        self.depth = self.depth.saturating_sub(1);
        Ok(())
    }

    /// `true`, `false`, `null` — and, at the root, the check Jackson makes that the word ends there:
    /// `nullx` is no `null`. Within a document `serde_json` refuses what follows a word anyway.
    fn literal(&mut self, word: &[u8], root: bool) -> Result<(), Refused> {
        if self.input.get(self.pos..self.pos.saturating_add(word.len())) != Some(word) {
            return refused(
                "Unrecognized token: was expecting (JSON String, Number, Array, Object or token 'null', 'true' or 'false')",
            );
        }
        self.advance(word.len());
        // `Character.isJavaIdentifierPart`, approximated: ASCII letters, digits, `_` and `$`, and anything
        // past ASCII.
        if root && self.peek().is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80) {
            return refused(
                "Unrecognized token: was expecting (JSON String, Number, Array, Object or token 'null', 'true' or 'false')",
            );
        }
        Ok(())
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.advance(1);
        }
        self.pos.saturating_sub(start)
    }

    fn number(&mut self) -> Result<(), Refused> {
        if self.peek() == Some(b'-') {
            self.advance(1);
        }
        let integer = match self.peek() {
            Some(b'0') => {
                self.advance(1);
                if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    return refused("Invalid numeric value: Leading zeroes not allowed");
                }
                1
            }
            Some(b'1'..=b'9') => self.digits(),
            _ => {
                return refused(
                    "Non-standard token: expected digit (0-9) to follow minus sign, for valid numeric value",
                );
            }
        };
        let mut fraction = 0;
        let mut exponent = 0;
        let mut decimal = false;
        if self.peek() == Some(b'.') {
            self.advance(1);
            decimal = true;
            fraction = self.digits();
            if fraction == 0 {
                return refused("Unexpected character: Decimal point not followed by a digit");
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.advance(1);
            decimal = true;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.advance(1);
            }
            exponent = self.digits();
            if exponent == 0 {
                return refused("Unexpected character: Exponent indicator not followed by a digit");
            }
        }
        let length = if decimal { integer.saturating_add(fraction).saturating_add(exponent) } else { integer };
        if length > MAX_NUMBER_LENGTH {
            return refused(format!(
                "Number value length ({length}) exceeds the maximum allowed ({MAX_NUMBER_LENGTH})"
            ));
        }
        Ok(())
    }

    /// A string, from after its opening quote to after its closing one. Most strings are left as they
    /// are; one holding an unpaired surrogate escape or a byte sequence only Jackson's decoder accepts is
    /// rewritten as the characters Jackson read.
    fn string(&mut self, name: bool) -> Result<(), Refused> {
        let start = self.pos;
        let mut units = 0usize;
        let mut clean = true;
        // The previous unit was a high surrogate written as an escape, not yet paired.
        let mut high_escape = false;
        loop {
            let byte = self.next().map_err(|_| {
                Refused("Unexpected end-of-input: was expecting closing quote for a string value".into())
            })?;
            let escaped_unit = match byte {
                b'"' => {
                    if high_escape {
                        if name {
                            return refused(
                                "Broken surrogate pair in field name: expected '\\' to start low surrogate, got 0x22",
                            );
                        }
                        clean = false;
                    }
                    break;
                }
                b'\\' => match self.next()? {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => None,
                    b'u' => Some(self.hex_escape()?),
                    other => return refused(format!("Unrecognized character escape (code {other})")),
                },
                0x00..=0x1F => {
                    return refused(format!(
                        "Illegal unquoted character ((CTRL-CHAR, code {byte})): has to be escaped using backslash to be included in string value"
                    ));
                }
                0x20..=0x7F => None,
                _ => {
                    let (count, valid) = self.multibyte(byte)?;
                    units = units.saturating_add(count);
                    clean &= valid;
                    if high_escape {
                        if name {
                            return refused(
                                "Broken surrogate pair in field name: expected '\\' to start low surrogate",
                            );
                        }
                        clean = false;
                    }
                    high_escape = false;
                    continue;
                }
            };
            units = units.saturating_add(1);
            match escaped_unit {
                Some(0xD800..=0xDBFF) => {
                    if high_escape {
                        if name {
                            return refused("Broken surrogate pair in field name: expected low surrogate, got 0xD800");
                        }
                        clean = false;
                    }
                    high_escape = true;
                }
                Some(0xDC00..=0xDFFF) => {
                    if !high_escape {
                        if name {
                            return refused("Unexpected low surrogate in field name");
                        }
                        clean = false;
                    }
                    high_escape = false;
                }
                _ => {
                    if high_escape {
                        if name {
                            return refused("Broken surrogate pair in field name: expected low surrogate");
                        }
                        clean = false;
                    }
                    high_escape = false;
                }
            }
        }
        let end = self.pos.saturating_sub(1);
        if name && units > MAX_NAME_LENGTH {
            return refused(format!("Name length ({units}) exceeds the maximum allowed ({MAX_NAME_LENGTH})"));
        }
        if !name && units > self.mapper.string {
            return refused(format!(
                "String value length ({units}) exceeds the maximum allowed ({})",
                self.mapper.string
            ));
        }
        if !clean {
            let content = self.input.get(start..end).unwrap_or_default();
            let out = self.out.get_or_insert_with(|| Vec::with_capacity(self.input.len()));
            out.extend_from_slice(self.input.get(self.copied..start).unwrap_or_default());
            write_units(out, &units_of(content));
            self.copied = end;
        }
        Ok(())
    }

    fn hex_escape(&mut self) -> Result<u16, Refused> {
        let mut value = 0u16;
        for _ in 0..4 {
            let digit = char::from(self.next()?).to_digit(16).ok_or_else(|| {
                Refused("Unexpected character: expected a hex-digit for character escape sequence".into())
            })?;
            value = (value << 4) | u16::try_from(digit).unwrap_or_default();
        }
        Ok(value)
    }

    /// One non-ASCII character as Jackson's UTF-8 decoder reads it: how many UTF-16 units it makes, and
    /// whether the bytes are standard UTF-8 that `serde_json` reads to the same units.
    fn multibyte(&mut self, lead: u8) -> Result<(usize, bool), Refused> {
        let (continuations, mut value) = match lead {
            0xC0..=0xDF => (1, u32::from(lead & 0x1F)),
            0xE0..=0xEF => (2, u32::from(lead & 0x0F)),
            0xF0..=0xF7 => (3, u32::from(lead & 0x07)),
            _ => return refused(format!("Invalid UTF-8 start byte 0x{lead:x}")),
        };
        for _ in 0..continuations {
            let byte = self.next()?;
            if byte & 0xC0 != 0x80 {
                return refused(format!("Invalid UTF-8 middle byte 0x{byte:x}"));
            }
            value = (value << 6) | u32::from(byte & 0x3F);
        }
        Ok(match continuations {
            1 => (1, value >= 0x80),
            2 => {
                if (0xD800..=0xDFFF).contains(&value) {
                    return refused(format!("Invalid UTF-8: Illegal surrogate character 0x{value:x}"));
                }
                (1, value >= 0x800)
            }
            _ => (2, (0x1_0000..=0x10_FFFF).contains(&value)),
        })
    }
}

/// A string's content as the UTF-16 units Jackson decodes it to — its escapes, and its bytes through
/// Jackson's lenient UTF-8 decoder. The content has been checked by [`Lexer::string`].
fn units_of(content: &[u8]) -> Vec<u16> {
    let mut units = Vec::with_capacity(content.len());
    let mut index = 0;
    let byte_at = |at: usize| content.get(at).copied().unwrap_or_default();
    while index < content.len() {
        let byte = byte_at(index);
        index = index.saturating_add(1);
        match byte {
            b'\\' => {
                let escape = byte_at(index);
                index = index.saturating_add(1);
                let unit = match escape {
                    b'b' => 0x08,
                    b'f' => 0x0C,
                    b'n' => 0x0A,
                    b'r' => 0x0D,
                    b't' => 0x09,
                    b'u' => {
                        let hex =
                            content.get(index..index.saturating_add(4)).and_then(|hex| std::str::from_utf8(hex).ok());
                        index = index.saturating_add(4);
                        hex.and_then(|hex| u16::from_str_radix(hex, 16).ok()).unwrap_or_default()
                    }
                    other => u16::from(other),
                };
                units.push(unit);
            }
            0x00..=0x7F => units.push(u16::from(byte)),
            _ => {
                let (continuations, mut value) = match byte {
                    0xC0..=0xDF => (1, u32::from(byte & 0x1F)),
                    0xE0..=0xEF => (2, u32::from(byte & 0x0F)),
                    _ => (3, u32::from(byte & 0x07)),
                };
                for _ in 0..continuations {
                    value = (value << 6) | u32::from(byte_at(index) & 0x3F);
                    index = index.saturating_add(1);
                }
                if continuations < 3 {
                    units.push(u16::try_from(value).unwrap_or_default());
                } else {
                    // `UTF8StreamJsonParser`'s arithmetic, kept exactly: an overlong four-byte form makes the
                    // offset negative, and the high unit is what `(char) (0xD800 | (c >> 10))` truncates it to.
                    let offset = i64::from(value).wrapping_sub(0x1_0000);
                    let high = (0xD800 | (offset >> 10)) & 0xFFFF;
                    let low = (0xDC00 | (offset & 0x3FF)) & 0xFFFF;
                    units.push(u16::try_from(high).unwrap_or_default());
                    units.push(u16::try_from(low).unwrap_or_default());
                }
            }
        }
    }
    units
}

/// Units written as JSON string content `serde_json` reads back to them, an unpaired surrogate as `?` —
/// what `String.getBytes(UTF_8)` makes of it on the Java side.
fn write_units(out: &mut Vec<u8>, units: &[u16]) {
    for c in char::decode_utf16(units.iter().copied()).map(|unit| unit.unwrap_or('?')) {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{0}'..='\u{1F}' => out.extend_from_slice(format!("\\u{:04X}", u32::from(c)).as_bytes()),
            _ => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prepared(body: &[u8]) -> Result<String, Refused> {
        prepare(body, CONTROL_PLANE).map(|document| String::from_utf8(document.into_owned()).unwrap_or_default())
    }

    #[test]
    fn a_document_that_needs_nothing_is_borrowed_and_cut_at_its_end() {
        let body = br#" {"a":"\uD83D\uDE00","b":[1,2.5e3]} trailing"#;
        let document = prepare(body, CONTROL_PLANE).unwrap_or_default();
        assert!(matches!(document, Cow::Borrowed(_)));
        assert_eq!(document.as_ref(), br#"{"a":"\uD83D\uDE00","b":[1,2.5e3]}"#);
        assert!(prepare(body, SPRING_MVC).is_err());
        assert!(prepare(b"{} \n", SPRING_MVC).is_ok());
    }

    #[test]
    fn only_the_strings_that_need_it_are_rewritten() {
        assert_eq!(
            prepared(br#"{"a":"x\uD800y","b":"\uDE00","c":"ok\n"}"#),
            Ok(r#"{"a":"x?y","b":"?","c":"ok\n"}"#.into())
        );
        assert_eq!(
            prepared(b"[\"a\xC0\xA2b\",\"\xC1\x9C\",\"\xC0\x80\"]"),
            Ok("[\"a\\\"b\",\"\\\\\",\"\\u0000\"]".into())
        );
        assert_eq!(prepared(b"[\"\\uD800\xF4\x90\x80\x80\"]"), Ok("[\"\u{10000}?\"]".into()));
    }

    #[test]
    fn a_name_is_held_to_its_pairs() {
        assert!(prepared(br#"{"a\uD800":1}"#).is_err());
        assert!(prepared(br#"{"a\uDC00":1}"#).is_err());
        assert!(prepared(br#"{"\uD800\u0041":1}"#).is_err());
        assert!(prepared(br#"{"\uD83D\uDE00":1}"#).is_ok());
        assert_eq!(prepared(b"{\"secret\xC1\xB3\":1}"), Ok(r#"{"secrets":1}"#.into()));
    }

    #[test]
    fn the_limits_are_jackson_s() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(prepared(deep(CONTROL_PLANE.depth).as_bytes()).is_ok());
        assert!(prepared(deep(CONTROL_PLANE.depth + 1).as_bytes()).is_err());
        assert!(prepare(deep(SPRING_MVC.depth).as_bytes(), SPRING_MVC).is_ok());
        assert!(prepare(deep(SPRING_MVC.depth + 1).as_bytes(), SPRING_MVC).is_err());
        let number = |digits: usize| format!("[{}]", "1".repeat(digits));
        assert!(prepared(number(MAX_NUMBER_LENGTH).as_bytes()).is_ok());
        assert!(prepared(number(MAX_NUMBER_LENGTH + 1).as_bytes()).is_err());
        assert!(prepared(format!("[-{}]", "1".repeat(MAX_NUMBER_LENGTH)).as_bytes()).is_ok());
        assert!(prepared(format!("[1.{}]", "1".repeat(MAX_NUMBER_LENGTH - 1)).as_bytes()).is_ok());
        assert!(prepared(format!("[1.{}]", "1".repeat(MAX_NUMBER_LENGTH)).as_bytes()).is_err());
        let name = |n: usize| format!("{{\"{}\":1}}", "k".repeat(n));
        assert!(prepared(name(MAX_NAME_LENGTH).as_bytes()).is_ok());
        assert!(prepared(name(MAX_NAME_LENGTH + 1).as_bytes()).is_err());
    }

    #[test]
    fn what_the_grammar_refuses_here_is_refused() {
        for body in [
            &b""[..],
            b"  ",
            b"01",
            b"[01]",
            b"[1.]",
            b"[1e]",
            b"[-]",
            b"[\"\\q\"]",
            b"[\"\\u12\"]",
            b"[\"a\tb\"]",
            b"[\"\xFF\"]",
            b"[\"\x80\"]",
            b"[\"\xC2A\"]",
            b"[\"\xED\xA0\x80\"]",
            b"[\"\xF8\x88\x80\x80\x80\"]",
            b"nullx",
            b"[nul]",
            b"{\"a\" 1}",
            b"{\"a\":1 \"b\":2}",
            b"{1:2}",
            b"[\"open",
        ] {
            assert!(prepared(body).is_err(), "{:?}", String::from_utf8_lossy(body));
        }
        assert_eq!(prepared(b"null}"), Ok("null".into()));
    }

    #[test]
    fn other_encodings_are_read_as_jackson_detects_them() {
        let utf16: Vec<u8> = "{\"a\":\"\u{e9}\"}".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(prepared(&utf16), Ok("{\"a\":\"\u{e9}\"}".into()));
        let utf32: Vec<u8> = "{}".chars().flat_map(|c| u32::from(c).to_be_bytes()).collect();
        assert_eq!(prepared(&utf32), Ok("{}".into()));
        assert_eq!(prepared(b"\xEF\xBB\xBF{}"), Ok("{}".into()));
        assert!(prepared(b"\x00\x00\xFF\xFE{}").is_err());
    }
}
