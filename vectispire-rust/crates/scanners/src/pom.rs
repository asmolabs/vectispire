//! The version a `pom.xml` states — `ProjectManifest.maven`, through the JDK's DOM parser as the Java side
//! configures it.
//!
//! **The XML is the audited repository's.** The Java side refuses a doctype outright (no entity is ever read, no
//! file of the scanning host, no connection opened), and runs under `FEATURE_SECURE_PROCESSING`, whose JDK 25
//! limits refuse an element deeper than **100**, more than **200** attributes on one element, and a name longer
//! than **1,000** characters. Its factory is *not* namespace-aware: `m:version` is an element named `m:version`,
//! and an undeclared prefix is no error.
//!
//! What a refusal changes is narrow — any error reads as "maven, version unknown" — but it is not nothing: a
//! document the JDK refuses and this reader accepted would report a version Java does not. So this is a
//! non-validating XML 1.0 and 1.1 well-formedness check, refusing what that parser refuses, that keeps the text of
//! the root's first `version` child, or of its first `parent`'s, as `getTextContent` assembles it: character
//! data and CDATA of every descendant, references resolved, comments and processing instructions left out, line
//! ends normalised. Pinned by `reference/workspace/cases/manifests.json`.
//!
//! **Encodings**: UTF-8 (with or without its mark), UTF-16 by its mark or by `<?` in either byte order, and the
//! declared ISO-8859-1, windows-1252 and US-ASCII under the names the JDK accepts for them. Another charset the JDK
//! knows (`ISO-8859-2`, `Shift_JIS`…) is read when the document is ASCII, where they all agree; a document of one
//! of those with other bytes is refused here and read by Java — the one difference left, on a file nobody writes.
//! The element and attribute names are checked against XML 1.0's fifth edition, where the JDK's tables are older:
//! the two differ only on names outside ASCII.

/// `jdk.xml.maxElementDepth` under secure processing.
pub const MAX_DEPTH: usize = 100;
/// `jdk.xml.elementAttributeLimit`.
pub const MAX_ATTRIBUTES: usize = 200;
/// `jdk.xml.maxXMLNameLimit`.
pub const MAX_NAME: usize = 1000;

/// The project's version as the document states it, untrimmed; `Ok(None)` when it states none; `Err` when the JDK
/// would have refused the document.
pub fn version(bytes: &[u8]) -> Result<Option<String>, Malformed> {
    let text = decode(bytes)?;
    let mut reader =
        Reader { chars: text.chars().collect(), at: 0, xml11: false, stack: Vec::new(), capture: Capture::default() };
    reader.document()?;
    let capture = reader.capture;
    Ok(capture.root_version.or(capture.parent_version))
}

/// The document is not one the JDK's parser reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

// ------------------------------------------------------------------------------------------------ decoding

fn decode(bytes: &[u8]) -> Result<String, Malformed> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return utf8(rest);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, u16::from_be_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, u16::from_le_bytes);
    }
    if bytes.starts_with(&[0x00, 0x3C, 0x00, 0x3F]) {
        return utf16(bytes, u16::from_be_bytes);
    }
    if bytes.starts_with(&[0x3C, 0x00, 0x3F, 0x00]) {
        return utf16(bytes, u16::from_le_bytes);
    }
    let Some(name) = declared_encoding(bytes) else {
        return utf8(bytes);
    };
    let valid_name = name.chars().next().is_some_and(|first| first.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid_name {
        return Err(Malformed);
    }
    let upper = name.to_ascii_uppercase();
    if UTF8.contains(&upper.as_str()) {
        utf8(bytes)
    } else if LATIN1.contains(&upper.as_str()) {
        Ok(bytes.iter().map(|&byte| char::from(byte)).collect())
    } else if WINDOWS_1252.contains(&upper.as_str()) {
        Ok(bytes.iter().map(|&byte| windows_1252(byte)).collect())
    } else if (ASCII.contains(&upper.as_str()) || ASCII_COMPATIBLE.contains(&upper.as_str())) && bytes.is_ascii() {
        Ok(bytes.iter().map(|&byte| char::from(byte)).collect())
    } else {
        // UTF-16 or UTF-32 declared in a document written in ASCII, a charset the JDK does not know, or an
        // ASCII-compatible one with bytes this reader does not decode.
        Err(Malformed)
    }
}

const UTF8: [&str; 2] = ["UTF-8", "UTF8"];
const LATIN1: [&str; 12] = [
    "ISO-8859-1",
    "ISO_8859-1",
    "ISO8859_1",
    "ISO8859-1",
    "ISO_8859_1",
    "8859_1",
    "LATIN1",
    "L1",
    "IBM819",
    "CP819",
    "CSISOLATIN1",
    "ISO-IR-100",
];
const WINDOWS_1252: [&str; 2] = ["WINDOWS-1252", "CP1252"];
const ASCII: [&str; 11] = [
    "US-ASCII",
    "ASCII",
    "ANSI_X3.4-1968",
    "ANSI_X3.4-1986",
    "ISO646-US",
    "US",
    "IBM367",
    "CP367",
    "CSASCII",
    "ISO-IR-6",
    "DEFAULT",
];
/// Charsets the JDK reads that agree with ASCII on ASCII.
const ASCII_COMPATIBLE: [&str; 40] = [
    "ISO-8859-2",
    "ISO-8859-3",
    "ISO-8859-4",
    "ISO-8859-5",
    "ISO-8859-6",
    "ISO-8859-7",
    "ISO-8859-8",
    "ISO-8859-9",
    "ISO-8859-13",
    "ISO-8859-15",
    "ISO-8859-16",
    "LATIN2",
    "LATIN9",
    "WINDOWS-1250",
    "WINDOWS-1251",
    "WINDOWS-1253",
    "WINDOWS-1254",
    "WINDOWS-1255",
    "WINDOWS-1256",
    "WINDOWS-1257",
    "WINDOWS-1258",
    "CP1250",
    "CP1251",
    "KOI8-R",
    "KOI8-U",
    "SHIFT_JIS",
    "SJIS",
    "MS932",
    "WINDOWS-31J",
    "EUC-JP",
    "EUC-KR",
    "GB2312",
    "GBK",
    "GB18030",
    "BIG5",
    "IBM437",
    "CP437",
    "IBM850",
    "CP850",
    "TIS-620",
];

fn utf8(bytes: &[u8]) -> Result<String, Malformed> {
    std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| Malformed)
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<String, Malformed> {
    let (pairs, odd) = bytes.as_chunks::<2>();
    if !odd.is_empty() {
        return Err(Malformed);
    }
    char::decode_utf16(pairs.iter().map(|pair| unit(*pair))).collect::<Result<String, _>>().map_err(|_| Malformed)
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

/// The `encoding` of a declaration written in ASCII at the very start; its syntax is checked by the reader.
fn declared_encoding(bytes: &[u8]) -> Option<String> {
    let head: String =
        bytes.iter().take(512).take_while(|byte| byte.is_ascii()).map(|&byte| char::from(byte)).collect();
    let body = head.strip_prefix("<?xml")?;
    if !body.starts_with([' ', '\t', '\r', '\n']) {
        return None;
    }
    let (declaration, _) = body.split_once("?>")?;
    let (_, rest) = declaration.split_once("encoding")?;
    let rest =
        rest.trim_start_matches([' ', '\t', '\n', '\r']).strip_prefix('=')?.trim_start_matches([' ', '\t', '\n', '\r']);
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let (value, _) = rest.strip_prefix(quote)?.split_once(quote)?;
    Some(value.to_owned())
}

// ------------------------------------------------------------------------------------------------ reading

/// What `childText(root, "version")` and `childText(child(root, "parent"), "version")` collect.
#[derive(Default)]
struct Capture {
    root_version: Option<String>,
    parent_version: Option<String>,
    seen_root_version: bool,
    seen_parent: bool,
    seen_parent_version: bool,
    /// The depth of the element whose text is being collected, and which of the two it is.
    collecting: Option<(usize, bool)>,
    text: String,
}

struct Reader {
    chars: Vec<char>,
    at: usize,
    xml11: bool,
    /// The open elements' names; the depth is its length.
    stack: Vec<String>,
    capture: Capture,
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
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

impl Reader {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn bump(&mut self) {
        self.at = self.at.saturating_add(1);
    }

    fn next_char(&mut self) -> Result<char, Malformed> {
        let c = self.peek().ok_or(Malformed)?;
        self.bump();
        Ok(c)
    }

    fn starts_with(&self, text: &str) -> bool {
        let mut at = self.at;
        for expected in text.chars() {
            if self.chars.get(at) != Some(&expected) {
                return false;
            }
            at = at.saturating_add(1);
        }
        true
    }

    fn eat(&mut self, text: &str) -> bool {
        let found = self.starts_with(text);
        if found {
            self.at = self.at.saturating_add(text.chars().count());
        }
        found
    }

    fn require(&mut self, text: &str) -> Result<(), Malformed> {
        if self.eat(text) { Ok(()) } else { Err(Malformed) }
    }

    fn skip_space(&mut self) -> bool {
        let start = self.at;
        while self.peek().is_some_and(is_space) {
            self.bump();
        }
        self.at > start
    }

    /// A character the document may hold as itself: XML 1.1 keeps most controls for references only.
    fn allowed_raw(&self, c: char) -> bool {
        let char = matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..);
        char && !(self.xml11 && matches!(c, '\u{7F}'..='\u{84}' | '\u{86}'..='\u{9F}'))
    }

    /// A character a reference may name.
    fn allowed_referenced(&self, c: char) -> bool {
        matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
            || (self.xml11 && matches!(c, '\u{1}'..='\u{1F}'))
    }

    fn name(&mut self) -> Result<String, Malformed> {
        let first = self.peek().filter(|&c| is_name_start(c)).ok_or(Malformed)?;
        let mut name = String::from(first);
        self.bump();
        let mut length = first.len_utf16();
        while let Some(c) = self.peek().filter(|&c| is_name_char(c)) {
            name.push(c);
            length = length.saturating_add(c.len_utf16());
            self.bump();
        }
        if length > MAX_NAME {
            return Err(Malformed);
        }
        Ok(name)
    }

    fn document(&mut self) -> Result<(), Malformed> {
        if self.starts_with("<?xml") && self.chars.get(self.at.saturating_add(5)).is_some_and(|&c| is_space(c)) {
            self.declaration()?;
        }
        self.normalize_line_ends();
        self.misc()?;
        if !self.starts_with("<") || self.starts_with("<!") || self.starts_with("<?") {
            return Err(Malformed);
        }
        self.element()?;
        self.misc()?;
        if self.peek().is_some() { Err(Malformed) } else { Ok(()) }
    }

    /// `<?xml version=… encoding=… standalone=…?>`: the version first and required, each pseudo-attribute after
    /// white space, in that order.
    fn declaration(&mut self) -> Result<(), Malformed> {
        self.require("<?xml")?;
        let mut spaced = self.skip_space();
        let mut seen_encoding = false;
        let mut seen_standalone = false;
        let mut first = true;
        loop {
            if self.eat("?>") {
                return if first { Err(Malformed) } else { Ok(()) };
            }
            if !spaced {
                return Err(Malformed);
            }
            let name = self.name()?;
            self.skip_space();
            self.require("=")?;
            self.skip_space();
            let quote = self.next_char()?;
            if quote != '"' && quote != '\'' {
                return Err(Malformed);
            }
            let mut value = String::new();
            loop {
                let c = self.next_char()?;
                if c == quote {
                    break;
                }
                value.push(c);
            }
            match name.as_str() {
                "version" if first => match value.as_str() {
                    "1.0" => {}
                    "1.1" => self.xml11 = true,
                    _ => return Err(Malformed),
                },
                "encoding" if !first && !seen_encoding && !seen_standalone => seen_encoding = true,
                "standalone" if !first && !seen_standalone && matches!(value.as_str(), "yes" | "no") => {
                    seen_standalone = true;
                }
                _ => return Err(Malformed),
            }
            first = false;
            spaced = self.skip_space();
        }
    }

    /// Comments, processing instructions and white space, before or after the root.
    fn misc(&mut self) -> Result<(), Malformed> {
        loop {
            self.skip_space();
            if self.starts_with("<!--") {
                self.comment()?;
            } else if self.starts_with("<?") {
                self.processing_instruction()?;
            } else {
                return Ok(());
            }
        }
    }

    fn comment(&mut self) -> Result<(), Malformed> {
        self.require("<!--")?;
        loop {
            if self.eat("--") {
                return if self.eat(">") { Ok(()) } else { Err(Malformed) };
            }
            let c = self.next_char()?;
            if !self.allowed_raw(c) {
                return Err(Malformed);
            }
        }
    }

    fn processing_instruction(&mut self) -> Result<(), Malformed> {
        self.require("<?")?;
        let target = self.name()?;
        if target.eq_ignore_ascii_case("xml") {
            return Err(Malformed);
        }
        if self.eat("?>") {
            return Ok(());
        }
        if !self.skip_space() {
            return Err(Malformed);
        }
        loop {
            if self.eat("?>") {
                return Ok(());
            }
            let c = self.next_char()?;
            if !self.allowed_raw(c) {
                return Err(Malformed);
            }
        }
    }

    /// The root and everything under it, without recursion: the depth is the stack's.
    fn element(&mut self) -> Result<(), Malformed> {
        loop {
            if self.eat("</") {
                let name = self.name()?;
                self.skip_space();
                self.require(">")?;
                if self.stack.last() != Some(&name) {
                    return Err(Malformed);
                }
                self.close();
                if self.stack.is_empty() {
                    return Ok(());
                }
            } else if self.starts_with("<!--") {
                self.comment()?;
            } else if self.starts_with("<?") {
                self.processing_instruction()?;
            } else if self.eat("<![CDATA[") {
                loop {
                    if self.eat("]]>") {
                        break;
                    }
                    let c = self.next_char()?;
                    if !self.allowed_raw(c) {
                        return Err(Malformed);
                    }
                    self.text(c);
                }
            } else if self.eat("<") {
                if self.open()? && self.stack.is_empty() {
                    return Ok(());
                }
            } else if self.peek() == Some('&') {
                let c = self.reference()?;
                self.text(c);
            } else if self.eat("]]>") {
                return Err(Malformed);
            } else {
                let c = self.next_char()?;
                if !self.allowed_raw(c) {
                    return Err(Malformed);
                }
                self.text(c);
            }
        }
    }

    /// A start tag, its `<` read; whether it was empty (`/>`) and is therefore already closed.
    fn open(&mut self) -> Result<bool, Malformed> {
        let name = self.name()?;
        let mut attributes: Vec<String> = Vec::new();
        loop {
            let spaced = self.skip_space();
            if self.eat("/>") {
                self.push(name)?;
                self.close();
                return Ok(true);
            }
            if self.eat(">") {
                self.push(name)?;
                return Ok(false);
            }
            if !spaced {
                return Err(Malformed);
            }
            let attribute = self.name()?;
            if attributes.contains(&attribute) {
                return Err(Malformed);
            }
            attributes.push(attribute);
            if attributes.len() > MAX_ATTRIBUTES {
                return Err(Malformed);
            }
            self.skip_space();
            self.require("=")?;
            self.skip_space();
            let quote = self.next_char()?;
            if quote != '"' && quote != '\'' {
                return Err(Malformed);
            }
            loop {
                match self.peek() {
                    Some(c) if c == quote => {
                        self.bump();
                        break;
                    }
                    Some('<') | None => return Err(Malformed),
                    Some('&') => {
                        self.reference()?;
                    }
                    Some(c) if self.allowed_raw(c) => self.bump(),
                    Some(_) => return Err(Malformed),
                }
            }
        }
    }

    /// `&name;`, `&#…;` or `&#x…;`: only the five predefined entities — nothing is declared, a doctype being refused.
    fn reference(&mut self) -> Result<char, Malformed> {
        self.require("&")?;
        if self.eat("#x") {
            return self.character_reference(16);
        }
        if self.eat("#") {
            return self.character_reference(10);
        }
        let name = self.name()?;
        self.require(";")?;
        match name.as_str() {
            "lt" => Ok('<'),
            "gt" => Ok('>'),
            "amp" => Ok('&'),
            "apos" => Ok('\''),
            "quot" => Ok('"'),
            _ => Err(Malformed),
        }
    }

    fn character_reference(&mut self, radix: u32) -> Result<char, Malformed> {
        let mut value: u32 = 0;
        let mut digits = 0usize;
        while let Some(digit) = self.peek().and_then(|c| c.to_digit(radix)) {
            value = value.checked_mul(radix).and_then(|value| value.checked_add(digit)).ok_or(Malformed)?;
            digits = digits.saturating_add(1);
            self.bump();
        }
        if digits == 0 {
            return Err(Malformed);
        }
        self.require(";")?;
        char::from_u32(value).filter(|&c| self.allowed_referenced(c)).ok_or(Malformed)
    }

    fn push(&mut self, name: String) -> Result<(), Malformed> {
        let depth = self.stack.len().saturating_add(1);
        if depth > MAX_DEPTH {
            return Err(Malformed);
        }
        let capture = &mut self.capture;
        if capture.collecting.is_none() {
            let parent_is_root = self.stack.len() == 1;
            let inside_first_parent = self.stack.len() == 2
                && capture.seen_parent
                && !capture.seen_parent_version
                && self.stack.last().is_some_and(|open| open == "parent");
            if parent_is_root && name == "version" && !capture.seen_root_version {
                capture.seen_root_version = true;
                capture.collecting = Some((depth, true));
            } else if parent_is_root && name == "parent" && !capture.seen_parent {
                capture.seen_parent = true;
            } else if inside_first_parent && name == "version" {
                capture.seen_parent_version = true;
                capture.collecting = Some((depth, false));
            }
        }
        self.stack.push(name);
        Ok(())
    }

    fn close(&mut self) {
        let depth = self.stack.len();
        self.stack.pop();
        if let Some((collecting, of_root)) = self.capture.collecting
            && collecting == depth
        {
            let text = std::mem::take(&mut self.capture.text);
            if of_root {
                self.capture.root_version = Some(text);
            } else {
                self.capture.parent_version = Some(text);
            }
            self.capture.collecting = None;
        }
    }

    /// A character of the element text being collected, if one is.
    fn text(&mut self, c: char) {
        if self.capture.collecting.is_some() {
            self.capture.text.push(c);
        }
    }

    /// Line ends as the parser hands them over, from here on: `\r\n` and `\r` read as `\n`, and in XML 1.1 `\r`
    /// followed by U+0085, U+0085 and U+2028 too. Done on the input, before any markup is read — a `\r` and a `\n`
    /// with a comment between them are two line ends — and never to a referenced character: `&#13;` stays.
    fn normalize_line_ends(&mut self) {
        let rest = self.chars.split_off(self.at.min(self.chars.len()));
        let mut normalized = Vec::with_capacity(rest.len());
        let mut iterator = rest.into_iter().peekable();
        while let Some(c) = iterator.next() {
            match c {
                '\r' => {
                    if iterator.peek().is_some_and(|&next| next == '\n' || (self.xml11 && next == '\u{85}')) {
                        iterator.next();
                    }
                    normalized.push('\n');
                }
                '\u{85}' | '\u{2028}' if self.xml11 => normalized.push('\n'),
                other => normalized.push(other),
            }
        }
        self.chars.extend(normalized);
    }
}
