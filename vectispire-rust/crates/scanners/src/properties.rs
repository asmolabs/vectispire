//! `java.util.Properties.load(InputStream)`, for the one value read from it: `gradle.properties`' `version`.
//!
//! The file is ISO-8859-1 — every byte one character, whatever the file was written in — with Java's escapes,
//! comments, separators and continuation lines, read as the JDK's `LineReader` and `loadConvert` read them. A
//! malformed `\uXXXX` anywhere in the file is an error for the whole file, as the JDK throws while loading. Pinned
//! by `reference/workspace/cases/manifests.json`.

/// The value the file gives `key`, the last one when it gives several; `Err` where `load` throws.
pub fn value_of(bytes: &[u8], key: &str) -> Result<Option<String>, Malformed> {
    let key: Vec<u16> = key.encode_utf16().collect();
    let mut lines = Lines { bytes, at: 0, skip_line_feed: false };
    let mut found = None;
    while let Some(line) = lines.next_line() {
        let (name, value) = split(&line);
        if convert(name)? == key {
            found = Some(convert(value)?);
        } else {
            // Converted all the same: a malformed escape in any line fails the load.
            convert(value)?;
        }
    }
    Ok(found.map(|units| vectispire_domain::java::from_utf16(&units)))
}

/// `Malformed \uxxxx encoding.`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

fn is_blank(c: u16) -> bool {
    c == u16::from(b' ') || c == u16::from(b'\t') || c == 0x0C
}

/// `Properties.LineReader`: logical lines, comments and blank lines dropped, continuations joined.
struct Lines<'a> {
    bytes: &'a [u8],
    at: usize,
    skip_line_feed: bool,
}

impl Lines<'_> {
    fn next_byte(&mut self) -> Option<u16> {
        let byte = self.bytes.get(self.at).copied()?;
        self.at = self.at.saturating_add(1);
        Some(u16::from(byte))
    }

    fn next_line(&mut self) -> Option<Vec<u16>> {
        let (cr, lf, backslash) = (u16::from(b'\r'), u16::from(b'\n'), u16::from(b'\\'));
        let mut line: Vec<u16> = Vec::new();
        let mut skip_white_space = true;
        let mut appended_line_begin = false;
        let mut preceding_backslash = false;
        loop {
            let Some(c) = self.next_byte() else {
                if line.is_empty() {
                    return None;
                }
                if preceding_backslash {
                    line.pop();
                }
                return Some(line);
            };
            if self.skip_line_feed {
                self.skip_line_feed = false;
                if c == lf {
                    continue;
                }
            }
            if skip_white_space {
                if is_blank(c) || (!appended_line_begin && (c == cr || c == lf)) {
                    continue;
                }
                skip_white_space = false;
                appended_line_begin = false;
            }
            if line.is_empty() && (c == u16::from(b'#') || c == u16::from(b'!')) {
                // A comment, to the end of its physical line: a backslash continues nothing here.
                loop {
                    match self.next_byte() {
                        None => return None,
                        Some(end) if end == cr || end == lf => break,
                        Some(_) => {}
                    }
                }
                skip_white_space = true;
                continue;
            }
            if c != lf && c != cr {
                line.push(c);
                preceding_backslash = c == backslash && !preceding_backslash;
                continue;
            }
            if line.is_empty() {
                skip_white_space = true;
                continue;
            }
            if self.at >= self.bytes.len() {
                if preceding_backslash {
                    line.pop();
                }
                return Some(line);
            }
            if !preceding_backslash {
                return Some(line);
            }
            // An odd backslash at the end of the line joins the next one, its leading blanks dropped.
            line.pop();
            skip_white_space = true;
            appended_line_begin = true;
            preceding_backslash = false;
            if c == cr {
                self.skip_line_feed = true;
            }
        }
    }
}

/// `load0`: the key up to the first unescaped `=`, `:` or blank; the value after the blanks and one separator.
fn split(line: &[u16]) -> (&[u16], &[u16]) {
    let (equals, colon, backslash) = (u16::from(b'='), u16::from(b':'), u16::from(b'\\'));
    let mut key_length = 0usize;
    let mut value_start = line.len();
    let mut has_separator = false;
    let mut preceding_backslash = false;
    while let Some(&c) = line.get(key_length) {
        if (c == equals || c == colon) && !preceding_backslash {
            value_start = key_length.saturating_add(1);
            has_separator = true;
            break;
        }
        if is_blank(c) && !preceding_backslash {
            value_start = key_length.saturating_add(1);
            break;
        }
        preceding_backslash = c == backslash && !preceding_backslash;
        key_length = key_length.saturating_add(1);
    }
    while let Some(&c) = line.get(value_start) {
        if !is_blank(c) {
            if !has_separator && (c == equals || c == colon) {
                has_separator = true;
            } else {
                break;
            }
        }
        value_start = value_start.saturating_add(1);
    }
    (line.get(..key_length).unwrap_or_default(), line.get(value_start..).unwrap_or_default())
}

/// `loadConvert`: `\uXXXX`, `\t`, `\r`, `\n`, `\f`, and any other escaped character as itself.
fn convert(segment: &[u16]) -> Result<Vec<u16>, Malformed> {
    let mut out = Vec::with_capacity(segment.len());
    let mut units = segment.iter().copied();
    while let Some(c) = units.next() {
        if c != u16::from(b'\\') {
            out.push(c);
            continue;
        }
        let escaped = units.next().ok_or(Malformed)?;
        let converted = match u8::try_from(escaped).ok() {
            Some(b'u') => {
                let mut value = 0u16;
                for _ in 0..4 {
                    let digit = units
                        .next()
                        .and_then(|hex| char::from_u32(u32::from(hex)))
                        .and_then(|hex| hex.to_digit(16))
                        .and_then(|digit| u16::try_from(digit).ok())
                        .ok_or(Malformed)?;
                    value = value.wrapping_shl(4) | digit;
                }
                value
            }
            Some(b't') => u16::from(b'\t'),
            Some(b'r') => u16::from(b'\r'),
            Some(b'n') => u16::from(b'\n'),
            Some(b'f') => 0x0C,
            _ => escaped,
        };
        out.push(converted);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(text: &[u8]) -> Result<Option<String>, Malformed> {
        value_of(text, "version")
    }

    #[test]
    fn lines_are_read_as_the_jdk_reads_them() {
        assert_eq!(version(b"version=1.0\n"), Ok(Some("1.0".into())));
        assert_eq!(version(b"  version   :   2.\\\n     0.\\u0031\\t \n"), Ok(Some("2.0.1\t ".into())));
        assert_eq!(version(b"# version=1\n! version=2\n"), Ok(None));
        assert_eq!(version(b"# a \\\nversion=6\n"), Ok(Some("6".into())), "a comment continues nothing");
        assert_eq!(version(b"version=7\\\n\nother=8\n"), Ok(Some("7".into())), "a blank line ends a continuation");
        assert_eq!(version(b"version=9\\"), Ok(Some("9".into())));
        assert_eq!(version(b"version=8.1\\\r\n  .2\r\n"), Ok(Some("8.1.2".into())));
        assert_eq!(version(b"vers\\ion=4\nversion\\=x=5\n"), Ok(Some("4".into())));
        assert_eq!(version(b"version\n"), Ok(Some(String::new())));
        assert_eq!(version(b"\x0cversion\x0c=\x0c10\x0c\n"), Ok(Some("10\u{c}".into())));
        assert_eq!(version(b"version=1-\xe9\n"), Ok(Some("1-\u{e9}".into())), "every byte one Latin-1 character");
        assert_eq!(version(b"version=1\nother=\\u12\n"), Err(Malformed), "anywhere in the file");
        assert_eq!(version(b"version=\\u00"), Err(Malformed));
        assert_eq!(version(b"version=\\uD800"), Ok(Some("?".into())));
    }
}
