//! The few `java.lang` behaviours the control plane's data contracts rest on, spelled once.
//!
//! **Each one differs from Rust's nearest equivalent**, and each difference reaches stored data: a tool
//! key stripped of a no-break space by Rust and not by Java is another issue's identity; a retention
//! setting of `٣` is three days to Java and unreadable to `str::parse`. They are held to
//! `reference/fingerprints/`, `reference/vocabulary/` and `reference/cron/`, which Java wrote.

use serde_json::Value;

/// `Character.isWhitespace`, which `String.strip` and `isBlank` ask: the Unicode space separators
/// **except the no-break ones** (U+00A0, U+2007, U+202F), the line and paragraph separators, and the
/// controls U+0009–U+000D and U+001C–U+001F. Rust's `char::is_whitespace` disagrees on six of these:
/// it takes the three no-break spaces and U+0085, and leaves U+001C–U+001F.
pub fn is_whitespace(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{20}' | '\u{1680}' | '\u{2000}'..='\u{2006}' | '\u{2008}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{205f}' | '\u{3000}')
}

/// `String.strip`: [`is_whitespace`] off both ends.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_whitespace)
}

/// `String.isBlank`: empty once stripped.
pub fn is_blank(text: &str) -> bool {
    strip(text).is_empty()
}

/// `String.trim`: every char up to U+0020 off both ends — the controls included, nothing beyond.
pub fn trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

/// `String.length()`: UTF-16 units, so an astral character counts two.
pub fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// A Java string's UTF-16 units as the string its UTF-8 bytes decode to — `getBytes(UTF_8)` writes an
/// unpaired surrogate as `?`, **not** as U+FFFD, which is what Rust's `String::from_utf16_lossy` writes.
///
/// A Rust `String` cannot hold an unpaired surrogate, so this is where one arriving from a lenient
/// reader has to be turned into what Java would have hashed. Anything hashed or stored after it then
/// agrees with Java byte for byte.
pub fn from_utf16(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied()).map(|unit| unit.unwrap_or('?')).collect()
}

/// The zero of every run of ten decimal digits `Character.digit(char, 10)` reads in the Basic
/// Multilingual Plane (Unicode 16, JDK 25) — held to Java's own list in `reference/vocabulary/`.
/// `Integer.parseInt` takes any of them: `٣` is three, `５` is five.
pub const DIGIT_ZEROS: [u32; 37] = [
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0x0DE6,
    0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40,
    0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
];

/// `Character.digit(char, 10)` — the `char` overload, which is what `parseInt` calls: a character outside
/// the Basic Multilingual Plane reaches it as two surrogates, neither a digit.
pub fn digit(c: char) -> Option<u32> {
    let code = u32::from(c);
    DIGIT_ZEROS.iter().find_map(|&zero| code.checked_sub(zero).filter(|&value| value < 10))
}

/// Where `Integer.parseInt` stopped, in UTF-16 units from the start of the text it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAnInt {
    /// Nothing to read.
    Empty,
    /// The unit at this index is not a digit, or is the digit that overflowed.
    At(usize),
}

/// `Integer.parseInt`'s reading, without its message: an optional sign, then at least one digit,
/// within `int`. Both of Java's overloads read this way and word the refusal differently
/// ([`parse_int`], [`parse_int_in`]).
pub fn read_int(text: &str) -> Result<i32, NotAnInt> {
    let mut chars = text.chars().peekable();
    let Some(&first) = chars.peek() else { return Err(NotAnInt::Empty) };
    let mut index = 0usize;
    let negative = first == '-';
    if first < '0' {
        if first != '-' && first != '+' {
            return Err(NotAnInt::At(0));
        }
        chars.next();
        index = 1;
        if chars.peek().is_none() {
            return Err(NotAnInt::At(1));
        }
    }
    // Accumulated as a magnitude, against the bound of its sign: -2147483648 is an int, 2147483648 is not.
    let limit: i64 = if negative { 1 << 31 } else { (1 << 31) - 1 };
    let mut magnitude: i64 = 0;
    for c in chars {
        let next = digit(c)
            .and_then(|d| magnitude.checked_mul(10)?.checked_add(i64::from(d)))
            .filter(|&value| value <= limit)
            .ok_or(NotAnInt::At(index))?;
        magnitude = next;
        index = index.checked_add(c.len_utf16()).ok_or(NotAnInt::At(index))?;
    }
    let value = if negative { magnitude.checked_neg().ok_or(NotAnInt::At(0))? } else { magnitude };
    i32::try_from(value).map_err(|_| NotAnInt::At(0))
}

/// `Integer.parseInt(String)`: every refusal is `For input string: "<text>"`.
pub fn parse_int(text: &str) -> Result<i32, String> {
    read_int(text).map_err(|_| format!("For input string: \"{text}\""))
}

/// `Integer.parseInt(CharSequence, begin, end, 10)` on the sub-sequence `text`: an empty one is
/// `For input string: ""`, anything else `Error at index <i> in: "<text>"`, the index counted from the
/// sub-sequence's start.
pub fn parse_int_in(text: &str) -> Result<i32, String> {
    read_int(text).map_err(|refusal| match refusal {
        NotAnInt::Empty => "For input string: \"\"".to_owned(),
        NotAnInt::At(index) => format!("Error at index {index} in: \"{text}\""),
    })
}

/// Jackson's `node.path(field)`: the member of an object, absent for anything else.
pub fn path<'a>(node: Option<&'a Value>, field: &str) -> Option<&'a Value> {
    node?.as_object()?.get(field)
}

/// Jackson's `asText(default)`: a string's text, a number's or a boolean's text form, `""` for an object
/// or an array **whatever the default** — a container's `asText()` is empty, and the default is taken only
/// for a missing or null node.
pub fn as_text(node: Option<&Value>, default: Option<&str>) -> Option<String> {
    match node {
        None | Some(Value::Null) => default.map(str::to_owned),
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Bool(flag)) => Some(flag.to_string()),
        Some(Value::Number(number)) => Some(if number.is_i64() || number.is_u64() {
            number.to_string()
        } else {
            number.as_f64().map_or_else(|| number.to_string(), crate::wire::java_double_to_string)
        }),
        Some(Value::Array(_) | Value::Object(_)) => Some(String::new()),
    }
}

/// `String.toLowerCase(Locale.ROOT)`.
///
/// Rust's `to_lowercase` applies the same unconditional mappings (the dotted capital I becomes `i̇`,
/// the Kelvin sign `k`) and differs on **one character**: the capital sigma, which the root locale lowers
/// by context — `ς` at the end of a word, `σ` elsewhere. Unicode, and Rust, decide "end of a word" by
/// skipping case-ignorable characters; Java decides it with its word `BreakIterator`, whose words run
/// across a hyphen, a period, an apostrophe or an underscore and between letters and digits: "ΣΣ-ı" keeps
/// two medial sigmas in Java and ends on a final one in Rust. An imported tool's name is lowered into its
/// key, so the difference would be fingerprint material; each sigma is therefore decided again here, by
/// [`sigma_is_final`].
pub fn to_lower_root(text: &str) -> String {
    if !text.contains('\u{3a3}') {
        return text.to_lowercase();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (index, &c) in chars.iter().enumerate() {
        if c == '\u{3a3}' {
            out.push(if sigma_is_final(&chars, index) { 'ς' } else { 'σ' });
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// What Java's word rules (the JDK's legacy `BreakIterator` word instance) make of a character, as far as
/// the sigma's context needs: letters and digits alternate within one word; a single mid-word mark joins
/// two letters, a single mid-number mark two digits; a danda ends a word; combining marks and format
/// characters are transparent; anything else stands alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WordClass {
    Letter,
    Digit,
    /// `.`, `'` and `"`, which join letters and digits alike.
    MidBoth,
    MidWord,
    MidNumber,
    Danda,
    Transparent,
    Alone,
}

fn word_class(c: char) -> WordClass {
    match c {
        '.' | '\'' | '"' => WordClass::MidBoth,
        // Dash and connector punctuation, the soft hyphen (a format character, but listed here, so a mark
        // of its own), the hyphenation point.
        '-'
        | '_'
        | '\u{ad}'
        | '\u{58a}'
        | '\u{5be}'
        | '\u{1400}'
        | '\u{1806}'
        | '\u{2010}'..='\u{2015}'
        | '\u{2027}'
        | '\u{203f}'
        | '\u{2040}'
        | '\u{2054}'
        | '\u{2e17}'
        | '\u{2e1a}'
        | '\u{2e3a}'
        | '\u{2e3b}'
        | '\u{2e40}'
        | '\u{301c}'
        | '\u{3030}'
        | '\u{30a0}'
        | '\u{fe31}'..='\u{fe34}'
        | '\u{fe4d}'..='\u{fe4f}'
        | '\u{fe58}'
        | '\u{fe63}'
        | '\u{ff0d}'
        | '\u{ff3f}' => WordClass::MidWord,
        ',' | '\u{66b}' => WordClass::MidNumber,
        '\u{964}' | '\u{965}' => WordClass::Danda,
        // Combining marks that are not alphabetic, and format characters: they never break a word.
        '\u{300}'..='\u{36f}'
        | '\u{483}'..='\u{489}'
        | '\u{1ab0}'..='\u{1aff}'
        | '\u{1dc0}'..='\u{1dff}'
        | '\u{20d0}'..='\u{20ff}'
        | '\u{fe00}'..='\u{fe0f}'
        | '\u{fe20}'..='\u{fe2f}'
        | '\u{600}'..='\u{605}'
        | '\u{61c}'
        | '\u{6dd}'
        | '\u{70f}'
        | '\u{180e}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}'
        | '\u{feff}'
        | '\u{fff9}'..='\u{fffb}' => WordClass::Transparent,
        // Kana and the unified ideographs have runs of their own; the circled letters are symbols.
        '\u{3005}'
        | '\u{3041}'..='\u{30fe}'
        | '\u{4e00}'..='\u{9fa5}'
        | '\u{f900}'..='\u{fa2d}'
        | '\u{24b6}'..='\u{24e9}' => WordClass::Alone,
        _ if c.is_numeric() => WordClass::Digit,
        _ if c.is_alphabetic() => WordClass::Letter,
        _ => WordClass::Alone,
    }
}

/// The next index at or after `from` whose class is not transparent.
fn next_solid(chars: &[char], from: usize) -> Option<usize> {
    (from..chars.len()).find(|&i| chars.get(i).is_some_and(|&c| word_class(c) != WordClass::Transparent))
}

/// Where the word starting at `start` ends: letters and digits alternating, each run joined by single
/// mid marks of its kind, a danda closing a run of letters, transparent characters carried along.
fn word_end(chars: &[char], start: usize) -> usize {
    let class_at = |i: usize| chars.get(i).map(|&c| word_class(c));
    let mut end = start;
    let mut after_danda = false;
    while let Some(i) = next_solid(chars, end) {
        let run = match class_at(i) {
            Some(WordClass::Letter) if !after_danda => WordClass::Letter,
            Some(WordClass::Digit) => WordClass::Digit,
            _ => break,
        };
        // The run, its joined continuations, then its trailing transparent characters.
        let mut cursor = i;
        loop {
            while let Some(next) = next_solid(chars, cursor.saturating_add(1)) {
                if class_at(next) == Some(run) {
                    cursor = next;
                } else {
                    break;
                }
            }
            let Some(mark) = next_solid(chars, cursor.saturating_add(1)) else { break };
            let joins = matches!(
                (run, class_at(mark)),
                (_, Some(WordClass::MidBoth))
                    | (WordClass::Letter, Some(WordClass::MidWord))
                    | (WordClass::Digit, Some(WordClass::MidNumber))
            );
            match next_solid(chars, mark.saturating_add(1)) {
                Some(after) if joins && class_at(after) == Some(run) => cursor = after,
                _ => break,
            }
        }
        end = cursor.saturating_add(1);
        after_danda = false;
        if run == WordClass::Letter
            && let Some(danda) = next_solid(chars, end).filter(|&d| class_at(d) == Some(WordClass::Danda))
        {
            end = danda.saturating_add(1);
            after_danda = true;
        }
    }
    // Transparent characters after the last solid one still belong to the word: no break falls before one.
    next_solid(chars, end).unwrap_or(chars.len()).max(end)
}

/// The word holding `index`, as `[start, end)`, words being found from the start of the text as Java's
/// iterator finds them: a word where one starts, otherwise a single character with its transparent tail.
fn word_around(chars: &[char], index: usize) -> (usize, usize) {
    let mut start = 0usize;
    while start < chars.len() {
        let starts_word =
            chars.get(start).is_some_and(|&c| matches!(word_class(c), WordClass::Letter | WordClass::Digit));
        let end = if starts_word {
            word_end(chars, start)
        } else {
            next_solid(chars, start.saturating_add(1)).unwrap_or(chars.len())
        };
        let end = end.max(start.saturating_add(1));
        if index < end {
            return (start, end);
        }
        start = end;
    }
    (index, index.saturating_add(1))
}

/// `Character.isLowerCase || isUpperCase || isTitleCase`, with the other-lowercase and other-uppercase
/// letters Java's `ConditionalSpecialCasing.isCased` adds — which Rust's properties already include.
fn is_cased(c: char) -> bool {
    c.is_lowercase()
        || c.is_uppercase()
        || matches!(c, '\u{1c5}' | '\u{1c8}' | '\u{1cb}' | '\u{1f2}' | '\u{1f88}'..='\u{1f8f}' | '\u{1f98}'..='\u{1f9f}'
            | '\u{1fa8}'..='\u{1faf}' | '\u{1fbc}' | '\u{1fcc}' | '\u{1ffc}')
}

/// `ConditionalSpecialCasing.isFinalCased`: a cased letter before the sigma within its word, and none after.
fn sigma_is_final(chars: &[char], index: usize) -> bool {
    let (start, end) = word_around(chars, index);
    let before = chars.get(start..index).unwrap_or_default();
    let after = chars.get(index.saturating_add(1)..end).unwrap_or_default();
    before.iter().any(|&c| is_cased(c)) && !after.iter().any(|&c| is_cased(c))
}

/// `String.CASE_INSENSITIVE_ORDER`: code point by code point (a surrogate pair read as one), each pair compared as
/// is, then upper-cased, then lower-cased, **by the simple one-to-one mappings** `Character.toUpperCase(int)` and
/// `toLowerCase(int)` use — and the shorter string, in UTF-16 units, first when one is a prefix of the other.
///
/// Not Rust's `to_lowercase` comparison: its full mappings turn `ß` into `SS` and `İ` into two characters, where
/// Java's simple mappings leave `ß` alone and make `İ` an `i`. The solutions tree is sorted by this, and a list
/// sorted otherwise is a screen that differs from the Java one.
pub fn compare_ignore_case(left: &str, right: &str) -> std::cmp::Ordering {
    let mut a = left.chars();
    let mut b = right.chars();
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) => {
                if x == y {
                    continue;
                }
                let (ux, uy) = (simple_upper(x), simple_upper(y));
                if ux == uy {
                    continue;
                }
                let (lx, ly) = (simple_lower(ux), simple_lower(uy));
                if lx != ly {
                    return (lx as u32).cmp(&(ly as u32));
                }
            }
            // A pair can only be equal in UTF-16 length up to here; what is left decides, in units.
            (rest_a, rest_b) => {
                let left_units = rest_a.map_or(0, char::len_utf16) + a.map(char::len_utf16).sum::<usize>();
                let right_units = rest_b.map_or(0, char::len_utf16) + b.map(char::len_utf16).sum::<usize>();
                return left_units.cmp(&right_units);
            }
        }
    }
}

/// `Character.toUpperCase(int)`: Rust's mapping where it is one character — Java's simple mapping is that one —
/// and the character itself where Rust's full mapping expands (`ß`, the ligatures), as Java has no simple one.
fn simple_upper(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(only), None) => only,
        _ => c,
    }
}

/// `Character.toLowerCase(int)`: as [`simple_upper`], and `İ` (U+0130) to `i`, its simple mapping, where Rust's
/// full one adds a combining dot.
fn simple_lower(c: char) -> char {
    if c == '\u{130}' {
        return 'i';
    }
    let mut lower = c.to_lowercase();
    match (lower.next(), lower.next()) {
        (Some(only), None) => only,
        _ => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_of_digits_is_ten_long() {
        // `Character.digit` answers 0 to 9: the unit after a run's nine is not a ten. The reference set pins
        // where the runs start; this pins where they stop.
        for zero in DIGIT_ZEROS {
            let nine = char::from_u32(zero + 9).unwrap();
            assert_eq!(digit(nine), Some(9), "{zero:#x}");
            if let Some(after) = char::from_u32(zero + 10).filter(|c| !DIGIT_ZEROS.contains(&u32::from(*c))) {
                assert_eq!(digit(after), None, "{zero:#x}");
            }
        }
    }
}
