//! What `ScimProvisioningService` decides about a SCIM request before it reads a row: the list's page (RFC 7644
//! §3.4.2.4), the filters it evaluates (§3.4.2.2), and how a group member is named — by a PATCH's value, by its
//! `members[value eq "…"]` path. The service is `vectispire-cp-access`'s `scim`; these are its pure parts.
//!
//! Held to `reference/access/scim/java-answers.json`, which `ScimReferenceSetTest` writes from the Java service
//! itself (its repositories mocked and recording what they were asked): the filters accepted and refused with the
//! controller's own error body, the pages, the member values and the removal paths.

use serde_json::Value;

use crate::{bounded_text, java, list_window};

/// `Page.MAX_COUNT`: the most resources a page answers, the figure every list route pages by.
pub const MAX_COUNT: i32 = 500;

const _: () = assert!(MAX_COUNT as i64 == list_window::MAX_LIMIT);

/// `ScimErrorResponse.INVALID_FILTER` (RFC 7644 §3.12): the filter is not one this endpoint evaluates.
pub const INVALID_FILTER: &str = "invalidFilter";

/// `ScimErrorResponse.UNIQUENESS` (RFC 7644 §3.3): a unique attribute's value is already in use — how a directory
/// tells "already provisioned, link it" from a failure.
pub const UNIQUENESS: &str = "uniqueness";

/// How much of a refused filter its refusal quotes.
const QUOTED_FILTER: usize = 200;

/// `Page`: one page of a SCIM list, `startIndex` 1-based, `totalResults` every resource the request matched.
///
/// **SCIM's rule, not `ListWindow`'s**: the RFC does not let a provider refuse these two. A `startIndex` below 1 is
/// read as 1, a negative `count` as 0 (which answers the total alone), a `count` past [`MAX_COUNT`] as [`MAX_COUNT`];
/// an identity provider answered a 400 stops synchronising. **Asked neither, every resource**, as before the routes
/// read them; a `startIndex` alone answers every resource from there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub resources: Vec<T>,
    /// Every resource the request matched, whatever the page.
    pub total_results: usize,
    /// The 1-based index of the first resource, as interpreted.
    pub start_index: i32,
}

impl<T> Page<T> {
    /// `Page.of`: `all` is every resource the request matched, in the order the pages are cut from.
    pub fn of(all: Vec<T>, start_index: Option<i32>, count: Option<i32>) -> Page<T> {
        let total_results = all.len();
        let start_index = start_index.map_or(1, |start| start.max(1));
        // `Math.min(start - 1L, size)`: in a wider type, so a start of `Integer.MAX_VALUE` is past the end, not a wrap.
        let from = usize::try_from(start_index.saturating_sub(1)).map_or(total_results, |skip| skip.min(total_results));
        let size = count.map_or(total_results, |count| usize::try_from(count.clamp(0, MAX_COUNT)).unwrap_or(0));
        let to = from.saturating_add(size).min(total_results);
        let resources = all.into_iter().skip(from).take(to.saturating_sub(from)).collect();
        Page { resources, total_results, start_index }
    }

    /// `Page.map`: the same page, each resource turned into what the route answers.
    pub fn map<R>(self, mapper: impl FnMut(T) -> R) -> Page<R> {
        Page {
            resources: self.resources.into_iter().map(mapper).collect(),
            total_results: self.total_results,
            start_index: self.start_index,
        }
    }
}

/// One of the two filters the users' list evaluates, with the value it looks the account up by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserFilter {
    /// `userName eq "…"`: the name lower-cased in the root locale, as every username is stored.
    UserName(String),
    /// `externalId eq "…"`: the identity provider's subject, as sent.
    ExternalId(String),
}

/// `InvalidFilterException`: answered 400 with `scimType` [`INVALID_FILTER`] and this message as its `detail`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidFilter(pub String);

/// The filter of a users' list: `None` without one — absent or blank, every account — the filter it names, or a
/// refusal.
///
/// **Anything but `userName eq "…"` and `externalId eq "…"` is refused, never answered with every account**: a
/// directory asking `emails[value eq "a@example.org"]` before creating an account read the first account of the list
/// as its match, and could bind or overwrite the wrong one. The attribute and the operator are read in any ASCII case
/// (`(?i)` without `UNICODE_CASE`), the value is a quoted string whose escapes are a backslash and one character, the
/// whole filter trimmed as `String.trim` trims.
pub fn user_filter(filter: Option<&str>) -> Result<Option<UserFilter>, InvalidFilter> {
    let Some(filter) = filter.filter(|filter| !java::is_blank(filter)) else {
        return Ok(None);
    };
    let trimmed = java::trim(filter);
    match supported(trimmed) {
        Some((true, value)) => Ok(Some(UserFilter::UserName(java::to_lower_root(&value)))),
        Some((false, value)) => Ok(Some(UserFilter::ExternalId(value))),
        None => Err(InvalidFilter(format!(
            "Unsupported filter \"{}\": only userName eq \"…\" and externalId eq \"…\" are evaluated.",
            bounded_text::clip(Some(trimmed), QUOTED_FILTER).unwrap_or_default()
        ))),
    }
}

/// `(?i)(userName|externalId)\s+eq\s+"((?:[^"\\]|\\.)*)"`, matched against the whole text, and the value unescaped
/// as `replaceAll("\\\\(.)", "$1")` unescapes it: whether the attribute is `userName`, and the value.
///
/// Read by hand rather than by a regular expression engine whose `\s`, `.` and case folding are not Java's. The
/// expression has one reading: a backslash is consumed only with the character after it, so the value ends at the
/// first quote no backslash escapes, and that quote must end the filter.
fn supported(text: &str) -> Option<(bool, String)> {
    let (is_user_name, rest) = match strip_word(text, "username") {
        Some(rest) => (true, rest),
        None => (false, strip_word(text, "externalid")?),
    };
    let rest = strip_spaces(rest)?;
    let rest = strip_spaces(strip_word(rest, "eq")?)?;
    let mut chars = rest.strip_prefix('"')?.chars();
    let mut value = String::new();
    loop {
        match chars.next()? {
            '"' => return chars.as_str().is_empty().then_some((is_user_name, value)),
            // `.` takes any character but a line terminator.
            '\\' => value.push(chars.next().filter(|&c| !is_line_terminator(c))?),
            c => value.push(c),
        }
    }
}

/// `word` (ASCII, lower case) at the start of `text` in any ASCII case, and what follows it.
fn strip_word<'a>(text: &'a str, word: &str) -> Option<&'a str> {
    let head = text.get(..word.len())?;
    if head.eq_ignore_ascii_case(word) { text.get(word.len()..) } else { None }
}

/// `\s+`: at least one of Java's six white-space characters (`[ \t\n\x0B\f\r]`, no Unicode space), and what follows.
fn strip_spaces(text: &str) -> Option<&str> {
    let rest = text.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']);
    (rest.len() < text.len()).then_some(rest)
}

/// A line terminator, which `.` does not match and before which a final `$` matches.
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// How a group's member is named: an account's identifier, or its username.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberRef {
    /// A number `Long.parseLong` reads (`+7`, `٧`): the account holding that identifier, if one does.
    Id(i64),
    /// Anything else: the account of that name, lower-cased in the root locale.
    UserName(String),
}

/// `resolveUserId`'s reading of a member's value, before the lookup: nothing for an absent or blank value.
pub fn member_ref(value: Option<&str>) -> Option<MemberRef> {
    let value = value.filter(|value| !java::is_blank(value))?;
    let trimmed = java::trim(value);
    Some(match java::read_long(trimmed) {
        Some(id) => MemberRef::Id(id),
        None => MemberRef::UserName(java::to_lower_root(trimmed)),
    })
}

/// The text of a PATCH entry's `value`, as Jackson 3's `asString()` gives it: a string as it is, a number or a
/// boolean as written, `null` as empty.
///
/// **An object or an array names no account**, as an entry without a `value` names nobody and is skipped — Java's
/// `asString(null)`. Its `asString()` threw on a container and answered the PATCH 500, the directory's malformed body
/// reported as the server's failure (asmolabs/vectispire#92).
pub fn member_value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some(String::new()),
        Value::Array(_) | Value::Object(_) => None,
        scalar => java::as_text(Some(scalar), None),
    }
}

/// What a PATCH `remove` takes away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removal {
    /// `members[value eq "…"]`: the member that value names, read as [`member_ref`] reads one.
    One(String),
    /// `members`: everybody.
    Everyone,
    /// Any other path, or none: nothing.
    Nothing,
}

/// `handleRemoveMembers`' reading of the path: `members[value eq ` exactly (case counts), every such prefix and
/// every `]` removed, then one leading quote and one quote that ends the text — `"$`, so also before a final line
/// terminator; or `members` in any case `equalsIgnoreCase` allows (`memberſ` included).
pub fn removal(path: Option<&str>) -> Removal {
    const PREFIX: &str = "members[value eq ";
    let path = path.unwrap_or("");
    if path.starts_with(PREFIX) {
        Removal::One(unquote(&path.replace(PREFIX, "").replace(']', "")))
    } else if is_members(path) {
        Removal::Everyone
    } else {
        Removal::Nothing
    }
}

/// `replaceAll("^\"|\"$", "")`.
fn unquote(value: &str) -> String {
    let rest = value.strip_prefix('"').unwrap_or(value);
    // `$` without MULTILINE matches at the end, before a final `\r\n`, or before one final terminator.
    for tail in ["", "\r\n", "\n", "\r", "\u{85}", "\u{2028}", "\u{2029}"] {
        if let Some(head) = rest.strip_suffix(tail).and_then(|head| head.strip_suffix('"')) {
            return format!("{head}{tail}");
        }
    }
    rest.to_owned()
}

/// `"members".equalsIgnoreCase(path)`: per character, equal once upper-cased or lower-cased — so `ſ`, whose upper
/// case is `S`, is an `s`. No other character's case mapping lands on a letter of `members`.
fn is_members(path: &str) -> bool {
    path.chars().count() == "members".len()
        && path
            .chars()
            .zip("members".chars())
            .all(|(c, expected)| c.to_ascii_lowercase() == expected || (c == '\u{17f}' && expected == 's'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_member_path_in_any_case_is_everyone() {
        assert_eq!(removal(Some("MEMBERS")), Removal::Everyone);
        assert_eq!(removal(Some("memberſ")), Removal::Everyone);
        assert_eq!(removal(Some(" members")), Removal::Nothing);
        assert_eq!(removal(None), Removal::Nothing);
    }

    #[test]
    fn a_quote_before_a_final_terminator_is_removed() {
        assert_eq!(unquote("\"7\"\r\n"), "7\r\n");
        assert_eq!(unquote("\"7\"\n\n"), "7\"\n\n");
        assert_eq!(unquote("\""), "");
        assert_eq!(unquote("\"\""), "");
    }
}
