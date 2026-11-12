//! Why a scan could not run, as it may leave the agent — `FailureReason.scrub`.
//!
//! **Scrubbed of every secret this process holds, by value, before the text leaves.** The control
//! plane scrubs again by shape, but it cannot know what this side was handed: the task's deployment key
//! and token, the API key, the signing key. The same scrubbed text is what the log shows.
//!
//! The Java class stays the reference: `reference/failure-reason/` holds its answers for inputs chosen
//! to tell two regex engines apart, and this module's test reads them. Java's `\s`, `\b` and `(?i)`
//! are ASCII-only on JDK 19 and later, so they are spelled ASCII-only here too.

use regex::Regex;
use std::sync::LazyLock;

/// The longest reason that leaves, in UTF-16 units as Java counts them.
pub const MAX_LENGTH: usize = 1_000;

const MASK: &str = "***";

/// A secret shorter than this is not looked for: it would mask unrelated words.
const MIN_SECRET_LENGTH: usize = 6;

/// Java's `\s`, outside a class.
const SPACE: &str = r"[ \t\n\x0B\x0C\r]";

#[allow(clippy::expect_used)] // Literals, compiled by the tests: a typo fails the build's first test.
fn compiled(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a valid literal pattern")
}

static PEM_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    compiled(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)")
});
static USER_INFO: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"(?-u:\b)((?i-u:[a-z][a-z0-9+.\-]*)://)([^ \t\n\x0B\x0C\r/@]+)@"));
static SEALED: LazyLock<Regex> = LazyLock::new(|| compiled(r"sealed:v[0-9]+:[A-Za-z0-9+/=]+"));
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| compiled(&format!(r"(?-u:\b)((?i-u:bearer){SPACE}+)[A-Za-z0-9._~+/=\-]+")));
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    compiled(&format!(
        r#"(?-u:\b)((?i-u:token|password|passwd|secret|api[_-]?key|private[_-]?key))({SPACE}*[=:]{SPACE}*)[^ \t\n\x0B\x0C\r,;&"']+"#
    ))
});
static CONTROL: LazyLock<Regex> = LazyLock::new(|| compiled(r"[\x00-\x1F\x7F\u{2028}\u{2029}]+"));
static SPACES: LazyLock<Regex> = LazyLock::new(|| compiled(" {2,}"));
/// Java's `\R`, the separator `String.split("\\R")` cuts a secret's lines at.
static LINE_BREAK: LazyLock<Regex> = LazyLock::new(|| compiled(r"\r\n|[\n\x0B\x0C\r\u{85}\u{2028}\u{2029}]"));

/// `raw` without `secrets` (each by value, and each of its lines), private-key blocks, envelopes,
/// bearer tokens, `token=…` assignments and URL user info; on one line; at most [`MAX_LENGTH`].
pub fn scrub<'a>(raw: &str, secrets: impl IntoIterator<Item = Option<&'a str>>) -> String {
    if raw.trim().is_empty() {
        return String::new();
    }
    let mut text = raw.to_owned();
    for secret in secrets.into_iter().flatten() {
        text = without(&text, secret);
    }
    text = PEM_BLOCK.replace_all(&text, "[private key removed]").into_owned();
    text = SEALED.replace_all(&text, format!("sealed:{MASK}").as_str()).into_owned();
    text = BEARER.replace_all(&text, format!("${{1}}{MASK}").as_str()).into_owned();
    text = ASSIGNMENT.replace_all(&text, format!("${{1}}${{2}}{MASK}").as_str()).into_owned();
    text = mask_user_info(&text);
    // Last, so a secret spread over lines was removed while its lines still were lines. A line break in
    // a reason is a forged second line on the screen and in the agent's log alike.
    text = CONTROL.replace_all(&text, " ").into_owned();
    text = SPACES.replace_all(&text, " ").into_owned();
    bounded(java_trim(&text))
}

fn without(text: &str, secret: &str) -> String {
    let trimmed = java_trim(secret);
    if trimmed.is_empty() {
        return text.to_owned();
    }
    let mut result =
        if utf16_length(trimmed) >= MIN_SECRET_LENGTH { text.replace(trimmed, MASK) } else { text.to_owned() };
    // A key is quoted a line at a time as often as whole: a parser names the line it choked on.
    for line in LINE_BREAK.split(trimmed) {
        let part = java_trim(line);
        if utf16_length(part) >= MIN_SECRET_LENGTH && !part.starts_with("-----") {
            result = result.replace(part, MASK);
        }
    }
    result
}

fn mask_user_info(text: &str) -> String {
    USER_INFO
        .replace_all(text, |captures: &regex::Captures<'_>| {
            let (scheme, user) = (&captures[1], &captures[2]);
            // An SSH login name is not a secret — `ssh://git@host` — but `user:password@` is.
            if scheme.eq_ignore_ascii_case("ssh://") && !user.contains(':') {
                captures[0].to_owned()
            } else {
                format!("{scheme}{MASK}@")
            }
        })
        .into_owned()
}

/// `String.trim`: every character up to U+0020 off both ends, and nothing else.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

fn utf16_length(text: &str) -> usize {
    text.encode_utf16().count()
}

/// At most [`MAX_LENGTH`] UTF-16 units, an ellipsis in the last one, never half a surrogate pair.
fn bounded(text: &str) -> String {
    if utf16_length(text) <= MAX_LENGTH {
        return text.to_owned();
    }
    let mut units = 0;
    let mut kept = String::new();
    for c in text.chars() {
        let width = c.len_utf16();
        if units + width > MAX_LENGTH - 1 {
            break;
        }
        units += width;
        kept.push(c);
    }
    kept.push('…');
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        for pattern in [&PEM_BLOCK, &USER_INFO, &SEALED, &BEARER, &ASSIGNMENT, &CONTROL, &SPACES, &LINE_BREAK] {
            assert!(!pattern.as_str().is_empty());
        }
    }

    #[test]
    fn a_secret_held_by_this_process_is_masked_by_value() {
        let reason =
            scrub("clone failed: auth invented-token-123 refused", [Some("invented-token-123"), None, Some("")]);
        assert_eq!(reason, "clone failed: auth *** refused");
    }

    #[test]
    fn a_reason_stays_on_one_line_and_within_its_bound() {
        assert_eq!(scrub("first\nsecond\r\n\tthird", []), "first second third");
        let long = "é".repeat(2_000);
        let bounded = scrub(&long, []);
        assert_eq!(utf16_length(&bounded), MAX_LENGTH);
        assert!(bounded.ends_with('…'));
    }
}
