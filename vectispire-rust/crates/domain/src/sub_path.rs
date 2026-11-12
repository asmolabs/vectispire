//! The directory inside a repository a scan is limited to — `RepositorySubPath`.
//!
//! **A path the agent resolves against a clone, so it is a security control like the URL.** An
//! absolute value replaces the base outright and `..` is never normalised: `/` walked the scanning
//! host, `../..` the directory where other teams' repositories are cloned at the same moment. Only
//! relative segments of ordinary characters pass; `.` and `..` are refused as segments rather than
//! normalised away. The sentences are the Java side's, word for word: they reach the scan's error.

const MAX_LENGTH: usize = 255;

/// `None` when the value is acceptable, otherwise the sentence to show. Blank means the root.
pub fn validate(sub_path: Option<&str>) -> Option<&'static str> {
    let value = java_trim(sub_path.unwrap_or(""));
    if value.is_empty() {
        return None;
    }
    // `String.length`: UTF-16 units.
    if value.encode_utf16().count() > MAX_LENGTH {
        return Some("The sub-path is longer than 255 characters.");
    }
    if value.starts_with('/') || value.contains('\\') || value.contains(':') {
        return Some("The sub-path must be relative to the repository root, like services/api.");
    }
    let refused = strip(value).split('/').any(|segment| {
        segment.is_empty()
            || segment == "."
            || segment == ".."
            || !segment.chars().all(|c| c.is_ascii_alphanumeric() || "._@+-".contains(c))
    });
    refused.then_some(
        "The sub-path may only name directories inside the repository: letters, digits and . _ - @ + — no empty, \
         \".\" or \"..\" segment.",
    )
}

/// The value as used — trimmed, without a trailing slash, empty for the root — or the refusal.
pub fn normalize(sub_path: Option<&str>) -> Result<String, &'static str> {
    match validate(sub_path) {
        Some(problem) => Err(problem),
        None => Ok(strip(java_trim(sub_path.unwrap_or(""))).to_owned()),
    }
}

fn strip(value: &str) -> &str {
    value.trim_end_matches('/')
}

/// `String.trim`: every char up to U+0020 off both ends.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_of_the_repository_passes_trimmed_and_without_its_trailing_slash() {
        assert_eq!(normalize(Some("  services/api/ ")), Ok("services/api".to_owned()));
        assert_eq!(normalize(Some("a.b_c-d@e+f")), Ok("a.b_c-d@e+f".to_owned()));
        assert_eq!(normalize(None), Ok(String::new()));
        assert_eq!(normalize(Some("  ")), Ok(String::new()));
    }

    #[test]
    fn a_way_out_of_the_clone_is_refused_not_normalised() {
        for refused in ["/", "/etc", "../x", "a/../b", "a/./b", "a//b", ".", "..", "a\\b", "c:x", "a b", "é"] {
            assert!(normalize(Some(refused)).is_err(), "{refused:?}");
        }
        assert_eq!(validate(Some(&"a".repeat(256))), Some("The sub-path is longer than 255 characters."));
        assert_eq!(validate(Some(&"a".repeat(255))), None);
    }
}
