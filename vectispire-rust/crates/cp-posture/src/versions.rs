//! `common.domain.dependencies.Versions`: which of the versions a finding says fix it is the highest — the
//! recommendation a high-impact fix carries.
//!
//! Segments split on `.`, `_`, `-`, `+`, compared as numbers when both are digits (as text past the range of a
//! `long`), a digit beating a word, words without case. A missing segment counts as zero: `2.17` is `2.17.0`.

use std::cmp::Ordering;

use vectispire_domain::java;

/// `Versions.highest`: blank candidates left out, the others trimmed; of two equal, the first.
pub fn highest<'a>(candidates: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut best: Option<&str> = None;
    for candidate in candidates {
        if java::is_blank(candidate) {
            continue;
        }
        let trimmed = java::trim(candidate);
        if best.is_none_or(|current| compare(trimmed, current) == Ordering::Greater) {
            best = Some(trimmed);
        }
    }
    best.map(str::to_owned)
}

/// `Versions.split`: a comma-separated column, each part trimmed, the empty ones left out.
pub fn split(comma_separated: Option<&str>) -> Vec<String> {
    let Some(text) = comma_separated else { return Vec::new() };
    if java::is_blank(text) {
        return Vec::new();
    }
    text.split(',').map(java::trim).filter(|part| !part.is_empty()).map(str::to_owned).collect()
}

/// `String.split("[._\\-+]")`: the trailing empty segments removed, as Java removes them.
fn segments(version: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = version.split(['.', '_', '-', '+']).collect();
    if parts.len() > 1 {
        while parts.last().is_some_and(|part| part.is_empty()) {
            parts.pop();
        }
    }
    parts
}

/// `Versions.compare`.
pub fn compare(left: &str, right: &str) -> Ordering {
    let left_parts = segments(left);
    let right_parts = segments(right);
    let length = left_parts.len().max(right_parts.len());
    for index in 0..length {
        let left_part = left_parts.get(index).copied().unwrap_or("0");
        let right_part = right_parts.get(index).copied().unwrap_or("0");
        let verdict = compare_part(left_part, right_part);
        if verdict != Ordering::Equal {
            return verdict;
        }
    }
    Ordering::Equal
}

fn is_number(part: &str) -> bool {
    !part.is_empty() && part.chars().all(|c| java::digit(c).is_some())
}

/// `Long.parseLong` of a run of digits, any of the ones `Character.digit` reads.
fn parse_long(part: &str) -> Option<i64> {
    part.chars().try_fold(0i64, |value, c| value.checked_mul(10)?.checked_add(i64::from(java::digit(c)?)))
}

fn compare_part(left: &str, right: &str) -> Ordering {
    let (left_number, right_number) = (is_number(left), is_number(right));
    if left_number && right_number {
        return match (parse_long(left), parse_long(right)) {
            (Some(a), Some(b)) => a.cmp(&b),
            // Too long for a long: by length, then as text.
            _ => java::utf16_len(left).cmp(&java::utf16_len(right)).then_with(|| java::compare_utf16(left, right)),
        };
    }
    if left_number != right_number {
        return if left_number { Ordering::Greater } else { Ordering::Less };
    }
    java::compare_ignore_case(left, right)
}
