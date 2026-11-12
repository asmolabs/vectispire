//! `CoverageScope`: the packages a `coverage_threshold` rule measures when it measures fewer than the whole report —
//! patterns over package paths (`org/example/service`), `**` any number of whole segments, `*` characters within one,
//! nothing else a wildcard. A package is in the scope when an `include` matches it — every package when none is
//! given — and no `exclude` does. Matching is case-sensitive, as the reports' paths are.

use vectispire_domain::bounded_text::clip;
use vectispire_domain::java;

use crate::suite_pattern::star_match;
use crate::{Refused, refused};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageScope {
    /// Sorted; empty is every package.
    pub include: Vec<String>,
    /// Sorted, possibly empty.
    pub exclude: Vec<String>,
}

pub const MAX_PATTERNS: usize = 20;
pub const MAX_PATTERN: usize = 500;

impl CoverageScope {
    /// `None` for a list not given, which is an empty one.
    pub fn new(
        include: Option<&[Option<String>]>,
        exclude: Option<&[Option<String>]>,
    ) -> Result<CoverageScope, Refused> {
        let include = patterns(include, "include")?;
        let exclude = patterns(exclude, "exclude")?;
        if include.is_empty() && exclude.is_empty() {
            return Err(refused(
                "A coverage scope names at least one pattern, in include or exclude; leave the scope out to measure the \
                 whole report.",
            ));
        }
        Ok(CoverageScope { include, exclude })
    }

    /// Whether a package's path is in the scope.
    pub fn matches(&self, path: &str) -> bool {
        let segments: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
        let included = self.include.is_empty() || self.include.iter().any(|pattern| matches(pattern, &segments));
        included && !self.exclude.iter().any(|pattern| matches(pattern, &segments))
    }

    /// The scope as a reader of a measurement or a signed document reads it, beside the figure.
    pub fn describe(&self) -> String {
        let included = if self.include.is_empty() {
            "every package".to_owned()
        } else {
            format!("packages matching {}", self.include.join(", "))
        };
        if self.exclude.is_empty() { included } else { format!("{included}, excluding {}", self.exclude.join(", ")) }
    }
}

fn patterns(given: Option<&[Option<String>]>, what: &str) -> Result<Vec<String>, Refused> {
    let Some(given) = given else { return Ok(Vec::new()) };
    if given.len() > MAX_PATTERNS {
        return Err(refused(format!("A coverage scope's {what} holds at most {MAX_PATTERNS} patterns.")));
    }
    let mut seen: Vec<String> = Vec::new();
    for pattern in given {
        let checked = check(pattern.as_deref(), what)?;
        if seen.contains(&checked) {
            return Err(refused(format!(
                "The pattern \"{}\" is in {what} twice.",
                clip(Some(&checked), 60).unwrap_or("")
            )));
        }
        seen.push(checked);
    }
    seen.sort_by(|left, right| java::compare_utf16(left, right));
    Ok(seen)
}

/// One pattern, refused in words when it is not one this reads the way its writer meant.
fn check(raw: Option<&str>, what: &str) -> Result<String, Refused> {
    let pattern = java::strip(raw.unwrap_or(""));
    let quoted = format!("\"{}\"", clip(Some(pattern), 60).unwrap_or(""));
    if pattern.is_empty() {
        return Err(refused(format!("A pattern in the coverage scope's {what} is empty.")));
    }
    if java::utf16_len(pattern) > MAX_PATTERN || pattern.chars().any(java::is_iso_control) {
        return Err(refused(format!(
            "A coverage scope's pattern is 1 to {MAX_PATTERN} characters, without control characters."
        )));
    }
    if pattern.contains('\\') {
        return Err(refused(format!(
            "The pattern {quoted} carries a backslash: segments are separated by /, whatever the system the report \
             was written on."
        )));
    }
    for wildcard in ['?', '[', ']', '{', '}', '!'] {
        if pattern.contains(wildcard) {
            return Err(refused(format!(
                "The pattern {quoted} carries \"{wildcard}\": only * (within a segment) and ** (any number of segments) \
                 are wildcards here."
            )));
        }
    }
    if pattern.starts_with('/') || pattern.ends_with('/') || pattern.contains("//") {
        return Err(refused(format!(
            "The pattern {quoted} has an empty segment: package paths have no leading or trailing slash — write **/ \
             to match anywhere, /** for everything below."
        )));
    }
    if !pattern.contains('/') && pattern.contains('.') {
        return Err(refused(format!(
            "The pattern {quoted} reads like a dotted package name; packages are matched as paths — write {}.",
            clip(Some(&pattern.replace('.', "/")), 60).unwrap_or("")
        )));
    }
    for segment in pattern.split('/') {
        if segment == "." || segment == ".." {
            return Err(refused(format!("The pattern {quoted} has a \"{segment}\" segment; a package path has none.")));
        }
        if segment.contains("**") && segment != "**" {
            return Err(refused(format!(
                "The pattern {quoted} uses ** inside a segment; ** stands for whole segments (**/service/**), * for \
                 characters within one (*-api)."
            )));
        }
    }
    Ok(pattern.to_owned())
}

/// Segment by segment, `**` taking none or more: the furthest positions reachable after each pattern segment, so a
/// pattern of a few dozen segments over a path of a few hundred never backtracks exponentially.
fn matches(pattern: &str, path: &[&str]) -> bool {
    let mut reachable = vec![false; path.len().saturating_add(1)];
    if let Some(first) = reachable.first_mut() {
        *first = true;
    }
    for part in pattern.split('/') {
        let mut next = vec![false; reachable.len()];
        if part == "**" {
            let mut any = false;
            for (was, now) in reachable.iter().zip(next.iter_mut()) {
                any |= *was;
                *now = any;
            }
        } else {
            let units: Vec<u16> = part.encode_utf16().collect();
            for (index, segment) in path.iter().enumerate() {
                let text: Vec<u16> = segment.encode_utf16().collect();
                if reachable.get(index) == Some(&true)
                    && star_match(&units, &text, None)
                    && let Some(slot) = next.get_mut(index.saturating_add(1))
                {
                    *slot = true;
                }
            }
        }
        reachable = next;
    }
    reachable.last() == Some(&true)
}
