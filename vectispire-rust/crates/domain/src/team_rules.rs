//! `TeamRules`: what a team may be called, and what a team may own.
//!
//! In the domain because more than the access module reads the kinds: a target's deletion revokes the grants of its
//! kind, a project's grantees are counted by the targets module, and the compliance and notification modules filter
//! on them. Held to `reference/teams/`, which `TeamRulesReferenceSetTest` writes.

use crate::bounded_text::{self, Refused};
use crate::java;

pub const MAX_NAME_LENGTH: usize = 100;
pub const MAX_DESCRIPTION_LENGTH: usize = 255;

pub const KIND_REPOSITORY: &str = "repository";
pub const KIND_CONTAINER: &str = "container";

/// A project, which grants its repositories as they are at each request (decision 0023). There is no solution kind,
/// deliberately: one level of inheritance is what an auditor can follow.
pub const KIND_PROJECT: &str = "project";

/// `TeamRules.validateName`: the name, trimmed (`String.trim`, so a no-break space stays), or a refusal. Uniqueness is
/// case-insensitive and a query, so it is the repository's.
pub fn validate_name(name: Option<&str>) -> Result<String, Refused> {
    let trimmed = java::trim(name.unwrap_or(""));
    if trimmed.is_empty() {
        return Err(Refused("A team name is required.".to_owned()));
    }
    if java::utf16_len(trimmed) > MAX_NAME_LENGTH {
        return Err(Refused(format!("A team name is at most {MAX_NAME_LENGTH} characters.")));
    }
    Ok(trimmed.to_owned())
}

/// `TeamRules.trimDescription`: trimmed, `None` when nothing is left, and clipped — not refused — past 255 units on a
/// character boundary, since nothing keys on a description.
pub fn trim_description(description: Option<&str>) -> Option<String> {
    let trimmed = java::trim(description?);
    if trimmed.is_empty() {
        return None;
    }
    bounded_text::clip(Some(trimmed), MAX_DESCRIPTION_LENGTH).map(str::to_owned)
}

/// `TeamRules.validateTargetKind`: one of the kinds, lower-cased in the root locale, or a refusal naming the kind as
/// it was sent (`null` when absent, as Java's concatenation writes it). Refused rather than stored: a kind this
/// version does not know resolves to no target, and the grant would show on the screen and open nothing.
pub fn validate_target_kind(kind: Option<&str>) -> Result<String, Refused> {
    let normalized = java::to_lower_root(java::trim(kind.unwrap_or("")));
    if [KIND_REPOSITORY, KIND_CONTAINER, KIND_PROJECT].contains(&normalized.as_str()) {
        return Ok(normalized);
    }
    Err(Refused(format!(
        "Unknown target kind \"{}\". Expected: {KIND_REPOSITORY}, {KIND_CONTAINER}, {KIND_PROJECT}.",
        kind.unwrap_or("null")
    )))
}
