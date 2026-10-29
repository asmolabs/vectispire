//! `AllowedComponent`: one package an organisation requires, named by a package-URL prefix, and the versions it
//! allows (decision 0032 §6, question 11) — exact versions, and Maven ranges on a `pkg:maven/` prefix only, since
//! "at least 3.2" needs the ecosystem's own order and Maven's is the one implemented and checked.
//!
//! A stored rule is never refused — its text is its digest — so the checks a person's declaration passes
//! ([`AllowedComponent::declared`]) are not the constructor's, which reads stored rules back too.

use vectispire_domain::bounded_text::clip;
use vectispire_domain::java;
use vectispire_domain::maven_version::MavenVersionRange;

use crate::{Refused, refused};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedComponent {
    /// A package URL without its version, matching a component whose package URL is exactly it or continues it
    /// with `@`, `/`, `?` or `#`: `pkg:npm/left` must not match `pkg:npm/left-pad`.
    pub purl_prefix: String,
    /// Sorted as `TreeSet<String>` sorts (UTF-16 units), distinct.
    pub versions: Vec<String>,
}

pub const MAX_PREFIX: usize = 500;
pub const MAX_VERSIONS: usize = 100;
pub const MAX_VERSION: usize = 255;

impl AllowedComponent {
    pub fn new(purl_prefix: &str, versions: &[String]) -> Result<AllowedComponent, Refused> {
        let prefix = require_prefix(purl_prefix)?;
        if versions.is_empty() || versions.len() > MAX_VERSIONS {
            return Err(refused(format!(
                "A package lists 1 to {MAX_VERSIONS} allowed versions; {prefix} lists {}.",
                versions.len()
            )));
        }
        let mut sorted: Vec<String> = Vec::new();
        for version in versions {
            let kept = java::strip(version);
            if kept.is_empty() || java::utf16_len(kept) > MAX_VERSION || kept.chars().any(java::is_iso_control) {
                return Err(refused(format!(
                    "An allowed version of {prefix} is 1 to {MAX_VERSION} characters; one is not."
                )));
            }
            sorted.push(kept.to_owned());
        }
        sorted.sort_by(|left, right| java::compare_utf16(left, right));
        sorted.dedup();
        Ok(AllowedComponent { purl_prefix: prefix, versions: sorted })
    }

    /// A package as a person declares it on a draft: the constructor's checks, a range only on a Maven package and
    /// only one that reads, and a prefix that does not end on its separator — refused here, never normalised and
    /// never in the constructor, which a published version's stored rule goes through.
    pub fn declared(purl_prefix: &str, versions: &[String]) -> Result<AllowedComponent, Refused> {
        let component = AllowedComponent::new(purl_prefix, versions)?;
        for version in &component.versions {
            if !MavenVersionRange::looks_like_range(Some(version)) {
                continue;
            }
            if !component.maven() {
                return Err(refused(format!(
                    "A version range is read in Maven's order, and applies to a pkg:maven/ package only; {} is not one \
                     — list the versions it allows.",
                    clip(Some(&component.purl_prefix), 60).unwrap_or("")
                )));
            }
            MavenVersionRange::parse(Some(version))?;
        }
        refuse_ending_on_separator(&component.purl_prefix)?;
        Ok(component)
    }

    /// Whether the prefix ends on a boundary `names` expects after it.
    pub fn ends_on_separator(&self) -> bool {
        ends_on_separator(&self.purl_prefix)
    }

    /// Whether the SBOM's stated version is allowed: written here exactly, or within a range on a Maven package.
    pub fn allows(&self, version: &str) -> bool {
        if self.versions.iter().any(|allowed| allowed == version) {
            return true;
        }
        self.maven()
            && self
                .versions
                .iter()
                .filter_map(|allowed| MavenVersionRange::read(Some(allowed)))
                .any(|range| range.contains(version))
    }

    fn maven(&self) -> bool {
        self.purl_prefix.starts_with("pkg:maven/")
    }

    /// Whether a component's package URL is this package's.
    pub fn names(&self, purl: Option<&str>) -> bool {
        names(&self.purl_prefix, purl)
    }
}

/// The prefix stripped, or a refusal.
pub fn require_prefix(purl_prefix: &str) -> Result<String, Refused> {
    let prefix = java::strip(purl_prefix);
    let length = java::utf16_len(prefix);
    if !prefix.starts_with("pkg:")
        || length <= 4
        || length > MAX_PREFIX
        || prefix.chars().any(|c| java::is_whitespace(c) || java::is_iso_control(c))
        || prefix.contains('@')
    {
        return Err(refused(format!(
            "A package is named by a package URL without its version, pkg:type/namespace/name, at most {MAX_PREFIX} \
             characters; \"{}\" is not one.",
            clip(Some(prefix), 60).unwrap_or("")
        )));
    }
    Ok(prefix.to_owned())
}

/// The refusal a person binding a prefix that ends on its separator reads.
pub fn refuse_ending_on_separator(prefix: &str) -> Result<(), Refused> {
    if !ends_on_separator(prefix) {
        return Ok(());
    }
    let mut trimmed = prefix.chars();
    trimmed.next_back();
    Err(refused(format!(
        "A package-URL prefix stops before the separator, never on it: \"{}\" names no package. Write \"{}\" for every \
         package it continues with /, @, ? or # — a namespace's packages — or name one package in full.",
        clip(Some(prefix), 60).unwrap_or(""),
        clip(Some(trimmed.as_str()), 60).unwrap_or("")
    )))
}

pub fn ends_on_separator(prefix: &str) -> bool {
    matches!(prefix.chars().last(), Some('/' | '?' | '#'))
}

pub fn names(prefix: &str, purl: Option<&str>) -> bool {
    let Some(rest) = purl.and_then(|purl| purl.strip_prefix(prefix)) else { return false };
    matches!(rest.chars().next(), None | Some('@' | '/' | '?' | '#'))
}
