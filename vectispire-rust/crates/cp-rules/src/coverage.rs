//! Whether static analysis rules cover the code and ecosystems in the estate.
//!
//! A port of `RuleCoverage` and `RuleCoverageService`.
//!
//! ## Three States
//!
//! - `UNCONFIGURED`: only the bundled rule ships (one pattern, one language: Python).
//! - `PARTIAL`: installed rules miss at least one ecosystem found in the estate inventory.
//! - `COVERED`: every ecosystem seen in the inventory is covered by installed rules.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use vectispire_domain::owasp_tag;
use vectispire_protocol::StoredFile;

/// Shipped rule directory name.
pub const BUNDLED_LANGUAGE: &str = "python";

/// Bundled rule paths in Vectispire.
pub const BUNDLED_RULES: [&str; 2] = ["gitleaks/gitleaks.toml", "semgrep/python/dangerous-eval.yaml"];

/// The bundled rule content for `semgrep/python/dangerous-eval.yaml`.
pub const BUNDLED_PYTHON_RULE: &str =
    include_str!("../../../reference/sast/bundled-rules/semgrep/python/dangerous-eval.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum State {
    Unconfigured,
    Partial,
    Covered,
}

/// The coverage assessment result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment {
    pub state: State,
    pub languages_with_rules: BTreeSet<String>,
    pub ecosystems_in_estate: BTreeSet<String>,
    pub uncovered: BTreeSet<String>,
    pub rule_files: usize,
}

/// Package ecosystems mapped to the Semgrep rule directory covering them.
pub fn ecosystems() -> &'static BTreeMap<&'static str, &'static str> {
    static MAP: std::sync::LazyLock<BTreeMap<&'static str, &'static str>> = std::sync::LazyLock::new(|| {
        let mut m = BTreeMap::new();
        m.insert("maven", "java");
        m.insert("gradle", "java");
        m.insert("npm", "javascript");
        m.insert("pypi", "python");
        m.insert("golang", "go");
        m.insert("go", "go");
        m.insert("cargo", "rust");
        m.insert("nuget", "csharp");
        m.insert("composer", "php");
        m.insert("gem", "ruby");
        m
    });
    &MAP
}

/// `semgrep/java/xss.yaml` → `Some("java")`.
pub fn language_of(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let mut parts = normalized.split('/').filter(|s| !s.trim().is_empty());
    let first = parts.next()?;
    if !first.eq_ignore_ascii_case("semgrep") {
        return None;
    }
    let lang = parts.next()?;
    let _file = parts.next()?;
    Some(lang.to_ascii_lowercase())
}

/// `pkg:maven/org.acme/thing@1.2` → `Some("maven")`.
pub fn ecosystem_of(purl: &str) -> Option<String> {
    let rest = purl.strip_prefix("pkg:")?;
    let slash = rest.find('/')?;
    if slash == 0 {
        return None;
    }
    Some(rest.get(..slash)?.to_ascii_lowercase())
}

/// A stored file's path expressed the way the shipped rule tree spells it (`semgrep/<upstream_path>`).
pub fn rule_tree_path(file: &StoredFile) -> String {
    let origin = file.original_name.as_deref().unwrap_or("").replace('\\', "/");
    if origin.contains('/') { format!("semgrep/{origin}") } else { file.path.clone() }
}

/// Assesses coverage of installed rules over the ecosystems present in inventory package URLs.
pub fn assess(rule_file_paths: &[String], purls: &[String]) -> Assessment {
    let mut languages = BTreeSet::new();
    for path in rule_file_paths {
        if let Some(lang) = language_of(path) {
            languages.insert(lang);
        }
    }

    let mut estate_ecosystems = BTreeSet::new();
    for purl in purls {
        if let Some(eco) = ecosystem_of(purl) {
            estate_ecosystems.insert(eco);
        }
    }

    let eco_map = ecosystems();
    let mut uncovered = BTreeSet::new();
    for eco in &estate_ecosystems {
        if eco_map.get(eco.as_str()).is_some_and(|req_lang| !languages.contains(*req_lang)) {
            uncovered.insert(eco.clone());
        }
    }

    let only_bundled = languages.is_empty() || (languages.len() == 1 && languages.contains(BUNDLED_LANGUAGE));
    let state = if only_bundled {
        State::Unconfigured
    } else if uncovered.is_empty() {
        State::Covered
    } else {
        State::Partial
    };

    Assessment {
        state,
        languages_with_rules: languages,
        ecosystems_in_estate: estate_ecosystems,
        uncovered: if state == State::Partial { uncovered } else { BTreeSet::new() },
        rule_files: rule_file_paths.len(),
    }
}

/// Extracts declared OWASP categories across all installed rule files (bundled + active).
pub fn declared_owasp_categories<'a>(contents: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let mut categories = BTreeSet::new();
    for content in contents {
        for cat in owasp_tag::declared_in(content) {
            categories.insert(cat);
        }
    }
    categories
}

/// Extracts declared OWASP categories grouped by language.
pub fn declared_owasp_categories_by_language<'a>(
    paths_and_contents: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut by_lang = BTreeMap::new();
    for (path, content) in paths_and_contents {
        if let Some(lang) = language_of(path) {
            let entry = by_lang.entry(lang).or_insert_with(BTreeSet::new);
            for cat in owasp_tag::declared_in(content) {
                entry.insert(cat);
            }
        }
    }
    by_lang
}
