//! Fetching a third-party rule set from upstream, and licence verification.
//!
//! A port of `RuleCatalogue` and `RuleCatalogueFetcher`.
//!
//! ## Upstream Source
//!
//! Only `opengrep/opengrep-rules` is fetched. `semgrep/semgrep-rules` is forbidden.
//! No YAML is parsed; test fixtures (`.test.yaml`) and files duplicating the secrets scanner are filtered.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vectispire_domain::owasp_tag;

use crate::ruleset::UploadedFile;

/// The fork taken before relicensing, and the only upstream this fetches.
pub const UPSTREAM: &str = "opengrep/opengrep-rules";

/// LGPL-2.1 plus a Commons Clause.
pub const LICENCE: &str = "LGPL-2.1 with Commons Clause";

/// Upstreams that are refused outright because their licence forbids distribution.
pub const FORBIDDEN: &[&str] = &["semgrep/semgrep-rules"];

pub const GITLEAKS_PORTS: &str = "generic/secrets/gitleaks/";
pub const SECURITY_SECRETS: &str = "generic/secrets/security/";

pub const GITLEAKS_COVERED_SECURITY_RULES: &[&str] = &[
    "detected-artifactory-token",
    "detected-aws-access-key-id-value",
    "detected-facebook-access-token",
    "detected-facebook-oauth",
    "detected-generic-api-key",
    "detected-generic-secret",
    "detected-github-token",
    "detected-google-api-key",
    "detected-google-cloud-api-key",
    "detected-heroku-api-key",
    "detected-jwt-token",
    "detected-mailchimp-api-key",
    "detected-mailgun-api-key",
    "detected-pgp-private-key-block",
    "detected-picatic-api-key",
    "detected-private-key",
    "detected-sendgrid-api-key",
    "detected-slack-token",
    "detected-slack-webhook",
    "detected-snyk-api-key",
    "detected-sonarqube-docs-api-key",
    "detected-square-access-token",
    "detected-stripe-api-key",
    "detected-stripe-restricted-api-key",
    "detected-telegram-bot-api-key",
    "detected-twilio-api-key",
    "google-maps-apikeyleak",
];

pub const NOT_A_LANGUAGE: &[&str] =
    &[".github", ".pre-commit-hooks", "stats", "scripts", "docs", "template", "libsonnet"];

const MAX_BYTES: u64 = 128 * 1024 * 1024;
const PREVIEW_LIFETIME: Duration = Duration::from_secs(600);

static COMMIT: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^[0-9a-f]{40}$").expect("a fixed pattern")
});

static YAML: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?i)\.ya?ml$").expect("a fixed pattern")
});

static DECLARES_RULES: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?m)^rules:").expect("a fixed pattern")
});

static DECLARES_A_RULE_ID: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?m)^\s*-?\s*id:\s*\S").expect("a fixed pattern")
});

static TEST_FIXTURE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"(?i)\.test\.ya?ml$").expect("a fixed pattern")
});

/// A file inside the fetched repository archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub content: String,
}

/// What the archive holds, grouped by language and OWASP categories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contents {
    pub languages: BTreeMap<String, usize>,
    pub categories: BTreeMap<String, usize>,
    pub licence: String,
    pub entries: Vec<Entry>,
    pub gitleaks_duplicates: usize,
}

/// A fetched release at a resolved commit SHA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub commit: String,
    pub contents: Contents,
    pub licence_sha256: String,
}

/// What the preview route returns: terms and counts, not the rules themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Preview {
    pub upstream: String,
    pub commit: String,
    pub licence_name: String,
    pub licence: String,
    #[serde(rename = "licence_sha256")]
    pub licence_sha256: String,
    pub languages: BTreeMap<String, usize>,
    pub categories: BTreeMap<String, usize>,
    pub gitleaks_duplicates: usize,
}

/// Why a catalogue operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CatalogueError(pub String);

/// Validates that `commit` is a 40-character hexadecimal SHA.
pub fn require_commit(commit: &str) -> Result<(), CatalogueError> {
    let trimmed = commit.trim().to_ascii_lowercase();
    if !COMMIT.is_match(&trimmed) {
        return Err(CatalogueError(format!("A full 40-character commit SHA is required, not \"{commit}\".")));
    }
    Ok(())
}

/// Verifies that the upstream repository is permitted.
pub fn require_allowed(repository: &str) -> Result<(), CatalogueError> {
    if FORBIDDEN.contains(&repository) {
        return Err(CatalogueError(format!(
            "{repository} is licensed under terms that forbid distributing its rules. Vectispire will not fetch it on anybody's behalf."
        )));
    }
    Ok(())
}

/// Checks whether an entry is a Semgrep rule file (and not a test fixture or non-rule).
pub fn is_rule(entry: &Entry) -> bool {
    YAML.is_match(&entry.path)
        && !TEST_FIXTURE.is_match(&entry.path)
        && DECLARES_RULES.is_match(&entry.content)
        && DECLARES_A_RULE_ID.is_match(&entry.content)
}

/// Checks whether an entry is a rule that duplicates Gitleaks.
pub fn is_gitleaks_duplicate(entry: &Entry) -> bool {
    let lower = entry.path.to_ascii_lowercase();
    if lower.starts_with(GITLEAKS_PORTS) {
        return true;
    }
    for stem in GITLEAKS_COVERED_SECURITY_RULES {
        let yml1 = format!("{SECURITY_SECRETS}{stem}.yaml");
        let yml2 = format!("{SECURITY_SECRETS}{stem}.yml");
        if lower == yml1 || lower == yml2 {
            return true;
        }
    }
    false
}

/// Extracts the top-level directory if it represents a programming language.
pub fn top_level_of(path: &str) -> Option<String> {
    let slash = path.find('/')?;
    if slash == 0 {
        return None;
    }
    let first = path.get(..slash)?.to_ascii_lowercase();
    if NOT_A_LANGUAGE.contains(&first.as_str()) { None } else { Some(first) }
}

/// Describes entries and licence into `Contents`.
pub fn describe(entries: Vec<Entry>, licence: String) -> Contents {
    let mut by_language: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
    let mut gitleaks_duplicates: usize = 0;

    for entry in &entries {
        if !is_rule(entry) {
            continue;
        }
        if is_gitleaks_duplicate(entry) {
            gitleaks_duplicates = gitleaks_duplicates.saturating_add(1);
        }
        if let Some(language) = top_level_of(&entry.path) {
            let count = by_language.entry(language).or_insert(0);
            *count = (*count).saturating_add(1);
        }
        for category in owasp_tag::declared_in(&entry.content) {
            let count = by_category.entry(category).or_insert(0);
            *count = (*count).saturating_add(1);
        }
    }

    Contents { languages: by_language, categories: by_category, licence, entries, gitleaks_duplicates }
}

/// Selects rule files for chosen languages.
pub fn select(
    contents: &Contents,
    languages: &BTreeSet<String>,
    include_gitleaks_duplicates: bool,
) -> Result<Vec<UploadedFile>, CatalogueError> {
    if languages.is_empty() {
        return Err(CatalogueError(
            "Choose at least one language: a rule set with no rules resolves the backlog.".to_owned(),
        ));
    }

    let mut unknown = Vec::new();
    for lang in languages {
        if !contents.languages.contains_key(lang) {
            unknown.push(lang.clone());
        }
    }
    if !unknown.is_empty() {
        return Err(CatalogueError(format!("No such language in this tag: {}.", unknown.join(", "))));
    }

    let mut selected = Vec::new();
    for entry in &contents.entries {
        if !is_rule(entry) {
            continue;
        }
        let Some(top) = top_level_of(&entry.path) else {
            continue;
        };
        if !languages.contains(&top) {
            continue;
        }
        if !include_gitleaks_duplicates && is_gitleaks_duplicate(entry) {
            continue;
        }
        selected.push(UploadedFile { name: Some(entry.path.clone()), content: Some(entry.content.clone()) });
    }

    selected.sort_by(|a, b| a.name.cmp(&b.name));

    if selected.is_empty() {
        return Err(CatalogueError(
            "These languages hold only rules that duplicate gitleaks, which the secrets step already runs. Choose another language, or include the gitleaks duplicates.".to_owned(),
        ));
    }

    Ok(selected)
}

/// Checks whether the chosen languages contain any rule that duplicates Gitleaks.
pub fn reaches_gitleaks_duplicates(contents: &Contents, languages: &BTreeSet<String>) -> bool {
    contents.entries.iter().any(|entry| {
        is_rule(entry)
            && is_gitleaks_duplicate(entry)
            && top_level_of(&entry.path).is_some_and(|lang| languages.contains(&lang))
    })
}

/// Builds display name for imported catalogue set.
pub fn name_for(commit: &str, languages: &BTreeSet<String>, holds_gitleaks_duplicates: bool) -> String {
    let short_commit = commit.get(..12).unwrap_or(commit);
    let langs: Vec<&str> = languages.iter().map(String::as_str).collect();
    let base = format!("{UPSTREAM}@{short_commit} ({})", langs.join(", "));
    if holds_gitleaks_duplicates { format!("{base} with gitleaks duplicates") } else { base }
}

/// Extracts root `LICENSE` file content from entries.
pub fn licence_of(entries: &[Entry]) -> Result<String, CatalogueError> {
    for entry in entries {
        if !entry.path.contains('/') && entry.path.to_ascii_lowercase().starts_with("license") {
            return Ok(entry.content.clone());
        }
    }
    Err(CatalogueError(format!(
        "No LICENSE file at the root of {UPSTREAM} at this tag. Refusing to offer rules whose terms cannot be shown."
    )))
}

/// Computes SHA-256 hex digest of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads regular files and licences from a directory path (up to `MAX_BYTES`).
pub fn read_entries_from_dir(root: &Path) -> Result<Vec<Entry>, CatalogueError> {
    let mut entries = Vec::new();
    let mut total_bytes: u64 = 0;

    fn walk(dir: &Path, root: &Path, entries: &mut Vec<Entry>, total_bytes: &mut u64) -> Result<(), CatalogueError> {
        let read_dir = std::fs::read_dir(dir)
            .map_err(|e| CatalogueError(format!("Could not read directory {}: {e}", dir.display())))?;
        for entry in read_dir {
            let entry = entry.map_err(|e| CatalogueError(format!("Read error: {e}")))?;
            let file_type = entry.file_type().map_err(|e| CatalogueError(format!("File type error: {e}")))?;
            let path = entry.path();
            if file_type.is_symlink() {
                // Symbolic links are deliberately skipped to prevent path traversal or secret leaks.
                continue;
            }
            if file_type.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some(".git") {
                    continue;
                }
                walk(&path, root, entries, total_bytes)?;
            } else if file_type.is_file() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();
                if name.ends_with(".yaml") || name.ends_with(".yml") || name.starts_with("license") {
                    let rel = path
                        .strip_prefix(root)
                        .map_err(|e| CatalogueError(format!("Strip prefix error: {e}")))?
                        .to_string_lossy()
                        .replace('\\', "/");
                    let content = std::fs::read_to_string(&path)
                        .map_err(|e| CatalogueError(format!("Could not read {}: {e}", path.display())))?;
                    *total_bytes = total_bytes.saturating_add(content.len() as u64);
                    if *total_bytes > MAX_BYTES {
                        return Err(CatalogueError(format!(
                            "The catalogue exceeds {} MB; refusing to read it into memory.",
                            MAX_BYTES / 1024 / 1024
                        )));
                    }
                    entries.push(Entry { path: rel, content });
                }
            }
        }
        Ok(())
    }

    walk(root, root, &mut entries, &mut total_bytes)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Upstream catalogue fetcher: clones `UPSTREAM` with shallow depth 1, verifies licence, caches preview.
#[derive(Clone)]
pub struct RuleCatalogueFetcher {
    cache: Arc<RwLock<Option<(Instant, Preview)>>>,
}

impl std::fmt::Debug for RuleCatalogueFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleCatalogueFetcher").finish_non_exhaustive()
    }
}

impl Default for RuleCatalogueFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleCatalogueFetcher {
    pub fn new() -> Self {
        Self { cache: Arc::new(RwLock::new(None)) }
    }

    /// Fetches the catalogue from a local directory (useful for tests or air-gapped environments).
    pub fn fetch_from_dir(&self, dir: &Path, commit: &str) -> Result<Fetched, CatalogueError> {
        let entries = read_entries_from_dir(dir)?;
        let licence = licence_of(&entries)?;
        let licence_sha256 = sha256_hex(licence.as_bytes());
        let contents = describe(entries, licence);
        Ok(Fetched { commit: commit.to_owned(), contents, licence_sha256 })
    }

    /// Fetches from the upstream Git repository.
    pub fn fetch(&self) -> Result<Fetched, CatalogueError> {
        require_allowed(UPSTREAM)?;
        let temp =
            tempfile::tempdir().map_err(|e| CatalogueError(format!("Could not create temporary directory: {e}")))?;

        let url = format!("https://github.com/{UPSTREAM}.git");
        let branch = "main".to_owned();

        let request = vectispire_git::CloneRequest {
            url,
            branch,
            into: temp.path().to_path_buf(),
            private_key: None,
            timeout: Duration::from_secs(300),
            host_keys: vectispire_git::HostKeyPolicy::TrustEveryHost,
            without_key: vectispire_git::WithoutKey::None,
            https: None,
            trust: vectispire_tls::TlsTrust::BuiltIn,
        };

        vectispire_git::clone(&request).map_err(|e| CatalogueError(format!("Could not reach {UPSTREAM}. ({e})")))?;

        let commit = vectispire_git::head_commit(temp.path())
            .map_err(|e| CatalogueError(format!("Could not read HEAD commit of {UPSTREAM}: {e}")))?;

        self.fetch_from_dir(temp.path(), &commit)
    }

    /// Retrieves preview, caching for up to 10 minutes.
    pub fn preview(&self) -> Result<Preview, CatalogueError> {
        {
            let guard = self.cache.read().map_err(|_| CatalogueError("Lock poisoned".to_owned()))?;
            if let Some((_, preview)) = guard.as_ref().filter(|(instant, _)| instant.elapsed() < PREVIEW_LIFETIME) {
                return Ok(preview.clone());
            }
        }

        let fetched = self.fetch()?;
        let preview = Preview {
            upstream: UPSTREAM.to_owned(),
            commit: fetched.commit,
            licence_name: LICENCE.to_owned(),
            licence: fetched.contents.licence,
            licence_sha256: fetched.licence_sha256,
            languages: fetched.contents.languages,
            categories: fetched.contents.categories,
            gitleaks_duplicates: fetched.contents.gitleaks_duplicates,
        };

        {
            let mut guard = self.cache.write().map_err(|_| CatalogueError("Lock poisoned".to_owned()))?;
            *guard = Some((Instant::now(), preview.clone()));
        }

        Ok(preview)
    }
}
