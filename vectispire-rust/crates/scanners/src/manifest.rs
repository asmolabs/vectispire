//! What the scanned tree says about itself: its ecosystem, and its own version — `ProjectManifest`.
//!
//! Read from the manifest rather than the SBOM, which describes a directory by its path and inventories the
//! project's dependencies, never the project.
//!
//! **Absent is not a failure here.** A repository may have no manifest — a documentation tree, scripts — and that
//! is an ordinary outcome, not a broken step; nor does a version count as observing anything
//! (`observed_nothing`). A manifest that is present but broken still answers "which ecosystem": its name said it,
//! and the type is reported without a version.
//!
//! **Only the root, in the order of authority**: the build file that produces the artifact before the
//! `package.json` of its front-end assets. A multi-module tree has as many versions as modules; picking one by
//! walking would pick it by directory order. Nothing is read through a link — `package.json -> /etc/…` read a host
//! file into the recorded version on the Java side — nor past [`source_files::MAX_BYTES`]. Pinned by
//! `reference/workspace/`.

use std::path::Path;

use vectispire_domain::java;

use crate::{jackson_tree, pom, properties, source_files};

/// A version string longer than this is not a version: a templated placeholder, a property never substituted,
/// which would reach a screen as a wall of text attributed to the project.
const MAX_VERSION: usize = 100;

/// `ProjectManifest.Project`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    /// The ecosystem as an operator names it — `maven`, `gradle`, `npm`, `python`.
    pub kind: &'static str,
    /// The project's own version; `None` when the manifest names the ecosystem without stating one.
    pub version: Option<String>,
}

/// Why a present manifest gave no version — any reason reads the same.
struct Unreadable;

type Reader = fn(&Path, &Path) -> Result<Option<String>, Unreadable>;

const READERS: [(&str, &str, Reader); 5] = [
    ("pom.xml", "maven", maven),
    ("build.gradle.kts", "gradle", gradle),
    ("build.gradle", "gradle", gradle),
    ("package.json", "npm", npm),
    ("pyproject.toml", "python", python),
];

/// The first manifest recognised at the root of the analysed tree.
pub fn read(source: &Path) -> Option<Project> {
    READERS.iter().find_map(|&(file_name, kind, reader)| {
        let manifest = source.join(file_name);
        source_files::is_regular_file(&manifest).then(|| Project {
            kind,
            version: reader(&manifest, source).ok().flatten().and_then(|version| trimmed(&version)),
        })
    })
}

/// `String.trim`, then nothing for a blank or overlong value — the length in UTF-16 units, as Java counts it.
fn trimmed(value: &str) -> Option<String> {
    let trimmed = java::trim(value);
    (!trimmed.is_empty() && java::utf16_len(trimmed) <= MAX_VERSION).then(|| trimmed.to_owned())
}

/// The bytes of a manifest, bounded and link-refusing; too large reads as unreadable.
fn bytes(file: &Path) -> Result<Vec<u8>, Unreadable> {
    source_files::read_bytes(file).ok().flatten().ok_or(Unreadable)
}

/// Maven states the version on the project, or inherits it from the parent — the root's direct children only:
/// every `<dependency>` carries a `<version>` too.
fn maven(manifest: &Path, _: &Path) -> Result<Option<String>, Unreadable> {
    pom::version(&bytes(manifest)?).map_err(|_| Unreadable)
}

/// Gradle keeps the version in `gradle.properties` far more often than in the script, where it is an expression
/// nobody here evaluates: what is not a literal is an unknown version, not a guess.
fn gradle(_: &Path, source: &Path) -> Result<Option<String>, Unreadable> {
    let file = source.join("gradle.properties");
    if !source_files::is_regular_file(&file) {
        return Ok(None);
    }
    properties::value_of(&bytes(&file)?, "version").map_err(|_| Unreadable)
}

fn npm(manifest: &Path, _: &Path) -> Result<Option<String>, Unreadable> {
    let document = jackson_tree::read_bytes(&bytes(manifest)?).map_err(|_| Unreadable)?;
    Ok(match document.as_ref().and_then(|document| document.get("version")) {
        Some(jackson_tree::Node::Text(version)) => Some(version.clone()),
        _ => None,
    })
}

fn python(manifest: &Path, _: &Path) -> Result<Option<String>, Unreadable> {
    Ok(python_version(&String::from_utf8_lossy(&bytes(manifest)?)))
}

/// PEP 621's `[project]` table or Poetry's `[tool.poetry]`, line by line — never the first `version =` of the
/// file, which belongs to whichever table comes first. A header opens one of the two tables or closes it; nothing
/// else is remembered, so a file of repeated headers is read in linear time (the Java side's single expression was
/// not).
pub fn python_version(content: &str) -> Option<String> {
    let mut in_project_table = false;
    for line in java_lines(content) {
        let stripped = java::strip(line);
        if stripped.starts_with('[') {
            in_project_table = stripped == "[project]" || stripped == "[tool.poetry]";
            continue;
        }
        if in_project_table && let Some(version) = version_line(stripped) {
            return trimmed(version);
        }
    }
    None
}

/// `content.split("\\R")`: at `\n`, U+000B, U+000C, `\r`, U+0085, U+2028, U+2029. Java takes `\r\n` as one break
/// where this sees an empty line between the two — which neither opens a table nor states a version.
fn java_lines(content: &str) -> impl Iterator<Item = &str> {
    content.split(['\n', '\u{b}', '\u{c}', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
}

/// `version\s*=\s*["']([^"']+)["'].*`, matched against the whole line.
fn version_line(line: &str) -> Option<&str> {
    let is_space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r');
    let rest = line.strip_prefix("version")?.trim_start_matches(is_space);
    let rest = rest.strip_prefix('=')?.trim_start_matches(is_space);
    let rest = rest.strip_prefix(['"', '\''])?;
    let end = rest.find(['"', '\''])?;
    rest.get(..end).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_the_project_tables() {
        assert_eq!(
            python_version("[project]\nversion = \"\"\nversion = \"2\"\n").as_deref(),
            Some("2"),
            "an empty one is no match"
        );
        assert_eq!(python_version("[project]\nversion = '1.0\"").as_deref(), Some("1.0"), "either quote closes");
        assert_eq!(python_version("[tool.black]\nversion = '1'\n[tool.poetry]\nversion='5'").as_deref(), Some("5"));
        assert_eq!(python_version("[project]\r\nname='a'\u{2028}version\t=\t\"7.7\"\u{b}x").as_deref(), Some("7.7"));
        assert_eq!(python_version("version = \"0\"\n[project]\n"), None);
    }

    #[test]
    fn a_version_is_trimmed_and_bounded_in_utf16_units() {
        assert_eq!(trimmed(" \u{1} 1.0\t").as_deref(), Some("1.0"));
        assert_eq!(trimmed("\u{a0}1"), Some("\u{a0}1".into()), "String.trim keeps a no-break space");
        assert_eq!(trimmed(&"1".repeat(100)).map(|version| version.len()), Some(100));
        assert_eq!(trimmed(&"1".repeat(101)), None);
        assert_eq!(trimmed(&"\u{1F600}".repeat(51)), None, "an astral character counts two");
        assert_eq!(trimmed("  "), None);
    }
}
