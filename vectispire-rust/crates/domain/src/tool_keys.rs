//! `ToolKeys`: the key naming the tool a plugin or imported finding belongs to — a fingerprint
//! input, and the scope a clean run resolves.
//!
//! **A data contract.** The prefixes, the separator and the lower-casing are in every such issue's
//! identity; the two prefixes are also the provenance an auditor reads (`plugin:` was analysed by
//! Vectispire, `import:` declared by a report somebody uploaded).

/// The prefix of a plugin's key: `plugin:<id>`.
pub const PLUGIN_PREFIX: &str = "plugin:";
/// The prefix of an imported report's key: `import:<source>/<tool>`.
pub const IMPORT_PREFIX: &str = "import:";
/// The widest key, in UTF-16 units: a 40-character source, a separator and a 100-character tool name
/// after the prefix.
pub const MAX_LENGTH: usize = 200;

/// A key part that is absent or blank once stripped, with Java's sentence: `A tool key needs a <what>.`
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("A tool key needs a {0}.")]
pub struct MissingPart(pub &'static str);

/// `ToolKeys.plugin`: `plugin:<id>`. The image and its version stay out, so a new version keeps the triage.
pub fn plugin(plugin_id: Option<&str>) -> Result<String, MissingPart> {
    Ok(format!("{PLUGIN_PREFIX}{}", require(plugin_id, "plugin id")?))
}

/// `ToolKeys.imported`: `import:<source>/<tool>`, the tool as SARIF's `tool.driver.name`, stripped and
/// lower-cased as `toLowerCase(Locale.ROOT)` does — "ESLint" and "eslint" from one source are one tool.
/// The source is checked first, so a key missing both names the source.
pub fn imported(source_slug: Option<&str>, tool_name: Option<&str>) -> Result<String, MissingPart> {
    let source = require(source_slug, "source")?;
    let tool = require(tool_name, "tool name")?;
    // Not `str::to_lowercase`: Java decides the capital sigma's final form with its word iterator, and the
    // key is fingerprint material (`java::to_lower_root`).
    Ok(format!("{IMPORT_PREFIX}{source}/{}", crate::java::to_lower_root(tool)))
}

/// Stripped as `String.strip` strips — **not** the no-break spaces, which Rust's `trim` would take, and
/// U+001C–U+001F, which it would leave — and refused when nothing is left.
fn require<'a>(value: Option<&'a str>, what: &'static str) -> Result<&'a str, MissingPart> {
    Some(crate::java::strip(value.unwrap_or(""))).filter(|stripped| !stripped.is_empty()).ok_or(MissingPart(what))
}
