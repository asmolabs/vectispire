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
