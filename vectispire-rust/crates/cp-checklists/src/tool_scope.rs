//! `ToolScope`: what a findings rule reads — one analyser's results, as Vectispire keeps them apart: a built-in step
//! of a scan, a plugin, or one tool of a declared source's imports. Each is examined in its own way, so a scope
//! names which record says whether it looked — never inferred from the findings present.
//!
//! The key is the fingerprint's own tool key for a plugin and an import (`ToolKeys`), so a scope counts exactly the
//! issues that tool's runs resolve.

use vectispire_domain::FindingType;
use vectispire_domain::bounded_text::clip;
use vectispire_domain::{java, plugin_manifest, tool_keys};

use crate::{Refused, refused};

pub const BUILT_IN_PREFIX: &str = "builtin:";

/// The built-in types a scan's own steps examine and record — the ones a scope may name.
pub const BUILT_IN_TYPES: [FindingType; 7] = [
    FindingType::Vulnerability,
    FindingType::Secret,
    FindingType::Iac,
    FindingType::Sast,
    FindingType::Quality,
    FindingType::Eol,
    FindingType::License,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolScope {
    /// A step of the scan itself.
    BuiltIn(FindingType),
    /// A plugin, by its id: the image and its digest stay out, as they stay out of its issues' identity.
    Plugin(String),
    /// One tool of a declared source's SARIF imports, its name lowered as the import keys it.
    Imported { source_slug: String, tool_name: String },
}

impl ToolScope {
    /// `builtin:sast`, `plugin:<id>`, `import:<source>/<tool>`.
    pub fn key(&self) -> String {
        match self {
            ToolScope::BuiltIn(kind) => format!("{BUILT_IN_PREFIX}{}", kind.wire_name()),
            ToolScope::Plugin(id) => tool_keys::plugin(Some(id)).unwrap_or_default(),
            ToolScope::Imported { source_slug, tool_name } => {
                tool_keys::imported(Some(source_slug), Some(tool_name)).unwrap_or_default()
            }
        }
    }

    /// The record's class name, as a reference answer names the kind.
    pub fn kind_name(&self) -> &'static str {
        match self {
            ToolScope::BuiltIn(_) => "BuiltIn",
            ToolScope::Plugin(_) => "Plugin",
            ToolScope::Imported { .. } => "Imported",
        }
    }

    /// A scope as a rule names it, refused in words: a scope nobody can examine would read "never examined"
    /// everywhere, and a misspelt one is a rule nobody meant.
    pub fn parse(value: Option<&str>) -> Result<ToolScope, Refused> {
        let scope = java::strip(value.unwrap_or(""));
        let quoted = clip(Some(scope), 60).unwrap_or("");
        if let Some(name) = scope.strip_prefix(BUILT_IN_PREFIX) {
            return FindingType::from_wire_name(Some(name))
                .filter(|kind| BUILT_IN_TYPES.contains(kind))
                .map(ToolScope::BuiltIn)
                .ok_or_else(|| {
                    let mut keys: Vec<String> =
                        BUILT_IN_TYPES.iter().map(|kind| format!("{BUILT_IN_PREFIX}{}", kind.wire_name())).collect();
                    keys.sort();
                    refused(format!("\"{quoted}\" names no built-in step; one of {}.", keys.join(", ")))
                });
        }
        if let Some(id) = scope.strip_prefix(tool_keys::PLUGIN_PREFIX) {
            return plugin_manifest::require_id(Some(id))
                .map(|id| ToolScope::Plugin(id.to_owned()))
                .map_err(|refusal| refused(format!("\"{quoted}\": {}", refusal.0)));
        }
        if let Some(rest) = scope.strip_prefix(tool_keys::IMPORT_PREFIX) {
            let (source, tool) = match rest.split_once('/') {
                Some((source, tool)) => (source, java::to_lower_root(java::strip(tool))),
                None => ("", String::new()),
            };
            if !is_slug(source)
                || tool.is_empty()
                || java::utf16_len(&tool) > 100
                || tool.contains(',')
                || tool.chars().any(java::is_iso_control)
            {
                return Err(refused(format!(
                    "\"{quoted}\" is no imported tool: import:<source>/<tool>, the declared source's slug and the \
                     tool's name as it declares it."
                )));
            }
            return Ok(ToolScope::Imported { source_slug: source.to_owned(), tool_name: tool });
        }
        Err(refused(format!(
            "A scope is builtin:<step>, plugin:<id> or import:<source>/<tool>{}",
            if scope.is_empty() { "; one is empty.".to_owned() } else { format!("; \"{quoted}\" is none of them.") }
        )))
    }
}

/// A declared source's slug, as `SarifSourceService` admits one: 2 to 40, lowercase, inner hyphens.
fn is_slug(value: &str) -> bool {
    let length = java::utf16_len(value);
    if !(2..=40).contains(&length) {
        return false;
    }
    let last = value.chars().count().saturating_sub(1);
    value
        .chars()
        .enumerate()
        .all(|(index, c)| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' && index != 0 && index != last)
}
