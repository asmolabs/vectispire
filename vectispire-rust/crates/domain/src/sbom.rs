//! `Sbom` and `LicenseBlocklist`: a Syft SBOM read once into what the rules use, and the forbidden licences
//! evaluated over it.
//!
//! Read as Java's Jackson tree reads it: a field that is not a string is absent, a string is trimmed with
//! `String.trim` and absent when that leaves nothing; licences have had two shapes (strings, then objects)
//! and both are read. Held to `reference/vocabulary/`.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::java;

/// `Sbom.isCatalogue`: an object carrying an `artifacts` array — which Syft writes even when it found no
/// package. **Anything else is absent, never an empty catalogue** (decision 0007): read as a catalogue, a
/// document of another shape is an image with no package, and the licence and end-of-life rules would
/// resolve every issue of the target on the strength of a file the cataloguer never wrote.
pub fn is_catalogue(document: Option<&Value>) -> bool {
    document.is_some_and(|document| {
        document.is_object() && java::path(Some(document), "artifacts").is_some_and(Value::is_array)
    })
}

/// One package, its licences already flattened from whichever shape Syft used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub name: Option<String>,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub licenses: Vec<String>,
}

/// An image's own distribution: it carries no purl, so no package-level lookup finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distro {
    /// Lower-cased: `debian`, `alpine`…
    pub id: String,
    pub version: String,
    /// The distribution's name, or its id as written when it has none.
    pub label: String,
}

/// `Sbom.artifacts`: every entry of `artifacts`, a malformed one read as far as it goes rather than
/// costing the scan.
pub fn artifacts(root: Option<&Value>) -> Vec<Artifact> {
    let Some(Value::Array(entries)) = java::path(root, "artifacts") else { return Vec::new() };
    entries
        .iter()
        .map(|entry| Artifact {
            name: text(Some(entry), "name"),
            version: text(Some(entry), "version"),
            purl: text(Some(entry), "purl"),
            licenses: licenses_of(entry),
        })
        .collect()
}

/// `Sbom.distro`: present only with both an id and a `versionID`, each a non-blank string.
pub fn distro(root: Option<&Value>) -> Option<Distro> {
    let block = java::path(root, "distro");
    let id = text(block, "id")?;
    let version = text(block, "versionID")?;
    let label = text(block, "name").unwrap_or_else(|| id.clone());
    Some(Distro { id: java::to_lower_root(&id), version, label })
}

fn licenses_of(artifact: &Value) -> Vec<String> {
    let Some(Value::Array(entries)) = java::path(Some(artifact), "licenses") else { return Vec::new() };
    entries
        .iter()
        .filter_map(|entry| match entry {
            // A plain string is taken as written, untrimmed — `asText()`, not `text`.
            Value::String(license) => Some(license.clone()),
            // `value` first, `spdxExpression` as the fallback: both appear, and an entry carrying only the
            // expression is still a licence.
            Value::Object(_) => text(Some(entry), "value").or_else(|| text(Some(entry), "spdxExpression")),
            _ => None,
        })
        .collect()
}

/// `Sbom.text`: the member if it is a string, trimmed, absent when empty.
fn text(node: Option<&Value>, field: &str) -> Option<String> {
    match java::path(node, field) {
        Some(Value::String(value)) => Some(java::trim(value)).filter(|t| !t.is_empty()).map(str::to_owned),
        _ => None,
    }
}

/// The forbidden licences, upper-cased for a case-insensitive comparison. Nothing is reported until a list
/// is configured: which licences are forbidden is an organisation's decision, not a default's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LicenseBlocklist {
    pub forbidden: BTreeSet<String>,
}

/// A component one of whose licences is on the list, the licence **as the SBOM spelled it**: normalising
/// it would hide a mismatch worth seeing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub license: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
}

impl LicenseBlocklist {
    /// `LicenseBlocklist.parse`: comma-separated, each entry trimmed (`String.trim`) and upper-cased
    /// (`toUpperCase(Locale.ROOT)`: `ß` is `SS`, `ı` is `I`), empty entries dropped.
    pub fn parse(raw: Option<&str>) -> LicenseBlocklist {
        let Some(raw) = raw.filter(|raw| !java::is_blank(raw)) else { return LicenseBlocklist::default() };
        let forbidden =
            raw.split(',').map(|entry| java::trim(entry).to_uppercase()).filter(|entry| !entry.is_empty()).collect();
        LicenseBlocklist { forbidden }
    }

    pub fn is_empty(&self) -> bool {
        self.forbidden.is_empty()
    }

    /// The components one of whose licences is forbidden, in SBOM order.
    pub fn violations(&self, artifacts: &[Artifact]) -> Vec<Violation> {
        if self.forbidden.is_empty() {
            return Vec::new();
        }
        artifacts
            .iter()
            .flat_map(|artifact| {
                artifact.licenses.iter().filter(|license| self.forbidden.contains(&license.to_uppercase())).map(
                    |license| Violation {
                        license: license.clone(),
                        package_name: artifact.name.clone(),
                        package_version: artifact.version.clone(),
                        purl: artifact.purl.clone(),
                    },
                )
            })
            .collect()
    }
}
