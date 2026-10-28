//! CycloneDX JSON SBOM parser and domain types for build imports.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

use super::component::BuildComponent;

pub const SPEC_VERSIONS: &[&str] = &["1.4", "1.5", "1.6"];
pub const MAX_COMPONENTS: usize = 50_000;
pub const MAX_NAME: usize = 255;
pub const MAX_VERSION: usize = 255;
pub const MAX_PURL: usize = 500;
pub const MAX_TYPE: usize = 50;
pub const MAX_LICENSE: usize = 255;
pub const MAX_TOOL: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildSbom {
    pub spec_version: String,
    pub tool: Option<String>,
    pub components: Vec<BuildComponent>,
}

impl BuildSbom {
    pub fn read(document: &[u8], max_bytes: usize) -> Result<Self, String> {
        if document.is_empty() {
            return Err("The SBOM is empty.".to_owned());
        }
        if document.len() > max_bytes {
            return Err(format!("The SBOM is larger than the {max_bytes} bytes accepted."));
        }

        let root: serde_json::Value =
            serde_json::from_slice(document).map_err(|err| format!("The SBOM is not readable JSON: {err}"))?;

        let obj = root.as_object().ok_or("A CycloneDX SBOM is a JSON object.")?;

        let bom_format = obj.get("bomFormat").and_then(|v| v.as_str());
        if bom_format != Some("CycloneDX") {
            return Err("Only CycloneDX JSON is read: the document's \"bomFormat\" is not \"CycloneDX\".".to_owned());
        }

        let spec = obj.get("specVersion").and_then(|v| v.as_str()).unwrap_or("");
        if !SPEC_VERSIONS.contains(&spec) {
            let clipped = if spec.len() > 20 {
                let mut s = spec.chars().take(20).collect::<String>();
                s.push('…');
                s
            } else {
                spec.to_owned()
            };
            return Err(format!("CycloneDX 1.4, 1.5 and 1.6 are read; this document says specVersion \"{clipped}\"."));
        }

        let listed = obj
            .get("components")
            .ok_or("The SBOM has no \"components\": a document that lists nothing is not one that found nothing.")?;
        let array = listed.as_array().ok_or("The \"components\" of a CycloneDX SBOM are an array.")?;

        let mut read = BTreeMap::new();
        let mut budget = MAX_COMPONENTS;
        walk(array, &mut read, &mut budget, "components")?;

        let tool = Self::extract_tool(obj.get("metadata").and_then(|m| m.get("tools")));

        Ok(BuildSbom { spec_version: spec.to_owned(), tool, components: read.into_values().collect() })
    }

    fn extract_tool(tools: Option<&serde_json::Value>) -> Option<String> {
        let tools = tools?;
        let list = if let Some(components) = tools.get("components").and_then(|c| c.as_array()) {
            components
        } else {
            tools.as_array()?
        };

        for tool in list {
            if let Some(name) = text(tool, "name") {
                let group =
                    text(tool, "group").or_else(|| text(tool, "vendor")).map(|g| format!("{g} ")).unwrap_or_default();
                let version = text(tool, "version").map(|v| format!(" {v}")).unwrap_or_default();
                let named = format!("{group}{name}{version}");
                let clipped = if named.len() > MAX_TOOL { named.chars().take(MAX_TOOL).collect() } else { named };
                return Some(clipped);
            }
        }
        None
    }

    pub fn canonical_purl(purl: &str) -> String {
        if !purl.starts_with("pkg:maven/") {
            return purl.to_owned();
        }
        let (head, subpath) = match purl.split_once('#') {
            Some((h, s)) => (h, format!("#{s}")),
            None => (purl, String::new()),
        };
        let (base, qualifiers_str) = match head.split_once('?') {
            Some((b, q)) => (b, q),
            None => return purl.to_owned(),
        };

        let mut kept = Vec::new();
        for q in qualifiers_str.split('&') {
            if !q.is_empty() && q != "type=jar" {
                kept.push(q);
            }
        }

        if kept.is_empty() { format!("{base}{subpath}") } else { format!("{base}?{}{subpath}", kept.join("&")) }
    }
}

fn walk(
    array: &[serde_json::Value],
    read: &mut BTreeMap<String, BuildComponent>,
    budget: &mut usize,
    where_path: &str,
) -> Result<(), String> {
    for (index, node) in array.iter().enumerate() {
        let at = format!("{where_path}[{index}]");
        if *budget == 0 {
            return Err(format!("The SBOM lists more than {MAX_COMPONENTS} components."));
        }
        *budget = budget.saturating_sub(1);

        let component = parse_component(node, &at)?;
        let key = if let Some(ref p) = component.purl {
            format!("purl:{p}")
        } else {
            format!("name:{}@{}", component.name, component.version.as_deref().unwrap_or(""))
        };
        read.entry(key).or_insert(component);

        if let Some(nested) = node.get("components")
            && !nested.is_null()
        {
            let nested_arr = nested.as_array().ok_or(format!("The \"components\" of {at} are not an array."))?;
            walk(nested_arr, read, budget, &format!("{at}.components"))?;
        }
    }
    Ok(())
}

fn parse_component(node: &serde_json::Value, at: &str) -> Result<BuildComponent, String> {
    let obj = node.as_object().ok_or(format!("Component {at} is not a JSON object."))?;
    let name = text(node, "name").ok_or(format!("Component {at} has no name."))?;
    let version = text(node, "version");
    let purl = text(node, "purl").map(|p| BuildSbom::canonical_purl(&p));
    let r#type = text(node, "type").map(|t| t.to_ascii_lowercase());
    let license = extract_license(obj.get("licenses"));

    bounded(&name, MAX_NAME, &format!("{at}'s name"))?;
    if let Some(ref v) = version {
        bounded(v, MAX_VERSION, &format!("{at}'s version"))?;
    }
    if let Some(ref p) = purl {
        bounded(p, MAX_PURL, &format!("{at}'s purl"))?;
        if !p.starts_with("pkg:") {
            return Err(format!("The purl of {at} does not begin with \"pkg:\"."));
        }
    }
    if let Some(ref t) = r#type {
        bounded(t, MAX_TYPE, &format!("{at}'s type"))?;
    }
    if let Some(ref l) = license {
        bounded(l, MAX_LICENSE, &format!("{at}'s licences"))?;
    }

    Ok(BuildComponent { name, version, purl, r#type, license })
}

fn extract_license(licenses: Option<&serde_json::Value>) -> Option<String> {
    let arr = licenses?.as_array()?;
    let mut values = Vec::new();
    let mut seen = BTreeSet::new();

    for choice in arr {
        let val = if let Some(lic) = choice.get("license") {
            text(lic, "id").or_else(|| text(lic, "name"))
        } else {
            text(choice, "expression")
        };
        if let Some(found) = val
            && seen.insert(found.clone())
        {
            values.push(found);
        }
    }

    if values.is_empty() { None } else { Some(values.join(" OR ")) }
}

fn bounded(value: &str, max: usize, what: &str) -> Result<(), String> {
    if value.chars().count() > max {
        return Err(format!("Component {what} is longer than {max} characters."));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(format!("Component {what} carries a control character."));
    }
    Ok(())
}

fn text(node: &serde_json::Value, field: &str) -> Option<String> {
    node.get(field).and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBuildSbom {
    pub source_id: i64,
    pub source_slug: String,
    pub repo_id: i64,
    pub commit: Option<String>,
    pub branch: Option<String>,
    pub document_sha256: String,
    pub imported_at: OffsetDateTime,
    pub imported_by: String,
    pub api_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSbomView {
    pub id: i64,
    #[serde(rename = "sourceId")]
    pub source_id: i64,
    #[serde(rename = "sourceSlug")]
    pub source_slug: String,
    #[serde(rename = "repoId")]
    pub repo_id: i64,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    pub tool: Option<String>,
    #[serde(rename = "componentsCount")]
    pub components_count: i32,
    pub commit: Option<String>,
    pub branch: Option<String>,
    #[serde(rename = "documentSha256")]
    pub document_sha256: String,
    #[serde(rename = "importedAt", with = "time::serde::rfc3339")]
    pub imported_at: OffsetDateTime,
    #[serde(rename = "importedBy")]
    pub imported_by: String,
    #[serde(rename = "completedScanId")]
    pub completed_scan_id: Option<i64>,
}
