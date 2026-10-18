//! A scan as the layers above the services hold it — `ScanView` — and the three columns a scan keeps as text and its
//! page reads back: `DetectedLanguages`, `ExaminedTypes`, `PluginOutcome`.
//!
//! **Three answers, not two**, for the first two (decision 0007): a set is "recorded, and these"; the empty set is
//! "recorded, and none"; `None` is "nobody recorded it" — a scan from before the column, an image, a census that
//! stopped at its bounds. Reading the last as the second would tell an operator a Java repository holds no Java.
//!
//! Held to Java by `reference/scanning/java-answers.json` (`columns`), what each reader makes of odd columns included.

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use vectispire_cp_db::ScanTarget;
use vectispire_domain::FindingType;
use vectispire_domain::java;

use crate::persistence::ScanRow;

/// `Language`'s wire names, in the enum's order — the one vocabulary of a plugin's manifest, a rule set's coverage and
/// a tree's census.
pub const LANGUAGES: [&str; 24] = vectispire_protocol::LANGUAGES;

/// A scan's properties under their own names. The payloads are not carried: whether it holds an SBOM is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanView {
    pub id: i64,
    pub branch: String,
    pub sub_path: Option<String>,
    pub status: String,
    pub duration_ms: Option<i64>,
    pub findings_count: i32,
    pub new_issues_count: i32,
    pub resolved_issues_count: i32,
    pub error: Option<String>,
    pub created_at: OffsetDateTime,
    pub version: Option<String>,
    pub project_type: Option<String>,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub required_agent_label: Option<String>,
    pub claimed_by: Option<String>,
    pub claimed_at: Option<OffsetDateTime>,
    pub lease_expires_at: Option<OffsetDateTime>,
    pub attempts: i32,
    pub not_before: Option<OffsetDateTime>,
    /// The column as stored; [`PluginOutcome::read`] reads it.
    pub plugin_steps: Option<String>,
    pub examined_types: Option<String>,
    pub detected_languages: Option<String>,
    pub sast_languages: Option<String>,
    pub has_sbom: bool,
}

impl From<ScanRow> for ScanView {
    fn from(row: ScanRow) -> ScanView {
        ScanView {
            id: row.id,
            branch: row.branch,
            sub_path: row.sub_path,
            status: row.status,
            duration_ms: row.duration_ms,
            findings_count: row.findings_count,
            new_issues_count: row.new_issues_count,
            resolved_issues_count: row.resolved_issues_count,
            error: row.error,
            created_at: row.created_at,
            version: row.version,
            project_type: row.project_type,
            repo_id: row.repo_id,
            container_id: row.container_id,
            required_agent_label: row.required_agent_label,
            claimed_by: row.claimed_by,
            claimed_at: row.claimed_at,
            lease_expires_at: row.lease_expires_at,
            attempts: row.attempts,
            not_before: row.not_before,
            plugin_steps: row.plugin_steps,
            examined_types: row.examined_types,
            detected_languages: row.detected_languages,
            sast_languages: row.sast_languages,
            has_sbom: row.has_sbom,
        }
    }
}

impl ScanView {
    /// `ScanEntity.target`: the repository, else the image, else `None` — a row no rule can place, which an
    /// unrestricted reader sees and a restricted one does not.
    pub fn target(&self) -> Option<ScanTarget> {
        match (self.repo_id, self.container_id) {
            (Some(id), _) => Some(ScanTarget::Repository(id)),
            (None, Some(id)) => Some(ScanTarget::Container(id)),
            (None, None) => None,
        }
    }
}

/// `Language.fromWireName`: trimmed as `String.trim` trims, lower-cased under `Locale.ROOT`, one of [`LANGUAGES`].
pub fn language(name: &str) -> Option<&'static str> {
    let normalized = java::to_lower_root(java::trim(name));
    LANGUAGES.iter().copied().find(|language| *language == normalized)
}

/// `DetectedLanguages`: the languages column.
pub mod detected_languages {
    use super::{LANGUAGES, language};

    /// `write`: wire names, sorted, comma-separated; the empty string for the empty set; `None` when nothing was
    /// recorded. A name this version does not know — sent by a newer executor — is left out: what the column claims,
    /// this version can read back.
    pub fn write<'a>(names: Option<impl IntoIterator<Item = &'a str>>) -> Option<String> {
        names.map(|names| {
            let mut known: Vec<&'static str> = names.into_iter().filter_map(language).collect();
            known.sort_unstable();
            known.dedup();
            known.join(",")
        })
    }

    /// `read`: the column's languages, in the enum's order; a name this version does not know, left out.
    pub fn read(column: Option<&str>) -> Option<Vec<&'static str>> {
        let column = column?;
        let mut found: Vec<&'static str> = column.split(',').filter_map(language).collect();
        found.sort_by_key(|name| LANGUAGES.iter().position(|known| known == name));
        found.dedup();
        Some(found)
    }
}

/// `ExaminedTypes`: the built-in types whose step produced in a scan.
pub mod examined_types {
    use vectispire_domain::{FindingType, java};

    /// `read`: wire names trimmed and matched exactly, in the enum's order; a name this version does not know, left
    /// out.
    pub fn read(column: Option<&str>) -> Option<Vec<FindingType>> {
        let column = column?;
        let named: Vec<&str> = column.split(',').map(java::trim).filter(|name| !name.is_empty()).collect();
        Some(FindingType::ALL.into_iter().filter(|kind| named.contains(&kind.wire_name())).collect())
    }

    /// `write`: wire names, sorted, comma-separated.
    pub fn write(examined: &[FindingType]) -> String {
        let mut names: Vec<&str> = examined.iter().map(|kind| kind.wire_name()).collect();
        names.sort_unstable();
        names.dedup();
        names.join(",")
    }
}

/// `PluginOutcome`: what became of one plugin in one scan, as `plugin_steps` keeps it — a JSON array of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginOutcome {
    pub plugin_id: Option<String>,
    pub manifest_digest: Option<String>,
    pub state: Option<String>,
    pub findings: Option<i32>,
    pub languages: Option<Vec<Option<String>>>,
    pub reason: Option<String>,
    pub refusal: Option<String>,
    pub signature: Option<String>,
}

/// A column [`PluginOutcome::read`] cannot answer for: an element that is `null`, which Java's `List.copyOf` refuses
/// past the parser's catch — the scan's page then answers 500 for that row, and so does this port's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a plugin outcome of the scan is null")]
pub struct NullOutcome;

impl PluginOutcome {
    /// `PluginOutcome.read`: as Jackson 2's default mapper with unknown fields ignored reads a `List<PluginOutcome>`.
    /// Anything it refuses reads as no outcome — the findings and the failures are still there, and they decide
    /// everything — except a `null` element (see [`NullOutcome`]).
    pub fn read(column: Option<&str>) -> Result<Vec<PluginOutcome>, NullOutcome> {
        let Some(column) = column.filter(|column| !java::is_blank(column)) else { return Ok(Vec::new()) };
        let Ok(Value::Array(elements)) = serde_json::from_str::<Value>(column) else { return Ok(Vec::new()) };
        let mut read = Vec::with_capacity(elements.len());
        for element in elements {
            match element {
                Value::Null => return Err(NullOutcome),
                Value::Object(fields) => match outcome(&fields) {
                    Some(outcome) => read.push(outcome),
                    None => return Ok(Vec::new()),
                },
                _ => return Ok(Vec::new()),
            }
        }
        Ok(read)
    }

    /// `PluginOutcome.write`'s array, `None` for a scan that ran no plugin.
    pub fn write(outcomes: &[PluginOutcome]) -> Option<String> {
        (!outcomes.is_empty()).then(|| vectispire_domain::wire::to_wire_string(outcomes))
    }
}

/// One element, or `None` where Jackson would refuse the whole column.
fn outcome(fields: &serde_json::Map<String, Value>) -> Option<PluginOutcome> {
    Some(PluginOutcome {
        plugin_id: text(fields.get("pluginId"))?,
        manifest_digest: text(fields.get("manifestDigest"))?,
        state: text(fields.get("state"))?,
        findings: int(fields.get("findings"))?,
        languages: match fields.get("languages") {
            None | Some(Value::Null) => None,
            Some(Value::Array(names)) => {
                Some(names.iter().map(|name| text(Some(name))).collect::<Option<Vec<Option<String>>>>()?)
            }
            Some(_) => return None,
        },
        reason: text(fields.get("reason"))?,
        refusal: text(fields.get("refusal"))?,
        signature: text(fields.get("signature"))?,
    })
}

/// A `String` component as Jackson coerces a scalar into one; an array or an object refuses the column.
fn text(value: Option<&Value>) -> Option<Option<String>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(text)) => Some(Some(text.clone())),
        Some(Value::Number(number)) => Some(Some(number.to_string())),
        Some(Value::Bool(flag)) => Some(Some(flag.to_string())),
        Some(_) => None,
    }
}

/// An `Integer` component: an integral number in range, a decimal truncated, a string read as one (blank as `null`).
fn int(value: Option<&Value>) -> Option<Option<i32>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(Value::Number(number)) => match number.as_i64() {
            Some(whole) => i32::try_from(whole).ok().map(Some),
            None => {
                let decimal = number.as_f64()?;
                if decimal.is_finite() && decimal.abs() < 2_147_483_648.0 {
                    #[allow(clippy::cast_possible_truncation)] // In range, checked on the line above.
                    Some(Some(decimal.trunc() as i32))
                } else {
                    None
                }
            }
        },
        Some(Value::String(text)) => {
            let trimmed = java::trim(text);
            if trimmed.is_empty() { Some(None) } else { java::read_int(trimmed).ok().map(Some) }
        }
        Some(_) => None,
    }
}

/// The built-in types whose steps a scan can examine — `ExaminedTypes.BUILT_IN`.
pub const BUILT_IN: [FindingType; 7] = [
    FindingType::Vulnerability,
    FindingType::Secret,
    FindingType::Iac,
    FindingType::Sast,
    FindingType::Quality,
    FindingType::Eol,
    FindingType::License,
];
