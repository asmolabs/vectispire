//! What a scan produced — `ScanArtifacts`, the body of `POST /api/v1/agent/jobs/{scanId}/result`.
//!
//! **Absent means "the step did not run"; an empty list means "found nothing"** (decision 0007). The
//! difference decides the fate of a whole backlog: the control plane resolves every issue of a type
//! that a result lists as empty, and none of a type it lists as absent. So every analysis is an
//! [`Option`], written `null` when absent and `[]` when it ran and found nothing, exactly as the Java
//! agent's mapper (`Jdk8Module`) writes an empty `Optional` and an empty list.
//!
//! **Shared, and changed only additively.** The scanner streams of the port fill this type; the
//! protocol stream owns it (`README.md`). A finding list is a [`Findings`]: each scanner keeps its own
//! finding type — the fingerprint material its reference set pins byte for byte — and hands it here
//! already serialized, so a field order or a number format decided by a scanner's parser reaches the
//! wire unchanged and nothing here has to know a scanner's types.
//!
//! **The field order is the Java record's**, so a body the Rust agent writes reads like the Java
//! agent's: `reference/artifacts/` holds bodies written here, and `ScanArtifactsReferenceSetTest`
//! reads each with the agent's mapper and writes it back to the same tree.

use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use std::time::Duration;

/// One analysis's findings, each already in its wire form.
///
/// A scanner turns its own findings into this with [`Findings::of`]; the protocol writes them as they
/// are. Empty is a claim — "ran, found nothing" — and so is only ever built on purpose.
#[derive(Debug, Clone, Default)]
pub struct Findings(Vec<Box<RawValue>>);

impl Findings {
    /// The findings of a step that ran, in the order the scanner produced them.
    pub fn of<T: Serialize>(findings: &[T]) -> Result<Findings, serde_json::Error> {
        findings.iter().map(serde_json::value::to_raw_value).collect::<Result<Vec<_>, _>>().map(Findings)
    }

    /// From findings already written, one JSON document each — for a parser that writes its own.
    pub fn from_documents<I: IntoIterator<Item = String>>(documents: I) -> Result<Findings, serde_json::Error> {
        documents.into_iter().map(RawValue::from_string).collect::<Result<Vec<_>, _>>().map(Findings)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for Findings {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

/// The build manifest a census found — `ProjectManifest.Project`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub version: Option<String>,
}

/// A step that did not complete — `ScanArtifacts.Failure`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// Named as an operator would recognize it, not as the code calls it.
    pub step: String,
    pub reason: String,
}

/// How a plugin's image was vouched for when it ran — `PluginStep.Signature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signature {
    Verified,
    Waived,
    NotRequired,
}

/// Why a plugin was not run — `PluginStep.Refusal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    Unsigned,
    SignatureUnverified,
    RegistryAuthenticationRequired,
}

/// What became of one plugin the task named — `PluginStep`, discriminated by `state` on the wire.
///
/// Four states, because a plugin needs "not applicable" (it looked at nothing) and "refused" beside
/// "ran" and "did not run": only `Produced` resolves anything.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PluginStep {
    #[serde(rename_all = "camelCase")]
    Produced {
        plugin_id: String,
        manifest_digest: String,
        tool_name: Option<String>,
        tool_version: Option<String>,
        /// Written as `[]` when it ran and found nothing — never left out.
        findings: Findings,
        signature: Option<Signature>,
    },
    #[serde(rename_all = "camelCase")]
    NotApplicable {
        plugin_id: String,
        manifest_digest: String,
        /// The wire names of `Language`, in the order the plugin's manifest declares them.
        languages: Vec<String>,
    },
    #[serde(rename_all = "camelCase")]
    Absent { plugin_id: String, manifest_digest: String, reason: String },
    #[serde(rename_all = "camelCase")]
    Refused { plugin_id: String, manifest_digest: String, refusal: Refusal, reason: String },
}

/// What a scan produced.
#[derive(Debug, Clone, Default)]
pub struct ScanArtifacts {
    /// The CycloneDX document, as the SBOM step wrote it.
    pub sbom: Option<Box<RawValue>>,
    pub project: Option<Project>,
    /// The languages the census saw, by `Language` wire name. Absent when no census was taken or it
    /// stopped short — never the empty set, which says "every file was seen and none has one".
    pub languages: Option<BTreeSet<String>>,
    pub dependencies: Option<Findings>,
    pub secrets: Option<Findings>,
    pub iac: Option<Findings>,
    pub sast: Option<Findings>,
    pub api_endpoints: Option<Findings>,
    pub api_contracts: Option<Findings>,
    /// One step per plugin the task named. Empty when it named none — which resolves nothing either.
    pub plugins: Vec<PluginStep>,
    pub failures: Vec<Failure>,
    pub duration: Duration,
}

impl ScanArtifacts {
    /// Whether no analysis produced anything — `observedNothing`. A plugin that ran counts; one that
    /// was not applicable looked at nothing.
    pub fn observed_nothing(&self) -> bool {
        self.dependencies.is_none()
            && self.secrets.is_none()
            && self.iac.is_none()
            && self.sast.is_none()
            && !self.plugins.iter().any(|step| matches!(step, PluginStep::Produced { .. }))
    }

    /// Records a step that did not complete.
    pub fn failed(&mut self, step: impl Into<String>, reason: impl Into<String>) {
        self.failures.push(Failure { step: step.into(), reason: reason.into() });
    }

    /// The body as sent, **once**: what the signature covers is these bytes, so nothing may serialize
    /// the result a second time on its way out.
    pub fn to_body(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl Serialize for ScanArtifacts {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The Java record's component order; `null` for an absent step, as `Jdk8Module` writes it.
        let mut map = serializer.serialize_map(Some(12))?;
        map.serialize_entry("sbom", &self.sbom)?;
        map.serialize_entry("project", &self.project)?;
        map.serialize_entry("languages", &self.languages)?;
        map.serialize_entry("dependencies", &self.dependencies)?;
        map.serialize_entry("secrets", &self.secrets)?;
        map.serialize_entry("iac", &self.iac)?;
        map.serialize_entry("sast", &self.sast)?;
        map.serialize_entry("apiEndpoints", &self.api_endpoints)?;
        map.serialize_entry("apiContracts", &self.api_contracts)?;
        map.serialize_entry("plugins", &self.plugins)?;
        map.serialize_entry("failures", &self.failures)?;
        map.serialize_entry("duration", &java_duration(self.duration))?;
        map.end()
    }
}

/// A duration as `java.time.Duration.toString` writes it — ISO-8601, the contract's
/// `format: duration`: `PT0S`, `PT12.345S`, `PT1M5S`, `PT2H`, `PT1H0.5S`.
pub fn java_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let nanos = duration.subsec_nanos();
    if seconds == 0 && nanos == 0 {
        return "PT0S".to_owned();
    }
    let (hours, minutes, secs) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    let mut text = String::from("PT");
    if hours != 0 {
        text.push_str(&format!("{hours}H"));
    }
    if minutes != 0 {
        text.push_str(&format!("{minutes}M"));
    }
    if secs == 0 && nanos == 0 {
        return text;
    }
    text.push_str(&secs.to_string());
    if nanos > 0 {
        // Nine digits, trailing zeros dropped: `.5`, `.345`, `.000000001`.
        let fraction = format!("{nanos:09}");
        text.push('.');
        text.push_str(fraction.trim_end_matches('0'));
    }
    text.push('S');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duration_is_written_as_java_writes_one() {
        let cases = [
            (Duration::ZERO, "PT0S"),
            (Duration::from_millis(12_345), "PT12.345S"),
            (Duration::from_secs(65), "PT1M5S"),
            (Duration::from_secs(7200), "PT2H"),
            (Duration::from_millis(3_600_500), "PT1H0.5S"),
            (Duration::from_nanos(1), "PT0.000000001S"),
            (Duration::from_secs(3_660), "PT1H1M"),
            (Duration::from_secs(86_400 * 2 + 1), "PT48H1S"),
        ];
        for (duration, written) in cases {
            assert_eq!(java_duration(duration), written, "{duration:?}");
        }
    }

    #[test]
    fn absent_is_null_and_found_nothing_is_an_empty_list() {
        let artifacts = ScanArtifacts { dependencies: Some(Findings::default()), ..ScanArtifacts::default() };
        let written: serde_json::Value = serde_json::from_str(&artifacts.to_body().unwrap()).unwrap();
        assert_eq!(written["dependencies"], serde_json::json!([]));
        assert!(written["secrets"].is_null());
        assert!(written.get("secrets").is_some(), "written as null, not left out");
        assert_eq!(written["plugins"], serde_json::json!([]));
        assert_eq!(written["duration"], "PT0S");
    }

    #[test]
    fn the_fields_leave_in_the_java_record_order() {
        let body = ScanArtifacts::default().to_body().unwrap();
        assert_eq!(
            body,
            r#"{"sbom":null,"project":null,"languages":null,"dependencies":null,"secrets":null,"iac":null,"sast":null,"apiEndpoints":null,"apiContracts":null,"plugins":[],"failures":[],"duration":"PT0S"}"#
        );
    }

    #[test]
    fn a_plugin_step_carries_its_state_first() {
        let step = PluginStep::Refused {
            plugin_id: "d".into(),
            manifest_digest: "e".repeat(64),
            refusal: Refusal::RegistryAuthenticationRequired,
            reason: "no credential".into(),
        };
        let written = serde_json::to_string(&step).unwrap();
        assert!(written.starts_with(r#"{"state":"refused","pluginId":"d","#), "{written}");
        assert!(written.contains(r#""refusal":"registry_authentication_required""#));
    }

    #[test]
    fn a_finding_keeps_the_bytes_its_scanner_wrote() {
        #[derive(Serialize)]
        struct Finding {
            rule: &'static str,
            line: i32,
            file: &'static str,
        }
        let findings = Findings::of(&[Finding { rule: "aws", line: 3, file: "a" }]).unwrap();
        assert_eq!(serde_json::to_string(&findings).unwrap(), r#"[{"rule":"aws","line":3,"file":"a"}]"#);
    }
}
