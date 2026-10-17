//! A result as the control plane reads it — `ScanArtifacts::read`, the server half of the result route.
//!
//! **Read exactly as the Java control plane's mapper reads it**, because what a result says is decided by
//! the reader (decision 0007): a step read as absent resolves nothing, read as empty it resolves the
//! target's whole backlog of that type. So every step stays an [`Option`] from the body to the caller —
//! `null`, or no field at all, is absent; `[]` is a step that ran and found nothing — and nothing here
//! flattens one into the other. The pinning is `reference/artifacts/java-read.json`: what Java's mapper
//! made of each body, step by step, or that it refused it.
//!
//! **A null element stays a null element.** `"secrets": [null]` is a step that ran, with one element
//! Java holds as `null`; it is kept as `None` in a [`Listed`] so that ingestion (task 2.8) decides what
//! Java decides with it, rather than this reader deciding for it. Two places drop nulls because the Java
//! record does: the languages and the plugin steps.
//!
//! **The SBOM is kept as the bytes that came**, borrowed from the body: a result may reach 256 MB, and a
//! `serde_json::Value` of it would cost several times that, on top of the body kept for its signature.
//! Nothing else is held as a tree either: each step is read into typed findings straight from the body.

use crate::artifacts::{Project, Refusal, ScanArtifacts, Signature};
use crate::coerce::{self, JavaDuration, Shape};
use crate::jackson::{self, Refused};
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::BTreeSet;
use vectispire_domain::java;
use vectispire_domain::severity::Severity;

/// A step's findings as Java holds them: each element, or `None` where the body had `null`.
pub type Listed<T> = Vec<Option<T>>;

/// What the control plane read from a result body.
#[derive(Debug, Clone)]
pub struct Received<'a> {
    /// The CycloneDX document, as sent. Absent for `null` or no field; any other JSON value is present,
    /// as Jackson holds it — `"sbom": 0` is an SBOM, for ingestion to make nothing of.
    pub sbom: Option<Cow<'a, RawValue>>,
    pub project: Option<Project>,
    /// As sent, unnormalised — `Java` and `java` are two names here, as in Java — with `null`s dropped.
    pub languages: Option<BTreeSet<String>>,
    pub dependencies: Option<Listed<DependencyFinding>>,
    pub secrets: Option<Listed<SecretFinding>>,
    pub iac: Option<Listed<IacFinding>>,
    pub sast: Option<Listed<SastFinding>>,
    pub api_endpoints: Option<Listed<ApiEndpoint>>,
    pub api_contracts: Option<Listed<ApiContract>>,
    /// Every step but the `null` ones. A `produced` step without its findings is read as absent, as the
    /// Java record turns it: it would otherwise resolve the plugin's whole backlog.
    pub plugins: Vec<ReceivedStep>,
    pub failures: Listed<ReceivedFailure>,
    /// Absent when the body has none — which Java holds as a `null` `Duration`.
    pub duration: Option<JavaDuration>,
}

/// `DependencyScanner.DependencyFinding`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DependencyFinding {
    pub identifier: Option<String>,
    pub severity: Option<Severity>,
    pub package_name: Option<String>,
    pub installed_version: Option<String>,
    pub fix_versions: Option<String>,
    pub description: Option<String>,
    pub reference_url: Option<String>,
    pub purl: Option<String>,
}

/// `SecretsScanner.SecretFinding`. `line` is an `int`: absent or `null` is 0.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecretFinding {
    pub rule: Option<String>,
    pub description: Option<String>,
    pub file: Option<String>,
    pub line: i32,
    pub fingerprint: Option<String>,
}

/// `IacScanner.IacFinding`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IacFinding {
    pub check_id: Option<String>,
    pub check_name: Option<String>,
    pub file: Option<String>,
    pub line: i32,
    pub guideline: Option<String>,
    pub resource: Option<String>,
}

/// `SastScanner.SastFinding`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SastFinding {
    pub rule_id: Option<String>,
    pub category: Option<String>,
    pub severity: Option<Severity>,
    pub confidence: Option<String>,
    pub file: Option<String>,
    pub line: i32,
    pub message: Option<String>,
    pub owasp_category: Option<String>,
}

/// `ApiVisibility`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiVisibility {
    Public,
    Internal,
    Unknown,
}

/// `ApiEndpoint`, normalised as its record's constructor normalises it: the method upper-cased, the path
/// `/` when blank and rooted otherwise, the visibility `UNKNOWN` when absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiEndpoint {
    pub method: Option<String>,
    pub path: String,
    pub auth_required: bool,
    pub auth_type: Option<String>,
    pub visibility: ApiVisibility,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub framework: Option<String>,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub tags: Option<String>,
}

/// `ApiContract`: `declaredPaths` absent or `null` is empty, a `null` path inside it stays.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApiContract {
    pub contract_path: Option<String>,
    pub format: Option<String>,
    pub title: Option<String>,
    pub version: Option<String>,
    pub endpoints_count: i32,
    pub declared_paths: Listed<String>,
}

/// `SarifFinding`, a plugin's finding.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SarifFinding {
    pub rule_id: Option<String>,
    pub severity: Option<Severity>,
    pub file: Option<String>,
    pub line: Option<i32>,
    pub message: Option<String>,
}

/// `ScanArtifacts.Failure`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceivedFailure {
    pub step: Option<String>,
    pub reason: Option<String>,
}

/// A `PluginStep` as read: the four states. A signature or a refusal Java does not know reads as `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedStep {
    Produced {
        plugin_id: Option<String>,
        manifest_digest: Option<String>,
        tool_name: Option<String>,
        tool_version: Option<String>,
        findings: Listed<SarifFinding>,
        signature: Option<Signature>,
    },
    /// `languages` are `Language` wire names, normalised, without duplicates, in the enum's order.
    NotApplicable {
        plugin_id: Option<String>,
        manifest_digest: Option<String>,
        languages: Vec<&'static str>,
    },
    Absent {
        plugin_id: Option<String>,
        manifest_digest: Option<String>,
        reason: Option<String>,
    },
    Refused {
        plugin_id: Option<String>,
        manifest_digest: Option<String>,
        refusal: Option<Refusal>,
        reason: Option<String>,
    },
}

/// The reason `ScanArtifacts` gives a `produced` step that came without findings.
pub const PRODUCED_WITHOUT_FINDINGS: &str = "the executor reported the plugin as run without a list of findings";

/// `Language`'s wire names, in the enum's order.
pub const LANGUAGES: [&str; 24] = [
    "apex",
    "bash",
    "c",
    "clojure",
    "csharp",
    "dockerfile",
    "elixir",
    "go",
    "html",
    "java",
    "javascript",
    "json",
    "kotlin",
    "ocaml",
    "php",
    "python",
    "ruby",
    "rust",
    "scala",
    "solidity",
    "swift",
    "terraform",
    "typescript",
    "yaml",
];

const SEVERITIES: [Severity; 6] =
    [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Negligible, Severity::Unknown];
const SEVERITY_NAMES: [&str; 6] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"];
const VISIBILITIES: [ApiVisibility; 3] = [ApiVisibility::Public, ApiVisibility::Internal, ApiVisibility::Unknown];
const VISIBILITY_NAMES: [&str; 3] = ["PUBLIC", "INTERNAL", "UNKNOWN"];
const SIGNATURES: [Signature; 3] = [Signature::Verified, Signature::Waived, Signature::NotRequired];
const SIGNATURE_NAMES: [&str; 3] = ["verified", "waived", "not_required"];
const REFUSALS: [Refusal; 3] =
    [Refusal::Unsigned, Refusal::SignatureUnverified, Refusal::RegistryAuthenticationRequired];
const REFUSAL_NAMES: [&str; 3] = ["unsigned", "signature_unverified", "registry_authentication_required"];

/// Why a result body was not read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    /// The body is the JSON `null`, which Java's mapper reads as no result at all rather than refusing:
    /// `AgentProtocolService.submitResult` then has a `null` to dereference. What to answer is the route's
    /// decision (task 2.9), not the reader's.
    #[error("the body is null")]
    Null,
    /// Jackson would have refused it — `submitResult` answers 400.
    #[error("{0}")]
    Refused(String),
}

impl From<Refused> for Unreadable {
    fn from(refused: Refused) -> Unreadable {
        Unreadable::Refused(refused.0)
    }
}

impl ScanArtifacts {
    /// A result body read as the Java control plane's mapper reads it. Verify the signature on these same
    /// bytes first: nothing here may be believed of a body that is not the agent's.
    pub fn read(body: &[u8]) -> Result<Received<'_>, Unreadable> {
        match jackson::prepare(body, jackson::CONTROL_PLANE)? {
            Cow::Borrowed(document) => read_document(document),
            // A rewritten body is already a copy of itself; the SBOM is cut out of that copy rather than
            // copied again, so that such a body costs one more body, not two.
            Cow::Owned(document) => {
                let (read, sbom) = {
                    let read = read_document(&document)?;
                    let at = read.sbom.as_ref().map(|raw| {
                        let start = (raw.get().as_ptr() as usize).saturating_sub(document.as_ptr() as usize);
                        start..start.saturating_add(raw.get().len())
                    });
                    (read.without_sbom(), at)
                };
                Ok(Received { sbom: sbom.map(|at| cut(document, at)).transpose()?.map(Cow::Owned), ..read })
            }
        }
    }
}

impl Received<'_> {
    /// `observedNothing`: no analysis ran, and no plugin produced.
    pub fn observed_nothing(&self) -> bool {
        self.dependencies.is_none()
            && self.secrets.is_none()
            && self.iac.is_none()
            && self.sast.is_none()
            && !self.plugins.iter().any(|step| matches!(step, ReceivedStep::Produced { .. }))
    }

    /// The same, owning its SBOM.
    pub fn into_owned(self) -> Received<'static> {
        let sbom = self.sbom.clone().map(|sbom| Cow::Owned(sbom.into_owned()));
        Received { sbom, ..self.without_sbom() }
    }

    fn without_sbom(self) -> Received<'static> {
        Received {
            sbom: None,
            project: self.project,
            languages: self.languages,
            dependencies: self.dependencies,
            secrets: self.secrets,
            iac: self.iac,
            sast: self.sast,
            api_endpoints: self.api_endpoints,
            api_contracts: self.api_contracts,
            plugins: self.plugins,
            failures: self.failures,
            duration: self.duration,
        }
    }
}

/// The SBOM's bytes, cut out of the rewritten document in place.
fn cut(document: Vec<u8>, at: std::ops::Range<usize>) -> Result<Box<RawValue>, Unreadable> {
    let mut text = String::from_utf8(document).map_err(|error| Unreadable::Refused(error.to_string()))?;
    text.truncate(at.end);
    text.drain(..at.start);
    // `RawValue::from_string` checks the text with `serde_json`'s depth limit of 128; an SBOM deeper than
    // that, which Jackson reads, is copied out under the lifted limit instead.
    if serde_json::from_str::<&RawValue>(&text).is_ok() {
        return RawValue::from_string(text).map_err(|error| Unreadable::Refused(error.to_string()));
    }
    let mut deserializer = serde_json::Deserializer::from_str(&text);
    deserializer.disable_recursion_limit();
    <Box<RawValue> as serde::Deserialize>::deserialize(&mut deserializer)
        .map_err(|error| Unreadable::Refused(error.to_string()))
}

fn read_document(document: &[u8]) -> Result<Received<'_>, Unreadable> {
    let text = std::str::from_utf8(document).map_err(|error| Unreadable::Refused(error.to_string()))?;
    let Some(members) = coerce::root(text, "ScanArtifacts")? else { return Err(Unreadable::Null) };
    Ok(Received {
        sbom: coerce::last(&members, "sbom", |raw| Ok(Some(raw)))?
            .flatten()
            .filter(|raw| raw.get() != "null")
            .map(Cow::Borrowed),
        project: coerce::last(&members, "project", project)?.flatten(),
        languages: coerce::last(&members, "languages", languages)?.flatten(),
        dependencies: coerce::last(&members, "dependencies", |raw| findings(raw, dependency))?.flatten(),
        secrets: coerce::last(&members, "secrets", |raw| findings(raw, secret))?.flatten(),
        iac: coerce::last(&members, "iac", |raw| findings(raw, iac))?.flatten(),
        sast: coerce::last(&members, "sast", |raw| findings(raw, sast))?.flatten(),
        api_endpoints: coerce::last(&members, "apiEndpoints", |raw| findings(raw, endpoint))?.flatten(),
        api_contracts: coerce::last(&members, "apiContracts", |raw| findings(raw, contract))?.flatten(),
        plugins: coerce::last(&members, "plugins", plugins)?.unwrap_or_default(),
        failures: coerce::last(&members, "failures", |raw| findings(raw, failure))?.flatten().unwrap_or_default(),
        duration: coerce::last(&members, "duration", coerce::duration)?.flatten(),
    })
}

/// A list of records, each read by `read`; `null` is absent, a `null` element is kept.
fn findings<T>(raw: &RawValue, read: fn(&RawValue) -> Result<T, Refused>) -> Result<Option<Listed<T>>, Refused> {
    let Some(elements) = coerce::list(raw, "java.util.ArrayList")? else { return Ok(None) };
    elements
        .into_iter()
        .map(|element| match coerce::shape(element)? {
            Shape::Null => Ok(None),
            Shape::Object => read(element).map(Some),
            Shape::Array => Err(Refused("Cannot deserialize a record from Array value".into())),
            _ => Err(Refused(
                "Cannot construct instance of a record: no String-, int- or boolean-argument constructor".into(),
            )),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

use coerce::Members;

fn fields(raw: &RawValue) -> Result<Members<'_>, Refused> {
    coerce::members_of(raw.get())
}

fn text(members: &Members<'_>, name: &str) -> Result<Option<String>, Refused> {
    Ok(coerce::last(members, name, coerce::text)?.flatten())
}

fn severity(members: &Members<'_>, name: &str) -> Result<Option<Severity>, Refused> {
    Ok(coerce::last(members, name, |raw| coerce::by_name(raw, &SEVERITY_NAMES))?
        .flatten()
        .and_then(|index| SEVERITIES.get(index).copied()))
}

fn int(members: &Members<'_>, name: &str) -> Result<i32, Refused> {
    Ok(coerce::last(members, name, coerce::int)?.unwrap_or_default())
}

fn project(raw: &RawValue) -> Result<Option<Project>, Refused> {
    let Some(members) = coerce::members(raw, "ProjectManifest.Project")? else { return Ok(None) };
    Ok(Some(Project { kind: text(&members, "type")?, version: text(&members, "version")? }))
}

fn languages(raw: &RawValue) -> Result<Option<BTreeSet<String>>, Refused> {
    let Some(elements) = coerce::list(raw, "java.util.HashSet")? else { return Ok(None) };
    let mut names = BTreeSet::new();
    for element in elements {
        if let Some(name) = coerce::text(element)? {
            names.insert(name);
        }
    }
    Ok(Some(names))
}

fn dependency(raw: &RawValue) -> Result<DependencyFinding, Refused> {
    let m = fields(raw)?;
    Ok(DependencyFinding {
        identifier: text(&m, "identifier")?,
        severity: severity(&m, "severity")?,
        package_name: text(&m, "packageName")?,
        installed_version: text(&m, "installedVersion")?,
        fix_versions: text(&m, "fixVersions")?,
        description: text(&m, "description")?,
        reference_url: text(&m, "referenceUrl")?,
        purl: text(&m, "purl")?,
    })
}

fn secret(raw: &RawValue) -> Result<SecretFinding, Refused> {
    let m = fields(raw)?;
    Ok(SecretFinding {
        rule: text(&m, "rule")?,
        description: text(&m, "description")?,
        file: text(&m, "file")?,
        line: int(&m, "line")?,
        fingerprint: text(&m, "fingerprint")?,
    })
}

fn iac(raw: &RawValue) -> Result<IacFinding, Refused> {
    let m = fields(raw)?;
    Ok(IacFinding {
        check_id: text(&m, "checkId")?,
        check_name: text(&m, "checkName")?,
        file: text(&m, "file")?,
        line: int(&m, "line")?,
        guideline: text(&m, "guideline")?,
        resource: text(&m, "resource")?,
    })
}

fn sast(raw: &RawValue) -> Result<SastFinding, Refused> {
    let m = fields(raw)?;
    Ok(SastFinding {
        rule_id: text(&m, "ruleId")?,
        category: text(&m, "category")?,
        severity: severity(&m, "severity")?,
        confidence: text(&m, "confidence")?,
        file: text(&m, "file")?,
        line: int(&m, "line")?,
        message: text(&m, "message")?,
        owasp_category: text(&m, "owaspCategory")?,
    })
}

fn endpoint(raw: &RawValue) -> Result<ApiEndpoint, Refused> {
    let m = fields(raw)?;
    // The record's constructor: `toUpperCase(Locale.ROOT)`, which Rust's `to_uppercase` agrees with — it has
    // no locale either, and both apply the special casings (`ß` is `SS`).
    let method = text(&m, "method")?.map(|method| method.to_uppercase());
    let path = match text(&m, "path")? {
        None => "/".to_owned(),
        Some(path) if java::is_blank(&path) => "/".to_owned(),
        Some(path) if path.starts_with('/') => path,
        Some(path) => format!("/{path}"),
    };
    let visibility = coerce::last(&m, "visibility", |raw| coerce::by_name(raw, &VISIBILITY_NAMES))?
        .flatten()
        .and_then(|index| VISIBILITIES.get(index).copied())
        .unwrap_or(ApiVisibility::Unknown);
    Ok(ApiEndpoint {
        method,
        path,
        auth_required: coerce::last(&m, "authRequired", coerce::boolean)?.unwrap_or_default(),
        auth_type: text(&m, "authType")?,
        visibility,
        file_path: text(&m, "filePath")?,
        line_number: coerce::last(&m, "lineNumber", coerce::boxed_int)?.flatten(),
        framework: text(&m, "framework")?,
        operation_id: text(&m, "operationId")?,
        summary: text(&m, "summary")?,
        tags: text(&m, "tags")?,
    })
}

fn contract(raw: &RawValue) -> Result<ApiContract, Refused> {
    let m = fields(raw)?;
    let declared_paths = coerce::last(&m, "declaredPaths", |raw| {
        let Some(elements) = coerce::list(raw, "java.util.ArrayList")? else { return Ok(Vec::new()) };
        elements.into_iter().map(coerce::text).collect::<Result<Vec<_>, _>>()
    })?;
    Ok(ApiContract {
        contract_path: text(&m, "contractPath")?,
        format: text(&m, "format")?,
        title: text(&m, "title")?,
        version: text(&m, "version")?,
        endpoints_count: int(&m, "endpointsCount")?,
        declared_paths: declared_paths.unwrap_or_default(),
    })
}

fn sarif(raw: &RawValue) -> Result<SarifFinding, Refused> {
    let m = fields(raw)?;
    Ok(SarifFinding {
        rule_id: text(&m, "ruleId")?,
        severity: severity(&m, "severity")?,
        file: text(&m, "file")?,
        line: coerce::last(&m, "line", coerce::boxed_int)?.flatten(),
        message: text(&m, "message")?,
    })
}

fn failure(raw: &RawValue) -> Result<ReceivedFailure, Refused> {
    let m = fields(raw)?;
    Ok(ReceivedFailure { step: text(&m, "step")?, reason: text(&m, "reason")? })
}

fn plugins(raw: &RawValue) -> Result<Vec<ReceivedStep>, Refused> {
    let Some(elements) = coerce::list(raw, "java.util.ArrayList")? else { return Ok(Vec::new()) };
    let mut steps = Vec::with_capacity(elements.len());
    for element in elements {
        let read = match coerce::shape(element)? {
            Shape::Null => None,
            Shape::Object => {
                let m = fields(element)?;
                // The type id is the first `state`; a later one is an unknown property of the subtype.
                let state = m.iter().find(|(key, _)| key == "state").map(|(_, value)| *value);
                let id = match state {
                    Some(value) => type_id(value)?,
                    None => {
                        return Err(Refused(
                            "Could not resolve subtype of PluginStep: missing type id property 'state'".into(),
                        ));
                    }
                };
                Some(step(&id, &m)?)
            }
            // `As.PROPERTY` falls back to the wrapper-array form: `["absent", {…}]`.
            Shape::Array => wrapped(element)?,
            _ => {
                return Err(Refused(
                    "Could not resolve subtype of PluginStep: missing type id property 'state'".into(),
                ));
            }
        };
        steps.extend(read);
    }
    Ok(steps)
}

/// A type id as Jackson takes one: a scalar's text; `null` or a structure is no id.
fn type_id(raw: &RawValue) -> Result<String, Refused> {
    match coerce::shape(raw)? {
        Shape::Text(id) => Ok(id.into_owned()),
        Shape::Number(token) => Ok(token.to_owned()),
        Shape::Bool(value) => Ok(value.to_string()),
        _ => Err(Refused("Could not resolve subtype of PluginStep: missing type id property 'state'".into())),
    }
}

/// `["<state>", {…}]`, the type id first: nothing after the id reads as a `null` step, which is dropped;
/// a `null` value or a third element is refused, as Jackson refuses them.
fn wrapped(raw: &RawValue) -> Result<Option<ReceivedStep>, Refused> {
    let elements = coerce::list(raw, "PluginStep")?.unwrap_or_default();
    let mut elements = elements.into_iter();
    let id =
        match elements.next() {
            Some(first) if matches!(coerce::shape(first)?, Shape::Text(_) | Shape::Number(_) | Shape::Bool(_)) => {
                type_id(first)?
            }
            _ => return Err(Refused(
                "Unexpected token, expected VALUE_STRING: need String, Number of Boolean value that contains type id"
                    .into(),
            )),
        };
    if !matches!(id.as_str(), "produced" | "not_applicable" | "absent" | "refused") {
        return Err(Refused(format!("Could not resolve type id '{id}' as a subtype of PluginStep")));
    }
    let Some(value) = elements.next() else { return Ok(None) };
    if elements.next().is_some() {
        return Err(Refused(
            "Unexpected token, expected END_ARRAY after type information and deserialized value".into(),
        ));
    }
    match coerce::shape(value)? {
        Shape::Object => step(&id, &fields(value)?).map(Some),
        _ => Err(Refused("Cannot construct a PluginStep from a scalar or a null".into())),
    }
}

fn step(id: &str, m: &Members<'_>) -> Result<ReceivedStep, Refused> {
    let plugin_id = text(m, "pluginId")?;
    let manifest_digest = text(m, "manifestDigest")?;
    Ok(match id {
        "produced" => {
            let findings = coerce::last(m, "findings", |raw| findings(raw, sarif))?.flatten();
            let signature = coerce::last(m, "signature", |raw| coerce::by_wire_name(raw, &SIGNATURE_NAMES))?
                .flatten()
                .and_then(|index| SIGNATURES.get(index).copied());
            match findings {
                Some(findings) => ReceivedStep::Produced {
                    plugin_id,
                    manifest_digest,
                    tool_name: text(m, "toolName")?,
                    tool_version: text(m, "toolVersion")?,
                    findings,
                    signature,
                },
                // Read, then turned by the record: the other fields are still read, and still refuse.
                None => {
                    text(m, "toolName")?;
                    text(m, "toolVersion")?;
                    ReceivedStep::Absent {
                        plugin_id,
                        manifest_digest,
                        reason: Some(PRODUCED_WITHOUT_FINDINGS.to_owned()),
                    }
                }
            }
        }
        "not_applicable" => {
            let indices = coerce::last(m, "languages", |raw| {
                let Some(elements) = coerce::list(raw, "java.util.HashSet<Language>")? else { return Ok(Vec::new()) };
                elements.into_iter().map(language).collect::<Result<Vec<_>, _>>()
            })?
            .unwrap_or_default();
            // `EnumSet.copyOf`: each language once, in the enum's order.
            let indices: BTreeSet<usize> = indices.into_iter().collect();
            ReceivedStep::NotApplicable {
                plugin_id,
                manifest_digest,
                languages: indices.into_iter().filter_map(|index| LANGUAGES.get(index).copied()).collect(),
            }
        }
        "absent" => ReceivedStep::Absent { plugin_id, manifest_digest, reason: text(m, "reason")? },
        "refused" => ReceivedStep::Refused {
            plugin_id,
            manifest_digest,
            refusal: coerce::last(m, "refusal", |raw| coerce::by_wire_name(raw, &REFUSAL_NAMES))?
                .flatten()
                .and_then(|index| REFUSALS.get(index).copied()),
            reason: text(m, "reason")?,
        },
        other => return Err(Refused(format!("Could not resolve type id '{other}' as a subtype of PluginStep"))),
    })
}

/// `Language.fromJson`: trimmed, lower-cased as `Locale.ROOT` lowers, one of the wire names — or the whole
/// body is refused. A `null` element is refused too: `EnumSet.copyOf` throws on it in the record.
fn language(raw: &RawValue) -> Result<usize, Refused> {
    let name = coerce::text(raw)?
        .ok_or_else(|| Refused("Cannot construct instance of PluginStep$NotApplicable: null language".into()))?;
    let normalized = java::to_lower_root(java::trim(&name));
    LANGUAGES
        .iter()
        .position(|wire| *wire == normalized)
        .ok_or_else(|| Refused(format!("Cannot construct instance of Language: Unknown language \"{name}\"")))
}
