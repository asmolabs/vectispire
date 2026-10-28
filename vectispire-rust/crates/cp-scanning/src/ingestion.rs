//! Steps into findings — `ScanIngestor` — task 2.8's file.
//! The port it implements is `ports::ScanIngestor`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::Clock;
use vectispire_domain::dependency_graph::{DependencyGraph, Directness};
use vectispire_domain::severity::Severity;
use vectispire_domain::{FindingType, bounded_text, java, tool_keys};
use vectispire_protocol::{ApiContract, ApiEndpoint, Received, ReceivedStep};

pub use crate::persistence::findings::NewFinding;
use crate::persistence::findings::save_all;
use crate::ports::{IngestError, PortError, Prepared, Reconciliation, ScanIngestor as ScanIngestorPort};
use crate::views::ScanView;

/// Where what a scan says the target is made of goes: its components, read from the SBOM, and its API endpoints and contracts.
///
/// **In the scan's transaction, which is not optional.** Java's ingestion is `Propagation.MANDATORY`: the inventory,
/// the findings and the backlog commit with the scan or not at all. When the transaction was an `Option` here, the
/// real implementations answered `None` by opening their own and committing it — the API inventory always did — so a
/// write the dispatcher rolled back (a failure, or a fold repeated after a triage) left its inventory committed.
pub trait InventorySink: Send + Sync {
    /// The SBOM's components for this scan, with their directness from the same document.
    fn components<'a>(
        &'a self,
        tx: &'a mut Tx,
        origin: ScanOrigin,
        sbom: &'a serde_json::Value,
        raw_sbom: &'a str,
        graph: &'a DependencyGraph,
    ) -> BoxFuture<'a, Result<(), PortError>>;

    /// The API surface, each half only if its analyzer ran. Never called with both absent.
    fn apis<'a>(
        &'a self,
        tx: &'a mut Tx,
        scan_id: i64,
        repo_id: Option<i64>,
        endpoints: Option<&'a [ApiEndpoint]>,
        contracts: Option<&'a [ApiContract]>,
    ) -> BoxFuture<'a, Result<(), PortError>>;
}

/// Stand-in for `InventorySink` when none is provided.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoInventory;

impl InventorySink for NoInventory {
    fn components<'a>(
        &'a self,
        _tx: &'a mut Tx,
        _origin: ScanOrigin,
        _sbom: &'a serde_json::Value,
        _raw_sbom: &'a str,
        _graph: &'a DependencyGraph,
    ) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async { Ok(()) })
    }

    fn apis<'a>(
        &'a self,
        _tx: &'a mut Tx,
        _scan_id: i64,
        _repo_id: Option<i64>,
        _endpoints: Option<&'a [ApiEndpoint]>,
        _contracts: Option<&'a [ApiContract]>,
    ) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Where findings rows are saved in the scan's transaction.
pub trait FindingSink: Send + Sync {
    fn save_all<'a>(&'a self, tx: &'a mut Tx, findings: &'a [NewFinding]) -> BoxFuture<'a, Result<(), PortError>>;
}

/// Real database persistence calling `persistence::findings::save_all`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DbFindingSink;

impl FindingSink for DbFindingSink {
    fn save_all<'a>(&'a self, tx: &'a mut Tx, findings: &'a [NewFinding]) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async move {
            save_all(tx, findings)
                .await
                .map_err(|e| PortError::from(Box::new(e) as Box<dyn std::error::Error + Send + Sync>))
        })
    }
}

/// What folding the findings did to the backlog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BacklogDelta {
    pub created: i32,
    pub resolved: i32,
    pub reopened: i32,
    pub still_open: i32,
    pub issue_ids: Vec<Option<i64>>,
}

/// Where a completed scan's findings become issues.
pub trait Backlog: Send + Sync {
    fn reconcile<'a>(
        &'a self,
        tx: &'a mut Tx,
        observation: &'a Observation,
    ) -> BoxFuture<'a, Result<BacklogDelta, PortError>>;
}

/// Stand-in for `Backlog` when none is provided.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBacklog;

impl Backlog for NoBacklog {
    fn reconcile<'a>(
        &'a self,
        _tx: &'a mut Tx,
        observation: &'a Observation,
    ) -> BoxFuture<'a, Result<BacklogDelta, PortError>> {
        Box::pin(async move {
            Ok(BacklogDelta {
                created: 0,
                resolved: 0,
                reopened: 0,
                still_open: 0,
                issue_ids: vec![None; observation.findings.len()],
            })
        })
    }
}

/// What enrichment found: a score per identifier where one is known, and the exploited ones.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Enrichment {
    pub epss_scores: BTreeMap<String, f64>,
    pub exploited: BTreeSet<String>,
}

/// Remote/stored exploitation metrics lookups.
pub trait Enricher: Send + Sync {
    fn enrich<'a>(&'a self, identifiers: &'a [String]) -> BoxFuture<'a, Option<Enrichment>>;

    /// The task that replaces this source, when it is a stand-in — see [`ScanIngestor::stand_ins`].
    fn stand_in(&self) -> Option<&'static str> {
        None
    }
}

/// Remote end-of-life catalog lookups.
pub trait EndOfLifeSource: Send + Sync {
    fn is_enabled(&self) -> bool;
    fn findings<'a>(&'a self, sbom: &'a serde_json::Value) -> BoxFuture<'a, Option<Vec<ObservedFinding>>>;
    fn describe(&self, finding: &ObservedFinding) -> String;

    /// The task that replaces this source, when it is a stand-in — see [`ScanIngestor::stand_ins`].
    fn stand_in(&self) -> Option<&'static str> {
        None
    }
}

/// Java's `EnrichmentService` until `threatintel` is ported: it answers nothing, so every vulnerability keeps its
/// built defaults — no EPSS score and **not exploited**. That is the one stand-in here that changes a verdict: a gate
/// asking for exploited vulnerabilities passes a scan Java would fail. Named so that the composition cannot keep it
/// quietly (`cp-app`'s `ingestion_composition` test lists it).
#[derive(Debug, Clone, Copy, Default)]
pub struct EnrichmentStandIn;

impl Enricher for EnrichmentStandIn {
    fn enrich<'a>(&'a self, _identifiers: &'a [String]) -> BoxFuture<'a, Option<Enrichment>> {
        Box::pin(async { None })
    }

    fn stand_in(&self) -> Option<&'static str> {
        Some("enrichment: threatintel's EnrichmentService, Phase 4 task 4.4")
    }
}

/// Java's `EndOfLifeService` until `threatintel` is ported. Answering "switched off" keeps the type out of the
/// examined set, so end-of-life issues already open stay open rather than resolve: "we stopped looking" is not "it is
/// fixed".
#[derive(Debug, Clone, Copy, Default)]
pub struct EndOfLifeStandIn;

impl EndOfLifeSource for EndOfLifeStandIn {
    fn is_enabled(&self) -> bool {
        false
    }

    fn findings<'a>(&'a self, _sbom: &'a serde_json::Value) -> BoxFuture<'a, Option<Vec<ObservedFinding>>> {
        Box::pin(async { None })
    }

    fn describe(&self, _finding: &ObservedFinding) -> String {
        String::new()
    }

    fn stand_in(&self) -> Option<&'static str> {
        Some("end of life: threatintel's EndOfLifeService, Phase 4 task 4.4")
    }
}

/// License analysis from SBOM.
pub trait LicenseSource: Send + Sync {
    fn findings<'a>(&'a self, sbom: &'a serde_json::Value) -> BoxFuture<'a, Result<Vec<ObservedFinding>, PortError>>;
}

/// Where the forbidden licences come from.
#[derive(Debug, Clone)]
enum Blocklist {
    /// Fixed at construction — the reference set's cases, which state the setting they were run with.
    Fixed(vectispire_domain::sbom::LicenseBlocklist),
    /// `LICENSE_BLOCKLIST`, read again on every scan as Java's `LicenseService.blocklist()` reads it: an
    /// administrator's change applies to the next scan, not the next start.
    Settings(vectispire_cp_settings::Settings),
}

/// Java's `LicenseService`: the components whose licence is on the forbidden list.
#[derive(Debug, Clone)]
pub struct LicenseService {
    blocklist: Blocklist,
}

impl LicenseService {
    /// A fixed list, for a case that states it.
    pub fn new(blocklist: vectispire_domain::sbom::LicenseBlocklist) -> Self {
        Self { blocklist: Blocklist::Fixed(blocklist) }
    }

    /// The list the settings hold at each scan — the control plane's.
    pub fn from_settings(settings: vectispire_cp_settings::Settings) -> Self {
        Self { blocklist: Blocklist::Settings(settings) }
    }

    async fn blocklist(&self) -> Result<vectispire_domain::sbom::LicenseBlocklist, PortError> {
        match &self.blocklist {
            Blocklist::Fixed(list) => Ok(list.clone()),
            Blocklist::Settings(settings) => {
                let raw = settings
                    .get(vectispire_cp_settings::Setting::LicenseBlocklist)
                    .await
                    .map_err(|e| Box::new(e) as PortError)?;
                Ok(vectispire_domain::sbom::LicenseBlocklist::parse(Some(&raw)))
            }
        }
    }
}

impl LicenseSource for LicenseService {
    fn findings<'a>(&'a self, sbom: &'a serde_json::Value) -> BoxFuture<'a, Result<Vec<ObservedFinding>, PortError>> {
        Box::pin(async move {
            let blocklist = self.blocklist().await?;
            let artifacts = vectispire_domain::sbom::artifacts(Some(sbom));
            Ok(blocklist
                .violations(&artifacts)
                .into_iter()
                .map(|violation| ObservedFinding {
                    type_: FindingType::License.wire_name().to_owned(),
                    source: "syft".to_owned(),
                    identifier: Some(violation.license),
                    severity: Some(Severity::Medium.wire_name().to_owned()),
                    package_name: violation.package_name,
                    package_version: violation.package_version,
                    purl: violation.purl,
                    file_path: None,
                    line: None,
                    direct_dependency: None,
                    owasp_category: None,
                    epss_score: None,
                    cvss_score: None,
                    cvss_vector: None,
                    fix_state: None,
                    fix_versions: None,
                    link: None,
                    kev: false,
                    description: None,
                    tool: None,
                    tool_name: None,
                    tool_version: None,
                })
                .collect())
        })
    }
}

/// A scan's identifier, target, and creation instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOrigin {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub created_at: OffsetDateTime,
}

impl ScanOrigin {
    pub fn of(scan: &ScanView) -> Self {
        Self { id: scan.id, repo_id: scan.repo_id, container_id: scan.container_id, created_at: scan.created_at }
    }
}

/// What one scan observed about one thing, before column clipping.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ObservedFinding {
    pub type_: String,
    pub source: String,
    pub identifier: Option<String>,
    pub severity: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
    pub file_path: Option<String>,
    pub line: Option<i32>,
    pub direct_dependency: Option<bool>,
    pub owasp_category: Option<String>,
    pub epss_score: Option<f64>,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fix_state: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
    pub kev: bool,
    pub description: Option<String>,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
}

impl ObservedFinding {
    pub fn from_finding(f: &NewFinding) -> Self {
        Self {
            type_: f.type_.clone(),
            source: f.source.clone(),
            identifier: f.identifier.clone(),
            severity: f.severity.clone(),
            package_name: f.package_name.clone(),
            package_version: f.package_version.clone(),
            purl: f.purl.clone(),
            file_path: f.file_path.clone(),
            line: f.line,
            direct_dependency: f.direct_dependency,
            owasp_category: f.owasp_category.clone(),
            epss_score: f.epss_score,
            cvss_score: f.cvss_score,
            cvss_vector: f.cvss_vector.clone(),
            fix_state: f.fix_state.clone(),
            fix_versions: f.fix_versions.clone(),
            link: f.link.clone(),
            kev: f.is_kev,
            description: f.description.clone(),
            tool: f.tool.clone(),
            tool_name: f.tool_name.clone(),
            tool_version: f.tool_version.clone(),
        }
    }
}

/// One scan's findings, as the backlog folds them.
#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub scan_id: i64,
    pub target: Option<ScanTarget>,
    pub findings: Vec<ObservedFinding>,
    pub scanned_types: BTreeSet<FindingType>,
    pub scanned_tools: BTreeSet<String>,
    pub descriptions: BTreeMap<Option<String>, String>,
}

/// What ingestion prepared outside the writing transaction.
#[derive(Debug, Clone)]
pub struct PreparedIngestion {
    pub end_of_life: Option<Vec<ObservedFinding>>,
    pub enrichment: Option<Enrichment>,
    pub at: OffsetDateTime,
}

/// Turning a scan's artifacts into findings, then into issues.
pub struct ScanIngestor {
    pub backlog: Arc<dyn Backlog>,
    pub inventory: Arc<dyn InventorySink>,
    pub enricher: Option<Arc<dyn Enricher>>,
    pub end_of_life: Option<Arc<dyn EndOfLifeSource>>,
    pub licenses: Option<Arc<dyn LicenseSource>>,
    pub clock: Arc<dyn Clock>,
    pub findings: Arc<dyn FindingSink>,
}

impl std::fmt::Debug for ScanIngestor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanIngestor")
            .field("clock", &self.clock)
            .field("has_enricher", &self.enricher.is_some())
            .field("has_end_of_life", &self.end_of_life.is_some())
            .field("has_licenses", &self.licenses.is_some())
            .finish_non_exhaustive()
    }
}

impl ScanIngestor {
    pub fn new(
        backlog: Arc<dyn Backlog>,
        inventory: Arc<dyn InventorySink>,
        enricher: Option<Arc<dyn Enricher>>,
        end_of_life: Option<Arc<dyn EndOfLifeSource>>,
        licenses: Option<Arc<dyn LicenseSource>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self { backlog, inventory, enricher, end_of_life, licenses, clock, findings: Arc::new(DbFindingSink) }
    }

    pub fn with_findings(mut self, findings: Arc<dyn FindingSink>) -> Self {
        self.findings = findings;
        self
    }

    /// The sources composed as stand-ins, each with the task that replaces it. A licence source is never one: Java's
    /// `LicenseService` belongs to scanning itself.
    pub fn stand_ins(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        names.extend(self.enricher.as_ref().and_then(|source| source.stand_in()));
        names.extend(self.end_of_life.as_ref().and_then(|source| source.stand_in()));
        names
    }

    /// Performs remote lookups before any database transaction opens.
    pub async fn prepare(&self, _scan: &ScanView, artifacts: &Received<'_>) -> PreparedIngestion {
        // Java's `prepare` dereferences every dependency for its identifier and throws on a `null` one, before it
        // asks either catalogue. Nothing is asked here either: `ingest` refuses the same result.
        if artifacts.dependencies.as_ref().is_some_and(|list| list.iter().any(Option::is_none)) {
            return PreparedIngestion { end_of_life: None, enrichment: None, at: self.clock.now() };
        }
        let identifiers = vulnerability_identifiers(artifacts);
        let sbom_val =
            artifacts.sbom.as_ref().and_then(|raw| serde_json::from_str::<serde_json::Value>(raw.get()).ok());
        let is_cat = vectispire_domain::sbom::is_catalogue(sbom_val.as_ref());

        let end_of_life = if is_cat {
            if let (Some(sbom), Some(eol)) = (&sbom_val, &self.end_of_life) {
                if eol.is_enabled() { eol.findings(sbom).await } else { None }
            } else {
                None
            }
        } else {
            None
        };

        let enrichment = if identifiers.is_empty() {
            None
        } else if let Some(enricher) = &self.enricher {
            enricher.enrich(&identifiers).await
        } else {
            None
        };

        PreparedIngestion { end_of_life, enrichment, at: self.clock.now() }
    }

    /// The result folded into the scan's findings and the target's backlog, in `tx`.
    pub async fn ingest(
        &self,
        tx: &mut Tx,
        scan: &ScanView,
        artifacts: &Received<'_>,
        prepared: &PreparedIngestion,
    ) -> Result<Reconciliation, IngestError> {
        let sbom_val =
            artifacts.sbom.as_ref().and_then(|raw| serde_json::from_str::<serde_json::Value>(raw.get()).ok());
        let graph = DependencyGraph::new(sbom_val.as_ref());

        if let (Some(sbom), Some(raw_sbom)) = (&sbom_val, artifacts.sbom.as_ref()) {
            self.inventory
                .components(&mut *tx, ScanOrigin::of(scan), sbom, raw_sbom.get(), &graph)
                .await
                .map_err(IngestError::Failed)?;
        }

        if artifacts.api_endpoints.is_some() || artifacts.api_contracts.is_some() {
            let endpoints =
                artifacts.api_endpoints.as_ref().map(|list| every(list, "apiEndpoints")).transpose()?.map(cloned);
            let contracts =
                artifacts.api_contracts.as_ref().map(|list| every(list, "apiContracts")).transpose()?.map(cloned);
            self.inventory
                .apis(&mut *tx, scan.id, scan.repo_id, endpoints.as_deref(), contracts.as_deref())
                .await
                .map_err(IngestError::Failed)?;
        }

        let mut findings: Vec<NewFinding> = Vec::new();
        let mut scanned_types: BTreeSet<FindingType> = BTreeSet::new();
        let mut scanned_tools: BTreeSet<String> = BTreeSet::new();
        let mut descriptions: BTreeMap<Option<String>, String> = BTreeMap::new();
        let now = self.clock.now();

        if let Some(dependencies) = &artifacts.dependencies {
            scanned_types.insert(FindingType::Vulnerability);
            for dep in every(dependencies, "dependencies")? {
                if let Some(desc) = &dep.description {
                    descriptions.insert(dep.identifier.clone(), desc.clone());
                }
                let directness =
                    graph.of(dep.purl.as_deref(), dep.package_name.as_deref(), dep.installed_version.as_deref());
                let finding = NewFinding {
                    scan_id: scan.id,
                    issue_id: None,
                    type_: FindingType::Vulnerability.wire_name().to_owned(),
                    source: "grype".to_owned(),
                    tool: None,
                    tool_name: None,
                    tool_version: None,
                    identifier: dep.identifier.clone(),
                    severity: dep.severity.map(|s| s.wire_name().to_owned()),
                    package_name: dep.package_name.clone(),
                    package_version: dep.installed_version.clone(),
                    purl: dep.purl.clone(),
                    file_path: None,
                    line: None,
                    direct_dependency: directness_of(directness),
                    owasp_category: None,
                    epss_score: None,
                    cvss_score: None,
                    cvss_vector: None,
                    fix_state: None,
                    fix_versions: dep.fix_versions.clone(),
                    link: dep.reference_url.clone(),
                    is_kev: false,
                    description: None,
                    created_at: now,
                };
                findings.push(finding);
            }
        }

        if let Some(secrets) = &artifacts.secrets {
            scanned_types.insert(FindingType::Secret);
            let mut seen_secrets = BTreeSet::new();
            for secret in every(secrets, "secrets")? {
                let location_key = format!("{}:{}", secret.file.as_deref().unwrap_or(""), secret.line);
                if seen_secrets.insert(location_key) {
                    let finding = NewFinding {
                        scan_id: scan.id,
                        issue_id: None,
                        type_: FindingType::Secret.wire_name().to_owned(),
                        source: "gitleaks".to_owned(),
                        tool: None,
                        tool_name: None,
                        tool_version: None,
                        identifier: secret.rule.clone(),
                        severity: Some(Severity::High.wire_name().to_owned()),
                        package_name: None,
                        package_version: None,
                        purl: None,
                        file_path: secret.file.clone(),
                        line: Some(secret.line),
                        direct_dependency: None,
                        owasp_category: None,
                        epss_score: None,
                        cvss_score: None,
                        cvss_vector: None,
                        fix_state: None,
                        fix_versions: None,
                        link: None,
                        is_kev: false,
                        description: secret.description.clone(),
                        created_at: now,
                    };
                    findings.push(finding);
                }
            }
        }

        if let Some(iac) = &artifacts.iac {
            scanned_types.insert(FindingType::Iac);
            for check in every(iac, "iac")? {
                let finding = NewFinding {
                    scan_id: scan.id,
                    issue_id: None,
                    type_: FindingType::Iac.wire_name().to_owned(),
                    source: "checkov".to_owned(),
                    tool: None,
                    tool_name: None,
                    tool_version: None,
                    identifier: check.check_id.clone(),
                    severity: Some(Severity::Medium.wire_name().to_owned()),
                    package_name: None,
                    package_version: None,
                    purl: None,
                    file_path: check.file.clone(),
                    line: Some(check.line),
                    direct_dependency: None,
                    owasp_category: None,
                    epss_score: None,
                    cvss_score: None,
                    cvss_vector: None,
                    fix_state: None,
                    fix_versions: None,
                    link: check.guideline.clone(),
                    is_kev: false,
                    description: check.check_name.clone(),
                    created_at: now,
                };
                findings.push(finding);
            }
        }

        if let Some(sast) = &artifacts.sast {
            scanned_types.insert(FindingType::Sast);
            scanned_types.insert(FindingType::Quality);
            for result in every(sast, "sast")? {
                let kind = if result.category.as_deref() == Some("security") {
                    FindingType::Sast
                } else {
                    FindingType::Quality
                };
                let severity = downgrade_low_confidence(result.severity, result.confidence.as_deref());
                let finding = NewFinding {
                    scan_id: scan.id,
                    issue_id: None,
                    type_: kind.wire_name().to_owned(),
                    source: "semgrep".to_owned(),
                    tool: None,
                    tool_name: None,
                    tool_version: None,
                    identifier: result.rule_id.clone(),
                    severity: severity.map(|s| s.wire_name().to_owned()),
                    package_name: None,
                    package_version: None,
                    purl: None,
                    file_path: result.file.clone(),
                    line: Some(result.line),
                    direct_dependency: None,
                    owasp_category: result.owasp_category.clone(),
                    epss_score: None,
                    cvss_score: None,
                    cvss_vector: None,
                    fix_state: None,
                    fix_versions: None,
                    link: None,
                    is_kev: false,
                    description: result.message.clone(),
                    created_at: now,
                };
                findings.push(finding);
            }
        }

        for step in &artifacts.plugins {
            let ReceivedStep::Produced { plugin_id, tool_name, tool_version, findings: step_findings, .. } = step
            else {
                continue;
            };
            let plugin_key =
                tool_keys::plugin(plugin_id.as_deref()).map_err(|err| IngestError::Failed(Box::new(err)))?;
            scanned_tools.insert(plugin_key.clone());
            for result in every(step_findings, "a plugin's findings")? {
                let severity = result.severity.unwrap_or(Severity::Medium);
                let finding = NewFinding {
                    scan_id: scan.id,
                    issue_id: None,
                    type_: FindingType::Plugin.wire_name().to_owned(),
                    source: plugin_id.clone().unwrap_or_default(),
                    tool: Some(plugin_key.clone()),
                    tool_name: tool_name.clone(),
                    tool_version: tool_version.clone(),
                    identifier: result.rule_id.clone(),
                    severity: Some(severity.wire_name().to_owned()),
                    package_name: None,
                    package_version: None,
                    purl: None,
                    file_path: result.file.clone(),
                    line: result.line,
                    direct_dependency: None,
                    owasp_category: None,
                    epss_score: None,
                    cvss_score: None,
                    cvss_vector: None,
                    fix_state: None,
                    fix_versions: None,
                    link: None,
                    is_kev: false,
                    description: result.message.clone(),
                    created_at: now,
                };
                findings.push(finding);
            }
        }

        if let Some(found) = &prepared.end_of_life {
            scanned_types.insert(FindingType::Eol);
            if let Some(source) = &self.end_of_life {
                for finding in found {
                    if finding.identifier.is_some() {
                        descriptions.insert(finding.identifier.clone(), source.describe(finding));
                    }
                }
            }
            for finding in found {
                findings.push(finding_from_observed(scan.id, finding, prepared.at));
            }
        }

        let is_catalogue = vectispire_domain::sbom::is_catalogue(sbom_val.as_ref());
        if is_catalogue && let (Some(sbom), Some(license_source)) = (&sbom_val, &self.licenses) {
            scanned_types.insert(FindingType::License);
            let found = license_source.findings(sbom).await.map_err(IngestError::Failed)?;
            for finding in &found {
                let mut f = finding_from_observed(scan.id, finding, now);
                let directness = graph.of(f.purl.as_deref(), f.package_name.as_deref(), f.package_version.as_deref());
                f.direct_dependency = directness_of(directness);
                findings.push(f);
            }
        }

        if let Some(enrichment) = &prepared.enrichment {
            for finding in &mut findings {
                if finding.type_ == FindingType::Vulnerability.wire_name()
                    && let Some(id) = &finding.identifier
                    && !java::is_blank(id)
                {
                    if let Some(&score) = enrichment.epss_scores.get(id) {
                        finding.epss_score = Some(score);
                    }
                    finding.is_kev = enrichment.exploited.contains(id);
                }
            }
        }

        let observed_findings: Vec<ObservedFinding> = findings.iter().map(ObservedFinding::from_finding).collect();
        let observation = Observation {
            scan_id: scan.id,
            target: scan.target(),
            findings: observed_findings,
            scanned_types: scanned_types.clone(),
            scanned_tools,
            descriptions,
        };

        let delta = self.backlog.reconcile(&mut *tx, &observation).await.map_err(IngestError::Failed)?;

        for (index, finding) in findings.iter_mut().enumerate() {
            finding.issue_id = delta.issue_ids.get(index).copied().flatten();
            fit_to_columns(finding);
        }

        if !findings.is_empty() {
            self.findings.save_all(tx, &findings).await.map_err(IngestError::Failed)?;
        }

        Ok(Reconciliation {
            created: delta.created,
            resolved: delta.resolved,
            reopened: delta.reopened,
            still_open: delta.still_open,
            examined: Some(scanned_types.into_iter().collect()),
        })
    }
}

impl ScanIngestorPort for ScanIngestor {
    fn prepare<'a>(&'a self, scan: &'a ScanView, artifacts: &'a Received<'_>) -> BoxFuture<'a, Prepared> {
        Box::pin(async move {
            let prepared = self.prepare(scan, artifacts).await;
            Arc::new(prepared) as Prepared
        })
    }

    fn ingest<'a>(
        &'a self,
        tx: &'a mut Tx,
        scan: &'a ScanView,
        artifacts: &'a Received<'_>,
        prepared: Prepared,
    ) -> BoxFuture<'a, Result<Reconciliation, IngestError>> {
        Box::pin(async move {
            let prep = match prepared.downcast_ref::<PreparedIngestion>() {
                Some(prep) => prep.clone(),
                None => self.prepare(scan, artifacts).await,
            };
            self.ingest(tx, scan, artifacts, &prep).await
        })
    }
}

/// A list of a result held as Java's ingestion reads it: every element, and a `null` one refused.
///
/// Java's record keeps a `null` element (`Listed`), and `ScanIngestor` — or, for the API lists, the inventory it hands
/// them to — dereferences each one: the `NullPointerException` leaves `record`, the scan's write rolls back and the
/// result is not taken. Skipping it instead, as this did, wrote a scan Java would have refused, and whatever the
/// element stood for was neither recorded nor reported (`reference/scanning/ingestion.json`, the `null-element:` cases).
fn every<'l, T>(list: &'l [Option<T>], what: &'static str) -> Result<Vec<&'l T>, IngestError> {
    list.iter()
        .map(|element| element.as_ref().ok_or_else(|| IngestError::Failed(Box::new(NullElement(what)))))
        .collect()
}

fn cloned<T: Clone>(list: Vec<&T>) -> Vec<T> {
    list.into_iter().cloned().collect()
}

/// A result list carried a `null` element — Java's `NullPointerException`.
#[derive(Debug, thiserror::Error)]
#[error("the result's {0} list carries a null element")]
pub struct NullElement(pub &'static str);

pub fn vulnerability_identifiers(artifacts: &Received<'_>) -> Vec<String> {
    let Some(dependencies) = &artifacts.dependencies else {
        return Vec::new();
    };
    let mut set = BTreeSet::new();
    for dep in dependencies.iter().flatten() {
        if let Some(id) = &dep.identifier
            && !java::is_blank(id)
        {
            set.insert(id.clone());
        }
    }
    set.into_iter().collect()
}

pub fn downgrade_low_confidence(severity: Option<Severity>, confidence: Option<&str>) -> Option<Severity> {
    let severity = severity?;
    if confidence != Some("LOW") {
        return Some(severity);
    }
    Some(match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium | Severity::Low => Severity::Low,
        Severity::Negligible | Severity::Unknown => severity,
    })
}

pub fn directness_of(directness: Directness) -> Option<bool> {
    match directness {
        Directness::Direct => Some(true),
        Directness::Transitive => Some(false),
        Directness::Unknown => None,
    }
}

pub fn fit_to_columns(finding: &mut NewFinding) {
    finding.identifier = bounded_text::clip(finding.identifier.as_deref(), 255).map(str::to_owned);
    finding.package_name = bounded_text::clip(finding.package_name.as_deref(), 255).map(str::to_owned);
    finding.package_version = bounded_text::clip(finding.package_version.as_deref(), 255).map(str::to_owned);
    finding.purl = bounded_text::clip(finding.purl.as_deref(), 255).map(str::to_owned);
    finding.file_path = bounded_text::clip(finding.file_path.as_deref(), 500).map(str::to_owned);
    finding.fix_versions = bounded_text::clip(finding.fix_versions.as_deref(), 255).map(str::to_owned);
    finding.link = bounded_text::clip(finding.link.as_deref(), 500).map(str::to_owned);
    finding.cvss_vector = bounded_text::clip(finding.cvss_vector.as_deref(), 255).map(str::to_owned);
    finding.fix_state = bounded_text::clip(finding.fix_state.as_deref(), 50).map(str::to_owned);
    finding.severity = bounded_text::clip(finding.severity.as_deref(), 50).map(str::to_owned);
    finding.description = bounded_text::clip(finding.description.as_deref(), bounded_text::TEXT_MAX).map(str::to_owned);
    finding.source = bounded_text::clip(Some(&finding.source), 50).unwrap_or("").to_owned();
    finding.tool = bounded_text::clip(finding.tool.as_deref(), 200).map(str::to_owned);
    finding.tool_name = bounded_text::clip(finding.tool_name.as_deref(), 100).map(str::to_owned);
    finding.tool_version = bounded_text::clip(finding.tool_version.as_deref(), 100).map(str::to_owned);
}

fn finding_from_observed(scan_id: i64, observed: &ObservedFinding, created_at: OffsetDateTime) -> NewFinding {
    NewFinding {
        scan_id,
        issue_id: None,
        type_: observed.type_.clone(),
        source: observed.source.clone(),
        tool: observed.tool.clone(),
        tool_name: observed.tool_name.clone(),
        tool_version: observed.tool_version.clone(),
        identifier: observed.identifier.clone(),
        severity: observed.severity.clone(),
        package_name: observed.package_name.clone(),
        package_version: observed.package_version.clone(),
        purl: observed.purl.clone(),
        file_path: observed.file_path.clone(),
        line: observed.line,
        direct_dependency: observed.direct_dependency,
        owasp_category: observed.owasp_category.clone(),
        epss_score: observed.epss_score,
        cvss_score: observed.cvss_score,
        cvss_vector: observed.cvss_vector.clone(),
        fix_state: observed.fix_state.clone(),
        fix_versions: observed.fix_versions.clone(),
        link: observed.link.clone(),
        is_kev: observed.kev,
        description: observed.description.clone(),
        created_at,
    }
}
