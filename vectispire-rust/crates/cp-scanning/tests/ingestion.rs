//! Conformance test of `ScanIngestor` against the 136 oracle cases in `reference/scanning/ingestion.json`.
//!
//! Asserts byte-identical agreement with Java for:
//! 1. `prepareAsked`: `eolCalled`, `enricherIdentifiers`, `preparedAt`
//! 2. `inventory`: `components` (including directness probes and sha256) and `apis`
//! 3. `observation`: `scanId`, `target`, `scannedTypes`, `scannedTools`, `descriptions`, `findings` (with fingerprints)
//! 4. `rows`: `saveAllCalled`, `items` (compact JSON matching `serializeFindingEntity`)
//! 5. `scanAfter`: `status`, `examinedTypes`, `findingsCount`, `newIssuesCount`, `resolvedIssuesCount`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::print_stdout
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use vectispire_cp_db::{ScanTarget, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_scanning::ingestion::{
    Backlog, BacklogDelta, EndOfLifeSource, Enricher, Enrichment, FindingSink, InventorySink, LicenseService,
    LicenseSource, NewFinding, Observation, ObservedFinding, ScanIngestor, ScanOrigin,
};
use vectispire_cp_scanning::ports::PortError;
use vectispire_cp_scanning::views::{ScanView, examined_types};
use vectispire_cp_targets::Clock;
use vectispire_domain::FindingType;
use vectispire_domain::dependency_graph::DependencyGraph;
use vectispire_domain::fingerprint;
use vectispire_domain::sbom::LicenseBlocklist;
use vectispire_protocol::{ApiContract, ApiEndpoint, ApiVisibility, ScanArtifacts};

#[derive(Debug)]
struct TestClock(Mutex<OffsetDateTime>);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

impl TestClock {
    fn set(&self, at: OffsetDateTime) {
        *self.0.lock().unwrap() = at;
    }
}

fn format_instant(dt: OffsetDateTime) -> String {
    let nanos = dt.nanosecond();
    if nanos == 0 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        )
    } else if nanos.is_multiple_of(1_000) {
        let micros = nanos / 1_000;
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
            micros
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
            nanos
        )
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let s = std::str::from_utf8(bytes).unwrap();
    fingerprint::sha256_fields(&[Some(s)])
}

fn target_key(target: Option<ScanTarget>) -> Option<String> {
    target.map(|t| match t {
        ScanTarget::Repository(id) => format!("repo:{id}"),
        ScanTarget::Container(id) => format!("container:{id}"),
    })
}

fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/admin")
        || lower.contains("/actuator")
        || lower.contains("/debug")
        || lower.contains("/internal")
        || lower.contains("/metrics")
        || lower.contains("/env")
        || lower.contains("/health")
}

struct TestInventorySink {
    components_call: Arc<Mutex<Option<serde_json::Value>>>,
    apis_call: Arc<Mutex<Option<serde_json::Value>>>,
}

impl InventorySink for TestInventorySink {
    fn components<'a>(
        &'a self,
        _tx: Option<&'a mut Tx>,
        origin: ScanOrigin,
        _sbom: &'a serde_json::Value,
        raw_sbom: &'a str,
        graph: &'a DependencyGraph,
    ) -> BoxFuture<'a, Result<(), PortError>> {
        let mut map = serde_json::Map::new();
        map.insert("scanId".to_owned(), serde_json::json!(origin.id));
        map.insert("repoId".to_owned(), serde_json::json!(origin.repo_id));
        map.insert("containerId".to_owned(), serde_json::json!(origin.container_id));
        map.insert("createdAt".to_owned(), serde_json::json!(format_instant(origin.created_at)));
        map.insert("sbomSha256".to_owned(), serde_json::json!(sha256_hex(raw_sbom.as_bytes())));

        let mut probes = serde_json::Map::new();
        for purl in [
            "pkg:npm/%40babel/traverse@7.22.0",
            "pkg:npm/direct-lib@1.0.0",
            "pkg:npm/trans-lib@2.0.0",
            "pkg:npm/unlinked-lib@3.0.0",
            "pkg:npm/pkg-0@1.0.0",
            "pkg:npm/pkg-1@1.0.0",
            "pkg:npm/pkg-1999@1.0.0",
        ] {
            let directness = graph.of(Some(purl), None, None);
            let name = match directness {
                vectispire_domain::dependency_graph::Directness::Direct => "DIRECT",
                vectispire_domain::dependency_graph::Directness::Transitive => "TRANSITIVE",
                vectispire_domain::dependency_graph::Directness::Unknown => "UNKNOWN",
            };
            probes.insert(purl.to_owned(), serde_json::json!(name));
        }
        map.insert("directnessProbes".to_owned(), serde_json::Value::Object(probes));

        *self.components_call.lock().unwrap() = Some(serde_json::Value::Object(map));
        Box::pin(async { Ok(()) })
    }

    fn apis<'a>(
        &'a self,
        _tx: Option<&'a mut Tx>,
        scan_id: i64,
        repo_id: Option<i64>,
        endpoints: Option<&'a [ApiEndpoint]>,
        contracts: Option<&'a [ApiContract]>,
    ) -> BoxFuture<'a, Result<(), PortError>> {
        let mut map = serde_json::Map::new();
        map.insert("scanId".to_owned(), serde_json::json!(scan_id));
        map.insert("repositoryId".to_owned(), serde_json::json!(repo_id));
        map.insert(
            "endpoints".to_owned(),
            match endpoints {
                None => serde_json::Value::Null,
                Some(eps) => {
                    let items: Vec<serde_json::Value> = eps
                        .iter()
                        .map(|ep| {
                            serde_json::json!({
                                "method": ep.method,
                                "path": ep.path,
                                "authRequired": ep.auth_required,
                                "authType": ep.auth_type,
                                "visibility": match ep.visibility {
                                    ApiVisibility::Public => "PUBLIC",
                                    ApiVisibility::Internal => "INTERNAL",
                                    ApiVisibility::Unknown => "UNKNOWN",
                                },
                                "filePath": ep.file_path,
                                "lineNumber": ep.line_number,
                                "framework": ep.framework,
                                "operationId": ep.operation_id,
                                "summary": ep.summary,
                                "tags": ep.tags,
                                "sensitivePath": is_sensitive_path(&ep.path),
                            })
                        })
                        .collect();
                    serde_json::Value::Array(items)
                }
            },
        );
        map.insert(
            "contracts".to_owned(),
            match contracts {
                None => serde_json::Value::Null,
                Some(cts) => {
                    let items: Vec<serde_json::Value> = cts
                        .iter()
                        .map(|c| {
                            let paths: Vec<serde_json::Value> =
                                c.declared_paths.iter().map(|p| serde_json::json!(p)).collect();
                            serde_json::json!({
                                "contractPath": c.contract_path,
                                "format": c.format,
                                "title": c.title,
                                "version": c.version,
                                "endpointsCount": c.endpoints_count,
                                "declaredPaths": paths,
                            })
                        })
                        .collect();
                    serde_json::Value::Array(items)
                }
            },
        );
        *self.apis_call.lock().unwrap() = Some(serde_json::Value::Object(map));
        Box::pin(async { Ok(()) })
    }
}

struct TestBacklog {
    created: i32,
    resolved: i32,
    reopened: i32,
    still_open: i32,
    issue_id_base: i64,
    observed_ref: Arc<Mutex<Option<Observation>>>,
}

impl Backlog for TestBacklog {
    fn reconcile<'a>(
        &'a self,
        _tx: Option<&'a mut Tx>,
        observation: &'a Observation,
    ) -> BoxFuture<'a, Result<BacklogDelta, PortError>> {
        *self.observed_ref.lock().unwrap() = Some(observation.clone());
        let issue_ids: Vec<Option<i64>> =
            (0..observation.findings.len()).map(|i| Some(self.issue_id_base + i as i64)).collect();
        let delta = BacklogDelta {
            created: self.created,
            resolved: self.resolved,
            reopened: self.reopened,
            still_open: self.still_open,
            issue_ids,
        };
        Box::pin(async move { Ok(delta) })
    }
}

struct TestFindingSink {
    save_all_called: Arc<AtomicBool>,
    saved_rows: Arc<Mutex<Vec<NewFinding>>>,
}

impl FindingSink for TestFindingSink {
    fn save_all<'a>(
        &'a self,
        _tx: Option<&'a mut Tx>,
        findings: &'a [NewFinding],
    ) -> BoxFuture<'a, Result<(), PortError>> {
        self.save_all_called.store(true, Ordering::SeqCst);
        self.saved_rows.lock().unwrap().extend_from_slice(findings);
        Box::pin(async { Ok(()) })
    }
}

struct TestEndOfLife {
    spec: serde_json::Value,
    called: Arc<AtomicBool>,
}

impl EndOfLifeSource for TestEndOfLife {
    fn is_enabled(&self) -> bool {
        self.spec.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false)
    }

    fn findings<'a>(&'a self, _sbom: &'a serde_json::Value) -> BoxFuture<'a, Option<Vec<ObservedFinding>>> {
        self.called.store(true, Ordering::SeqCst);
        let result = match self.spec.get("findings") {
            None | Some(serde_json::Value::Null) => None,
            Some(node) => {
                let list = node.as_array().unwrap().iter().map(read_observed_finding_node).collect();
                Some(list)
            }
        };
        Box::pin(async move { result })
    }

    fn describe(&self, finding: &ObservedFinding) -> String {
        let descriptions = self.spec.get("descriptions");
        if let (Some(id), Some(descs)) = (&finding.identifier, descriptions)
            && let Some(desc) = descs.get(id).and_then(|v| v.as_str())
        {
            return desc.to_owned();
        }
        format!("EOL: {}", finding.identifier.as_deref().unwrap_or(""))
    }
}

struct TestEnricher {
    spec: serde_json::Value,
    asked: Arc<Mutex<Option<Vec<String>>>>,
}

impl Enricher for TestEnricher {
    fn enrich<'a>(&'a self, identifiers: &'a [String]) -> BoxFuture<'a, Option<Enrichment>> {
        *self.asked.lock().unwrap() = Some(identifiers.to_vec());
        if self.spec.get("off").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Box::pin(async { None });
        }
        let mut epss_scores = BTreeMap::new();
        if let Some(epss) = self.spec.get("epss").and_then(|v| v.as_object()) {
            for (k, v) in epss {
                if let Some(score) = v.as_f64() {
                    epss_scores.insert(k.clone(), score);
                }
            }
        }
        let mut exploited = BTreeSet::new();
        if let Some(kev) = self.spec.get("kev").and_then(|v| v.as_array()) {
            for item in kev {
                if let Some(s) = item.as_str() {
                    exploited.insert(s.to_owned());
                }
            }
        }
        Box::pin(async move { Some(Enrichment { epss_scores, exploited }) })
    }
}

fn text_or_null(n: &serde_json::Value, field: &str) -> Option<String> {
    n.get(field).and_then(|v| v.as_str()).map(str::to_owned)
}

fn read_observed_finding_node(n: &serde_json::Value) -> ObservedFinding {
    ObservedFinding {
        type_: text_or_null(n, "type").unwrap_or_default(),
        source: text_or_null(n, "source").unwrap_or_default(),
        identifier: text_or_null(n, "identifier"),
        severity: text_or_null(n, "severity"),
        package_name: text_or_null(n, "packageName"),
        package_version: text_or_null(n, "packageVersion"),
        purl: text_or_null(n, "purl"),
        file_path: text_or_null(n, "filePath"),
        line: n.get("line").and_then(|v| v.as_i64()).map(|v| v as i32),
        direct_dependency: n.get("directDependency").and_then(|v| v.as_bool()),
        owasp_category: text_or_null(n, "owaspCategory"),
        epss_score: n.get("epssScore").and_then(|v| v.as_f64()),
        cvss_score: n.get("cvssScore").and_then(|v| v.as_f64()),
        cvss_vector: text_or_null(n, "cvssVector"),
        fix_state: text_or_null(n, "fixState"),
        fix_versions: text_or_null(n, "fixVersions"),
        link: text_or_null(n, "link"),
        kev: n.get("kev").and_then(|v| v.as_bool()).unwrap_or(false),
        description: text_or_null(n, "description"),
        tool: None,
        tool_name: None,
        tool_version: None,
    }
}

fn generate_large_sbom_result(components: usize, padding: usize) -> Vec<u8> {
    let pad = "p".repeat(padding);
    let mut sb = String::with_capacity(components * (padding + 220));
    sb.push_str("{\"sbom\":{\"source\":{\"id\":\"root\",\"type\":\"directory\"},\"artifacts\":[");
    for i in 0..components {
        if i > 0 {
            sb.push(',');
        }
        let license = if i == 0 {
            "\"GPL-3.0-only\""
        } else if i == 1 {
            "\"AGPL-3.0-only\""
        } else {
            "\"MIT\""
        };
        sb.push_str(&format!(
            "{{\"id\":\"id-{i}\",\"name\":\"pkg-{i}\",\"version\":\"1.0.0\",\"purl\":\"pkg:npm/pkg-{i}@1.0.0\",\"licenses\":[{license}],\"description\":\"{pad}\"}}"
        ));
    }
    sb.push_str("],\"artifactRelationships\":[");
    sb.push_str("{\"parent\":\"id-0\",\"child\":\"root\",\"type\":\"dependency-of\"},");
    sb.push_str("{\"parent\":\"id-1\",\"child\":\"id-0\",\"type\":\"dependency-of\"}");
    for i in 0..components {
        sb.push_str(&format!(",{{\"parent\":\"root\",\"child\":\"id-{i}\",\"type\":\"contains\"}}"));
    }
    sb.push_str("]},\"dependencies\":[");
    sb.push_str("{\"identifier\":\"CVE-2026-0001\",\"severity\":\"CRITICAL\",\"packageName\":\"pkg-0\",\"installedVersion\":\"1.0.0\",\"fixVersions\":\"1.0.1\",\"description\":\"root vuln\",\"referenceUrl\":\"https://example.invalid/1\",\"purl\":\"pkg:npm/pkg-0@1.0.0\"},");
    sb.push_str("{\"identifier\":\"CVE-2026-0002\",\"severity\":\"MEDIUM\",\"packageName\":\"pkg-1\",\"installedVersion\":\"1.0.0\",\"fixVersions\":null,\"description\":null,\"referenceUrl\":null,\"purl\":\"pkg:npm/pkg-1@1.0.0\"}");
    sb.push_str("]}");
    sb.into_bytes()
}

fn build_source_bytes(source: &serde_json::Value) -> Vec<u8> {
    let kind = source["kind"].as_str().unwrap();
    match kind {
        "body" => source["body"].as_str().unwrap().as_bytes().to_vec(),
        "scanner-dependencies" => {
            let findings_rel = source["findings"].as_str().unwrap();
            let findings_text = vectispire_testkit::read(findings_rel);
            let mut parts = Vec::new();
            if let Some(sbom_rel) = source.get("sbom").and_then(|v| v.as_str()) {
                let sbom_text = vectispire_testkit::read(sbom_rel);
                parts.push(format!("\"sbom\":{}", sbom_text.trim()));
            }
            let findings_node: serde_json::Value = serde_json::from_str(findings_text.trim()).unwrap();
            if findings_node.is_null() {
                parts.push("\"dependencies\":null".to_owned());
            } else if findings_node.is_array() {
                parts.push(format!("\"dependencies\":{}", findings_text.trim()));
            } else if findings_node.is_object() && findings_node.get("failure").is_some() {
                parts.push("\"dependencies\":null".to_owned());
                let reason = findings_node["failure"].as_str().unwrap();
                parts.push(format!(
                    "\"failures\":[{{\"step\":\"dependencies\",\"reason\":{}}}]",
                    serde_json::json!(reason)
                ));
            } else {
                parts.push("\"dependencies\":null".to_owned());
            }
            format!("{{{}}}", parts.join(",")).into_bytes()
        }
        "scanner-sbom" => {
            let sbom_rel = source["sbom"].as_str().unwrap();
            let sbom_text = vectispire_testkit::read(sbom_rel);
            format!("{{\"sbom\":{}}}", sbom_text.trim()).into_bytes()
        }
        "scanner-sast" => {
            let outcome_rel = source["outcome"].as_str().unwrap();
            let outcome_text = vectispire_testkit::read(outcome_rel);
            let lines: Vec<&str> = outcome_text.lines().collect();
            let tag = lines[0];
            match tag {
                "findings" => format!("{{\"sast\":{}}}", lines[1]).into_bytes(),
                "absent" => b"{\"sast\":null}".to_vec(),
                "failure" => serde_json::to_vec(&serde_json::json!({
                    "sast": null,
                    "failures": [{"step": "sast", "reason": lines[1]}]
                }))
                .unwrap(),
                _ => panic!("Unknown SAST outcome tag: {tag}"),
            }
        }
        "scanner-iac" => {
            let outcome_rel = source["outcome"].as_str().unwrap();
            let outcome_text = vectispire_testkit::read(outcome_rel);
            let lines: Vec<&str> = outcome_text.lines().collect();
            let tag = lines[0];
            match tag {
                "findings" => format!("{{\"iac\":{}}}", lines[1]).into_bytes(),
                "absent" => b"{\"iac\":null}".to_vec(),
                _ => panic!("Unknown IaC outcome tag: {tag}"),
            }
        }
        "scanner-secrets" => {
            let findings_rel = source["findings"].as_str().unwrap();
            let findings_text = vectispire_testkit::read(findings_rel);
            let findings_node: serde_json::Value = serde_json::from_str(findings_text.trim()).unwrap();
            let mut doc = serde_json::Map::new();
            if findings_node.is_null() {
                doc.insert("secrets".to_owned(), serde_json::Value::Null);
            } else if findings_node.is_array() {
                doc.insert("secrets".to_owned(), findings_node);
            } else if findings_node.is_object() && findings_node.get("failure").is_some() {
                doc.insert("secrets".to_owned(), serde_json::Value::Null);
                let reason = findings_node["failure"].as_str().unwrap();
                doc.insert("failures".to_owned(), serde_json::json!([{"step": "secrets", "reason": reason}]));
            } else {
                doc.insert("secrets".to_owned(), serde_json::Value::Null);
            }
            serde_json::to_vec(&doc).unwrap()
        }
        "generated-large-sbom" => {
            let components = source["components"].as_u64().unwrap() as usize;
            let padding = source["padding"].as_u64().unwrap() as usize;
            generate_large_sbom_result(components, padding)
        }
        _ => panic!("Unknown source kind: {kind}"),
    }
}

fn fingerprint_of(target: Option<ScanTarget>, finding: &ObservedFinding) -> Option<String> {
    let target = target?;
    let domain_target = match target {
        ScanTarget::Repository(id) => vectispire_domain::ScanTarget::Repository(id),
        ScanTarget::Container(id) => vectispire_domain::ScanTarget::Container(id),
    };
    let finding_type = FindingType::from_wire_name(Some(&finding.type_))?;
    if finding_type.tool_scoped() {
        fingerprint::of_tool(
            domain_target,
            finding_type,
            finding.tool.as_deref(),
            finding.identifier.as_deref(),
            finding.file_path.as_deref(),
        )
        .ok()
    } else {
        Some(fingerprint::of(&fingerprint::Input {
            target: domain_target,
            finding_type,
            identifier: finding.identifier.as_deref(),
            purl: finding.purl.as_deref(),
            package_name: finding.package_name.as_deref(),
            file_path: finding.file_path.as_deref(),
        }))
    }
}

fn serialize_observed_finding(f: &ObservedFinding, fp: Option<&str>) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("fingerprint".to_owned(), serde_json::json!(fp));
    map.insert("type".to_owned(), serde_json::json!(f.type_));
    map.insert("source".to_owned(), serde_json::json!(f.source));
    map.insert("identifier".to_owned(), serde_json::json!(f.identifier));
    map.insert("severity".to_owned(), serde_json::json!(f.severity));
    map.insert("packageName".to_owned(), serde_json::json!(f.package_name));
    map.insert("packageVersion".to_owned(), serde_json::json!(f.package_version));
    map.insert("purl".to_owned(), serde_json::json!(f.purl));
    map.insert("filePath".to_owned(), serde_json::json!(f.file_path));
    map.insert("line".to_owned(), serde_json::json!(f.line));
    map.insert("directDependency".to_owned(), serde_json::json!(f.direct_dependency));
    map.insert("owaspCategory".to_owned(), serde_json::json!(f.owasp_category));
    map.insert("epssScore".to_owned(), serde_json::json!(f.epss_score));
    map.insert("cvssScore".to_owned(), serde_json::json!(f.cvss_score));
    map.insert("cvssVector".to_owned(), serde_json::json!(f.cvss_vector));
    map.insert("fixState".to_owned(), serde_json::json!(f.fix_state));
    map.insert("fixVersions".to_owned(), serde_json::json!(f.fix_versions));
    map.insert("link".to_owned(), serde_json::json!(f.link));
    map.insert("kev".to_owned(), serde_json::json!(f.kev));
    map.insert("description".to_owned(), serde_json::json!(f.description));
    map.insert("tool".to_owned(), serde_json::json!(f.tool));
    map.insert("toolName".to_owned(), serde_json::json!(f.tool_name));
    map.insert("toolVersion".to_owned(), serde_json::json!(f.tool_version));
    serde_json::Value::Object(map)
}

fn serialize_finding_entity(f: &NewFinding) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("scanId".to_owned(), serde_json::json!(f.scan_id));
    map.insert(
        "issueId".to_owned(),
        match f.issue_id {
            Some(id) => serde_json::json!(id),
            None => serde_json::Value::Null,
        },
    );
    map.insert("type".to_owned(), serde_json::json!(f.type_));
    map.insert("source".to_owned(), serde_json::json!(f.source));
    map.insert("tool".to_owned(), serde_json::json!(f.tool));
    map.insert("toolName".to_owned(), serde_json::json!(f.tool_name));
    map.insert("toolVersion".to_owned(), serde_json::json!(f.tool_version));
    map.insert("identifier".to_owned(), serde_json::json!(f.identifier));
    map.insert("severity".to_owned(), serde_json::json!(f.severity));
    map.insert("packageName".to_owned(), serde_json::json!(f.package_name));
    map.insert("packageVersion".to_owned(), serde_json::json!(f.package_version));
    map.insert("purl".to_owned(), serde_json::json!(f.purl));
    map.insert("filePath".to_owned(), serde_json::json!(f.file_path));
    map.insert("line".to_owned(), serde_json::json!(f.line));
    map.insert("directDependency".to_owned(), serde_json::json!(f.direct_dependency));
    map.insert("owaspCategory".to_owned(), serde_json::json!(f.owasp_category));
    map.insert("epssScore".to_owned(), serde_json::json!(f.epss_score));
    map.insert("cvssScore".to_owned(), serde_json::json!(f.cvss_score));
    map.insert("cvssVector".to_owned(), serde_json::json!(f.cvss_vector));
    map.insert("fixState".to_owned(), serde_json::json!(f.fix_state));
    map.insert("fixVersions".to_owned(), serde_json::json!(f.fix_versions));
    map.insert("link".to_owned(), serde_json::json!(f.link));
    map.insert("kev".to_owned(), serde_json::json!(f.is_kev));
    map.insert("description".to_owned(), serde_json::json!(f.description));
    map.insert("createdAt".to_owned(), serde_json::json!(format_instant(f.created_at)));
    serde_json::Value::Object(map)
}

#[tokio::test]
async fn ingestion_oracle_conformance() {
    let doc = vectispire_testkit::read_json("scanning/ingestion.json");
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 136, "all 136 reference cases must be verified");

    let scan_created_at = OffsetDateTime::parse(doc["scanCreatedAt"].as_str().unwrap(), &Rfc3339).unwrap();
    let prepare_at = OffsetDateTime::parse(doc["prepareAt"].as_str().unwrap(), &Rfc3339).unwrap();
    let ingest_at = OffsetDateTime::parse(doc["ingestAt"].as_str().unwrap(), &Rfc3339).unwrap();

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];

        let scan_id = input["scanId"].as_i64().unwrap();
        let repo_id = input["repoId"].as_i64();
        let container_id = input["containerId"].as_i64();

        let scan = ScanView {
            id: scan_id,
            branch: "main".to_owned(),
            sub_path: None,
            status: "scanning".to_owned(),
            duration_ms: None,
            findings_count: 0,
            new_issues_count: 0,
            resolved_issues_count: 0,
            error: None,
            created_at: scan_created_at,
            version: None,
            project_type: None,
            repo_id,
            container_id,
            required_agent_label: None,
            claimed_by: None,
            claimed_at: None,
            lease_expires_at: None,
            attempts: 0,
            not_before: None,
            plugin_steps: None,
            examined_types: None,
            detected_languages: None,
            sast_languages: None,
            has_sbom: false,
        };

        let bytes = build_source_bytes(&input["source"]);
        let artifacts = match ScanArtifacts::read(&bytes) {
            Ok(art) => art,
            Err(err) => panic!("{name}: could not parse artifacts: {err}"),
        };

        let clock = Arc::new(TestClock(Mutex::new(prepare_at)));

        let eol_called = Arc::new(AtomicBool::new(false));
        let end_of_life: Option<Arc<dyn EndOfLifeSource>> = if input["endOfLife"].is_null() {
            None
        } else {
            Some(Arc::new(TestEndOfLife { spec: input["endOfLife"].clone(), called: eol_called.clone() }))
        };

        let enricher_asked = Arc::new(Mutex::new(None));
        let enricher: Option<Arc<dyn Enricher>> = if input["enricher"].is_null() {
            None
        } else {
            Some(Arc::new(TestEnricher { spec: input["enricher"].clone(), asked: enricher_asked.clone() }))
        };

        let licenses: Option<Arc<dyn LicenseSource>> =
            input.get("licenseBlocklist").and_then(|v| v.as_str()).map(|blocklist| {
                let parsed = LicenseBlocklist::parse(Some(blocklist));
                Arc::new(LicenseService::new(parsed)) as Arc<dyn LicenseSource>
            });

        let components_call = Arc::new(Mutex::new(None));
        let apis_call = Arc::new(Mutex::new(None));
        let inventory =
            Arc::new(TestInventorySink { components_call: components_call.clone(), apis_call: apis_call.clone() });

        let observed_ref = Arc::new(Mutex::new(None));
        let recon = &input["reconciliation"];
        let backlog = Arc::new(TestBacklog {
            created: recon["created"].as_i64().unwrap() as i32,
            resolved: recon["resolved"].as_i64().unwrap() as i32,
            reopened: recon["reopened"].as_i64().unwrap() as i32,
            still_open: recon["stillOpen"].as_i64().unwrap() as i32,
            issue_id_base: recon["issueIdBase"].as_i64().unwrap(),
            observed_ref: observed_ref.clone(),
        });

        let save_all_called = Arc::new(AtomicBool::new(false));
        let saved_rows = Arc::new(Mutex::new(Vec::new()));
        let finding_sink =
            Arc::new(TestFindingSink { save_all_called: save_all_called.clone(), saved_rows: saved_rows.clone() });

        let ingestor = ScanIngestor::new(backlog, inventory, enricher, end_of_life, licenses, clock.clone())
            .with_findings(finding_sink);

        // 1. Prepare
        let prepared = ingestor.prepare(&scan, &artifacts).await;

        // Check prepareAsked
        let exp_prepare = &case["prepareAsked"];
        assert_eq!(eol_called.load(Ordering::SeqCst), exp_prepare["eolCalled"].as_bool().unwrap(), "{name}: eolCalled");
        let actual_enricher_ids = enricher_asked.lock().unwrap().clone();
        if exp_prepare["enricherIdentifiers"].is_null() {
            assert!(actual_enricher_ids.is_none(), "{name}: enricherIdentifiers should be null");
        } else {
            let exp_ids: Vec<String> = exp_prepare["enricherIdentifiers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(actual_enricher_ids.unwrap(), exp_ids, "{name}: enricherIdentifiers");
        }
        assert_eq!(format_instant(prepared.at), exp_prepare["preparedAt"].as_str().unwrap(), "{name}: preparedAt");

        // 2. Ingest
        clock.set(ingest_at);
        let reconciliation = ingestor.ingest(None, &scan, &artifacts, &prepared).await.unwrap();

        // 3. Inventory
        let exp_inv = &case["inventory"];
        let actual_components = components_call.lock().unwrap().clone();
        if exp_inv["components"].is_null() {
            assert!(actual_components.is_none(), "{name}: inventory.components should be null");
        } else {
            assert_eq!(actual_components.unwrap(), exp_inv["components"], "{name}: inventory.components");
        }

        let actual_apis = apis_call.lock().unwrap().clone();
        if exp_inv["apis"].is_null() {
            assert!(actual_apis.is_none(), "{name}: inventory.apis should be null");
        } else {
            assert_eq!(actual_apis.unwrap(), exp_inv["apis"], "{name}: inventory.apis");
        }

        // 4. Observation
        let exp_obs = &case["observation"];
        let obs = observed_ref.lock().unwrap().clone().expect("observation was recorded");
        assert_eq!(obs.scan_id, exp_obs["scanId"].as_i64().unwrap(), "{name}: observation.scanId");
        assert_eq!(target_key(obs.target).as_deref(), exp_obs["target"].as_str(), "{name}: observation.target");

        let mut actual_types: Vec<&str> = obs.scanned_types.iter().map(|t| t.wire_name()).collect();
        actual_types.sort_unstable();
        let exp_types: Vec<&str> =
            exp_obs["scannedTypes"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(actual_types, exp_types, "{name}: observation.scannedTypes");

        let actual_tools: Vec<String> = obs.scanned_tools.into_iter().collect();
        let exp_tools: Vec<String> =
            exp_obs["scannedTools"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect();
        assert_eq!(actual_tools, exp_tools, "{name}: observation.scannedTools");

        // Descriptions
        let mut actual_descs = serde_json::Map::new();
        let mut actual_null_desc: Option<String> = None;
        for (k, v) in obs.descriptions {
            match k {
                Some(key) => {
                    actual_descs.insert(key, serde_json::json!(v));
                }
                None => {
                    actual_null_desc = Some(v);
                }
            }
        }
        assert_eq!(
            serde_json::Value::Object(actual_descs),
            exp_obs["descriptions"],
            "{name}: observation.descriptions"
        );
        assert_eq!(
            actual_null_desc.as_deref(),
            exp_obs.get("nullIdentifierDescription").and_then(|v| v.as_str()),
            "{name}: nullIdentifierDescription"
        );

        // Findings
        let exp_findings = exp_obs["findings"].as_array().unwrap();
        assert_eq!(obs.findings.len(), exp_findings.len(), "{name}: observation.findings count");
        for (i, f) in obs.findings.iter().enumerate() {
            let fp = fingerprint_of(obs.target, f);
            let actual_node = serialize_observed_finding(f, fp.as_deref());
            let exp_str = exp_findings[i].as_str().unwrap();
            let exp_node: serde_json::Value = serde_json::from_str(exp_str).unwrap();
            assert_eq!(actual_node, exp_node, "{name}: finding {i}");
        }

        // 5. Rows
        let exp_rows = &case["rows"];
        assert_eq!(
            save_all_called.load(Ordering::SeqCst),
            exp_rows["saveAllCalled"].as_bool().unwrap(),
            "{name}: saveAllCalled"
        );
        let rows = saved_rows.lock().unwrap().clone();
        let exp_items = exp_rows["items"].as_array().unwrap();
        assert_eq!(rows.len(), exp_items.len(), "{name}: rows count");
        for (i, row) in rows.iter().enumerate() {
            let actual_node = serialize_finding_entity(row);
            let exp_str = exp_items[i].as_str().unwrap();
            let exp_node: serde_json::Value = serde_json::from_str(exp_str).unwrap();
            assert_eq!(actual_node, exp_node, "{name}: row {i}");
        }

        // 6. ScanAfter
        let exp_scan = &case["scanAfter"];
        let nothing_examined = artifacts.observed_nothing() && !artifacts.failures.is_empty();
        let status = if nothing_examined { "failed" } else { "completed" };
        let findings_count = reconciliation.created + reconciliation.reopened + reconciliation.still_open;
        assert_eq!(status, exp_scan["status"].as_str().unwrap(), "{name}: status");
        assert_eq!(findings_count, exp_scan["findingsCount"].as_i64().unwrap() as i32, "{name}: findingsCount");
        assert_eq!(
            reconciliation.created,
            exp_scan["newIssuesCount"].as_i64().unwrap() as i32,
            "{name}: newIssuesCount"
        );
        assert_eq!(
            reconciliation.resolved,
            exp_scan["resolvedIssuesCount"].as_i64().unwrap() as i32,
            "{name}: resolvedIssuesCount"
        );
        let examined_str = reconciliation.examined.as_deref().map(examined_types::write);
        assert_eq!(examined_str.as_deref(), exp_scan["examinedTypes"].as_str(), "{name}: examinedTypes");
    }
}
