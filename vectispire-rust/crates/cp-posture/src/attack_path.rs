//! The attack-path graph — `common.domain.attackpath` and `AttackPathService.buildGraph`: ingress, the routes a
//! repository exposes, its worst open vulnerabilities and secrets, and the data they lead to.
//!
//! A pure function of the repository, its endpoints and its open, unsettled issues: the service reads those, this
//! draws. Every map is written in the order Java's `LinkedHashMap`s (and, since the fix, its `ordered` maps) hold.

use std::cmp::Ordering;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use vectispire_domain::java;

use crate::arithmetic;

/// Keys and values in the order written — `LinkedHashMap<String, String>` on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ordered(pub Vec<(String, String)>);

impl Ordered {
    fn of(pairs: &[(&str, &str)]) -> Ordered {
        Ordered(pairs.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect())
    }

    fn put(&mut self, key: &str, value: impl Into<String>) {
        self.0.push((key.to_owned(), value.into()));
    }
}

impl Serialize for Ordered {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (key, value) in &self.0 {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackPathNode {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub severity: String,
    pub is_exploitable: bool,
    pub note: &'static str,
    pub metadata: Ordered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackPathEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub label: &'static str,
    pub is_critical_path: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackPath {
    pub id: &'static str,
    pub scenario: &'static str,
    pub params: Ordered,
    pub risk_level: &'static str,
    pub is_directly_exploitable: bool,
    pub node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackPathGraph {
    pub target_id: Option<i64>,
    pub target_name: String,
    pub total_paths: i32,
    pub critical_exploitable_paths: i32,
    pub risk_score: i32,
    pub nodes: Vec<AttackPathNode>,
    pub edges: Vec<AttackPathEdge>,
    pub attack_paths: Vec<AttackPath>,
}

/// An endpoint, as the graph reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub id: Option<i64>,
    pub method: String,
    pub path: String,
    pub auth_required: bool,
    pub visibility: String,
    pub file_path: Option<String>,
    pub framework: Option<String>,
}

/// `IssueRows.GraphNode`: an open, unsettled issue of the repository.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphIssue {
    pub id: Option<i64>,
    pub repo_id: Option<i64>,
    pub type_: Option<String>,
    pub severity: Option<String>,
    pub identifier: Option<String>,
    pub description: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub file_path: Option<String>,
    pub cvss_score: Option<f64>,
    pub epss_score: Option<f64>,
    pub is_kev: Option<bool>,
}

impl GraphIssue {
    fn kev(&self) -> bool {
        self.is_kev == Some(true)
    }
}

/// How many vulnerabilities, and how many secrets, the graph draws: the worst first, the rest still scored.
const NODES_PER_TARGET: usize = 10;

fn severity_rank(issue: &GraphIssue) -> u8 {
    match java::to_upper_root(issue.severity.as_deref().unwrap_or_default()).as_str() {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}

/// KEV first, then by severity, then by id so two runs of one estate draw one picture.
fn worst_first(a: &GraphIssue, b: &GraphIssue) -> Ordering {
    u8::from(!a.kev())
        .cmp(&u8::from(!b.kev()))
        .then_with(|| severity_rank(a).cmp(&severity_rank(b)))
        .then_with(|| a.id.unwrap_or(i64::MAX).cmp(&b.id.unwrap_or(i64::MAX)))
}

fn is_sensitive(path: &str) -> bool {
    let lower = java::to_lower_root(path);
    ["admin", "auth", "login", "user", "payment", "checkout", "secret", "token", "upload"]
        .iter()
        .any(|word| lower.contains(word))
}

fn note_for(remote_code_execution: bool, actively_exploited: bool) -> &'static str {
    match (remote_code_execution, actively_exploited) {
        (true, true) => "RCE_ACTIVELY_EXPLOITED",
        (true, false) => "RCE_EXECUTABLE",
        (false, true) => "ACTIVELY_EXPLOITED",
        (false, false) => "EXECUTABLE",
    }
}

/// `String.valueOf(Long)` of an id that may be missing — `"null"`, as Java concatenates it.
fn id_text(id: Option<i64>) -> String {
    id.map_or_else(|| "null".to_owned(), |id| id.to_string())
}

/// `String.valueOf(Double)`.
fn double_text(value: f64) -> String {
    vectispire_domain::wire::java_double_to_string(value)
}

fn calculate_risk_score(critical_paths: i32, unauth_count: usize, vuln_count: usize, secret_count: usize) -> i32 {
    if critical_paths == 0 && vuln_count == 0 && secret_count == 0 {
        return 10;
    }
    let count = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    let base = i64::from(critical_paths)
        .saturating_mul(35)
        .saturating_add(count(secret_count).saturating_mul(25))
        .saturating_add(count(vuln_count.min(3)).saturating_mul(10))
        .saturating_add(count(unauth_count.min(3)).saturating_mul(5));
    // `Math.min(100, Math.max(15, base))` on ints: a count past `int` wraps in Java; no estate holds that many.
    i32::try_from(base.clamp(15, 100)).unwrap_or(100)
}

/// `buildGraph`.
pub fn build_graph(
    repository_id: i64,
    repository_name: String,
    endpoints: &[Endpoint],
    open_issues: &[GraphIssue],
) -> AttackPathGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut paths = Vec::new();

    let ingress = "ingress-ext";
    nodes.push(AttackPathNode {
        id: ingress.to_owned(),
        label: "Internet Ingress (0.0.0.0/0)".to_owned(),
        type_: "INTERNET_INGRESS",
        severity: "INFO".to_owned(),
        is_exploitable: true,
        note: "PUBLIC_INGRESS",
        metadata: Ordered::of(&[("exposure", "PUBLIC"), ("protocol", "HTTPS / HTTP")]),
    });

    let mut exposed: Vec<&Endpoint> = Vec::new();
    let mut unauthenticated: Vec<&Endpoint> = Vec::new();
    let mut counter: usize = 0;
    for endpoint in endpoints {
        let unauth = !endpoint.auth_required;
        let public = endpoint.visibility.eq_ignore_ascii_case("PUBLIC") || unauth;
        if !public {
            continue;
        }
        counter = counter.saturating_add(1);
        let node_id = format!("ep-{}", endpoint.id.map_or_else(|| counter.to_string(), |id| id.to_string()));
        let severity = if unauth { if is_sensitive(&endpoint.path) { "CRITICAL" } else { "HIGH" } } else { "MEDIUM" };
        let mut meta = Ordered::default();
        meta.put("method", endpoint.method.clone());
        meta.put("path", endpoint.path.clone());
        meta.put("authRequired", endpoint.auth_required.to_string());
        if let Some(file) = &endpoint.file_path {
            meta.put("filePath", file.clone());
        }
        if let Some(framework) = &endpoint.framework {
            meta.put("framework", framework.clone());
        }
        nodes.push(AttackPathNode {
            id: node_id.clone(),
            label: format!("{} {}", endpoint.method, endpoint.path),
            type_: "API_ENDPOINT",
            severity: severity.to_owned(),
            is_exploitable: unauth,
            note: if unauth { "UNAUTHENTICATED_ROUTE" } else { "AUTHENTICATED_PUBLIC_ROUTE" },
            metadata: meta,
        });
        edges.push(AttackPathEdge {
            id: format!("edge-ingress-{node_id}"),
            source: ingress.to_owned(),
            target: node_id,
            label: if unauth { "EXPOSE_UNAUTHENTICATED" } else { "EXPOSES_PUBLIC" },
            is_critical_path: unauth,
        });
        exposed.push(endpoint);
        if unauth {
            unauthenticated.push(endpoint);
        }
    }

    let mut critical: Vec<&GraphIssue> = Vec::new();
    let mut secrets: Vec<&GraphIssue> = Vec::new();
    for issue in open_issues {
        let kind = issue.type_.as_deref().map(java::to_lower_root).unwrap_or_default();
        let severity = java::to_upper_root(issue.severity.as_deref().unwrap_or("LOW"));
        if kind.contains("secret") || kind.contains("gitleaks") {
            secrets.push(issue);
        } else if severity == "CRITICAL" || severity == "HIGH" || issue.kev() {
            critical.push(issue);
        }
    }
    // Ranked, then cut: the graph draws the worst ten of each, the score counts them all.
    critical.sort_by(|a, b| worst_first(a, b));
    secrets.sort_by(|a, b| worst_first(a, b));
    let critical_found = critical.len();
    let secrets_found = secrets.len();
    critical.truncate(NODES_PER_TARGET);
    secrets.truncate(NODES_PER_TARGET);

    for (index, vuln) in critical.iter().enumerate() {
        // Numbered from one where the issue has no id, as Java's counter does.
        let node_id =
            format!("vuln-{}", vuln.id.map_or_else(|| index.saturating_add(1).to_string(), |id| id.to_string()));
        let label = format!(
            "{}{}",
            vuln.identifier.as_deref().unwrap_or("Vuln"),
            vuln.package_name.as_deref().map(|name| format!(" ({name})")).unwrap_or_default()
        );
        let rce = vuln.severity.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("CRITICAL"))
            || vuln.kev()
            || vuln
                .description
                .as_deref()
                .is_some_and(|text| java::to_lower_root(text).contains("remote code execution"));
        let mut meta = Ordered::default();
        if let Some(identifier) = &vuln.identifier {
            meta.put("cve", identifier.clone());
        }
        if let Some(package) = &vuln.package_name {
            meta.put("package", package.clone());
        }
        if let Some(version) = &vuln.package_version {
            meta.put("version", version.clone());
        }
        if let Some(cvss) = vuln.cvss_score {
            meta.put("cvss", double_text(cvss));
        }
        if let Some(epss) = vuln.epss_score {
            meta.put("epss", format!("{}%", arithmetic::fixed(epss * 100.0, 2)));
        }
        meta.put("isKev", vuln.kev().to_string());
        if let Some(file) = &vuln.file_path {
            meta.put("filePath", file.clone());
        }
        nodes.push(AttackPathNode {
            id: node_id.clone(),
            label,
            type_: "VULNERABLE_COMPONENT",
            severity: vuln.severity.as_deref().map_or_else(|| "HIGH".to_owned(), java::to_upper_root),
            is_exploitable: !unauthenticated.is_empty(),
            note: note_for(rce, vuln.kev()),
            metadata: meta,
        });
        if exposed.is_empty() {
            edges.push(AttackPathEdge {
                id: format!("edge-direct-{node_id}"),
                source: ingress.to_owned(),
                target: node_id,
                label: "REACHES_COMPONENT",
                is_critical_path: rce,
            });
        } else {
            for endpoint in &exposed {
                // `"ep-" + ep.id()`: the id, even where the node above was numbered — Java's own inconsistency.
                let endpoint_node = format!("ep-{}", id_text(endpoint.id));
                edges.push(AttackPathEdge {
                    id: format!("edge-{endpoint_node}-{node_id}"),
                    source: endpoint_node,
                    target: node_id.clone(),
                    label: "INVOKES_DEPENDENCY",
                    is_critical_path: !endpoint.auth_required && rce,
                });
            }
        }
    }

    let sink = "sink-db";
    nodes.push(AttackPathNode {
        id: sink.to_owned(),
        label: "Database / Production Data Sink".to_owned(),
        type_: "DATABASE",
        severity: "CRITICAL".to_owned(),
        is_exploitable: !critical.is_empty(),
        note: "SENSITIVE_DATA_STORE",
        metadata: Ordered::of(&[
            ("asset", "PostgreSQL / MySQL Storage"),
            ("impact", "Data Exfiltration & Integrity Loss"),
        ]),
    });
    for vuln in &critical {
        let node_id = format!("vuln-{}", id_text(vuln.id));
        edges.push(AttackPathEdge {
            id: format!("edge-{node_id}-{sink}"),
            source: node_id,
            target: sink.to_owned(),
            label: "EXFILTRATES_DATA",
            is_critical_path: vuln.severity.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("CRITICAL"))
                || vuln.kev(),
        });
    }

    for (index, secret) in secrets.iter().enumerate() {
        let node_id =
            format!("secret-{}", secret.id.map_or_else(|| index.saturating_add(1).to_string(), |id| id.to_string()));
        let mut meta = Ordered::default();
        if let Some(file) = &secret.file_path {
            meta.put("filePath", file.clone());
        }
        if let Some(description) = &secret.description {
            meta.put("description", description.clone());
        }
        nodes.push(AttackPathNode {
            id: node_id.clone(),
            label: secret.identifier.clone().unwrap_or_else(|| "Hardcoded Secret".to_owned()),
            type_: "SECRET",
            severity: "CRITICAL".to_owned(),
            is_exploitable: true,
            note: "HARDCODED_CREDENTIAL",
            metadata: meta,
        });
        match critical.first() {
            Some(first) => edges.push(AttackPathEdge {
                id: format!("edge-vuln-{node_id}"),
                source: format!("vuln-{}", id_text(first.id)),
                target: node_id,
                label: "COMPROMISES_CREDENTIALS",
                is_critical_path: true,
            }),
            None => edges.push(AttackPathEdge {
                id: format!("edge-ingress-{node_id}"),
                source: ingress.to_owned(),
                target: node_id,
                label: "DIRECT_EXPOSURE",
                is_critical_path: true,
            }),
        }
    }

    let mut critical_exploitable: i32 = 0;
    if let (Some(endpoint), Some(top)) = (unauthenticated.first(), critical.first()) {
        critical_exploitable = critical_exploitable.saturating_add(1);
        paths.push(AttackPath {
            id: "path-rce-exfil",
            scenario: "UNAUTH_RCE_CHAIN",
            params: Ordered::of(&[
                ("method", endpoint.method.as_str()),
                ("path", endpoint.path.as_str()),
                ("identifier", top.identifier.as_deref().unwrap_or_default()),
                ("package", top.package_name.as_deref().unwrap_or_default()),
            ]),
            risk_level: "CRITICAL",
            is_directly_exploitable: true,
            node_ids: vec![
                ingress.to_owned(),
                format!("ep-{}", id_text(endpoint.id)),
                format!("vuln-{}", id_text(top.id)),
                sink.to_owned(),
            ],
        });
    }
    if let Some(first) = secrets.first() {
        critical_exploitable = critical_exploitable.saturating_add(1);
        paths.push(AttackPath {
            id: "path-secret-leak",
            scenario: "PLAINTEXT_SECRET",
            params: Ordered::of(&[("file", first.file_path.as_deref().unwrap_or_default())]),
            risk_level: "CRITICAL",
            is_directly_exploitable: true,
            node_ids: vec![ingress.to_owned(), format!("secret-{}", id_text(first.id)), sink.to_owned()],
        });
    }
    if paths.is_empty() {
        paths.push(AttackPath {
            id: "path-baseline",
            scenario: "NO_CRITICAL_PATH",
            params: Ordered::default(),
            risk_level: "LOW",
            is_directly_exploitable: false,
            node_ids: vec![ingress.to_owned(), sink.to_owned()],
        });
    }

    // Scored on what the target holds, not on what the picture shows: crossing the cut must never lower it.
    let score = calculate_risk_score(critical_exploitable, unauthenticated.len(), critical_found, secrets_found);
    AttackPathGraph {
        target_id: Some(repository_id),
        target_name: repository_name,
        total_paths: i32::try_from(paths.len()).unwrap_or(i32::MAX),
        critical_exploitable_paths: critical_exploitable,
        risk_score: score,
        nodes,
        edges,
        attack_paths: paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(id: i64, path: &str, auth: bool, visibility: &str) -> Endpoint {
        Endpoint {
            id: Some(id),
            method: "GET".to_owned(),
            path: path.to_owned(),
            auth_required: auth,
            visibility: visibility.to_owned(),
            file_path: None,
            framework: None,
        }
    }

    fn issue(id: i64, type_: &str, severity: &str, kev: bool) -> GraphIssue {
        GraphIssue {
            id: Some(id),
            repo_id: Some(1),
            type_: Some(type_.to_owned()),
            severity: Some(severity.to_owned()),
            identifier: Some(format!("CVE-{id}")),
            description: None,
            package_name: Some("lib".to_owned()),
            package_version: None,
            file_path: Some("a/b".to_owned()),
            cvss_score: None,
            epss_score: Some(0.12345),
            is_kev: Some(kev),
        }
    }

    #[test]
    fn nothing_exposed_and_nothing_open_is_the_baseline() {
        let graph = build_graph(1, "r".to_owned(), &[endpoint(1, "/x", true, "INTERNAL")], &[]);
        assert_eq!(graph.risk_score, 10);
        assert_eq!(graph.attack_paths.len(), 1);
        assert_eq!(graph.attack_paths[0].scenario, "NO_CRITICAL_PATH");
        assert_eq!(graph.nodes.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), vec!["ingress-ext", "sink-db"]);
    }

    #[test]
    fn an_unauthenticated_sensitive_route_and_a_critical_make_the_rce_chain() {
        let graph = build_graph(
            1,
            "r".to_owned(),
            &[endpoint(5, "/ADMIN", false, "INTERNAL"), endpoint(6, "/health", true, "public")],
            &[issue(3, "vulnerability", "critical", false), issue(4, "Secret", "low", false)],
        );
        let ep = graph.nodes.iter().find(|n| n.id == "ep-5").unwrap();
        assert_eq!((ep.severity.as_str(), ep.note), ("CRITICAL", "UNAUTHENTICATED_ROUTE"));
        let public = graph.nodes.iter().find(|n| n.id == "ep-6").unwrap();
        assert_eq!((public.severity.as_str(), public.note), ("MEDIUM", "AUTHENTICATED_PUBLIC_ROUTE"));
        let vuln = graph.nodes.iter().find(|n| n.id == "vuln-3").unwrap();
        assert_eq!(vuln.note, "RCE_EXECUTABLE");
        assert!(vuln.metadata.0.contains(&("epss".to_owned(), "12.35%".to_owned())));
        assert_eq!(
            graph.attack_paths.iter().map(|p| p.scenario).collect::<Vec<_>>(),
            vec!["UNAUTH_RCE_CHAIN", "PLAINTEXT_SECRET"]
        );
        assert!(graph.edges.iter().any(|e| e.id == "edge-ep-5-vuln-3" && e.is_critical_path));
        assert_eq!(graph.nodes.iter().find(|n| n.id == "ep-5").unwrap().label, "GET /ADMIN");
        assert!(graph.edges.iter().any(|e| e.id == "edge-ep-6-vuln-3" && !e.is_critical_path));
        assert!(graph.edges.iter().any(|e| e.id == "edge-vuln-secret-4" && e.source == "vuln-3"));
        // 2 paths × 35 + 1 secret × 25 + 1 vulnerability × 10 + 1 unauthenticated route × 5.
        assert_eq!(graph.risk_score, 100, "capped at 100");
    }

    #[test]
    fn the_worst_ten_are_drawn_and_every_one_scored() {
        let mut issues: Vec<GraphIssue> = (1..=14).map(|id| issue(id, "vulnerability", "high", false)).collect();
        issues.push(issue(99, "vulnerability", "critical", false));
        issues.push(issue(100, "vulnerability", "medium", true));
        issues.push(issue(101, "vulnerability", "medium", false));
        let graph = build_graph(1, "r".to_owned(), &[], &issues);
        let drawn: Vec<&str> =
            graph.nodes.iter().filter(|n| n.type_ == "VULNERABLE_COMPONENT").map(|n| n.id.as_str()).collect();
        assert_eq!(drawn.len(), 10);
        assert_eq!(&drawn[..3], &["vuln-100", "vuln-99", "vuln-1"]);
        assert_eq!(graph.nodes.iter().find(|n| n.id == "vuln-100").unwrap().note, "RCE_ACTIVELY_EXPLOITED");
        assert!(graph.edges.iter().any(|e| e.id == "edge-direct-vuln-1"));
        assert_eq!(graph.risk_score, 30);
    }
}
