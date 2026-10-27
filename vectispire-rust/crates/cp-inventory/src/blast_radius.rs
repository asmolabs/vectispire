//! Builds organizational dependency graphs and calculates vulnerability blast radius across repositories and containers.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use vectispire_cp_db::Visibility;
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_scanning::views::{FindingOnScan, ScanFindingView, ScanView};
use vectispire_cp_targets::Targets;
use vectispire_cp_targets::views::{ContainerView, RepositoryView};

use crate::blast_radius_graph::{
    BlastDependencyGraph, BlastRadiusReport, GraphEdge, GraphNode, TargetImpact, TopImpactPackage, extract_ecosystem,
};
use crate::error::InventoryError;

#[derive(Debug, Clone)]
pub struct BlastRadiusService {
    targets: Arc<Targets>,
    findings_repo: Arc<ScanCatalog>,
}

impl BlastRadiusService {
    pub fn new(targets: Arc<Targets>, findings_repo: Arc<ScanCatalog>) -> Self {
        Self { targets, findings_repo }
    }

    pub async fn explore(
        &self,
        raw_query: Option<&str>,
        allowed: &Visibility,
    ) -> Result<BlastRadiusReport, InventoryError> {
        // Java's `BoundedText.search(rawQuery, "q")`: blank is the whole graph, past 500 characters a 400 rather than a
        // search of the estate for it.
        let query =
            vectispire_domain::bounded_text::optional(raw_query, vectispire_domain::bounded_text::SEARCH_MAX, "q")
                .map_err(|refused| InventoryError::invalid(refused.0))?
                .unwrap_or_default();
        let is_cve_query = query.to_uppercase().starts_with("CVE-");

        let rows = self.findings_repo.findings_for_graph(&query, is_cve_query, true, allowed).await?;

        let repos_map = self.named_repositories(&rows).await?;
        let containers_map = self.named_containers(&rows).await?;

        let mut targets_list = Vec::new();
        let mut nodes = FirstSeen::default();
        let mut edges = Vec::new();

        let mut direct_count: i32 = 0;
        let mut transitive_count: i32 = 0;
        let mut unique_cves = HashSet::new();
        let mut max_cvss = 0.0f64;

        let mut findings_by_scan: BTreeMap<i64, (ScanView, Vec<ScanFindingView>)> = BTreeMap::new();
        for row in rows {
            let entry = findings_by_scan.entry(row.scan.id).or_insert_with(|| (row.scan, Vec::new()));
            entry.1.push(row.finding);
        }

        for (_, (scan, scan_findings)) in findings_by_scan {
            let target_kind = if scan.repo_id.is_some() { "REPOSITORY" } else { "CONTAINER" };
            let target_id = scan.repo_id.or(scan.container_id);
            let Some(tid) = target_id else { continue };

            // Java's: the repository's own name — absent when it has none, never one made up — the image as
            // `name:tag`, and `target-<id>` only for a target the lookup did not find.
            let target_name = match (scan.repo_id, scan.container_id) {
                (Some(repo_id), _) if repos_map.contains_key(&repo_id) => {
                    repos_map.get(&repo_id).and_then(|r| r.name.clone())
                }
                (None, Some(container_id)) if containers_map.contains_key(&container_id) => {
                    containers_map.get(&container_id).map(|c| format!("{}:{}", c.image_name, c.tag))
                }
                _ => Some(format!("target-{tid}")),
            };

            let target_context = if scan.repo_id.is_some() {
                scan.branch.clone()
            } else if let Some(container_id) = scan.container_id {
                containers_map.get(&container_id).map(|c| c.tag.clone()).unwrap_or_else(|| "latest".to_owned())
            } else {
                "latest".to_owned()
            };

            let target_node_id = format!("target-{}-{}", target_kind.to_ascii_lowercase(), tid);

            for finding in scan_findings {
                let pkg_name = finding.package_name.as_deref().unwrap_or("unknown");
                let cve_id = finding.identifier.as_deref();

                let is_direct = finding.is_direct_dependency.unwrap_or(false);
                if is_direct {
                    direct_count = direct_count.saturating_add(1);
                } else {
                    transitive_count = transitive_count.saturating_add(1);
                }

                if let Some(cve) = cve_id
                    && cve.to_ascii_uppercase().starts_with("CVE-")
                {
                    unique_cves.insert(cve.to_owned());
                }

                if let Some(score) = finding.cvss_score
                    && score > max_cvss
                {
                    max_cvss = score;
                }

                let source_file = if let Some(ref path) = finding.file_path {
                    if !path.trim().is_empty() {
                        path.clone()
                    } else if let Some(ref purl) = finding.purl {
                        extract_ecosystem(Some(purl.as_str()))
                    } else {
                        "manifest".to_owned()
                    }
                } else if let Some(ref purl) = finding.purl {
                    extract_ecosystem(Some(purl.as_str()))
                } else {
                    "manifest".to_owned()
                };

                let cves_for_finding = match cve_id {
                    Some(cve) if cve.to_ascii_uppercase().starts_with("CVE-") => {
                        vec![cve.to_owned()]
                    }
                    _ => Vec::new(),
                };

                let pkg_ver = finding.package_version.as_deref().unwrap_or("latest").to_owned();

                targets_list.push(TargetImpact {
                    target_id: Some(tid),
                    target_kind: target_kind.to_owned(),
                    target_name: target_name.clone(),
                    target_context: target_context.clone(),
                    source_file,
                    purl: finding.purl.clone(),
                    package_name: pkg_name.to_owned(),
                    package_version: pkg_ver.clone(),
                    is_direct,
                    cves: cves_for_finding.clone(),
                    scan_id: Some(scan.id),
                });

                // Target Node
                nodes.put_if_absent(target_node_id.clone(), || GraphNode {
                    id: target_node_id.clone(),
                    label: target_name.clone(),
                    r#type: "TARGET".to_owned(),
                    version: Some(if scan.branch.is_empty() { "main".to_owned() } else { scan.branch.clone() }),
                    ecosystem: Some(target_kind.to_owned()),
                    score: 0,
                    is_direct,
                    cves: Vec::new(),
                });

                // Package Node
                let pkg_node_id = format!("pkg-{}@{}", pkg_name, pkg_ver);
                let score_int =
                    finding.cvss_score.and_then(|cvss| format!("{:.0}", cvss * 10.0).parse::<i32>().ok()).unwrap_or(0);

                nodes.put_if_absent(pkg_node_id.clone(), || GraphNode {
                    id: pkg_node_id.clone(),
                    label: Some(pkg_name.to_owned()),
                    r#type: "PACKAGE".to_owned(),
                    version: Some(pkg_ver.clone()),
                    ecosystem: Some(extract_ecosystem(finding.purl.as_deref())),
                    score: score_int,
                    is_direct,
                    cves: cves_for_finding.clone(),
                });

                // Edge Target -> Package
                edges.push(GraphEdge {
                    source: target_node_id.clone(),
                    target: pkg_node_id.clone(),
                    relationship: if is_direct {
                        "DIRECT_DEPENDENCY".to_owned()
                    } else {
                        "TRANSITIVE_DEPENDENCY".to_owned()
                    },
                });

                // Add CVE Node if present
                if let Some(cve) = cve_id
                    && cve.to_ascii_uppercase().starts_with("CVE-")
                {
                    let cve_node_id = format!("cve-{}", cve);
                    let cve_score = finding
                        .cvss_score
                        .and_then(|cvss| format!("{:.0}", cvss * 10.0).parse::<i32>().ok())
                        .unwrap_or(50);

                    nodes.put_if_absent(cve_node_id.clone(), || GraphNode {
                        id: cve_node_id.clone(),
                        label: Some(cve.to_owned()),
                        r#type: "CVE".to_owned(),
                        version: None,
                        ecosystem: None,
                        score: cve_score,
                        is_direct,
                        cves: vec![cve.to_owned()],
                    });

                    edges.push(GraphEdge {
                        source: pkg_node_id,
                        target: cve_node_id,
                        relationship: "AFFECTED_BY".to_owned(),
                    });
                }
            }
        }

        let unique_targets_count = i32::try_from(
            targets_list.iter().map(|t| format!("{}:{:?}", t.target_kind, t.target_id)).collect::<HashSet<_>>().len(),
        )
        .unwrap_or(0);

        let score = BlastRadiusReport::calculate_score(
            unique_targets_count,
            direct_count,
            transitive_count,
            i32::try_from(unique_cves.len()).unwrap_or(0),
            max_cvss,
        );

        Ok(BlastRadiusReport {
            query,
            query_type: if is_cve_query { "CVE".to_owned() } else { "PACKAGE".to_owned() },
            total_targets_affected: unique_targets_count,
            direct_usages: direct_count,
            transitive_usages: transitive_count,
            total_associated_cves: i32::try_from(unique_cves.len()).unwrap_or(0),
            blast_radius_score: score,
            targets: targets_list,
            graph: BlastDependencyGraph { nodes: nodes.nodes, edges },
        })
    }

    pub async fn get_top_impact_packages(
        &self,
        limit: usize,
        allowed: &Visibility,
    ) -> Result<Vec<TopImpactPackage>, InventoryError> {
        let impacts = self.findings_repo.package_impacts(allowed).await?;
        let mut packages = impacts
            .into_iter()
            .map(|impact| {
                let max_cvss = impact.max_cvss.unwrap_or(0.0);
                let direct = i32::try_from(impact.direct_usages).unwrap_or(0);
                let transitive = i32::try_from(impact.transitive_usages).unwrap_or(0);
                let targets = i32::try_from(impact.distinct_targets()).unwrap_or(0);
                let cves = i32::try_from(impact.distinct_cves).unwrap_or(0);

                TopImpactPackage {
                    package_name: impact.package_name,
                    ecosystem: extract_ecosystem(impact.any_purl.as_deref()),
                    affected_targets_count: targets,
                    direct_usages: direct,
                    transitive_usages: transitive,
                    total_cves: cves,
                    max_cvss,
                    blast_radius_score: BlastRadiusReport::calculate_score(targets, direct, transitive, cves, max_cvss),
                }
            })
            .collect::<Vec<_>>();

        packages.sort_by_key(|a| std::cmp::Reverse(a.blast_radius_score));
        let take_limit = if limit > 0 { limit } else { 10 };
        packages.truncate(take_limit);

        Ok(packages)
    }

    async fn named_repositories(&self, rows: &[FindingOnScan]) -> Result<HashMap<i64, RepositoryView>, InventoryError> {
        let ids: BTreeSet<i64> = rows.iter().filter_map(|r| r.scan.repo_id).collect();
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let repos = self.targets.catalog_repositories_by_ids(&ids).await?;
        Ok(repos.into_iter().map(|r| (r.id, r)).collect())
    }

    async fn named_containers(&self, rows: &[FindingOnScan]) -> Result<HashMap<i64, ContainerView>, InventoryError> {
        let ids: BTreeSet<i64> = rows.iter().filter_map(|r| r.scan.container_id).collect();
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let containers = self.targets.catalog_containers_by_ids(&ids).await?;
        Ok(containers.into_iter().map(|c| (c.id, c)).collect())
    }
}

/// Java's `nodesMap.putIfAbsent`, in the order the nodes were first met — where a `HashMap`'s values came out in an
/// order drawn afresh in every process, so one graph was drawn differently from one call to the next.
#[derive(Default)]
struct FirstSeen {
    seen: HashSet<String>,
    nodes: Vec<GraphNode>,
}

impl FirstSeen {
    fn put_if_absent(&mut self, id: String, node: impl FnOnce() -> GraphNode) {
        if self.seen.insert(id) {
            self.nodes.push(node());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, score: i32) -> GraphNode {
        GraphNode {
            id: id.into(),
            label: None,
            r#type: "PACKAGE".into(),
            version: None,
            ecosystem: None,
            score,
            is_direct: false,
            cves: Vec::new(),
        }
    }

    /// `putIfAbsent`, in the order first met: the first node of an id is kept, and the order does not move between
    /// two calls the way a `HashMap`'s did.
    #[test]
    fn the_graph_keeps_its_nodes_in_the_order_they_were_met() {
        let mut nodes = FirstSeen::default();
        for (id, score) in [("target-1", 1), ("pkg-b", 2), ("pkg-a", 3), ("target-1", 9)] {
            nodes.put_if_absent(id.to_owned(), || node(id, score));
        }
        let read: Vec<(String, i32)> = nodes.nodes.into_iter().map(|node| (node.id, node.score)).collect();
        assert_eq!(read, vec![("target-1".into(), 1), ("pkg-b".into(), 2), ("pkg-a".into(), 3)]);
    }

    /// Java's `GraphNode.riskScore`, and a target with no name labelled `null`.
    #[test]
    fn a_node_goes_out_under_java_s_names() {
        let json = serde_json::to_value(node("target-1", 50)).unwrap();
        assert_eq!(json["riskScore"], 50);
        assert!(json.get("score").is_none());
        assert!(json["label"].is_null());
    }
}
