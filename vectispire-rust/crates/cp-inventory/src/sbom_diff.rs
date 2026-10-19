//! Computes deterministic SBOM and vulnerability diffs between two scans.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use vectispire_cp_access::rows;
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_scanning::views::{ScanFindingView, ScanView};

use crate::diff::{ComponentChangeType, ComponentDelta, CveDelta, CveDeltaStatus, SbomDiffReport};
use crate::error::InventoryError;
use crate::license::SbomLicences;
use crate::persistence::{ComponentRow, InventoryRepository};

#[derive(Debug, Clone)]
pub struct SbomDiffService {
    db: Db,
    scans: Arc<ScanCatalog>,
}

#[derive(Clone, Debug)]
struct ComponentInfo {
    name: String,
    version: Option<String>,
    purl: Option<String>,
    type_: Option<String>,
    is_direct: Option<bool>,
    license: Option<String>,
}

impl SbomDiffService {
    pub fn new(db: Db, scans: Arc<ScanCatalog>) -> Self {
        Self { db, scans }
    }

    pub async fn diff(
        &self,
        from_scan_id: i64,
        to_scan_id: i64,
        allowed: &Visibility,
    ) -> Result<Option<SbomDiffReport>, InventoryError> {
        let from_scan = self.scans.scan(from_scan_id).await?;
        let from_scan = rows::require_visible_scan(from_scan, ScanView::target, allowed)?;

        let to_scan = self.scans.scan(to_scan_id).await?;
        let to_scan = rows::require_visible_scan(to_scan, ScanView::target, allowed)?;

        self.compare(from_scan, to_scan).await
    }

    pub async fn diff_latest_target(
        &self,
        repo_id: Option<i64>,
        container_id: Option<i64>,
        allowed: &Visibility,
    ) -> Result<Option<SbomDiffReport>, InventoryError> {
        let target = if let Some(rid) = repo_id {
            ScanTarget::Repository(rid)
        } else if let Some(cid) = container_id {
            ScanTarget::Container(cid)
        } else {
            return Err(InventoryError::not_found("Target not found."));
        };
        self.diff_latest(target, allowed).await
    }

    pub async fn diff_latest(
        &self,
        target: ScanTarget,
        allowed: &Visibility,
    ) -> Result<Option<SbomDiffReport>, InventoryError> {
        rows::require_visible(target, allowed)?;
        let recent = self.scans.recent_ids(target, 2).await?;

        if let (Some(&second), Some(&first)) = (recent.get(1), recent.first()) {
            let from_scan =
                self.scans.scan(second).await?.ok_or_else(|| InventoryError::not_found("Scan not found."))?;
            let to_scan = self.scans.scan(first).await?.ok_or_else(|| InventoryError::not_found("Scan not found."))?;
            self.compare(from_scan, to_scan).await
        } else if let Some(&only) = recent.first() {
            let scan = self.scans.scan(only).await?.ok_or_else(|| InventoryError::not_found("Scan not found."))?;
            self.compare(scan.clone(), scan).await
        } else {
            Ok(None)
        }
    }

    async fn compare(&self, from_scan: ScanView, to_scan: ScanView) -> Result<Option<SbomDiffReport>, InventoryError> {
        let from_components = self.load_components(&from_scan).await?;
        let to_components = self.load_components(&to_scan).await?;

        let mut all_names = BTreeSet::new();
        for k in from_components.keys() {
            all_names.insert(k.clone());
        }
        for k in to_components.keys() {
            all_names.insert(k.clone());
        }

        let mut component_deltas = Vec::new();
        let mut added: i32 = 0;
        let mut removed: i32 = 0;
        let mut version_changed: i32 = 0;
        let mut license_changed: i32 = 0;

        for name in all_names {
            let old_comp = from_components.get(&name);
            let new_comp = to_components.get(&name);

            match (old_comp, new_comp) {
                (None, Some(new_c)) => {
                    added = added.saturating_add(1);
                    component_deltas.push(ComponentDelta {
                        name: new_c.name.clone(),
                        purl: new_c.purl.clone(),
                        r#type: new_c.type_.clone(),
                        is_direct: new_c.is_direct,
                        previous_version: None,
                        new_version: new_c.version.clone(),
                        previous_license: None,
                        new_license: new_c.license.clone(),
                        change_type: ComponentChangeType::Added,
                    });
                }
                (Some(old_c), None) => {
                    removed = removed.saturating_add(1);
                    component_deltas.push(ComponentDelta {
                        name: old_c.name.clone(),
                        purl: old_c.purl.clone(),
                        r#type: old_c.type_.clone(),
                        is_direct: old_c.is_direct,
                        previous_version: old_c.version.clone(),
                        new_version: None,
                        previous_license: old_c.license.clone(),
                        new_license: None,
                        change_type: ComponentChangeType::Removed,
                    });
                }
                (Some(old_c), Some(new_c)) => {
                    let v_diff = old_c.version != new_c.version;
                    let l_diff = old_c.license != new_c.license;

                    if v_diff {
                        version_changed = version_changed.saturating_add(1);
                        component_deltas.push(ComponentDelta {
                            name: new_c.name.clone(),
                            purl: new_c.purl.clone(),
                            r#type: new_c.type_.clone(),
                            is_direct: new_c.is_direct,
                            previous_version: old_c.version.clone(),
                            new_version: new_c.version.clone(),
                            previous_license: old_c.license.clone(),
                            new_license: new_c.license.clone(),
                            change_type: ComponentChangeType::VersionChanged,
                        });
                    } else if l_diff {
                        license_changed = license_changed.saturating_add(1);
                        component_deltas.push(ComponentDelta {
                            name: new_c.name.clone(),
                            purl: new_c.purl.clone(),
                            r#type: new_c.type_.clone(),
                            is_direct: new_c.is_direct,
                            previous_version: old_c.version.clone(),
                            new_version: new_c.version.clone(),
                            previous_license: old_c.license.clone(),
                            new_license: new_c.license.clone(),
                            change_type: ComponentChangeType::LicenseChanged,
                        });
                    }
                }
                (None, None) => {}
            }
        }

        let cve_deltas = self.compute_cve_deltas(from_scan.id, to_scan.id).await?;
        let introduced_cves =
            i32::try_from(cve_deltas.iter().filter(|c| c.status == CveDeltaStatus::Introduced).count())
                .unwrap_or(i32::MAX);
        let resolved_cves = i32::try_from(cve_deltas.iter().filter(|c| c.status == CveDeltaStatus::Resolved).count())
            .unwrap_or(i32::MAX);

        let from_ver = from_scan.version.unwrap_or_else(|| format!("scan-{}", from_scan.id));
        let to_ver = to_scan.version.unwrap_or_else(|| format!("scan-{}", to_scan.id));

        Ok(Some(SbomDiffReport {
            from_scan_id: from_scan.id,
            to_scan_id: to_scan.id,
            from_version: from_ver,
            to_version: to_ver,
            added,
            removed,
            version_changed,
            license_changed,
            introduced_cves,
            resolved_cves,
            component_deltas,
            cve_deltas,
        }))
    }

    async fn compute_cve_deltas(&self, from_scan_id: i64, to_scan_id: i64) -> Result<Vec<CveDelta>, InventoryError> {
        let is_vuln = |f: &ScanFindingView| {
            f.type_.eq_ignore_ascii_case("vulnerability")
                || f.identifier
                    .as_deref()
                    .map(|id| {
                        id.to_ascii_uppercase().starts_with("CVE-") || id.to_ascii_uppercase().starts_with("GHSA-")
                    })
                    .unwrap_or(false)
        };

        let norm_key = |f: &ScanFindingView| {
            format!("{}:{}", f.identifier.as_deref().unwrap_or(""), f.package_name.as_deref().unwrap_or(""))
        };

        let from_findings = self.scans.findings(from_scan_id).await?;
        let to_findings = self.scans.findings(to_scan_id).await?;

        let mut from_map = HashMap::new();
        for f in from_findings.into_iter().filter(is_vuln) {
            from_map.entry(norm_key(&f)).or_insert(f);
        }

        let mut to_map = HashMap::new();
        for f in to_findings.into_iter().filter(is_vuln) {
            to_map.entry(norm_key(&f)).or_insert(f);
        }

        let mut results = Vec::new();

        for (key, finding) in &to_map {
            let status =
                if from_map.contains_key(key) { CveDeltaStatus::Persistent } else { CveDeltaStatus::Introduced };

            results.push(CveDelta {
                identifier: finding.identifier.clone().unwrap_or_else(|| "UNKNOWN".to_owned()),
                severity: finding.severity.clone(),
                package_name: finding.package_name.clone().or_else(|| finding.file_path.clone()),
                package_version: finding.package_version.clone(),
                status,
            });
        }

        for (key, finding) in &from_map {
            if !to_map.contains_key(key) {
                results.push(CveDelta {
                    identifier: finding.identifier.clone().unwrap_or_else(|| "UNKNOWN".to_owned()),
                    severity: finding.severity.clone(),
                    package_name: finding.package_name.clone().or_else(|| finding.file_path.clone()),
                    package_version: finding.package_version.clone(),
                    status: CveDeltaStatus::Resolved,
                });
            }
        }

        Ok(results)
    }

    async fn load_components(&self, scan: &ScanView) -> Result<HashMap<String, ComponentInfo>, InventoryError> {
        let mut map = HashMap::new();
        let artifacts = self.artifacts(scan.id).await?;

        let rows: Vec<ComponentRow> = InventoryRepository::find_components_by_scan_id(&self.db, scan.id).await?;

        if !rows.is_empty() {
            let mut licenses = HashMap::new();
            for artifact in &artifacts {
                if let Some(name) = artifact.get("name").and_then(|v| v.as_str())
                    && !name.trim().is_empty()
                {
                    let ver = artifact.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    let key = format!("{name}@{ver}");
                    licenses.entry(key).or_insert_with(|| SbomLicences::declared_or_unknown(artifact));
                }
            }

            for row in rows {
                let listed_as = row.scanned_version.as_deref().or(row.version.as_deref()).unwrap_or("");
                let lic_key = format!("{}@{}", row.name, listed_as);
                let license = if let Some(ref decl) = row.declared_license {
                    if !decl.trim().is_empty() {
                        Some(decl.clone())
                    } else {
                        licenses.get(&lic_key).cloned().or_else(|| Some(SbomLicences::UNDECLARED.to_owned()))
                    }
                } else {
                    licenses.get(&lic_key).cloned().or_else(|| Some(SbomLicences::UNDECLARED.to_owned()))
                };

                map.insert(
                    row.name.clone(),
                    ComponentInfo {
                        name: row.name,
                        version: row.version,
                        purl: row.purl,
                        type_: row.type_,
                        is_direct: row.is_direct,
                        license,
                    },
                );
            }
            return Ok(map);
        }

        // Fallback to raw SBOM JSON if t_component was empty
        for artifact in artifacts {
            let name = artifact.get("name").and_then(|v| v.as_str());
            let Some(name_str) = name else { continue };
            if name_str.trim().is_empty() {
                continue;
            }
            let version = artifact.get("version").and_then(|v| v.as_str()).map(|s| s.to_owned());
            let purl = artifact.get("purl").and_then(|v| v.as_str()).map(|s| s.to_owned());
            let type_ = artifact.get("type").and_then(|v| v.as_str()).map(|s| s.to_owned());
            let lic = Some(SbomLicences::declared_or_unknown(&artifact));

            map.insert(
                name_str.to_owned(),
                ComponentInfo { name: name_str.to_owned(), version, purl, type_, is_direct: None, license: lic },
            );
        }

        Ok(map)
    }

    async fn artifacts(&self, scan_id: i64) -> Result<Vec<serde_json::Value>, InventoryError> {
        let sbom_opt = self.scans.sbom(scan_id).await?;
        let Some(sbom) = sbom_opt else {
            return Ok(Vec::new());
        };
        if sbom.trim().is_empty() {
            return Ok(Vec::new());
        }

        let root: serde_json::Value = serde_json::from_str(&sbom).map_err(|e| {
            tracing::warn!(scan_id, error = %e, "SBOM unreadable in diff");
            InventoryError::not_found(format!("Scan {} SBOM unreadable.", scan_id))
        })?;

        let artifacts = root.get("artifacts").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        Ok(artifacts)
    }
}
