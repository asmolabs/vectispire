//! License governance service: compliance policies, license cataloging, risk analysis, and conflicts.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_scanning::views::{ScanFindingView, ScanSbom};
use vectispire_cp_targets::Targets;
use vectispire_domain::list_window::ListWindow;

use crate::component::ComponentOrigin;
use crate::error::InventoryError;
use crate::license::{
    Compatibility, CompatibilityCell, LicenseConflict, LicenseConflictMatrix, LicenseEntry, LicensePolicy,
    LicenseRiskCategory, LicenseSummary, SbomLicences,
};
use crate::persistence::{InventoryRepository, StoreError};

#[derive(Debug, Clone)]
pub struct LicenseGovernanceService {
    db: Db,
    scans: Arc<ScanCatalog>,
    targets: Arc<Targets>,
    audit: Arc<AuditLog>,
}

impl LicenseGovernanceService {
    pub const SCAN_BATCH: usize = 1_000;
    pub const TEXT_MAX: usize = 65_535;

    pub fn new(db: Db, scans: Arc<ScanCatalog>, targets: Arc<Targets>, audit: Arc<AuditLog>) -> Self {
        Self { db, scans, targets, audit }
    }

    pub async fn get_policy(&self) -> Result<LicensePolicy, StoreError> {
        let entity = InventoryRepository::find_license_policy(&self.db).await?;
        Ok(entity.map(Self::to_domain_policy).unwrap_or_else(LicensePolicy::default_policy))
    }

    pub async fn update_policy(
        &self,
        policy: LicensePolicy,
        actor: &RequestActor,
    ) -> Result<LicensePolicy, InventoryError> {
        Self::require_storable(&policy.explicitly_allowed_licenses, "allowed")?;
        Self::require_storable(&policy.explicitly_disallowed_licenses, "disallowed")?;

        let disallowed_cats =
            policy.disallowed_categories.iter().map(|c| c.as_str().to_owned()).collect::<Vec<_>>().join(",");
        let allowed_lics = policy.explicitly_allowed_licenses.iter().cloned().collect::<Vec<_>>().join(",");
        let disallowed_lics = policy.explicitly_disallowed_licenses.iter().cloned().collect::<Vec<_>>().join(",");

        let mut tx = self.db.begin(vectispire_cp_db::Mode::ReadWrite).await.map_err(StoreError::from)?;
        InventoryRepository::upsert_license_policy(
            &mut tx,
            &disallowed_cats,
            if allowed_lics.is_empty() { None } else { Some(&allowed_lics) },
            if disallowed_lics.is_empty() { None } else { Some(&disallowed_lics) },
            // The application's instant, as Java's `clock.instant()`: the database's `now()` is the session's zone.
            time::OffsetDateTime::now_utc(),
        )
        .await?;
        tx.commit().await.map_err(StoreError::from)?;

        let desc =
            format!("Updated open source license compliance policy (disallowed={:?})", policy.disallowed_categories);
        self.audit.record(actor.entry(AuditOperation::SettingUpdated, "license_policy", &desc)).await;

        Ok(policy)
    }

    fn require_storable(licences: &BTreeSet<String>, which: &str) -> Result<(), InventoryError> {
        for lic in licences {
            if lic.contains(',') {
                return Err(InventoryError::invalid(format!(
                    "\"{lic}\" contains a comma: list each {which} licence as an entry of its own."
                )));
            }
        }
        let joined = licences.iter().cloned().collect::<Vec<_>>().join(",");
        if joined.len() > Self::TEXT_MAX {
            return Err(InventoryError::invalid(format!(
                "The {which} licence list is at most {} characters.",
                Self::TEXT_MAX
            )));
        }
        Ok(())
    }

    fn to_domain_policy(entity: crate::persistence::LicensePolicyRow) -> LicensePolicy {
        let mut disallowed = BTreeSet::new();
        for part in entity.disallowed_categories.split(',') {
            let trimmed = part.trim();
            if let Some(cat) = LicenseRiskCategory::parse(trimmed) {
                disallowed.insert(cat);
            } else if !trimmed.is_empty() {
                tracing::warn!(
                    category = trimmed,
                    "Licence policy names an unknown risk category - it forbids nothing."
                );
            }
        }

        let allowed = entity
            .allowed_licenses
            .map(|s| {
                s.split(',').map(|item| item.trim().to_ascii_uppercase()).filter(|item| !item.is_empty()).collect()
            })
            .unwrap_or_default();

        let disallowed_lics = entity
            .disallowed_licenses
            .map(|s| {
                s.split(',').map(|item| item.trim().to_ascii_uppercase()).filter(|item| !item.is_empty()).collect()
            })
            .unwrap_or_default();

        LicensePolicy {
            disallowed_categories: disallowed,
            explicitly_allowed_licenses: allowed,
            explicitly_disallowed_licenses: disallowed_lics,
        }
    }

    pub async fn get_inventory(
        &self,
        allowed: &Visibility,
        repo_id_filter: Option<i64>,
        container_id_filter: Option<i64>,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<LicenseEntry>, InventoryError> {
        Self::require_estate_or_target(allowed, repo_id_filter, container_id_filter)?;
        let window = ListWindow::requested(limit, offset).map_err(InventoryError::invalid)?;
        let inventory = self.get_raw_inventory(allowed, repo_id_filter, container_id_filter).await?;

        if let Some(w) = window {
            let mut sorted = inventory;
            sorted.sort_by(Self::page_order);
            Ok(w.of(&sorted))
        } else {
            Ok(inventory)
        }
    }

    pub async fn get_summary(
        &self,
        allowed: &Visibility,
        repo_id_filter: Option<i64>,
        container_id_filter: Option<i64>,
    ) -> Result<LicenseSummary, InventoryError> {
        Self::require_estate_or_target(allowed, repo_id_filter, container_id_filter)?;
        let inventory = self.get_raw_inventory(allowed, repo_id_filter, container_id_filter).await?;
        Ok(Self::summarize(&inventory))
    }

    pub async fn evaluate_conflicts(
        &self,
        allowed: &Visibility,
        repo_id: Option<i64>,
        container_id: Option<i64>,
        is_proprietary_target: bool,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<LicenseConflict>, InventoryError> {
        Self::require_estate_or_target(allowed, repo_id, container_id)?;
        let window = ListWindow::requested(limit, offset).map_err(InventoryError::invalid)?;
        let inventory = self.get_raw_inventory(allowed, repo_id, container_id).await?;

        if let Some(w) = window {
            let mut sorted = inventory;
            sorted.sort_by(Self::page_order);
            let conflicts = Self::conflicts_of(&sorted, is_proprietary_target);
            Ok(w.of(&conflicts))
        } else {
            Ok(Self::conflicts_of(&inventory, is_proprietary_target))
        }
    }

    pub fn get_compatibility_rules(&self) -> Vec<CompatibilityCell> {
        LicenseConflictMatrix::get_standard_compatibility_rules()
    }

    fn require_estate_or_target(
        allowed: &Visibility,
        repo_id_filter: Option<i64>,
        container_id_filter: Option<i64>,
    ) -> Result<(), InventoryError> {
        if repo_id_filter.is_none() && container_id_filter.is_none() && !matches!(allowed, Visibility::Everything) {
            return Err(InventoryError::not_found("Not found."));
        }
        if let Some(rid) = repo_id_filter {
            vectispire_cp_access::rows::require_visible(ScanTarget::Repository(rid), allowed)?;
        }
        if let Some(cid) = container_id_filter {
            vectispire_cp_access::rows::require_visible(ScanTarget::Container(cid), allowed)?;
        }
        Ok(())
    }

    async fn get_raw_inventory(
        &self,
        allowed: &Visibility,
        repo_id_filter: Option<i64>,
        container_id_filter: Option<i64>,
    ) -> Result<Vec<LicenseEntry>, InventoryError> {
        let selected: Vec<ScanSbom> = if let Some(repo_id) = repo_id_filter {
            self.scans.sboms_of_targets(&[ScanTarget::Repository(repo_id)]).await?
        } else if let Some(container_id) = container_id_filter {
            self.scans.sboms_of_targets(&[ScanTarget::Container(container_id)]).await?
        } else if let Visibility::Only(only) = allowed {
            let targets: Vec<ScanTarget> = only.iter().copied().collect();
            let mut theirs = self.scans.sboms_of_targets(&targets).await?;
            theirs.retain(|s| s.target().is_some_and(|t| allowed.permits(t)));
            theirs
        } else {
            self.scans.sboms().await?
        };

        let reads_sbom = |scan: &ScanSbom| {
            if repo_id_filter.is_none() && container_id_filter.is_some() { scan.repo_id.is_none() } else { true }
        };

        let named_entries = self.named(selected, reads_sbom).await?;
        let filtered = named_entries
            .into_iter()
            .filter(|entry| Self::target_of(entry).is_some_and(|t| allowed.permits(t)))
            .collect();
        Ok(filtered)
    }

    async fn named(
        &self,
        selected: Vec<ScanSbom>,
        reads_sbom: impl Fn(&ScanSbom) -> bool,
    ) -> Result<Vec<LicenseEntry>, InventoryError> {
        let policy = self.get_policy().await?;

        let repos = self
            .targets
            .catalog_repositories()
            .await?
            .into_iter()
            .map(|r| (r.id, r.name.unwrap_or_else(|| format!("repo-{}", r.id))))
            .collect::<HashMap<_, _>>();

        let containers = self
            .targets
            .catalog_containers()
            .await?
            .into_iter()
            .map(|c| (c.id, format!("{}:{}", c.image_name, c.tag)))
            .collect::<HashMap<_, _>>();

        let name_of = |scan: &ScanSbom| -> String {
            if let Some(repo_id) = scan.repo_id
                && let Some(name) = repos.get(&repo_id)
            {
                return name.clone();
            }
            if let Some(container_id) = scan.container_id
                && let Some(name) = containers.get(&container_id)
            {
                return name.clone();
            }
            "General".to_owned()
        };

        self.entries(selected, reads_sbom, &policy, name_of).await
    }

    async fn entries(
        &self,
        selected: Vec<ScanSbom>,
        reads_sbom: impl Fn(&ScanSbom) -> bool,
        policy: &LicensePolicy,
        name_of: impl Fn(&ScanSbom) -> String,
    ) -> Result<Vec<LicenseEntry>, InventoryError> {
        let mut entry_map: HashMap<String, LicenseEntry> = HashMap::new();
        let mut scans_map: BTreeMap<i64, ScanSbom> = BTreeMap::new();
        for scan in selected {
            scans_map.entry(scan.id).or_insert(scan);
        }

        // 1. Ingest real licenses from Scan SBOMs (CycloneDX / Syft)
        for scan in scans_map.values() {
            if !reads_sbom(scan) {
                continue;
            }

            let target_id = scan.repo_id.or(scan.container_id);
            let target_kind = if scan.repo_id.is_some() {
                "repository"
            } else if scan.container_id.is_some() {
                "container"
            } else {
                "general"
            };

            if let Some(ref sbom_str) = scan.sbom
                && !sbom_str.trim().is_empty()
                && let Ok(root) = serde_json::from_str::<serde_json::Value>(sbom_str)
                && let Some(artifacts) = root.get("artifacts").and_then(|a| a.as_array())
            {
                let target_name = name_of(scan);
                for artifact in artifacts {
                    let name = artifact.get("name").and_then(|v| v.as_str());
                    let Some(name_str) = name else { continue };
                    if name_str.trim().is_empty() {
                        continue;
                    }

                    let version = artifact.get("version").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let purl = artifact.get("purl").and_then(|v| v.as_str()).map(|s| s.to_owned());
                    let license = SbomLicences::declared_or_unknown(artifact);
                    let risk = LicenseRiskCategory::classify(&license);
                    let compliant = policy.is_compliant(Some(&license), risk);
                    let violation_reason = if compliant {
                        None
                    } else {
                        Some(format!("License {} is forbidden under active compliance policy ({:?})", license, risk))
                    };

                    let key = format!("{}:{}:{}:{}", target_kind, target_id.unwrap_or(0), name_str, version);

                    entry_map.insert(
                        key,
                        LicenseEntry {
                            package_name: name_str.to_owned(),
                            package_version: version.to_owned(),
                            purl,
                            license,
                            risk_category: risk,
                            compliant,
                            violation_reason,
                            target_id,
                            target_kind: target_kind.to_owned(),
                            target_name: target_name.clone(),
                        },
                    );
                }
            }
        }

        // 2. Check components from Component table
        let scan_ids: Vec<i64> = scans_map.keys().copied().collect();
        let mut components = Vec::new();
        for chunk in scan_ids.chunks(Self::SCAN_BATCH) {
            components.extend(InventoryRepository::find_components_by_scan_ids(&self.db, chunk).await?);
        }

        for comp in components {
            let scan = match scans_map.get(&comp.scan_id) {
                Some(s) => s,
                None => continue,
            };

            let target_id = scan.repo_id.or(scan.container_id);
            let target_kind = if scan.repo_id.is_some() {
                "repository"
            } else if scan.container_id.is_some() {
                "container"
            } else {
                "general"
            };

            let prefix = format!("{}:{}:{}:", target_kind, target_id.unwrap_or(0), comp.name);
            let key = format!("{}{}", prefix, comp.version.as_deref().unwrap_or(""));
            let origin = ComponentOrigin::of_stored(comp.origin.as_deref());

            if origin.from_build() {
                let mut scanned: Option<LicenseEntry> = None;
                if origin == ComponentOrigin::Both {
                    let scanned_key = format!("{}{}", prefix, comp.scanned_version.as_deref().unwrap_or(""));
                    if scanned_key == key {
                        scanned = entry_map.get(&key).cloned();
                    } else {
                        scanned = entry_map.remove(&scanned_key);
                    }
                }

                let license = if let Some(ref decl) = comp.declared_license {
                    if !decl.trim().is_empty() {
                        decl.clone()
                    } else if let Some(ref s) = scanned {
                        s.license.clone()
                    } else if let Some(e) = entry_map.get(&key) {
                        e.license.clone()
                    } else {
                        SbomLicences::UNDECLARED.to_owned()
                    }
                } else if let Some(ref s) = scanned {
                    s.license.clone()
                } else if let Some(e) = entry_map.get(&key) {
                    e.license.clone()
                } else {
                    SbomLicences::UNDECLARED.to_owned()
                };

                let risk = LicenseRiskCategory::classify(&license);
                let compliant = policy.is_compliant(Some(&license), risk);
                let violation_reason = if compliant {
                    None
                } else {
                    Some(format!("License {} is forbidden under active compliance policy ({:?})", license, risk))
                };

                entry_map.insert(
                    key,
                    LicenseEntry {
                        package_name: comp.name,
                        package_version: comp.version.unwrap_or_else(|| "unknown".to_owned()),
                        purl: comp.purl,
                        license,
                        risk_category: risk,
                        compliant,
                        violation_reason,
                        target_id,
                        target_kind: target_kind.to_owned(),
                        target_name: name_of(scan),
                    },
                );
                continue;
            }

            if let std::collections::hash_map::Entry::Vacant(e) = entry_map.entry(key) {
                let inferred = SbomLicences::UNDECLARED.to_owned();
                let risk = LicenseRiskCategory::classify(&inferred);
                let compliant = policy.is_compliant(Some(&inferred), risk);
                let violation_reason = if compliant {
                    None
                } else {
                    Some(format!("License {} is forbidden under active compliance policy ({:?})", inferred, risk))
                };

                e.insert(LicenseEntry {
                    package_name: comp.name,
                    package_version: comp.version.unwrap_or_else(|| "unknown".to_owned()),
                    purl: comp.purl,
                    license: inferred,
                    risk_category: risk,
                    compliant,
                    violation_reason,
                    target_id,
                    target_kind: target_kind.to_owned(),
                    target_name: name_of(scan),
                });
            }
        }

        // 3. Check direct license findings from scanners
        let mut license_findings: Vec<ScanFindingView> = Vec::new();
        if !scan_ids.is_empty() {
            license_findings = self.scans.license_findings(&scan_ids).await?;
            license_findings.sort_by(|a, b| a.scan_id.cmp(&b.scan_id).then_with(|| a.id.cmp(&b.id)));
        }

        for finding in license_findings {
            let scan = match scans_map.get(&finding.scan_id) {
                Some(s) => s,
                None => continue,
            };

            let target_id = scan.repo_id.or(scan.container_id);
            let target_kind = if scan.repo_id.is_some() {
                "repository"
            } else if scan.container_id.is_some() {
                "container"
            } else {
                "general"
            };

            let license = finding.identifier.as_deref().unwrap_or(SbomLicences::UNDECLARED);
            let risk = LicenseRiskCategory::classify(license);
            let compliant = policy.is_compliant(Some(license), risk);
            let violation_reason = if compliant {
                None
            } else {
                Some(format!("License {} is forbidden under active compliance policy ({:?})", license, risk))
            };

            let pkg_name = finding.package_name.as_deref().unwrap_or("unknown");
            let pkg_ver = finding.package_version.as_deref().unwrap_or("");
            let key = format!("{}:{}:{}:{}", target_kind, target_id.unwrap_or(0), pkg_name, pkg_ver);

            entry_map.insert(
                key,
                LicenseEntry {
                    package_name: pkg_name.to_owned(),
                    package_version: if pkg_ver.is_empty() { "unknown".to_owned() } else { pkg_ver.to_owned() },
                    purl: finding.purl,
                    license: license.to_owned(),
                    risk_category: risk,
                    compliant,
                    violation_reason,
                    target_id,
                    target_kind: target_kind.to_owned(),
                    target_name: name_of(scan),
                },
            );
        }

        Ok(entry_map.into_values().collect())
    }

    fn summarize(inventory: &[LicenseEntry]) -> LicenseSummary {
        let mut breakdown: BTreeMap<LicenseRiskCategory, i64> = BTreeMap::new();
        for cat in LicenseRiskCategory::ALL {
            breakdown.insert(cat, 0);
        }

        let mut unique_licenses = BTreeSet::new();
        let mut non_compliant: i64 = 0;

        for entry in inventory {
            let count = breakdown.entry(entry.risk_category).or_insert(0);
            *count = count.saturating_add(1);
            if !entry.license.trim().is_empty() {
                unique_licenses.insert(&entry.license);
            }
            if !entry.compliant {
                non_compliant = non_compliant.saturating_add(1);
            }
        }

        LicenseSummary {
            total_dependencies: i64::try_from(inventory.len()).unwrap_or(0),
            unique_licenses: i64::try_from(unique_licenses.len()).unwrap_or(0),
            non_compliant_count: non_compliant,
            breakdown_by_risk: breakdown,
        }
    }

    fn conflicts_of(inventory: &[LicenseEntry], is_proprietary_target: bool) -> Vec<LicenseConflict> {
        let mut conflicts = Vec::new();
        for entry in inventory {
            let eval = LicenseConflictMatrix::evaluate(
                &entry.package_name,
                &entry.package_version,
                &entry.license,
                &entry.target_kind,
                &entry.target_name,
                is_proprietary_target,
            );
            if eval.compatibility != Compatibility::Compatible {
                conflicts.push(eval);
            }
        }
        conflicts
    }

    fn target_of(entry: &LicenseEntry) -> Option<ScanTarget> {
        let id = entry.target_id?;
        match entry.target_kind.as_str() {
            "repository" => Some(ScanTarget::Repository(id)),
            "container" => Some(ScanTarget::Container(id)),
            _ => None,
        }
    }

    fn page_order(a: &LicenseEntry, b: &LicenseEntry) -> std::cmp::Ordering {
        a.target_kind
            .cmp(&b.target_kind)
            .then_with(|| a.target_id.cmp(&b.target_id))
            .then_with(|| a.package_name.cmp(&b.package_name))
            .then_with(|| a.package_version.cmp(&b.package_version))
            .then_with(|| a.license.cmp(&b.license))
            .then_with(|| a.purl.cmp(&b.purl))
            .then_with(|| a.risk_category.cmp(&b.risk_category))
            .then_with(|| a.compliant.cmp(&b.compliant))
            .then_with(|| a.violation_reason.cmp(&b.violation_reason))
            .then_with(|| a.target_name.cmp(&b.target_name))
    }
}
