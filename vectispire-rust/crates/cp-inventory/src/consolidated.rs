//! Project consolidated SBOM (Decision 0023).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use time::OffsetDateTime;
use vectispire_cp_access::rows::{ScopeKind, VisibleScope};
use vectispire_cp_db::{Db, ScanTarget};
use vectispire_cp_scanning::ScanCatalog;

use crate::component::ComponentOrigin;
use crate::component_catalog::ComponentCatalog;
use crate::persistence::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InventoryState {
    Listed,
    Empty,
    Absent,
    #[serde(rename = "never_scanned")]
    NeverScanned,
}

impl InventoryState {
    pub fn is_known(&self) -> bool {
        matches!(self, InventoryState::Listed | InventoryState::Empty)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentTarget {
    pub kind: String,
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetInventory {
    pub kind: String,
    pub id: i64,
    pub name: String,
    #[serde(rename = "scanId")]
    pub scan_id: Option<i64>,
    #[serde(rename = "scannedAt", with = "time::serde::rfc3339::option")]
    pub scanned_at: Option<OffsetDateTime>,
    pub inventory: InventoryState,
    #[serde(rename = "componentCount")]
    pub component_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergedComponent {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub r#type: Option<String>,
    pub targets: Vec<ComponentTarget>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsolidatedInventory {
    pub kind: String,
    pub id: i64,
    pub name: String,
    pub partial: bool,
    pub complete: bool,
    pub targets: Vec<TargetInventory>,
    pub components: Vec<MergedComponent>,
}

#[derive(Debug, Clone)]
pub struct ConsolidatedInventoryService {
    db: Db,
    scans: Arc<ScanCatalog>,
    components: Arc<ComponentCatalog>,
}

impl ConsolidatedInventoryService {
    pub fn new(db: Db, scans: Arc<ScanCatalog>, components: Arc<ComponentCatalog>) -> Self {
        Self { db, scans, components }
    }

    pub async fn of(&self, scope: &VisibleScope) -> Result<ConsolidatedInventory, StoreError> {
        let targets = &scope.visible;
        let newest_map = self.scans.newest_completed(targets).await.map_err(|e| StoreError::Other(e.to_string()))?;

        let scan_ids: Vec<i64> = newest_map.values().map(|r| r.scan_id).collect();
        let by_scan = self.components.components_of(&scan_ids).await?;

        let mut repos = BTreeSet::new();
        let mut containers = BTreeSet::new();
        for t in targets {
            match t {
                ScanTarget::Repository(id) => {
                    repos.insert(*id);
                }
                ScanTarget::Container(id) => {
                    containers.insert(*id);
                }
            }
        }

        let names = vectispire_cp_targets::naming::for_ids(&self.db, &repos, &containers)
            .await
            .map_err(|e| StoreError::Message(e.to_string()))?;

        let mut read_targets = Vec::new();
        let mut merged: HashMap<Key, Merging> = HashMap::new();
        let mut keys_in_order = Vec::new();

        for target in targets {
            let (kind, id) = match target {
                ScanTarget::Repository(id) => ("repository", *id),
                ScanTarget::Container(id) => ("container", *id),
            };
            let target_name = names.of(
                if kind == "repository" { Some(id) } else { None },
                if kind == "container" { Some(id) } else { None },
            );
            let comp_target = ComponentTarget { kind: kind.to_owned(), id, name: target_name.clone() };

            let scan_row = newest_map.get(target);
            let (scan_id, scanned_at, state, count) = match scan_row {
                None => (None, None, InventoryState::NeverScanned, 0),
                Some(s) => {
                    let listed = by_scan.get(&s.scan_id).map(|v| v.as_slice()).unwrap_or(&[]);
                    let state = if !listed.is_empty() {
                        InventoryState::Listed
                    } else if s.sbom_stored {
                        InventoryState::Empty
                    } else {
                        InventoryState::Absent
                    };

                    for comp in listed {
                        let key = Key::of(comp.purl.as_deref(), &comp.name, comp.version.as_deref());
                        let entry = merged.entry(key.clone()).or_insert_with(|| {
                            keys_in_order.push(key);
                            Merging {
                                name: comp.name.clone(),
                                version: comp.version.clone(),
                                purl: comp.purl.clone(),
                                type_: comp.r#type.clone(),
                                targets: Vec::new(),
                                from_build: false,
                                from_scanner: false,
                            }
                        });
                        entry.add_target(&comp_target, comp.origin);
                    }

                    (Some(s.scan_id), Some(s.created_at), state, listed.len())
                }
            };

            read_targets.push(TargetInventory {
                kind: kind.to_owned(),
                id,
                name: target_name,
                scan_id,
                scanned_at,
                inventory: state,
                component_count: count,
            });
        }

        let mut merge: Vec<MergedComponent> = merged.into_values().map(|m| m.done()).collect();
        merge.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then_with(|| a.version.cmp(&b.version))
                .then_with(|| a.purl.cmp(&b.purl))
        });

        let complete = read_targets.iter().all(|t| t.inventory.is_known());

        let kind_str = match scope.kind {
            ScopeKind::Project => "project",
            ScopeKind::Solution => "solution",
        };

        Ok(ConsolidatedInventory {
            kind: kind_str.to_owned(),
            id: scope.id,
            name: scope.name.clone(),
            partial: scope.partial,
            complete,
            targets: read_targets,
            components: merge,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    identity: String,
    version: Option<String>,
}

impl Key {
    fn of(purl: Option<&str>, name: &str, version: Option<&str>) -> Self {
        let identity = match purl {
            Some(p) if !p.trim().is_empty() => format!("purl:{p}"),
            _ => format!("name:{name}"),
        };
        Self { identity, version: version.map(|v| v.to_owned()) }
    }
}

struct Merging {
    name: String,
    version: Option<String>,
    purl: Option<String>,
    type_: Option<String>,
    targets: Vec<ComponentTarget>,
    from_build: bool,
    from_scanner: bool,
}

impl Merging {
    fn add_target(&mut self, target: &ComponentTarget, origin: ComponentOrigin) {
        if !self.targets.iter().any(|t| t == target) {
            self.targets.push(target.clone());
        }
        if origin.from_build() {
            self.from_build = true;
        }
        if origin != ComponentOrigin::Build {
            self.from_scanner = true;
        }
    }

    fn done(self) -> MergedComponent {
        let mut sources = Vec::new();
        if self.from_build {
            sources.push("build".to_owned());
        }
        if self.from_scanner {
            sources.push("scanner".to_owned());
        }
        MergedComponent {
            name: self.name,
            version: self.version,
            purl: self.purl,
            r#type: self.type_,
            targets: self.targets,
            sources,
        }
    }
}
