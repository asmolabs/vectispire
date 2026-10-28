//! Read catalogue of components for given scans.

use std::collections::HashMap;
use vectispire_cp_db::Db;

use crate::component::ComponentOrigin;
use crate::persistence::{InventoryRepository, StoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogComponent {
    pub scan_id: i64,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub r#type: Option<String>,
    pub origin: ComponentOrigin,
}

#[derive(Debug, Clone)]
pub struct ComponentCatalog {
    db: Db,
}

impl ComponentCatalog {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn components_of(&self, scan_ids: &[i64]) -> Result<HashMap<i64, Vec<CatalogComponent>>, StoreError> {
        let rows = InventoryRepository::find_components_by_scan_ids(&self.db, scan_ids).await?;
        let mut by_scan: HashMap<i64, Vec<CatalogComponent>> = HashMap::new();
        for r in rows {
            by_scan.entry(r.scan_id).or_default().push(CatalogComponent {
                scan_id: r.scan_id,
                name: r.name,
                version: r.version,
                purl: r.purl,
                r#type: r.type_,
                origin: ComponentOrigin::of_stored(r.origin.as_deref()),
            });
        }
        Ok(by_scan)
    }
}
