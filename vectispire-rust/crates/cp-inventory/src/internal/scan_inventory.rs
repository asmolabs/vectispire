//! Ingestion sink implementation connecting `cp-scanning` to `cp-inventory`.

use std::sync::Arc;

use serde_json::Value;
use vectispire_cp_db::Tx;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_scanning::ingestion::{InventorySink, ScanOrigin};
use vectispire_cp_scanning::ports::PortError;
use vectispire_domain::dependency_graph::DependencyGraph;
use vectispire_protocol::{ApiContract, ApiEndpoint};

use crate::{ApiInventoryService, ComponentInventory};

#[derive(Debug)]
pub struct ScanInventory {
    components: Arc<ComponentInventory>,
    apis: Arc<ApiInventoryService>,
}

impl ScanInventory {
    pub fn new(components: Arc<ComponentInventory>, apis: Arc<ApiInventoryService>) -> Self {
        Self { components, apis }
    }
}

impl InventorySink for ScanInventory {
    fn components<'a>(
        &'a self,
        tx: Option<&'a mut Tx>,
        origin: ScanOrigin,
        sbom: &'a Value,
        _raw_sbom: &'a str,
        graph: &'a DependencyGraph,
    ) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async move {
            self.components.record(tx, origin, sbom, graph).await.map_err(|e| Box::new(e) as PortError)?;
            Ok(())
        })
    }

    fn apis<'a>(
        &'a self,
        _tx: Option<&'a mut Tx>,
        scan_id: i64,
        repo_id: Option<i64>,
        endpoints: Option<&'a [ApiEndpoint]>,
        contracts: Option<&'a [ApiContract]>,
    ) -> BoxFuture<'a, Result<(), PortError>> {
        Box::pin(async move {
            self.apis
                .record(scan_id, repo_id, endpoints.map(|eps| eps.to_vec()), contracts.map(|cs| cs.to_vec()))
                .await
                .map_err(|e| Box::new(e) as PortError)?;
            Ok(())
        })
    }
}
