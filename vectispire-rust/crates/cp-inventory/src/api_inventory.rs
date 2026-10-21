//! Manages API endpoint inventory, declared contracts, shadow API detection,
//! and synthesized OpenAPI 3.0.3 generation.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::json;
use time::OffsetDateTime;
use vectispire_cp_db::Visibility;
use vectispire_cp_db::{Db, Tx};
use vectispire_protocol::{ApiContract, ApiEndpoint, ApiVisibility};

use crate::api_surface::{
    ApiContractView, AttackSurfaceSummary, EndpointView, GlobalAttackSurface, OperationIds, RepositoryApisOverview,
    ShadowApiDiff, ShadowApiStatus, is_sensitive_path,
};
use crate::error::InventoryError;
use crate::persistence::{
    ApiContractRow, ApiEndpointRow, InventoryRepository, NewApiContract, NewApiEndpoint, StoreError,
};

#[derive(Debug, Clone)]
pub struct ApiInventoryService {
    db: Db,
}

impl ApiInventoryService {
    pub const MAX_PER_REPOSITORY: usize = 1_000;
    pub const LOOKUP_BATCH: usize = 1_000;
    pub const OPERATIONS: [&'static str; 8] = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];
    pub const ANY_METHOD: &'static str = "all";

    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// A scan's API surface, **in the scan's transaction**: written with the findings and the backlog, or rolled back
    /// with them. It opened a transaction of its own and committed it, so a scan whose write failed — or was folded
    /// again after a triage — kept the inventory of a result that was never taken.
    pub async fn record(
        &self,
        tx: &mut Tx,
        scan_id: i64,
        repo_id: Option<i64>,
        mut endpoints_found: Option<Vec<ApiEndpoint>>,
        contracts_found: Option<Vec<ApiContract>>,
    ) -> Result<(), StoreError> {
        if let Some(ref eps) = endpoints_found
            && eps.len() > Self::MAX_PER_REPOSITORY
        {
            tracing::warn!(
                scan_id,
                reported = eps.len(),
                max = Self::MAX_PER_REPOSITORY,
                repo_id = ?repo_id,
                "Scan reported more API endpoints than kept; previous inventory is kept."
            );
            endpoints_found = None;
        }

        if endpoints_found.is_some() {
            if let Some(rid) = repo_id {
                let _ = InventoryRepository::delete_api_endpoints_by_repo_tx(tx, rid).await?;
            }
            let _ = InventoryRepository::delete_api_endpoints_by_scan_id(tx, scan_id).await?;
        }

        if contracts_found.is_some() {
            if let Some(rid) = repo_id {
                let _ = InventoryRepository::delete_api_contracts_by_repo_tx(tx, rid).await?;
            }
            let _ = InventoryRepository::delete_api_contracts_by_scan_id(tx, scan_id).await?;
        }

        let now = OffsetDateTime::now_utc();

        if let Some(endpoints) = endpoints_found
            && !endpoints.is_empty()
        {
            let mut seen = HashSet::new();
            let mut unique: Vec<ApiEndpoint> = Vec::new();
            for ep in endpoints {
                let method = ep.method.as_deref().unwrap_or(Self::ANY_METHOD).to_ascii_uppercase();
                let key = format!("{}:{}", method, ep.path);
                if seen.insert(key) {
                    unique.push(ep);
                }
            }

            let new_endpoints: Vec<NewApiEndpoint> = unique
                .into_iter()
                .map(|ep| NewApiEndpoint {
                    scan_id,
                    repository_id: repo_id,
                    http_method: ep.method.unwrap_or_else(|| Self::ANY_METHOD.to_owned()),
                    path: ep.path,
                    auth_required: ep.auth_required,
                    auth_type: ep.auth_type,
                    visibility: visibility_to_str(ep.visibility).to_owned(),
                    file_path: ep.file_path,
                    line_number: ep.line_number,
                    framework: ep.framework,
                    operation_id: ep.operation_id,
                    summary: ep.summary,
                    tags: ep.tags,
                    created_at: now,
                })
                .collect();

            InventoryRepository::insert_api_endpoints(tx, &new_endpoints).await?;
        }

        if let Some(contracts) = contracts_found
            && !contracts.is_empty()
        {
            let new_contracts: Vec<NewApiContract> = contracts
                .into_iter()
                .map(|c| NewApiContract {
                    repository_id: repo_id.unwrap_or(0),
                    scan_id: Some(scan_id),
                    contract_path: c.contract_path.unwrap_or_default(),
                    format: c.format,
                    title: c.title,
                    version: c.version,
                    endpoints_count: c.endpoints_count,
                    created_at: now,
                })
                .collect();

            InventoryRepository::insert_api_contracts(tx, &new_contracts).await?;
        }

        Ok(())
    }

    pub async fn clear_all(&self) -> Result<(), StoreError> {
        let mut tx = self.db.begin(vectispire_cp_db::Mode::ReadWrite).await.map_err(StoreError::from)?;
        let _ = InventoryRepository::delete_all_api_endpoints(&mut tx).await?;
        let _ = InventoryRepository::delete_all_api_contracts(&mut tx).await?;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(())
    }

    pub async fn clear_for_repository(&self, repo_id: i64, allowed: &Visibility) -> Result<(), InventoryError> {
        vectispire_cp_access::rows::require_visible(vectispire_cp_db::ScanTarget::Repository(repo_id), allowed)?;
        let _ = InventoryRepository::delete_api_endpoints_by_repo(&self.db, repo_id).await?;
        let _ = InventoryRepository::delete_api_contracts_by_repo(&self.db, repo_id).await?;
        Ok(())
    }

    pub async fn for_repository(
        &self,
        repository_id: i64,
        allowed: &Visibility,
    ) -> Result<RepositoryApisOverview, InventoryError> {
        vectispire_cp_access::rows::require_visible(vectispire_cp_db::ScanTarget::Repository(repository_id), allowed)?;
        let raw_endpoints = InventoryRepository::find_api_endpoints_by_repo(&self.db, repository_id).await?;
        let contract_rows = InventoryRepository::find_api_contracts_by_repo(&self.db, repository_id).await?;

        let (views, domain_endpoints, diff) = Self::compute_diff_and_views(&raw_endpoints, &contract_rows);
        let summary = AttackSurfaceSummary::from(&domain_endpoints, Some(&diff));

        let contract_views = contract_rows
            .into_iter()
            .map(|c| ApiContractView {
                id: Some(c.id),
                repository_id: Some(c.repository_id),
                scan_id: c.scan_id,
                contract_path: c.contract_path,
                format: c.format,
                title: c.title,
                version: c.version,
                endpoints_count: c.endpoints_count,
                created_at: c.created_at,
            })
            .collect();

        Ok(RepositoryApisOverview { repository_id, endpoints: views, contracts: contract_views, summary })
    }

    pub async fn global_attack_surface(&self, allowed: &Visibility) -> Result<GlobalAttackSurface, InventoryError> {
        let repo_ids = match allowed {
            Visibility::Everything => None,
            Visibility::Only(targets) => {
                let ids: Vec<i64> = targets
                    .iter()
                    .filter_map(|t| match t {
                        vectispire_cp_db::ScanTarget::Repository(id) => Some(*id),
                        _ => None,
                    })
                    .collect();
                Some(ids)
            }
        };

        let raw_all = if let Some(ref ids) = repo_ids {
            let mut list = Vec::new();
            for chunk in ids.chunks(Self::LOOKUP_BATCH) {
                list.extend(InventoryRepository::find_api_endpoints_by_repos(&self.db, chunk).await?);
            }
            list
        } else {
            InventoryRepository::find_all_api_endpoints(&self.db).await?
        };

        let all_contracts = if let Some(ref ids) = repo_ids {
            let mut list = Vec::new();
            for chunk in ids.chunks(Self::LOOKUP_BATCH) {
                list.extend(InventoryRepository::find_api_contracts_by_repos(&self.db, chunk).await?);
            }
            list
        } else {
            InventoryRepository::find_all_api_contracts(&self.db).await?
        };

        let frameworks = InventoryRepository::find_distinct_frameworks(&self.db).await?;

        // Deduplicate in memory by repositoryId + method + path (keep latest by ID)
        let mut by_repo_method_path: HashMap<String, ApiEndpointRow> = HashMap::new();
        for e in raw_all {
            let key = format!("{}:{}:{}", e.repository_id.unwrap_or(0), e.http_method.to_ascii_uppercase(), e.path);
            by_repo_method_path.insert(key, e);
        }
        let deduped = by_repo_method_path.into_values().collect::<Vec<_>>();

        let (all_views, domain_list, diff) = Self::compute_diff_and_views(&deduped, &all_contracts);
        let summary = AttackSurfaceSummary::from(&domain_list, Some(&diff));

        let mut high_risk = Vec::new();
        for view in &all_views {
            let unauth = !view.auth_required;
            let sensitive = is_sensitive_path(&view.path);
            let pub_vis = view.visibility == "PUBLIC";

            if unauth && (sensitive || pub_vis) {
                let mut hr_view = view.clone();
                hr_view.shadow_status = "HIGH_RISK_EXPOSURE".to_owned();
                high_risk.push(hr_view);
            }
        }

        Ok(GlobalAttackSurface {
            total_endpoints: summary.total_endpoints,
            public_endpoints: summary.public_endpoints,
            internal_endpoints: summary.internal_endpoints,
            unauthenticated_endpoints: summary.unauthenticated_endpoints,
            shadow_endpoints: summary.shadow_endpoints,
            sensitive_unprotected_endpoints: summary.sensitive_unprotected_endpoints,
            frameworks,
            high_risk_endpoints: high_risk,
            all_endpoints: all_views,
        })
    }

    pub async fn export_synthesized_open_api_json(
        &self,
        repository_id: i64,
        allowed: &Visibility,
    ) -> Result<String, InventoryError> {
        vectispire_cp_access::rows::require_visible(vectispire_cp_db::ScanTarget::Repository(repository_id), allowed)?;
        let raw_endpoints = InventoryRepository::find_api_endpoints_by_repo(&self.db, repository_id).await?;

        let mut by_path: BTreeMap<String, HashMap<String, ApiEndpointRow>> = BTreeMap::new();
        let mut sorted = raw_endpoints;
        sorted.sort_by_key(|e| e.id);

        for ep in sorted {
            by_path.entry(ep.path.clone()).or_default().insert(ep.http_method.to_ascii_lowercase(), ep);
        }

        let mut paths_object = serde_json::Map::new();
        let mut operation_ids = OperationIds::new();

        for (path, by_method) in by_path {
            let mut item = serde_json::Map::new();
            let any_method = by_method.get(Self::ANY_METHOD);

            for verb in Self::OPERATIONS {
                let declared = by_method.get(verb);
                let endpoint = declared.or(any_method);
                let Some(ep) = endpoint else { continue };

                let summary = if let Some(ref s) = ep.summary {
                    if declared.is_some() { s.clone() } else { format!("{s} (any method)") }
                } else if let Some(ref fp) = ep.file_path {
                    let base = format!("Discovered in {fp}");
                    if declared.is_some() { base } else { format!("{base} (any method)") }
                } else if declared.is_some() {
                    "Discovered endpoint".to_owned()
                } else {
                    "Discovered endpoint (any method)".to_owned()
                };

                let op_id = Self::unique_operation_id(ep, verb, &path, declared.is_none(), &mut operation_ids);

                item.insert(
                    verb.to_owned(),
                    json!({
                        "summary": summary,
                        "operationId": op_id,
                        "responses": {
                            "200": {
                                "description": "OK response"
                            }
                        }
                    }),
                );
            }

            if !item.is_empty() {
                paths_object.insert(path, serde_json::Value::Object(item));
            }
        }

        let document = json!({
            "openapi": "3.0.3",
            "info": {
                "title": "Vectispire Synthesized API Inventory",
                "version": "1.0.0",
                "description": "Automatically generated by Vectispire Attack Surface Discovery"
            },
            "paths": paths_object
        });

        serde_json::to_string_pretty(&document).map_err(|e| InventoryError::Unexpected(Box::new(e)))
    }

    fn unique_operation_id(
        endpoint: &ApiEndpointRow,
        verb: &str,
        path: &str,
        any_method: bool,
        taken: &mut OperationIds,
    ) -> String {
        let base = if let Some(ref op_id) = endpoint.operation_id {
            if any_method { format!("{op_id}_{verb}") } else { op_id.clone() }
        } else {
            let sanitized = path.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect::<String>();
            format!("{verb}_{sanitized}")
        };

        taken.claim(&base)
    }

    fn compute_diff_and_views(
        raw_endpoints: &[ApiEndpointRow],
        contract_rows: &[ApiContractRow],
    ) -> (Vec<EndpointView>, Vec<ApiEndpoint>, ShadowApiDiff) {
        let mut by_method_path: HashMap<String, ApiEndpointRow> = HashMap::new();
        for e in raw_endpoints {
            by_method_path.insert(format!("{}:{}", e.http_method.to_ascii_uppercase(), e.path), e.clone());
        }
        let endpoints = by_method_path.into_values().collect::<Vec<_>>();

        let domain_endpoints: Vec<ApiEndpoint> = endpoints
            .iter()
            .map(|e| ApiEndpoint {
                method: Some(e.http_method.clone()),
                path: e.path.clone(),
                auth_required: e.auth_required,
                auth_type: e.auth_type.clone(),
                visibility: parse_visibility(&e.visibility),
                file_path: e.file_path.clone(),
                line_number: e.line_number,
                framework: e.framework.clone(),
                operation_id: e.operation_id.clone(),
                summary: e.summary.clone(),
                tags: e.tags.clone(),
            })
            .collect();

        let domain_contracts: Vec<ApiContract> = contract_rows
            .iter()
            .map(|c| ApiContract {
                contract_path: Some(c.contract_path.clone()),
                format: c.format.clone(),
                title: c.title.clone(),
                version: c.version.clone(),
                endpoints_count: c.endpoints_count,
                declared_paths: Default::default(),
            })
            .collect();

        let diff = ShadowApiDiff::compute(&domain_endpoints, &domain_contracts);
        let shadow_path_methods: HashSet<String> = diff
            .shadow_endpoints
            .iter()
            .map(|se| format!("{}:{}", se.method.as_deref().unwrap_or(Self::ANY_METHOD).to_ascii_uppercase(), se.path))
            .collect();

        let mut views = Vec::new();
        for e in &endpoints {
            let key = format!("{}:{}", e.http_method.to_ascii_uppercase(), e.path);
            let status = if contract_rows.is_empty() {
                ShadowApiStatus::Undocumented.as_str()
            } else if shadow_path_methods.contains(&key) {
                ShadowApiStatus::ShadowApi.as_str()
            } else {
                ShadowApiStatus::Documented.as_str()
            };

            views.push(EndpointView {
                id: Some(e.id),
                scan_id: Some(e.scan_id),
                repository_id: e.repository_id,
                method: e.http_method.clone(),
                path: e.path.clone(),
                auth_required: e.auth_required,
                auth_type: e.auth_type.clone(),
                visibility: e.visibility.clone(),
                file_path: e.file_path.clone(),
                line_number: e.line_number,
                framework: e.framework.clone(),
                operation_id: e.operation_id.clone(),
                summary: e.summary.clone(),
                tags: e.tags.clone(),
                shadow_status: status.to_owned(),
                created_at: e.created_at,
            });
        }

        (views, domain_endpoints, diff)
    }
}

fn parse_visibility(s: &str) -> ApiVisibility {
    match s {
        "PUBLIC" => ApiVisibility::Public,
        "INTERNAL" => ApiVisibility::Internal,
        _ => ApiVisibility::Unknown,
    }
}

fn visibility_to_str(v: ApiVisibility) -> &'static str {
    match v {
        ApiVisibility::Public => "PUBLIC",
        ApiVisibility::Internal => "INTERNAL",
        ApiVisibility::Unknown => "UNKNOWN",
    }
}
