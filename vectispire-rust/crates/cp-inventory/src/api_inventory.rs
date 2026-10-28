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
            let unique = latest_in_place(endpoints, |ep| {
                format!("{}:{}", ep.method.as_deref().unwrap_or(Self::ANY_METHOD).to_uppercase(), ep.path)
            });

            let new_endpoints: Vec<NewApiEndpoint> = unique
                .into_iter()
                .map(|ep| NewApiEndpoint {
                    scan_id,
                    repository_id: repo_id,
                    http_method: fit(ep.method.as_deref().unwrap_or(Self::ANY_METHOD), 20),
                    path: fit(&ep.path, 1000),
                    auth_required: ep.auth_required,
                    auth_type: fit_optional(ep.auth_type.as_deref(), 50),
                    visibility: visibility_to_str(ep.visibility).to_owned(),
                    file_path: fit_optional(ep.file_path.as_deref(), 1000),
                    line_number: ep.line_number,
                    framework: fit_optional(ep.framework.as_deref(), 50),
                    operation_id: fit_optional(ep.operation_id.as_deref(), 255),
                    summary: fit_optional(ep.summary.as_deref(), 500),
                    tags: fit_optional(ep.tags.as_deref(), 255),
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
                    contract_path: fit(c.contract_path.as_deref().unwrap_or_default(), 1000),
                    format: fit_optional(c.format.as_deref(), 50),
                    title: fit_optional(c.title.as_deref(), 255),
                    version: fit_optional(c.version.as_deref(), 50),
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

        let endpoints = latest_in_place(raw_endpoints, |e| format!("{}:{}", e.http_method.to_uppercase(), e.path));
        let (views, domain_endpoints, diff) = Self::compute_diff_and_views(&endpoints, &contract_rows);
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

        // By repository, method and path: one route in two repositories is two routes of the estate.
        let deduped = latest_in_place(raw_all, |e| {
            format!("{}:{}:{}", e.repository_id.unwrap_or(0), e.http_method.to_uppercase(), e.path)
        });

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

    /// The views of endpoints de-duplicated by the caller — by method and path for one repository, by repository too
    /// for the estate. It de-duplicated by method and path itself, so the estate's view merged the same route of two
    /// repositories into one, and every figure of the global attack surface counted it once.
    fn compute_diff_and_views(
        endpoints: &[ApiEndpointRow],
        contract_rows: &[ApiContractRow],
    ) -> (Vec<EndpointView>, Vec<ApiEndpoint>, ShadowApiDiff) {
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
        for e in endpoints {
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

/// Java's `LinkedHashMap.put` over `items`: one per key, the **last** written, in the place the key **first** took.
///
/// What every de-duplication of endpoints here does on the Java side. The ones it replaced kept the first (a scan's
/// own endpoints) or went through a `HashMap`, whose order is drawn afresh in every process — the same repository's
/// view came back in a different order from one call to the next.
fn latest_in_place<T, K: std::hash::Hash + Eq>(items: impl IntoIterator<Item = T>, key: impl Fn(&T) -> K) -> Vec<T> {
    let mut place: HashMap<K, usize> = HashMap::new();
    let mut kept: Vec<T> = Vec::new();
    for item in items {
        match place.entry(key(&item)) {
            std::collections::hash_map::Entry::Occupied(at) => {
                if let Some(slot) = kept.get_mut(*at.get()) {
                    *slot = item;
                }
            }
            std::collections::hash_map::Entry::Vacant(at) => {
                at.insert(kept.len());
                kept.push(item);
            }
        }
    }
    kept
}

/// Java's `trim(value, max)` before an endpoint or a contract is saved: a field a scanner reported longer than its
/// column is cut, not refused. Unbounded, one over-long path failed the scan's whole write on PostgreSQL (and on MySQL
/// in strict mode).
fn fit(value: &str, max: usize) -> String {
    vectispire_domain::bounded_text::clip(Some(value), max).unwrap_or_default().to_owned()
}

fn fit_optional(value: Option<&str>, max: usize) -> Option<String> {
    vectispire_domain::bounded_text::clip(value, max).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LinkedHashMap.put`: one per key, the last written, where the key first stood.
    #[test]
    fn a_duplicate_keeps_its_place_and_takes_the_last_value() {
        let kept = latest_in_place([("GET /a", 1), ("POST /b", 2), ("GET /a", 3), ("PUT /c", 4)], |(key, _)| *key);
        assert_eq!(kept, vec![("GET /a", 3), ("POST /b", 2), ("PUT /c", 4)]);
    }

    /// Java's `trim(value, max)` before the insert: cut to the column, never refused.
    #[test]
    fn a_field_longer_than_its_column_is_cut() {
        assert_eq!(fit(&"p".repeat(1_001), 1_000).len(), 1_000);
        assert_eq!(fit("/short", 1_000), "/short");
        assert_eq!(fit_optional(Some(&"s".repeat(501)), 500).map(|kept| kept.len()), Some(500));
        assert_eq!(fit_optional(None, 500), None);
    }
}
