//! Queries on `t_scan` and `t_finding` for `ScanCatalog` (inventory, blast radius, license governance).

use std::collections::{BTreeMap, HashMap};

use sqlx::{AssertSqlSafe, Row};
use time::OffsetDateTime;
use vectispire_cp_db::types::UtcInstant;
use vectispire_cp_db::{ScanTarget, Tx, Visibility};

use super::{LatestRow, ScanRow, StoreError};

/// A finding of one scan, as persistence records it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanFindingView {
    pub id: i64,
    pub scan_id: i64,
    pub type_: String,
    pub severity: Option<String>,
    pub identifier: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
    pub file_path: Option<String>,
    pub owasp_category: Option<String>,
    pub source: Option<String>,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
    pub epss_score: Option<f64>,
    pub is_kev: bool,
    pub created_at: OffsetDateTime,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fix_state: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
    pub issue_id: Option<i64>,
    pub is_direct_dependency: Option<bool>,
    pub line: Option<i32>,
    pub description: Option<String>,
}

/// A finding and the scan row it was produced in.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingOnScanRow {
    pub finding: ScanFindingView,
    pub scan: ScanRow,
}

/// A scan's identifier, its targets and its SBOM, and nothing else of the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSbom {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub sbom: Option<String>,
}

impl ScanSbom {
    pub fn target(&self) -> Option<ScanTarget> {
        match (self.repo_id, self.container_id) {
            (Some(id), _) => Some(ScanTarget::Repository(id)),
            (None, Some(id)) => Some(ScanTarget::Container(id)),
            (None, None) => None,
        }
    }
}

/// A target's newest completed scan, with whether it still holds its SBOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewestCompletedScanRow {
    pub repository_id: Option<i64>,
    pub container_id: Option<i64>,
    pub scan_id: i64,
    pub created_at: OffsetDateTime,
    pub sbom_stored: bool,
}

impl NewestCompletedScanRow {
    pub fn target(&self) -> Option<ScanTarget> {
        match (self.repository_id, self.container_id) {
            (Some(id), _) => Some(ScanTarget::Repository(id)),
            (None, Some(id)) => Some(ScanTarget::Container(id)),
            (None, None) => None,
        }
    }
}

/// What one package amounts to across everything the caller may see.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageImpact {
    pub package_name: String,
    pub any_purl: Option<String>,
    pub distinct_repositories: i64,
    pub distinct_containers: i64,
    pub direct_usages: i64,
    pub transitive_usages: i64,
    pub distinct_cves: i64,
    pub max_cvss: Option<f64>,
}

impl PackageImpact {
    pub fn distinct_targets(&self) -> i64 {
        self.distinct_repositories.saturating_add(self.distinct_containers)
    }
}

macro_rules! parse_finding {
    ($r:ident) => {{
        let created_at: UtcInstant = $r.get("created_at");
        let is_kev = match $r.try_get::<bool, _>("is_kev") {
            Ok(v) => v,
            Err(_) => match $r.try_get::<i8, _>("is_kev") {
                Ok(i) => i != 0,
                _ => false,
            },
        };
        let is_direct_dependency = match $r.try_get::<Option<bool>, _>("is_direct_dependency") {
            Ok(v) => v,
            Err(_) => match $r.try_get::<Option<i8>, _>("is_direct_dependency") {
                Ok(Some(i)) => Some(i != 0),
                _ => None,
            },
        };
        ScanFindingView {
            id: $r.get("id"),
            scan_id: $r.get("scan_id"),
            type_: $r.get("type"),
            severity: $r.get("severity"),
            identifier: $r.get("identifier"),
            package_name: $r.get("package_name"),
            package_version: $r.get("package_version"),
            purl: $r.get("purl"),
            file_path: $r.get("file_path"),
            owasp_category: $r.get("owasp_category"),
            source: $r.get("source"),
            tool: $r.get("tool"),
            tool_name: $r.get("tool_name"),
            tool_version: $r.get("tool_version"),
            epss_score: $r.get("epss_score"),
            is_kev,
            created_at: created_at.0,
            cvss_score: $r.get("cvss_score"),
            cvss_vector: $r.get("cvss_vector"),
            fix_state: $r.get("fix_state"),
            fix_versions: $r.get("fix_versions"),
            link: $r.get("link"),
            issue_id: $r.get("issue_id"),
            is_direct_dependency,
            line: $r.get("line"),
            description: $r.get("description"),
        }
    }};
}

macro_rules! parse_scan_from_prefix {
    ($r:ident) => {{
        let s_created_at: UtcInstant = $r.get("s_created_at");
        let s_claimed_at: Option<UtcInstant> = $r.get("s_claimed_at");
        let s_lease_expires_at: Option<UtcInstant> = $r.get("s_lease_expires_at");
        let s_not_before: Option<UtcInstant> = $r.get("s_not_before");
        let s_has_sbom = match $r.try_get::<bool, _>("s_has_sbom") {
            Ok(v) => v,
            Err(_) => match $r.try_get::<i64, _>("s_has_sbom") {
                Ok(i) => i != 0,
                Err(_) => match $r.try_get::<i32, _>("s_has_sbom") {
                    Ok(i) => i != 0,
                    _ => false,
                },
            },
        };
        ScanRow {
            id: $r.get("s_id"),
            branch: $r.get("s_branch"),
            sub_path: $r.get("s_sub_path"),
            status: $r.get("s_status"),
            duration_ms: $r.get("s_duration_ms"),
            findings_count: $r.get("s_findings_count"),
            new_issues_count: $r.get("s_new_issues_count"),
            resolved_issues_count: $r.get("s_resolved_issues_count"),
            error: $r.get("s_error"),
            created_at: s_created_at.0,
            version: $r.get("s_version"),
            project_type: $r.get("s_project_type"),
            repo_id: $r.get("s_repo_id"),
            container_id: $r.get("s_container_id"),
            required_agent_label: $r.get("s_required_agent_label"),
            claimed_by: $r.get("s_claimed_by"),
            claimed_at: s_claimed_at.map(|u| u.0),
            lease_expires_at: s_lease_expires_at.map(|u| u.0),
            attempts: $r.get("s_attempts"),
            not_before: s_not_before.map(|u| u.0),
            plugin_steps: $r.get("s_plugin_steps"),
            examined_types: $r.get("s_examined_types"),
            detected_languages: $r.get("s_detected_languages"),
            sast_languages: $r.get("s_sast_languages"),
            has_sbom: s_has_sbom,
        }
    }};
}

pub async fn sboms_of_all(tx: &mut Tx) -> Result<Vec<ScanSbom>, StoreError> {
    let sql = "select id, repo_id, container_id, sbom from t_scan where sbom is not null";
    match tx {
        Tx::MySql(conn) => {
            let rows = sqlx::query(sql).fetch_all(&mut **conn).await?;
            Ok(rows
                .into_iter()
                .map(|r| ScanSbom {
                    id: r.get("id"),
                    repo_id: r.get("repo_id"),
                    container_id: r.get("container_id"),
                    sbom: r.get("sbom"),
                })
                .collect())
        }
        Tx::PostgreSql(conn) => {
            let rows = sqlx::query(sql).fetch_all(&mut **conn).await?;
            Ok(rows
                .into_iter()
                .map(|r| ScanSbom {
                    id: r.get("id"),
                    repo_id: r.get("repo_id"),
                    container_id: r.get("container_id"),
                    sbom: r.get("sbom"),
                })
                .collect())
        }
    }
}

pub async fn sboms_of_untargeted(tx: &mut Tx) -> Result<Vec<ScanSbom>, StoreError> {
    let sql = "select id, repo_id, container_id, sbom from t_scan where repo_id is null and container_id is null and sbom is not null";
    match tx {
        Tx::MySql(conn) => {
            let rows = sqlx::query(sql).fetch_all(&mut **conn).await?;
            Ok(rows
                .into_iter()
                .map(|r| ScanSbom {
                    id: r.get("id"),
                    repo_id: r.get("repo_id"),
                    container_id: r.get("container_id"),
                    sbom: r.get("sbom"),
                })
                .collect())
        }
        Tx::PostgreSql(conn) => {
            let rows = sqlx::query(sql).fetch_all(&mut **conn).await?;
            Ok(rows
                .into_iter()
                .map(|r| ScanSbom {
                    id: r.get("id"),
                    repo_id: r.get("repo_id"),
                    container_id: r.get("container_id"),
                    sbom: r.get("sbom"),
                })
                .collect())
        }
    }
}

pub async fn sboms_of_targets(tx: &mut Tx, targets: &[ScanTarget]) -> Result<Vec<ScanSbom>, StoreError> {
    let mut repos = Vec::new();
    let mut containers = Vec::new();
    for target in targets {
        match target {
            ScanTarget::Repository(id) => repos.push(*id),
            ScanTarget::Container(id) => containers.push(*id),
        }
    }
    repos.sort_unstable();
    repos.dedup();
    containers.sort_unstable();
    containers.dedup();

    let mut result_map: HashMap<i64, ScanSbom> = HashMap::new();

    const BATCH: usize = 1_000;
    for chunk in repos.chunks(BATCH) {
        match tx {
            Tx::MySql(conn) => {
                let placeholders = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "select id, repo_id, container_id, sbom from t_scan where repo_id in ({placeholders}) and sbom is not null"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in rows {
                    let sbom = ScanSbom {
                        id: r.get("id"),
                        repo_id: r.get("repo_id"),
                        container_id: r.get("container_id"),
                        sbom: r.get("sbom"),
                    };
                    result_map.entry(sbom.id).or_insert(sbom);
                }
            }
            Tx::PostgreSql(conn) => {
                let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "select id, repo_id, container_id, sbom from t_scan where repo_id in ({placeholders}) and sbom is not null"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in rows {
                    let sbom = ScanSbom {
                        id: r.get("id"),
                        repo_id: r.get("repo_id"),
                        container_id: r.get("container_id"),
                        sbom: r.get("sbom"),
                    };
                    result_map.entry(sbom.id).or_insert(sbom);
                }
            }
        }
    }

    for chunk in containers.chunks(BATCH) {
        match tx {
            Tx::MySql(conn) => {
                let placeholders = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "select id, repo_id, container_id, sbom from t_scan where container_id in ({placeholders}) and sbom is not null"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in rows {
                    let sbom = ScanSbom {
                        id: r.get("id"),
                        repo_id: r.get("repo_id"),
                        container_id: r.get("container_id"),
                        sbom: r.get("sbom"),
                    };
                    result_map.entry(sbom.id).or_insert(sbom);
                }
            }
            Tx::PostgreSql(conn) => {
                let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "select id, repo_id, container_id, sbom from t_scan where container_id in ({placeholders}) and sbom is not null"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in rows {
                    let sbom = ScanSbom {
                        id: r.get("id"),
                        repo_id: r.get("repo_id"),
                        container_id: r.get("container_id"),
                        sbom: r.get("sbom"),
                    };
                    result_map.entry(sbom.id).or_insert(sbom);
                }
            }
        }
    }

    Ok(result_map.into_values().collect())
}

pub async fn newest_completed(
    tx: &mut Tx,
    targets: &[ScanTarget],
) -> Result<BTreeMap<ScanTarget, NewestCompletedScanRow>, StoreError> {
    let mut repos = Vec::new();
    let mut containers = Vec::new();
    for target in targets {
        match target {
            ScanTarget::Repository(id) => repos.push(*id),
            ScanTarget::Container(id) => containers.push(*id),
        }
    }
    repos.sort_unstable();
    repos.dedup();
    containers.sort_unstable();
    containers.dedup();

    let mut result = BTreeMap::new();
    const BATCH: usize = 1_000;

    for chunk in repos.chunks(BATCH) {
        match tx {
            Tx::MySql(conn) => {
                let placeholders = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "select s.repo_id, s.container_id, s.id, s.created_at, (case when s.sbom is null then 0 else 1 end) as sbom_stored \
                     from t_scan s \
                     where s.repo_id in ({placeholders}) \
                       and s.id = (select max(l.id) from t_scan l where l.repo_id = s.repo_id and l.status = 'completed')"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in rows {
                    let created_at: UtcInstant = r.get("created_at");
                    let sbom_stored = match r.try_get::<bool, _>("sbom_stored") {
                        Ok(v) => v,
                        Err(_) => match r.try_get::<i64, _>("sbom_stored") {
                            Ok(i) => i != 0,
                            _ => false,
                        },
                    };
                    let row = NewestCompletedScanRow {
                        repository_id: r.get("repo_id"),
                        container_id: r.get("container_id"),
                        scan_id: r.get("id"),
                        created_at: created_at.0,
                        sbom_stored,
                    };
                    if let Some(target) = row.target() {
                        result.insert(target, row);
                    }
                }
            }
            Tx::PostgreSql(conn) => {
                let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "select s.repo_id, s.container_id, s.id, s.created_at, (case when s.sbom is null then false else true end) as sbom_stored \
                     from t_scan s \
                     where s.repo_id in ({placeholders}) \
                       and s.id = (select max(l.id) from t_scan l where l.repo_id = s.repo_id and l.status = 'completed')"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in rows {
                    let created_at: UtcInstant = r.get("created_at");
                    let sbom_stored = match r.try_get::<bool, _>("sbom_stored") {
                        Ok(v) => v,
                        Err(_) => match r.try_get::<i64, _>("sbom_stored") {
                            Ok(i) => i != 0,
                            _ => false,
                        },
                    };
                    let row = NewestCompletedScanRow {
                        repository_id: r.get("repo_id"),
                        container_id: r.get("container_id"),
                        scan_id: r.get("id"),
                        created_at: created_at.0,
                        sbom_stored,
                    };
                    if let Some(target) = row.target() {
                        result.insert(target, row);
                    }
                }
            }
        }
    }

    for chunk in containers.chunks(BATCH) {
        match tx {
            Tx::MySql(conn) => {
                let placeholders = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "select s.repo_id, s.container_id, s.id, s.created_at, (case when s.sbom is null then 0 else 1 end) as sbom_stored \
                     from t_scan s \
                     where s.container_id in ({placeholders}) \
                       and s.id = (select max(l.id) from t_scan l where l.container_id = s.container_id and l.status = 'completed')"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in rows {
                    let created_at: UtcInstant = r.get("created_at");
                    let sbom_stored = match r.try_get::<bool, _>("sbom_stored") {
                        Ok(v) => v,
                        Err(_) => match r.try_get::<i64, _>("sbom_stored") {
                            Ok(i) => i != 0,
                            _ => false,
                        },
                    };
                    let row = NewestCompletedScanRow {
                        repository_id: r.get("repo_id"),
                        container_id: r.get("container_id"),
                        scan_id: r.get("id"),
                        created_at: created_at.0,
                        sbom_stored,
                    };
                    if let Some(target) = row.target() {
                        result.insert(target, row);
                    }
                }
            }
            Tx::PostgreSql(conn) => {
                let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "select s.repo_id, s.container_id, s.id, s.created_at, (case when s.sbom is null then false else true end) as sbom_stored \
                     from t_scan s \
                     where s.container_id in ({placeholders}) \
                       and s.id = (select max(l.id) from t_scan l where l.container_id = s.container_id and l.status = 'completed')"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in rows {
                    let created_at: UtcInstant = r.get("created_at");
                    let sbom_stored = match r.try_get::<bool, _>("sbom_stored") {
                        Ok(v) => v,
                        Err(_) => match r.try_get::<i64, _>("sbom_stored") {
                            Ok(i) => i != 0,
                            _ => false,
                        },
                    };
                    let row = NewestCompletedScanRow {
                        repository_id: r.get("repo_id"),
                        container_id: r.get("container_id"),
                        scan_id: r.get("id"),
                        created_at: created_at.0,
                        sbom_stored,
                    };
                    if let Some(target) = row.target() {
                        result.insert(target, row);
                    }
                }
            }
        }
    }

    Ok(result)
}

pub async fn recent_ids(tx: &mut Tx, target: ScanTarget, limit: usize) -> Result<Vec<i64>, StoreError> {
    let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
    let target_id = match target {
        ScanTarget::Repository(id) | ScanTarget::Container(id) => id,
    };
    match tx {
        Tx::MySql(conn) => {
            let sql = match target {
                ScanTarget::Repository(_) => "select id from t_scan where repo_id = ? order by id desc limit ?",
                ScanTarget::Container(_) => "select id from t_scan where container_id = ? order by id desc limit ?",
            };
            let rows = sqlx::query(sql).bind(target_id).bind(limit_i64).fetch_all(&mut **conn).await?;
            Ok(rows.into_iter().map(|r| r.get("id")).collect())
        }
        Tx::PostgreSql(conn) => {
            let sql = match target {
                ScanTarget::Repository(_) => "select id from t_scan where repo_id = $1 order by id desc limit $2",
                ScanTarget::Container(_) => "select id from t_scan where container_id = $1 order by id desc limit $2",
            };
            let rows = sqlx::query(sql).bind(target_id).bind(limit_i64).fetch_all(&mut **conn).await?;
            Ok(rows.into_iter().map(|r| r.get("id")).collect())
        }
    }
}

pub async fn findings(tx: &mut Tx, scan_id: i64) -> Result<Vec<ScanFindingView>, StoreError> {
    let sql = match tx {
        Tx::MySql(_) => {
            "select id, scan_id, type, severity, identifier, package_name, package_version, purl, file_path, owasp_category, source, tool, tool_name, tool_version, epss_score, is_kev, created_at, cvss_score, cvss_vector, fix_state, fix_versions, link, issue_id, is_direct_dependency, line, description from t_finding where scan_id = ? order by id"
        }
        Tx::PostgreSql(_) => {
            "select id, scan_id, type, severity, identifier, package_name, package_version, purl, file_path, owasp_category, source, tool, tool_name, tool_version, epss_score, is_kev, created_at, cvss_score, cvss_vector, fix_state, fix_versions, link, issue_id, is_direct_dependency, line, description from t_finding where scan_id = $1 order by id"
        }
    };
    match tx {
        Tx::MySql(conn) => {
            let rows = sqlx::query(sql).bind(scan_id).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_finding!(r)).collect())
        }
        Tx::PostgreSql(conn) => {
            let rows = sqlx::query(sql).bind(scan_id).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_finding!(r)).collect())
        }
    }
}

pub async fn license_findings(tx: &mut Tx, scan_ids: &[i64]) -> Result<Vec<ScanFindingView>, StoreError> {
    if scan_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut distinct = scan_ids.to_vec();
    distinct.sort_unstable();
    distinct.dedup();

    let mut found = Vec::new();
    const BATCH: usize = 1_000;
    for chunk in distinct.chunks(BATCH) {
        match tx {
            Tx::MySql(conn) => {
                let placeholders = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "select id, scan_id, type, severity, identifier, package_name, package_version, purl, file_path, owasp_category, source, tool, tool_name, tool_version, epss_score, is_kev, created_at, cvss_score, cvss_vector, fix_state, fix_versions, link, issue_id, is_direct_dependency, line, description from t_finding where scan_id in ({placeholders}) and lower(type) = 'license' order by id"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in &rows {
                    found.push(parse_finding!(r));
                }
            }
            Tx::PostgreSql(conn) => {
                let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "select id, scan_id, type, severity, identifier, package_name, package_version, purl, file_path, owasp_category, source, tool, tool_name, tool_version, epss_score, is_kev, created_at, cvss_score, cvss_vector, fix_state, fix_versions, link, issue_id, is_direct_dependency, line, description from t_finding where scan_id in ({placeholders}) and lower(type) = 'license' order by id"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                for r in &rows {
                    found.push(parse_finding!(r));
                }
            }
        }
    }
    Ok(found)
}

pub async fn package_impacts(tx: &mut Tx, allowed: &Visibility) -> Result<Vec<PackageImpact>, StoreError> {
    if allowed.is_empty() {
        return Ok(Vec::new());
    }

    let (repo_ids, container_ids) = match allowed {
        Visibility::Everything => (None, None),
        Visibility::Only(targets) => {
            let mut repos = Vec::new();
            let mut containers = Vec::new();
            for target in targets {
                match target {
                    ScanTarget::Repository(id) => repos.push(*id),
                    ScanTarget::Container(id) => containers.push(*id),
                }
            }
            if repos.is_empty() && containers.is_empty() {
                return Ok(Vec::new());
            }
            (Some(repos), Some(containers))
        }
    };

    match tx {
        Tx::MySql(conn) => {
            let mut vis_clause = String::new();
            let mut binds: Vec<i64> = Vec::new();
            if let (Some(r), Some(c)) = (&repo_ids, &container_ids) {
                let mut parts = Vec::new();
                if !r.is_empty() {
                    let ph = vec!["?"; r.len()].join(",");
                    parts.push(format!("s.repo_id in ({ph})"));
                    binds.extend(r);
                }
                if !c.is_empty() {
                    let ph = vec!["?"; c.len()].join(",");
                    parts.push(format!("(s.repo_id is null and s.container_id in ({ph}))"));
                    binds.extend(c);
                }
                if !parts.is_empty() {
                    vis_clause = format!(" and ({})", parts.join(" or "));
                }
            }

            let sql = format!(
                "select f.package_name, \
                        min(f.purl) as any_purl, \
                        count(distinct s.repo_id) as repos, \
                        count(distinct case when s.repo_id is null then s.container_id else null end) as containers, \
                        sum(case when f.is_direct_dependency = 1 or f.is_direct_dependency = true then 1 else 0 end) as direct, \
                        count(f.id) as total, \
                        count(distinct case when lower(f.identifier) like 'cve-%' then f.identifier else null end) as cves, \
                        max(f.cvss_score) as cvss \
                 from t_finding f \
                 join t_scan s on f.scan_id = s.id \
                 where f.package_name is not null and trim(f.package_name) != '' {vis_clause} \
                 group by f.package_name"
            );

            let mut q = sqlx::query(AssertSqlSafe(sql));
            for b in binds {
                q = q.bind(b);
            }
            let rows = q.fetch_all(&mut **conn).await?;

            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let total: i64 = match r.try_get::<i64, _>("total") {
                    Ok(v) => v,
                    Err(_) => i64::from(r.get::<i32, _>("total")),
                };
                let direct: i64 = match r.try_get::<Option<i64>, _>("direct") {
                    Ok(Some(v)) => v,
                    _ => match r.try_get::<Option<f64>, _>("direct") {
                        #[allow(clippy::cast_possible_truncation)]
                        Ok(Some(v)) => v as i64,
                        _ => match r.try_get::<Option<i32>, _>("direct") {
                            Ok(Some(v)) => i64::from(v),
                            _ => 0,
                        },
                    },
                };
                let repos: i64 = match r.try_get::<i64, _>("repos") {
                    Ok(v) => v,
                    Err(_) => i64::from(r.get::<i32, _>("repos")),
                };
                let containers: i64 = match r.try_get::<i64, _>("containers") {
                    Ok(v) => v,
                    Err(_) => i64::from(r.get::<i32, _>("containers")),
                };
                let cves: i64 = match r.try_get::<i64, _>("cves") {
                    Ok(v) => v,
                    Err(_) => i64::from(r.get::<i32, _>("cves")),
                };
                let cvss: Option<f64> = r.get("cvss");
                out.push(PackageImpact {
                    package_name: r.get("package_name"),
                    any_purl: r.get("any_purl"),
                    distinct_repositories: repos,
                    distinct_containers: containers,
                    direct_usages: direct,
                    transitive_usages: total.saturating_sub(direct),
                    distinct_cves: cves,
                    max_cvss: cvss,
                });
            }
            Ok(out)
        }
        Tx::PostgreSql(conn) => {
            let mut vis_clause = String::new();
            let mut binds: Vec<i64> = Vec::new();
            let mut p_idx: usize = 1;
            if let (Some(r), Some(c)) = (&repo_ids, &container_ids) {
                let mut parts = Vec::new();
                if !r.is_empty() {
                    let ph =
                        (p_idx..p_idx.saturating_add(r.len())).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    p_idx = p_idx.saturating_add(r.len());
                    parts.push(format!("s.repo_id in ({ph})"));
                    binds.extend(r);
                }
                if !c.is_empty() {
                    let ph =
                        (p_idx..p_idx.saturating_add(c.len())).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    parts.push(format!("(s.repo_id is null and s.container_id in ({ph}))"));
                    binds.extend(c);
                }
                if !parts.is_empty() {
                    vis_clause = format!(" and ({})", parts.join(" or "));
                }
            }

            let sql = format!(
                "select f.package_name, \
                        min(f.purl) as any_purl, \
                        count(distinct s.repo_id) as repos, \
                        count(distinct case when s.repo_id is null then s.container_id else null end) as containers, \
                        sum(case when f.is_direct_dependency = true then 1 else 0 end) as direct, \
                        count(f.id) as total, \
                        count(distinct case when lower(f.identifier) like 'cve-%' then f.identifier else null end) as cves, \
                        max(f.cvss_score) as cvss \
                 from t_finding f \
                 join t_scan s on f.scan_id = s.id \
                 where f.package_name is not null and trim(f.package_name) != '' {vis_clause} \
                 group by f.package_name"
            );

            let mut q = sqlx::query(AssertSqlSafe(sql));
            for b in binds {
                q = q.bind(b);
            }
            let rows = q.fetch_all(&mut **conn).await?;

            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let total: i64 = match r.try_get::<i64, _>("total") {
                    Ok(v) => v,
                    Err(_) => i64::from(r.get::<i32, _>("total")),
                };
                let direct: i64 = match r.try_get::<Option<i64>, _>("direct") {
                    Ok(Some(v)) => v,
                    _ => match r.try_get::<Option<f64>, _>("direct") {
                        #[allow(clippy::cast_possible_truncation)]
                        Ok(Some(v)) => v as i64,
                        _ => match r.try_get::<Option<i32>, _>("direct") {
                            Ok(Some(v)) => i64::from(v),
                            _ => 0,
                        },
                    },
                };
                let repos: i64 = match r.try_get::<i64, _>("repos") {
                    Ok(v) => v,
                    Err(_) => i64::from(r.get::<i32, _>("repos")),
                };
                let containers: i64 = match r.try_get::<i64, _>("containers") {
                    Ok(v) => v,
                    Err(_) => i64::from(r.get::<i32, _>("containers")),
                };
                let cves: i64 = match r.try_get::<i64, _>("cves") {
                    Ok(v) => v,
                    Err(_) => i64::from(r.get::<i32, _>("cves")),
                };
                let cvss: Option<f64> = r.get("cvss");
                out.push(PackageImpact {
                    package_name: r.get("package_name"),
                    any_purl: r.get("any_purl"),
                    distinct_repositories: repos,
                    distinct_containers: containers,
                    direct_usages: direct,
                    transitive_usages: total.saturating_sub(direct),
                    distinct_cves: cves,
                    max_cvss: cvss,
                });
            }
            Ok(out)
        }
    }
}

pub async fn findings_for_graph(
    tx: &mut Tx,
    query: &str,
    is_cve_query: bool,
    exclude_secrets: bool,
    allowed: &Visibility,
) -> Result<Vec<FindingOnScanRow>, StoreError> {
    if allowed.is_empty() {
        return Ok(Vec::new());
    }

    let (repo_ids, container_ids) = match allowed {
        Visibility::Everything => (None, None),
        Visibility::Only(targets) => {
            let mut repos = Vec::new();
            let mut containers = Vec::new();
            for target in targets {
                match target {
                    ScanTarget::Repository(id) => repos.push(*id),
                    ScanTarget::Container(id) => containers.push(*id),
                }
            }
            if repos.is_empty() && containers.is_empty() {
                return Ok(Vec::new());
            }
            (Some(repos), Some(containers))
        }
    };

    let trimmed = query.trim();
    let has_query = !trimmed.is_empty();

    let scan_cols = "s.id as s_id, s.branch as s_branch, s.sub_path as s_sub_path, s.status as s_status, \
                     s.duration_ms as s_duration_ms, s.findings_count as s_findings_count, \
                     s.new_issues_count as s_new_issues_count, s.resolved_issues_count as s_resolved_issues_count, \
                     s.error as s_error, s.created_at as s_created_at, s.version as s_version, \
                     s.project_type as s_project_type, s.repo_id as s_repo_id, s.container_id as s_container_id, \
                     s.required_agent_label as s_required_agent_label, s.claimed_by as s_claimed_by, \
                     s.claimed_at as s_claimed_at, s.lease_expires_at as s_lease_expires_at, \
                     s.attempts as s_attempts, s.not_before as s_not_before, s.plugin_steps as s_plugin_steps, \
                     s.examined_types as s_examined_types, s.detected_languages as s_detected_languages, \
                     s.sast_languages as s_sast_languages, (case when s.sbom is null then 0 else 1 end) as s_has_sbom";

    let finding_cols = "f.id, f.scan_id, f.type, f.severity, f.identifier, f.package_name, f.package_version, \
                        f.purl, f.file_path, f.owasp_category, f.source, f.tool, f.tool_name, f.tool_version, \
                        f.epss_score, f.is_kev, f.created_at, f.cvss_score, f.cvss_vector, f.fix_state, \
                        f.fix_versions, f.link, f.issue_id, f.is_direct_dependency, f.line, f.description";

    match tx {
        Tx::MySql(conn) => {
            let mut conditions = vec!["f.package_name is not null and trim(f.package_name) != ''".to_string()];
            if exclude_secrets {
                conditions.push("(f.type is null or lower(f.type) != 'secret')".to_string());
            }

            let mut str_binds: Vec<String> = Vec::new();
            if has_query {
                if is_cve_query {
                    conditions.push("lower(f.identifier) = ?".to_string());
                    str_binds.push(trimmed.to_lowercase());
                } else {
                    conditions.push("(lower(f.package_name) like ? or lower(f.purl) like ?)".to_string());
                    let pat = format!("%{}%", trimmed.to_lowercase());
                    str_binds.push(pat.clone());
                    str_binds.push(pat);
                }
            }

            let mut num_binds: Vec<i64> = Vec::new();
            if let (Some(r), Some(c)) = (&repo_ids, &container_ids) {
                let mut parts = Vec::new();
                if !r.is_empty() {
                    let ph = vec!["?"; r.len()].join(",");
                    parts.push(format!("s.repo_id in ({ph})"));
                    num_binds.extend(r);
                }
                if !c.is_empty() {
                    let ph = vec!["?"; c.len()].join(",");
                    parts.push(format!("(s.repo_id is null and s.container_id in ({ph}))"));
                    num_binds.extend(c);
                }
                if !parts.is_empty() {
                    conditions.push(format!("({})", parts.join(" or ")));
                }
            }

            let where_sql = conditions.join(" and ");
            let sql = format!(
                "select {finding_cols}, {scan_cols} \
                 from t_finding f \
                 join t_scan s on f.scan_id = s.id \
                 where {where_sql} \
                 order by f.id"
            );

            let mut q = sqlx::query(AssertSqlSafe(sql));
            for s in str_binds {
                q = q.bind(s);
            }
            for n in num_binds {
                q = q.bind(n);
            }
            let rows = q.fetch_all(&mut **conn).await?;

            let mut out = Vec::with_capacity(rows.len());
            for r in &rows {
                let finding = parse_finding!(r);
                let scan = parse_scan_from_prefix!(r);
                out.push(FindingOnScanRow { finding, scan });
            }
            Ok(out)
        }
        Tx::PostgreSql(conn) => {
            let mut conditions = vec!["f.package_name is not null and trim(f.package_name) != ''".to_string()];
            if exclude_secrets {
                conditions.push("(f.type is null or lower(f.type) != 'secret')".to_string());
            }

            let mut p_idx: usize = 1;
            let mut str_binds: Vec<String> = Vec::new();
            if has_query {
                if is_cve_query {
                    conditions.push(format!("lower(f.identifier) = ${p_idx}"));
                    p_idx = p_idx.saturating_add(1);
                    str_binds.push(trimmed.to_lowercase());
                } else {
                    let next_p = p_idx.saturating_add(1);
                    conditions.push(format!("(lower(f.package_name) like ${p_idx} or lower(f.purl) like ${next_p})"));
                    p_idx = p_idx.saturating_add(2);
                    let pat = format!("%{}%", trimmed.to_lowercase());
                    str_binds.push(pat.clone());
                    str_binds.push(pat);
                }
            }

            let mut num_binds: Vec<i64> = Vec::new();
            if let (Some(r), Some(c)) = (&repo_ids, &container_ids) {
                let mut parts = Vec::new();
                if !r.is_empty() {
                    let ph =
                        (p_idx..p_idx.saturating_add(r.len())).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    p_idx = p_idx.saturating_add(r.len());
                    parts.push(format!("s.repo_id in ({ph})"));
                    num_binds.extend(r);
                }
                if !c.is_empty() {
                    let ph =
                        (p_idx..p_idx.saturating_add(c.len())).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    parts.push(format!("(s.repo_id is null and s.container_id in ({ph}))"));
                    num_binds.extend(c);
                }
                if !parts.is_empty() {
                    conditions.push(format!("({})", parts.join(" or ")));
                }
            }

            let where_sql = conditions.join(" and ");
            let sql = format!(
                "select {finding_cols}, {scan_cols} \
                 from t_finding f \
                 join t_scan s on f.scan_id = s.id \
                 where {where_sql} \
                 order by f.id"
            );

            let mut q = sqlx::query(AssertSqlSafe(sql));
            for s in str_binds {
                q = q.bind(s);
            }
            for n in num_binds {
                q = q.bind(n);
            }
            let rows = q.fetch_all(&mut **conn).await?;

            let mut out = Vec::with_capacity(rows.len());
            for r in &rows {
                let finding = parse_finding!(r);
                let scan = parse_scan_from_prefix!(r);
                out.push(FindingOnScanRow { finding, scan });
            }
            Ok(out)
        }
    }
}

/// Identifiers of scans holding an SBOM strictly older than `before`, newest first.
pub async fn ids_with_sbom_before(tx: &mut Tx, before: i64, limit: i64) -> Result<Vec<i64>, StoreError> {
    match tx {
        Tx::MySql(conn) => {
            let rows: Vec<i64> = sqlx::query_scalar(AssertSqlSafe(
                "select id from t_scan where sbom is not null and id < ? order by id desc limit ?",
            ))
            .bind(before)
            .bind(limit)
            .fetch_all(&mut **conn)
            .await?;
            Ok(rows)
        }
        Tx::PostgreSql(conn) => {
            let rows: Vec<i64> = sqlx::query_scalar(AssertSqlSafe(
                "select id from t_scan where sbom is not null and id < $1 order by id desc limit $2",
            ))
            .bind(before)
            .bind(limit)
            .fetch_all(&mut **conn)
            .await?;
            Ok(rows)
        }
    }
}

const SCAN_COLS_CONST: &str = "s.id as s_id, s.branch as s_branch, s.sub_path as s_sub_path, s.status as s_status, \
                 s.duration_ms as s_duration_ms, s.findings_count as s_findings_count, \
                 s.new_issues_count as s_new_issues_count, s.resolved_issues_count as s_resolved_issues_count, \
                 s.error as s_error, s.created_at as s_created_at, s.version as s_version, \
                 s.project_type as s_project_type, s.repo_id as s_repo_id, s.container_id as s_container_id, \
                 s.required_agent_label as s_required_agent_label, s.claimed_by as s_claimed_by, \
                 s.claimed_at as s_claimed_at, s.lease_expires_at as s_lease_expires_at, \
                 s.attempts as s_attempts, s.not_before as s_not_before, s.plugin_steps as s_plugin_steps, \
                 s.examined_types as s_examined_types, s.detected_languages as s_detected_languages, \
                 s.sast_languages as s_sast_languages, (case when s.sbom is null then 0 else 1 end) as s_has_sbom";

const FINDING_COLS_CONST: &str = "f.id, f.scan_id, f.type, f.severity, f.identifier, f.package_name, f.package_version, \
                    f.purl, f.file_path, f.owasp_category, f.source, f.tool, f.tool_name, f.tool_version, \
                    f.epss_score, f.is_kev, f.created_at, f.cvss_score, f.cvss_vector, f.fix_state, \
                    f.fix_versions, f.link, f.issue_id, f.is_direct_dependency, f.line, f.description";

pub async fn last_scan_at_per_repository(tx: &mut Tx) -> Result<BTreeMap<i64, OffsetDateTime>, StoreError> {
    let sql = "select repository_id, max(created_at) as last_scan from t_scan where repository_id is not null and status = 'completed' group by repository_id";
    match tx {
        Tx::MySql(conn) => {
            let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
            let mut map = BTreeMap::new();
            for r in rows {
                let repo_id: i64 = r.get("repository_id");
                let last_scan: Option<UtcInstant> = r.try_get("last_scan").ok().flatten();
                if let Some(instant) = last_scan {
                    map.insert(repo_id, instant.0);
                }
            }
            Ok(map)
        }
        Tx::PostgreSql(conn) => {
            let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
            let mut map = BTreeMap::new();
            for r in rows {
                let repo_id: i64 = r.get("repository_id");
                let last_scan: Option<UtcInstant> = r.try_get("last_scan").ok().flatten();
                if let Some(instant) = last_scan {
                    map.insert(repo_id, instant.0);
                }
            }
            Ok(map)
        }
    }
}

pub async fn history_of_repository(
    tx: &mut Tx,
    repo_id: i64,
    branch: Option<&str>,
    limit: usize,
) -> Result<Vec<ScanRow>, StoreError> {
    let limit_i64 = i64::try_from(limit).unwrap_or(200);
    match (tx, branch) {
        (Tx::MySql(conn), Some(b)) => {
            let sql = format!(
                "select {SCAN_COLS_CONST} from t_scan s where s.repo_id = ? and s.branch = ? order by s.created_at desc, s.id desc limit ?"
            );
            let rows =
                sqlx::query(AssertSqlSafe(sql)).bind(repo_id).bind(b).bind(limit_i64).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_scan_from_prefix!(r)).collect())
        }
        (Tx::MySql(conn), None) => {
            let sql = format!(
                "select {SCAN_COLS_CONST} from t_scan s where s.repo_id = ? order by s.created_at desc, s.id desc limit ?"
            );
            let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).bind(limit_i64).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_scan_from_prefix!(r)).collect())
        }
        (Tx::PostgreSql(conn), Some(b)) => {
            let sql = format!(
                "select {SCAN_COLS_CONST} from t_scan s where s.repo_id = $1 and s.branch = $2 order by s.created_at desc, s.id desc limit $3"
            );
            let rows =
                sqlx::query(AssertSqlSafe(sql)).bind(repo_id).bind(b).bind(limit_i64).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_scan_from_prefix!(r)).collect())
        }
        (Tx::PostgreSql(conn), None) => {
            let sql = format!(
                "select {SCAN_COLS_CONST} from t_scan s where s.repo_id = $1 order by s.created_at desc, s.id desc limit $2"
            );
            let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).bind(limit_i64).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_scan_from_prefix!(r)).collect())
        }
    }
}

pub async fn findings_of_scans(tx: &mut Tx, scan_ids: &[i64]) -> Result<Vec<ScanFindingView>, StoreError> {
    if scan_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    const BATCH: usize = 1_000;
    for chunk in scan_ids.chunks(BATCH) {
        match tx {
            Tx::MySql(conn) => {
                let placeholders = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "select id, scan_id, type, severity, identifier, package_name, package_version, purl, file_path, owasp_category, source, tool, tool_name, tool_version, epss_score, is_kev, created_at, cvss_score, cvss_vector, fix_state, fix_versions, link, issue_id, is_direct_dependency, line, description from t_finding where scan_id in ({placeholders}) order by id"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                found.extend(rows.iter().map(|r| parse_finding!(r)));
            }
            Tx::PostgreSql(conn) => {
                let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "select id, scan_id, type, severity, identifier, package_name, package_version, purl, file_path, owasp_category, source, tool, tool_name, tool_version, epss_score, is_kev, created_at, cvss_score, cvss_vector, fix_state, fix_versions, link, issue_id, is_direct_dependency, line, description from t_finding where scan_id in ({placeholders}) order by id"
                );
                let mut q = sqlx::query(AssertSqlSafe(sql));
                for id in chunk {
                    q = q.bind(id);
                }
                let rows = q.fetch_all(&mut **conn).await?;
                found.extend(rows.iter().map(|r| parse_finding!(r)));
            }
        }
    }
    Ok(found)
}

pub async fn sightings_of_issue(tx: &mut Tx, issue_id: i64, limit: usize) -> Result<Vec<FindingOnScanRow>, StoreError> {
    let limit_i64 = i64::try_from(limit).unwrap_or(100);
    match tx {
        Tx::MySql(conn) => {
            let sql = format!(
                "select {FINDING_COLS_CONST}, {SCAN_COLS_CONST} from t_finding f join t_scan s on f.scan_id = s.id where f.issue_id = ? order by s.created_at desc, s.id desc limit ?"
            );
            let rows = sqlx::query(AssertSqlSafe(sql)).bind(issue_id).bind(limit_i64).fetch_all(&mut **conn).await?;
            Ok(rows
                .iter()
                .map(|r| {
                    let finding = parse_finding!(r);
                    let scan = parse_scan_from_prefix!(r);
                    FindingOnScanRow { finding, scan }
                })
                .collect())
        }
        Tx::PostgreSql(conn) => {
            let sql = format!(
                "select {FINDING_COLS_CONST}, {SCAN_COLS_CONST} from t_finding f join t_scan s on f.scan_id = s.id where f.issue_id = $1 order by s.created_at desc, s.id desc limit $2"
            );
            let rows = sqlx::query(AssertSqlSafe(sql)).bind(issue_id).bind(limit_i64).fetch_all(&mut **conn).await?;
            Ok(rows
                .iter()
                .map(|r| {
                    let finding = parse_finding!(r);
                    let scan = parse_scan_from_prefix!(r);
                    FindingOnScanRow { finding, scan }
                })
                .collect())
        }
    }
}

macro_rules! parse_latest_row {
    ($r:ident) => {{
        let created_at: UtcInstant = $r.get("created_at");
        LatestRow {
            target_id: $r.get("target_id"),
            scan_id: $r.get("id"),
            status: $r.get("status"),
            created_at: created_at.0,
            error: $r.get("error"),
        }
    }};
}

pub async fn latest_finished_per_repository(tx: &mut Tx) -> Result<Vec<LatestRow>, StoreError> {
    let sql = "select s.repo_id as target_id, s.id as id, s.status as status, s.created_at as created_at, s.error as error from t_scan s where s.repo_id is not null and s.id = (select max(l.id) from t_scan l where l.repo_id = s.repo_id and l.status in ('completed', 'failed'))";
    match tx {
        Tx::MySql(conn) => {
            let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_latest_row!(r)).collect())
        }
        Tx::PostgreSql(conn) => {
            let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_latest_row!(r)).collect())
        }
    }
}

pub async fn latest_finished_per_container(tx: &mut Tx) -> Result<Vec<LatestRow>, StoreError> {
    let sql = "select s.container_id as target_id, s.id as id, s.status as status, s.created_at as created_at, s.error as error from t_scan s where s.container_id is not null and s.id = (select max(l.id) from t_scan l where l.container_id = s.container_id and l.status in ('completed', 'failed'))";
    match tx {
        Tx::MySql(conn) => {
            let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_latest_row!(r)).collect())
        }
        Tx::PostgreSql(conn) => {
            let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
            Ok(rows.iter().map(|r| parse_latest_row!(r)).collect())
        }
    }
}

pub async fn latest_finished_of_target(tx: &mut Tx, target: ScanTarget) -> Result<Option<LatestRow>, StoreError> {
    match target {
        ScanTarget::Repository(repo_id) => match tx {
            Tx::MySql(conn) => {
                let sql = "select repo_id as target_id, id, status, created_at, error from t_scan where repo_id = ? and status in ('completed', 'failed') order by id desc limit 1";
                let row = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).fetch_optional(&mut **conn).await?;
                Ok(row.as_ref().map(|r| parse_latest_row!(r)))
            }
            Tx::PostgreSql(conn) => {
                let sql = "select repo_id as target_id, id, status, created_at, error from t_scan where repo_id = $1 and status in ('completed', 'failed') order by id desc limit 1";
                let row = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).fetch_optional(&mut **conn).await?;
                Ok(row.as_ref().map(|r| parse_latest_row!(r)))
            }
        },
        ScanTarget::Container(container_id) => match tx {
            Tx::MySql(conn) => {
                let sql = "select container_id as target_id, id, status, created_at, error from t_scan where container_id = ? and status in ('completed', 'failed') order by id desc limit 1";
                let row = sqlx::query(AssertSqlSafe(sql)).bind(container_id).fetch_optional(&mut **conn).await?;
                Ok(row.as_ref().map(|r| parse_latest_row!(r)))
            }
            Tx::PostgreSql(conn) => {
                let sql = "select container_id as target_id, id, status, created_at, error from t_scan where container_id = $1 and status in ('completed', 'failed') order by id desc limit 1";
                let row = sqlx::query(AssertSqlSafe(sql)).bind(container_id).fetch_optional(&mut **conn).await?;
                Ok(row.as_ref().map(|r| parse_latest_row!(r)))
            }
        },
    }
}
