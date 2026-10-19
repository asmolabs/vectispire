//! Persistence statements for inventory tables:
//! `t_component`, `t_build_sbom`, `t_build_sbom_component`, `t_license_policy`,
//! `t_api_endpoint`, `t_api_contract`.

use sqlx::{AssertSqlSafe, Row};
use time::OffsetDateTime;
use vectispire_cp_db::types::UtcInstant;
use vectispire_cp_db::{Db, Mode, Tx};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error("{0}")]
    Other(String),
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComponentRow {
    pub id: i64,
    pub scan_id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub scan_created_at: Option<OffsetDateTime>,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub type_: Option<String>,
    pub is_direct: Option<bool>,
    pub origin: Option<String>,
    pub build_sbom_id: Option<i64>,
    pub scanned_version: Option<String>,
    pub scanned_purl: Option<String>,
    pub declared_license: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewComponent {
    pub scan_id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub scan_created_at: Option<OffsetDateTime>,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub type_: Option<String>,
    pub is_direct: Option<bool>,
    pub origin: Option<String>,
    pub build_sbom_id: Option<i64>,
    pub scanned_version: Option<String>,
    pub scanned_purl: Option<String>,
    pub declared_license: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BuildSbomRow {
    pub id: i64,
    pub source_id: i64,
    pub source_slug: String,
    pub repo_id: i64,
    pub spec_version: String,
    pub tool: Option<String>,
    pub components_count: i32,
    pub commit_sha: Option<String>,
    pub branch_name: Option<String>,
    pub document_sha256: String,
    pub imported_at: OffsetDateTime,
    pub imported_by: String,
    pub api_key_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewBuildSbom {
    pub source_id: i64,
    pub source_slug: String,
    pub repo_id: i64,
    pub spec_version: String,
    pub tool: Option<String>,
    pub components_count: i32,
    pub commit_sha: Option<String>,
    pub branch_name: Option<String>,
    pub document_sha256: String,
    pub imported_at: OffsetDateTime,
    pub imported_by: String,
    pub api_key_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BuildSbomComponentRow {
    pub id: i64,
    pub import_id: i64,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub type_: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewBuildSbomComponent {
    pub import_id: i64,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub type_: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LicensePolicyRow {
    pub id: i64,
    pub disallowed_categories: String,
    pub allowed_licenses: Option<String>,
    pub disallowed_licenses: Option<String>,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiEndpointRow {
    pub id: i64,
    pub scan_id: i64,
    pub repository_id: Option<i64>,
    pub http_method: String,
    pub path: String,
    pub auth_required: bool,
    pub auth_type: Option<String>,
    pub visibility: String,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub framework: Option<String>,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub tags: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewApiEndpoint {
    pub scan_id: i64,
    pub repository_id: Option<i64>,
    pub http_method: String,
    pub path: String,
    pub auth_required: bool,
    pub auth_type: Option<String>,
    pub visibility: String,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub framework: Option<String>,
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub tags: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApiContractRow {
    pub id: i64,
    pub repository_id: i64,
    pub scan_id: Option<i64>,
    pub contract_path: String,
    pub format: Option<String>,
    pub title: Option<String>,
    pub version: Option<String>,
    pub endpoints_count: i32,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewApiContract {
    pub repository_id: i64,
    pub scan_id: Option<i64>,
    pub contract_path: String,
    pub format: Option<String>,
    pub title: Option<String>,
    pub version: Option<String>,
    pub endpoints_count: i32,
    pub created_at: OffsetDateTime,
}

macro_rules! parse_bool {
    ($row:expr, $col:expr) => {
        match $row.try_get::<Option<bool>, _>($col) {
            Ok(val) => val,
            Err(_) => match $row.try_get::<Option<i8>, _>($col) {
                Ok(Some(n)) => Some(n != 0),
                Ok(None) => None,
                Err(_) => None,
            },
        }
    };
}

macro_rules! parse_bool_required {
    ($row:expr, $col:expr) => {
        match $row.try_get::<bool, _>($col) {
            Ok(val) => val,
            Err(_) => match $row.try_get::<i8, _>($col) {
                Ok(n) => n != 0,
                Err(_) => false,
            },
        }
    };
}

macro_rules! parse_component_row {
    ($r:expr) => {{
        let scan_created_at: Option<UtcInstant> = $r.try_get("scan_created_at").ok().flatten();
        let is_direct = parse_bool!($r, "is_direct");
        ComponentRow {
            id: $r.get("id"),
            scan_id: $r.get("scan_id"),
            repo_id: $r.get("repo_id"),
            container_id: $r.get("container_id"),
            scan_created_at: scan_created_at.map(|t| t.0),
            name: $r.get("name"),
            version: $r.get("version"),
            purl: $r.get("purl"),
            type_: $r.get("type"),
            is_direct,
            origin: $r.get("origin"),
            build_sbom_id: $r.get("build_sbom_id"),
            scanned_version: $r.get("scanned_version"),
            scanned_purl: $r.get("scanned_purl"),
            declared_license: $r.get("declared_license"),
        }
    }};
}

macro_rules! parse_build_sbom_row {
    ($r:expr) => {{
        let imported_at: UtcInstant = $r.get("imported_at");
        BuildSbomRow {
            id: $r.get("id"),
            source_id: $r.get("source_id"),
            source_slug: $r.get("source_slug"),
            repo_id: $r.get("repo_id"),
            spec_version: $r.get("spec_version"),
            tool: $r.get("tool"),
            components_count: $r.get("components_count"),
            commit_sha: $r.get("commit_sha"),
            branch_name: $r.get("branch_name"),
            document_sha256: $r.get("document_sha256"),
            imported_at: imported_at.0,
            imported_by: $r.get("imported_by"),
            api_key_id: $r.get("api_key_id"),
        }
    }};
}

macro_rules! parse_build_sbom_component_row {
    ($r:expr) => {
        BuildSbomComponentRow {
            id: $r.get("id"),
            import_id: $r.get("import_id"),
            name: $r.get("name"),
            version: $r.get("version"),
            purl: $r.get("purl"),
            type_: $r.get("type"),
            license: $r.get("license"),
        }
    };
}

macro_rules! parse_api_endpoint_row {
    ($r:expr) => {{
        let created_at: UtcInstant = $r.get("created_at");
        let auth_required = parse_bool_required!($r, "auth_required");
        ApiEndpointRow {
            id: $r.get("id"),
            scan_id: $r.get("scan_id"),
            repository_id: $r.get("repository_id"),
            http_method: $r.get("http_method"),
            path: $r.get("path"),
            auth_required,
            auth_type: $r.get("auth_type"),
            visibility: $r.get("visibility"),
            file_path: $r.get("file_path"),
            line_number: $r.get("line_number"),
            framework: $r.get("framework"),
            operation_id: $r.get("operation_id"),
            summary: $r.get("summary"),
            tags: $r.get("tags"),
            created_at: created_at.0,
        }
    }};
}

macro_rules! parse_api_contract_row {
    ($r:expr) => {{
        let created_at: UtcInstant = $r.get("created_at");
        ApiContractRow {
            id: $r.get("id"),
            repository_id: $r.get("repository_id"),
            scan_id: $r.get("scan_id"),
            contract_path: $r.get("contract_path"),
            format: $r.get("format"),
            title: $r.get("title"),
            version: $r.get("version"),
            endpoints_count: $r.get("endpoints_count"),
            created_at: created_at.0,
        }
    }};
}

macro_rules! parse_license_policy_row {
    ($r:expr) => {{
        let updated_at: UtcInstant = $r.get("updated_at");
        LicensePolicyRow {
            id: $r.get("id"),
            disallowed_categories: $r.get("disallowed_categories"),
            allowed_licenses: $r.get("allowed_licenses"),
            disallowed_licenses: $r.get("disallowed_licenses"),
            updated_at: updated_at.0,
        }
    }};
}

#[derive(Debug, Clone, Copy)]
pub struct InventoryRepository;

impl InventoryRepository {
    // -------------------------------------------------------------------------
    // t_component queries
    // -------------------------------------------------------------------------

    pub async fn delete_components_by_scan_id(tx: &mut Tx, scan_id: i64) -> Result<u64, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "delete from t_component where scan_id = ?",
            Tx::PostgreSql(_) => "delete from t_component where scan_id = $1",
        };
        let rows = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(scan_id).execute(&mut **conn).await?.rows_affected()
            }
            Tx::PostgreSql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(scan_id).execute(&mut **conn).await?.rows_affected()
            }
        };
        Ok(rows)
    }

    pub async fn delete_components_by_scan_ids(tx: &mut Tx, scan_ids: &[i64]) -> Result<u64, StoreError> {
        if scan_ids.is_empty() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for chunk in scan_ids.chunks(1000) {
            let res = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("delete from t_component where scan_id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("delete from t_component where scan_id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
            };
            total = total.saturating_add(res);
        }
        Ok(total)
    }

    pub async fn delete_components_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for chunk in ids.chunks(1000) {
            let res = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("delete from t_component where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("delete from t_component where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
            };
            total = total.saturating_add(res);
        }
        Ok(total)
    }

    pub async fn insert_components(tx: &mut Tx, components: &[NewComponent]) -> Result<(), StoreError> {
        if components.is_empty() {
            return Ok(());
        }
        for chunk in components.chunks(500) {
            match tx {
                Tx::MySql(conn) => {
                    let mut sql = String::from(
                        "insert into t_component (scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license) values ",
                    );
                    for i in 0..chunk.len() {
                        if i > 0 {
                            sql.push_str(", ");
                        }
                        sql.push_str("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                    }
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for c in chunk {
                        q = q
                            .bind(c.scan_id)
                            .bind(c.repo_id)
                            .bind(c.container_id)
                            .bind(c.scan_created_at.map(UtcInstant))
                            .bind(&c.name)
                            .bind(&c.version)
                            .bind(&c.purl)
                            .bind(&c.type_)
                            .bind(c.is_direct)
                            .bind(&c.origin)
                            .bind(c.build_sbom_id)
                            .bind(&c.scanned_version)
                            .bind(&c.scanned_purl)
                            .bind(&c.declared_license);
                    }
                    q.execute(&mut **conn).await?;
                }
                Tx::PostgreSql(conn) => {
                    let mut sql = String::from(
                        "insert into t_component (scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license) values ",
                    );
                    for i in 0..chunk.len() {
                        if i > 0 {
                            sql.push_str(", ");
                        }
                        let base = i.saturating_mul(14);
                        let params = (1..=14)
                            .map(|offset| format!("${}", base.saturating_add(offset)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        sql.push_str(&format!("({params})"));
                    }
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for c in chunk {
                        q = q
                            .bind(c.scan_id)
                            .bind(c.repo_id)
                            .bind(c.container_id)
                            .bind(c.scan_created_at.map(UtcInstant))
                            .bind(&c.name)
                            .bind(&c.version)
                            .bind(&c.purl)
                            .bind(&c.type_)
                            .bind(c.is_direct)
                            .bind(&c.origin)
                            .bind(c.build_sbom_id)
                            .bind(&c.scanned_version)
                            .bind(&c.scanned_purl)
                            .bind(&c.declared_license);
                    }
                    q.execute(&mut **conn).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn update_components(tx: &mut Tx, components: &[ComponentRow]) -> Result<(), StoreError> {
        for c in components {
            let sql = match tx {
                Tx::MySql(_) => {
                    "update t_component set version = ?, purl = ?, origin = ?, build_sbom_id = ?, scanned_version = ?, scanned_purl = ?, declared_license = ? where id = ?"
                }
                Tx::PostgreSql(_) => {
                    "update t_component set version = $1, purl = $2, origin = $3, build_sbom_id = $4, scanned_version = $5, scanned_purl = $6, declared_license = $7 where id = $8"
                }
            };
            match tx {
                Tx::MySql(conn) => {
                    sqlx::query(AssertSqlSafe(sql))
                        .bind(&c.version)
                        .bind(&c.purl)
                        .bind(&c.origin)
                        .bind(c.build_sbom_id)
                        .bind(&c.scanned_version)
                        .bind(&c.scanned_purl)
                        .bind(&c.declared_license)
                        .bind(c.id)
                        .execute(&mut **conn)
                        .await?;
                }
                Tx::PostgreSql(conn) => {
                    sqlx::query(AssertSqlSafe(sql))
                        .bind(&c.version)
                        .bind(&c.purl)
                        .bind(&c.origin)
                        .bind(c.build_sbom_id)
                        .bind(&c.scanned_version)
                        .bind(&c.scanned_purl)
                        .bind(&c.declared_license)
                        .bind(c.id)
                        .execute(&mut **conn)
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn find_components_by_scan_id(db: &Db, scan_id: i64) -> Result<Vec<ComponentRow>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        Self::find_components_by_scan_id_tx(&mut tx, scan_id).await
    }

    pub async fn find_components_by_scan_id_tx(tx: &mut Tx, scan_id: i64) -> Result<Vec<ComponentRow>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => {
                "select id, scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license from t_component where scan_id = ? order by id asc"
            }
            Tx::PostgreSql(_) => {
                "select id, scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license from t_component where scan_id = $1 order by id asc"
            }
        };
        match tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(scan_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_component_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(scan_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_component_row!(r)).collect())
            }
        }
    }

    pub async fn lock_scan_components(tx: &mut Tx, scan_id: i64) -> Result<Vec<ComponentRow>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => {
                "select id, scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license from t_component where scan_id = ? for update"
            }
            Tx::PostgreSql(_) => {
                "select id, scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license from t_component where scan_id = $1 for update"
            }
        };
        match tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(scan_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_component_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(scan_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_component_row!(r)).collect())
            }
        }
    }

    pub async fn find_components_by_scan_ids(db: &Db, scan_ids: &[i64]) -> Result<Vec<ComponentRow>, StoreError> {
        if scan_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let mut result = Vec::new();
        for chunk in scan_ids.chunks(1000) {
            match &mut tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!(
                        "select id, scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license from t_component where scan_id in ({placeholders})"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    result.extend(rows.into_iter().map(|r| parse_component_row!(r)));
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!(
                        "select id, scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license from t_component where scan_id in ({placeholders})"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    result.extend(rows.into_iter().map(|r| parse_component_row!(r)));
                }
            }
        }
        Ok(result)
    }

    /// Which of these scans the inventory holds components of — the backfill keeps the others.
    pub async fn indexed_among(db: &Db, scan_ids: &[i64]) -> Result<Vec<i64>, StoreError> {
        if scan_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let mut result = Vec::new();
        for chunk in scan_ids.chunks(1000) {
            match &mut tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("select distinct scan_id from t_component where scan_id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    for r in rows {
                        let scan_id: i64 = r.get("scan_id");
                        result.push(scan_id);
                    }
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("select distinct scan_id from t_component where scan_id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    for r in rows {
                        let scan_id: i64 = r.get("scan_id");
                        result.push(scan_id);
                    }
                }
            }
        }
        Ok(result)
    }

    pub async fn count_components_by_scan_ids(db: &Db, scan_ids: &[i64]) -> Result<i64, StoreError> {
        if scan_ids.is_empty() {
            return Ok(0);
        }
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let mut total: i64 = 0;
        for chunk in scan_ids.chunks(1000) {
            let count: i64 = match &mut tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("select count(*) from t_component where scan_id in ({placeholders})");
                    let mut q = sqlx::query_scalar(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.fetch_one(&mut **conn).await?
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("select count(*) from t_component where scan_id in ({placeholders})");
                    let mut q = sqlx::query_scalar(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.fetch_one(&mut **conn).await?
                }
            };
            total = total.saturating_add(count);
        }
        Ok(total)
    }

    pub async fn search_components(
        db: &Db,
        name_like: &str,
        version: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ComponentRow>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = match &tx {
            Tx::MySql(_) => {
                "select id, scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license \
                 from t_component \
                 where lower(name) like ? and (? is null or version = ?) \
                 order by id desc limit ?"
            }
            Tx::PostgreSql(_) => {
                "select id, scan_id, repo_id, container_id, scan_created_at, name, version, purl, type, is_direct, origin, build_sbom_id, scanned_version, scanned_purl, declared_license \
                 from t_component \
                 where lower(name) like $1 and ($2 is null or version = $2) \
                 order by id desc limit $3"
            }
        };
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql))
                    .bind(name_like)
                    .bind(version)
                    .bind(version)
                    .bind(limit)
                    .fetch_all(&mut **conn)
                    .await?;
                Ok(rows.into_iter().map(|r| parse_component_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql))
                    .bind(name_like)
                    .bind(version)
                    .bind(limit)
                    .fetch_all(&mut **conn)
                    .await?;
                Ok(rows.into_iter().map(|r| parse_component_row!(r)).collect())
            }
        }
    }

    pub async fn versions_of(
        db: &Db,
        name_like: &str,
        limit: i64,
    ) -> Result<Vec<(String, Option<i64>, Option<i64>)>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = match &tx {
            Tx::MySql(_) => {
                "select distinct version, repo_id, container_id from t_component where lower(name) like ? and version is not null limit ?"
            }
            Tx::PostgreSql(_) => {
                "select distinct version, repo_id, container_id from t_component where lower(name) like $1 and version is not null limit $2"
            }
        };
        let rows = match &mut tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(name_like)
                .bind(limit)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| {
                    let version: String = r.get("version");
                    let repo_id: Option<i64> = r.get("repo_id");
                    let container_id: Option<i64> = r.get("container_id");
                    (version, repo_id, container_id)
                })
                .collect(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .bind(name_like)
                .bind(limit)
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| {
                    let version: String = r.get("version");
                    let repo_id: Option<i64> = r.get("repo_id");
                    let container_id: Option<i64> = r.get("container_id");
                    (version, repo_id, container_id)
                })
                .collect(),
        };
        Ok(rows)
    }

    pub async fn distinct_purls(db: &Db) -> Result<Vec<String>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = "select distinct purl from t_component where purl is not null order by purl asc";
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("purl")).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("purl")).collect())
            }
        }
    }

    pub async fn distinct_purls_by_target(db: &Db) -> Result<Vec<(Option<i64>, Option<i64>, String)>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = "select distinct repo_id, container_id, purl from t_component where purl is not null";
        let rows = match &mut tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| {
                    let repo_id: Option<i64> = r.get("repo_id");
                    let container_id: Option<i64> = r.get("container_id");
                    let purl: String = r.get("purl");
                    (repo_id, container_id, purl)
                })
                .collect(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql))
                .fetch_all(&mut **conn)
                .await?
                .into_iter()
                .map(|r| {
                    let repo_id: Option<i64> = r.get("repo_id");
                    let container_id: Option<i64> = r.get("container_id");
                    let purl: String = r.get("purl");
                    (repo_id, container_id, purl)
                })
                .collect(),
        };
        Ok(rows)
    }

    pub async fn distinct_repositories_with_components(db: &Db) -> Result<Vec<i64>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = "select distinct repo_id from t_component where repo_id is not null";
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("repo_id")).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("repo_id")).collect())
            }
        }
    }

    pub async fn distinct_containers_with_components(db: &Db) -> Result<Vec<i64>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = "select distinct container_id from t_component where container_id is not null";
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("container_id")).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("container_id")).collect())
            }
        }
    }

    pub async fn newest_scan_completed_by(db: &Db, build_sbom_ids: &[i64]) -> Result<Vec<(i64, i64)>, StoreError> {
        if build_sbom_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let mut result = Vec::new();
        for chunk in build_sbom_ids.chunks(1000) {
            match &mut tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!(
                        "select build_sbom_id, max(scan_id) as scan_id from t_component where build_sbom_id in ({placeholders}) group by build_sbom_id"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    for r in rows {
                        let build_id: i64 = r.get("build_sbom_id");
                        let scan_id: i64 = r.get("scan_id");
                        result.push((build_id, scan_id));
                    }
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!(
                        "select build_sbom_id, max(scan_id) as scan_id from t_component where build_sbom_id in ({placeholders}) group by build_sbom_id"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    for r in rows {
                        let build_id: i64 = r.get("build_sbom_id");
                        let scan_id: i64 = r.get("scan_id");
                        result.push((build_id, scan_id));
                    }
                }
            }
        }
        Ok(result)
    }

    // -------------------------------------------------------------------------
    // t_build_sbom & t_build_sbom_component queries
    // -------------------------------------------------------------------------

    pub async fn insert_build_sbom(tx: &mut Tx, row: &NewBuildSbom) -> Result<i64, StoreError> {
        match tx {
            Tx::MySql(conn) => {
                let sql = "insert into t_build_sbom (source_id, source_slug, repo_id, spec_version, tool, components_count, commit_sha, branch_name, document_sha256, imported_at, imported_by, api_key_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                let res = sqlx::query(AssertSqlSafe(sql))
                    .bind(row.source_id)
                    .bind(&row.source_slug)
                    .bind(row.repo_id)
                    .bind(&row.spec_version)
                    .bind(&row.tool)
                    .bind(row.components_count)
                    .bind(&row.commit_sha)
                    .bind(&row.branch_name)
                    .bind(&row.document_sha256)
                    .bind(UtcInstant(row.imported_at))
                    .bind(&row.imported_by)
                    .bind(&row.api_key_id)
                    .execute(&mut **conn)
                    .await?;
                Ok(res.last_insert_id() as i64)
            }
            Tx::PostgreSql(conn) => {
                let sql = "insert into t_build_sbom (source_id, source_slug, repo_id, spec_version, tool, components_count, commit_sha, branch_name, document_sha256, imported_at, imported_by, api_key_id) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) returning id";
                let id: i64 = sqlx::query_scalar(AssertSqlSafe(sql))
                    .bind(row.source_id)
                    .bind(&row.source_slug)
                    .bind(row.repo_id)
                    .bind(&row.spec_version)
                    .bind(&row.tool)
                    .bind(row.components_count)
                    .bind(&row.commit_sha)
                    .bind(&row.branch_name)
                    .bind(&row.document_sha256)
                    .bind(UtcInstant(row.imported_at))
                    .bind(&row.imported_by)
                    .bind(&row.api_key_id)
                    .fetch_one(&mut **conn)
                    .await?;
                Ok(id)
            }
        }
    }

    pub async fn insert_build_sbom_components(
        tx: &mut Tx,
        components: &[NewBuildSbomComponent],
    ) -> Result<(), StoreError> {
        if components.is_empty() {
            return Ok(());
        }
        for chunk in components.chunks(500) {
            match tx {
                Tx::MySql(conn) => {
                    let mut sql = String::from(
                        "insert into t_build_sbom_component (import_id, name, version, purl, type, license) values ",
                    );
                    for i in 0..chunk.len() {
                        if i > 0 {
                            sql.push_str(", ");
                        }
                        sql.push_str("(?, ?, ?, ?, ?, ?)");
                    }
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for c in chunk {
                        q = q
                            .bind(c.import_id)
                            .bind(&c.name)
                            .bind(&c.version)
                            .bind(&c.purl)
                            .bind(&c.type_)
                            .bind(&c.license);
                    }
                    q.execute(&mut **conn).await?;
                }
                Tx::PostgreSql(conn) => {
                    let mut sql = String::from(
                        "insert into t_build_sbom_component (import_id, name, version, purl, type, license) values ",
                    );
                    for i in 0..chunk.len() {
                        if i > 0 {
                            sql.push_str(", ");
                        }
                        let base = i.saturating_mul(6);
                        let params = (1..=6)
                            .map(|offset| format!("${}", base.saturating_add(offset)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        sql.push_str(&format!("({params})"));
                    }
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for c in chunk {
                        q = q
                            .bind(c.import_id)
                            .bind(&c.name)
                            .bind(&c.version)
                            .bind(&c.purl)
                            .bind(&c.type_)
                            .bind(&c.license);
                    }
                    q.execute(&mut **conn).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn find_newest_build_sbom_for_repo(
        tx: &mut Tx,
        repo_id: i64,
        branch: Option<&str>,
    ) -> Result<Option<BuildSbomRow>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => {
                "select id, source_id, source_slug, repo_id, spec_version, tool, components_count, commit_sha, branch_name, document_sha256, imported_at, imported_by, api_key_id \
                 from t_build_sbom \
                 where repo_id = ? and (? is null or branch_name = ? or branch_name is null) \
                 order by id desc limit 1"
            }
            Tx::PostgreSql(_) => {
                "select id, source_id, source_slug, repo_id, spec_version, tool, components_count, commit_sha, branch_name, document_sha256, imported_at, imported_by, api_key_id \
                 from t_build_sbom \
                 where repo_id = $1 and ($2 is null or branch_name = $2 or branch_name is null) \
                 order by id desc limit 1"
            }
        };
        match tx {
            Tx::MySql(conn) => {
                let row = sqlx::query(AssertSqlSafe(sql))
                    .bind(repo_id)
                    .bind(branch)
                    .bind(branch)
                    .fetch_optional(&mut **conn)
                    .await?;
                Ok(row.map(|r| parse_build_sbom_row!(r)))
            }
            Tx::PostgreSql(conn) => {
                let row =
                    sqlx::query(AssertSqlSafe(sql)).bind(repo_id).bind(branch).fetch_optional(&mut **conn).await?;
                Ok(row.map(|r| parse_build_sbom_row!(r)))
            }
        }
    }

    pub async fn find_build_sbom_components(
        tx: &mut Tx,
        import_id: i64,
    ) -> Result<Vec<BuildSbomComponentRow>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => {
                "select id, import_id, name, version, purl, type, license from t_build_sbom_component where import_id = ? order by id asc"
            }
            Tx::PostgreSql(_) => {
                "select id, import_id, name, version, purl, type, license from t_build_sbom_component where import_id = $1 order by id asc"
            }
        };
        match tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(import_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_build_sbom_component_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(import_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_build_sbom_component_row!(r)).collect())
            }
        }
    }

    pub async fn find_build_sboms_by_repo(db: &Db, repo_id: i64, limit: i64) -> Result<Vec<BuildSbomRow>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = match &tx {
            Tx::MySql(_) => {
                "select id, source_id, source_slug, repo_id, spec_version, tool, components_count, commit_sha, branch_name, document_sha256, imported_at, imported_by, api_key_id \
                 from t_build_sbom where repo_id = ? order by id desc limit ?"
            }
            Tx::PostgreSql(_) => {
                "select id, source_id, source_slug, repo_id, spec_version, tool, components_count, commit_sha, branch_name, document_sha256, imported_at, imported_by, api_key_id \
                 from t_build_sbom where repo_id = $1 order by id desc limit $2"
            }
        };
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).bind(limit).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_build_sbom_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).bind(limit).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_build_sbom_row!(r)).collect())
            }
        }
    }

    pub async fn find_build_sbom_ids_by_repo(tx: &mut Tx, repo_id: i64) -> Result<Vec<i64>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "select id from t_build_sbom where repo_id = ? order by id asc",
            Tx::PostgreSql(_) => "select id from t_build_sbom where repo_id = $1 order by id asc",
        };
        match tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("id")).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("id")).collect())
            }
        }
    }

    pub async fn find_build_sbom_ids_imported_before(
        tx: &mut Tx,
        cutoff: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<i64>, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "select id from t_build_sbom where imported_at < ? order by id asc limit ?",
            Tx::PostgreSql(_) => "select id from t_build_sbom where imported_at < $1 order by id asc limit $2",
        };
        match tx {
            Tx::MySql(conn) => {
                let rows =
                    sqlx::query(AssertSqlSafe(sql)).bind(UtcInstant(cutoff)).bind(limit).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("id")).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows =
                    sqlx::query(AssertSqlSafe(sql)).bind(UtcInstant(cutoff)).bind(limit).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("id")).collect())
            }
        }
    }

    pub async fn delete_build_sbom_components_by_import_ids(
        tx: &mut Tx,
        import_ids: &[i64],
    ) -> Result<u64, StoreError> {
        if import_ids.is_empty() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for chunk in import_ids.chunks(1000) {
            let res = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("delete from t_build_sbom_component where import_id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("delete from t_build_sbom_component where import_id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
            };
            total = total.saturating_add(res);
        }
        Ok(total)
    }

    pub async fn delete_build_sboms_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut total: u64 = 0;
        for chunk in ids.chunks(1000) {
            let res = match tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!("delete from t_build_sbom where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!("delete from t_build_sbom where id in ({placeholders})");
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    q.execute(&mut **conn).await?.rows_affected()
                }
            };
            total = total.saturating_add(res);
        }
        Ok(total)
    }

    // -------------------------------------------------------------------------
    // t_license_policy queries
    // -------------------------------------------------------------------------

    pub async fn find_license_policy(db: &Db) -> Result<Option<LicensePolicyRow>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = match &tx {
            Tx::MySql(_) => {
                "select id, disallowed_categories, allowed_licenses, disallowed_licenses, updated_at from t_license_policy where id = 1"
            }
            Tx::PostgreSql(_) => {
                "select id, disallowed_categories, allowed_licenses, disallowed_licenses, updated_at from t_license_policy where id = 1"
            }
        };
        match &mut tx {
            Tx::MySql(conn) => {
                let row = sqlx::query(AssertSqlSafe(sql)).fetch_optional(&mut **conn).await?;
                Ok(row.map(|r| parse_license_policy_row!(r)))
            }
            Tx::PostgreSql(conn) => {
                let row = sqlx::query(AssertSqlSafe(sql)).fetch_optional(&mut **conn).await?;
                Ok(row.map(|r| parse_license_policy_row!(r)))
            }
        }
    }

    pub async fn upsert_license_policy(
        tx: &mut Tx,
        disallowed_categories: &str,
        allowed_licenses: Option<&str>,
        disallowed_licenses: Option<&str>,
    ) -> Result<(), StoreError> {
        let sql = match tx {
            Tx::MySql(_) => {
                "insert into t_license_policy (id, disallowed_categories, allowed_licenses, disallowed_licenses, updated_at) \
                 values (1, ?, ?, ?, now()) \
                 on duplicate key update disallowed_categories = values(disallowed_categories), allowed_licenses = values(allowed_licenses), disallowed_licenses = values(disallowed_licenses), updated_at = now()"
            }
            Tx::PostgreSql(_) => {
                "insert into t_license_policy (id, disallowed_categories, allowed_licenses, disallowed_licenses, updated_at) \
                 values (1, $1, $2, $3, current_timestamp) \
                 on conflict (id) do update set disallowed_categories = excluded.disallowed_categories, allowed_licenses = excluded.allowed_licenses, disallowed_licenses = excluded.disallowed_licenses, updated_at = current_timestamp"
            }
        };
        match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql))
                    .bind(disallowed_categories)
                    .bind(allowed_licenses)
                    .bind(disallowed_licenses)
                    .execute(&mut **conn)
                    .await?;
            }
            Tx::PostgreSql(conn) => {
                sqlx::query(AssertSqlSafe(sql))
                    .bind(disallowed_categories)
                    .bind(allowed_licenses)
                    .bind(disallowed_licenses)
                    .execute(&mut **conn)
                    .await?;
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------------------
    // t_api_endpoint & t_api_contract queries
    // -------------------------------------------------------------------------

    pub async fn delete_api_endpoints_by_scan_id(tx: &mut Tx, scan_id: i64) -> Result<u64, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "delete from t_api_endpoint where scan_id = ?",
            Tx::PostgreSql(_) => "delete from t_api_endpoint where scan_id = $1",
        };
        let rows = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(scan_id).execute(&mut **conn).await?.rows_affected()
            }
            Tx::PostgreSql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(scan_id).execute(&mut **conn).await?.rows_affected()
            }
        };
        Ok(rows)
    }

    pub async fn delete_api_contracts_by_scan_id(tx: &mut Tx, scan_id: i64) -> Result<u64, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "delete from t_api_contract where scan_id = ?",
            Tx::PostgreSql(_) => "delete from t_api_contract where scan_id = $1",
        };
        let rows = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(scan_id).execute(&mut **conn).await?.rows_affected()
            }
            Tx::PostgreSql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(scan_id).execute(&mut **conn).await?.rows_affected()
            }
        };
        Ok(rows)
    }

    pub async fn delete_all_api_endpoints(tx: &mut Tx) -> Result<u64, StoreError> {
        let sql = "delete from t_api_endpoint";
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql)).execute(&mut **conn).await?.rows_affected(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql)).execute(&mut **conn).await?.rows_affected(),
        };
        Ok(rows)
    }

    pub async fn delete_all_api_contracts(tx: &mut Tx) -> Result<u64, StoreError> {
        let sql = "delete from t_api_contract";
        let rows = match tx {
            Tx::MySql(conn) => sqlx::query(AssertSqlSafe(sql)).execute(&mut **conn).await?.rows_affected(),
            Tx::PostgreSql(conn) => sqlx::query(AssertSqlSafe(sql)).execute(&mut **conn).await?.rows_affected(),
        };
        Ok(rows)
    }

    pub async fn delete_api_endpoints_by_repo_tx(tx: &mut Tx, repo_id: i64) -> Result<u64, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "delete from t_api_endpoint where repository_id = ?",
            Tx::PostgreSql(_) => "delete from t_api_endpoint where repository_id = $1",
        };
        let rows = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(repo_id).execute(&mut **conn).await?.rows_affected()
            }
            Tx::PostgreSql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(repo_id).execute(&mut **conn).await?.rows_affected()
            }
        };
        Ok(rows)
    }

    pub async fn delete_api_endpoints_by_repo(db: &Db, repo_id: i64) -> Result<u64, StoreError> {
        let mut tx = db.begin(Mode::ReadWrite).await?;
        let count = Self::delete_api_endpoints_by_repo_tx(&mut tx, repo_id).await?;
        tx.commit().await?;
        Ok(count)
    }

    pub async fn delete_api_contracts_by_repo_tx(tx: &mut Tx, repo_id: i64) -> Result<u64, StoreError> {
        let sql = match tx {
            Tx::MySql(_) => "delete from t_api_contract where repository_id = ?",
            Tx::PostgreSql(_) => "delete from t_api_contract where repository_id = $1",
        };
        let rows = match tx {
            Tx::MySql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(repo_id).execute(&mut **conn).await?.rows_affected()
            }
            Tx::PostgreSql(conn) => {
                sqlx::query(AssertSqlSafe(sql)).bind(repo_id).execute(&mut **conn).await?.rows_affected()
            }
        };
        Ok(rows)
    }

    pub async fn delete_api_contracts_by_repo(db: &Db, repo_id: i64) -> Result<u64, StoreError> {
        let mut tx = db.begin(Mode::ReadWrite).await?;
        let count = Self::delete_api_contracts_by_repo_tx(&mut tx, repo_id).await?;
        tx.commit().await?;
        Ok(count)
    }

    pub async fn insert_api_endpoints(tx: &mut Tx, endpoints: &[NewApiEndpoint]) -> Result<(), StoreError> {
        if endpoints.is_empty() {
            return Ok(());
        }
        for chunk in endpoints.chunks(500) {
            match tx {
                Tx::MySql(conn) => {
                    let mut sql = String::from(
                        "insert into t_api_endpoint (scan_id, repository_id, http_method, path, auth_required, auth_type, visibility, file_path, line_number, framework, operation_id, summary, tags, created_at) values ",
                    );
                    for i in 0..chunk.len() {
                        if i > 0 {
                            sql.push_str(", ");
                        }
                        sql.push_str("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                    }
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for ep in chunk {
                        q = q
                            .bind(ep.scan_id)
                            .bind(ep.repository_id)
                            .bind(&ep.http_method)
                            .bind(&ep.path)
                            .bind(ep.auth_required)
                            .bind(&ep.auth_type)
                            .bind(&ep.visibility)
                            .bind(&ep.file_path)
                            .bind(ep.line_number)
                            .bind(&ep.framework)
                            .bind(&ep.operation_id)
                            .bind(&ep.summary)
                            .bind(&ep.tags)
                            .bind(UtcInstant(ep.created_at));
                    }
                    q.execute(&mut **conn).await?;
                }
                Tx::PostgreSql(conn) => {
                    let mut sql = String::from(
                        "insert into t_api_endpoint (scan_id, repository_id, http_method, path, auth_required, auth_type, visibility, file_path, line_number, framework, operation_id, summary, tags, created_at) values ",
                    );
                    for i in 0..chunk.len() {
                        if i > 0 {
                            sql.push_str(", ");
                        }
                        let base = i.saturating_mul(14);
                        let params = (1..=14)
                            .map(|offset| format!("${}", base.saturating_add(offset)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        sql.push_str(&format!("({params})"));
                    }
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for ep in chunk {
                        q = q
                            .bind(ep.scan_id)
                            .bind(ep.repository_id)
                            .bind(&ep.http_method)
                            .bind(&ep.path)
                            .bind(ep.auth_required)
                            .bind(&ep.auth_type)
                            .bind(&ep.visibility)
                            .bind(&ep.file_path)
                            .bind(ep.line_number)
                            .bind(&ep.framework)
                            .bind(&ep.operation_id)
                            .bind(&ep.summary)
                            .bind(&ep.tags)
                            .bind(UtcInstant(ep.created_at));
                    }
                    q.execute(&mut **conn).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn insert_api_contracts(tx: &mut Tx, contracts: &[NewApiContract]) -> Result<(), StoreError> {
        if contracts.is_empty() {
            return Ok(());
        }
        for chunk in contracts.chunks(500) {
            match tx {
                Tx::MySql(conn) => {
                    let mut sql = String::from(
                        "insert into t_api_contract (repository_id, scan_id, contract_path, format, title, version, endpoints_count, created_at) values ",
                    );
                    for i in 0..chunk.len() {
                        if i > 0 {
                            sql.push_str(", ");
                        }
                        sql.push_str("(?, ?, ?, ?, ?, ?, ?, ?)");
                    }
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for c in chunk {
                        q = q
                            .bind(c.repository_id)
                            .bind(c.scan_id)
                            .bind(&c.contract_path)
                            .bind(&c.format)
                            .bind(&c.title)
                            .bind(&c.version)
                            .bind(c.endpoints_count)
                            .bind(UtcInstant(c.created_at));
                    }
                    q.execute(&mut **conn).await?;
                }
                Tx::PostgreSql(conn) => {
                    let mut sql = String::from(
                        "insert into t_api_contract (repository_id, scan_id, contract_path, format, title, version, endpoints_count, created_at) values ",
                    );
                    for i in 0..chunk.len() {
                        if i > 0 {
                            sql.push_str(", ");
                        }
                        let base = i.saturating_mul(8);
                        let params = (1..=8)
                            .map(|offset| format!("${}", base.saturating_add(offset)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        sql.push_str(&format!("({params})"));
                    }
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for c in chunk {
                        q = q
                            .bind(c.repository_id)
                            .bind(c.scan_id)
                            .bind(&c.contract_path)
                            .bind(&c.format)
                            .bind(&c.title)
                            .bind(&c.version)
                            .bind(c.endpoints_count)
                            .bind(UtcInstant(c.created_at));
                    }
                    q.execute(&mut **conn).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn find_api_endpoints_by_repo(db: &Db, repo_id: i64) -> Result<Vec<ApiEndpointRow>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = match &tx {
            Tx::MySql(_) => {
                "select id, scan_id, repository_id, http_method, path, auth_required, auth_type, visibility, file_path, line_number, framework, operation_id, summary, tags, created_at \
                 from t_api_endpoint where repository_id = ? order by path asc, id asc"
            }
            Tx::PostgreSql(_) => {
                "select id, scan_id, repository_id, http_method, path, auth_required, auth_type, visibility, file_path, line_number, framework, operation_id, summary, tags, created_at \
                 from t_api_endpoint where repository_id = $1 order by path asc, id asc"
            }
        };
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_api_endpoint_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_api_endpoint_row!(r)).collect())
            }
        }
    }

    pub async fn find_api_contracts_by_repo(db: &Db, repo_id: i64) -> Result<Vec<ApiContractRow>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = match &tx {
            Tx::MySql(_) => {
                "select id, repository_id, scan_id, contract_path, format, title, version, endpoints_count, created_at \
                 from t_api_contract where repository_id = ? order by id asc"
            }
            Tx::PostgreSql(_) => {
                "select id, repository_id, scan_id, contract_path, format, title, version, endpoints_count, created_at \
                 from t_api_contract where repository_id = $1 order by id asc"
            }
        };
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_api_contract_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).bind(repo_id).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_api_contract_row!(r)).collect())
            }
        }
    }

    pub async fn find_api_endpoints_by_repos(db: &Db, repo_ids: &[i64]) -> Result<Vec<ApiEndpointRow>, StoreError> {
        if repo_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let mut result = Vec::new();
        for chunk in repo_ids.chunks(1000) {
            match &mut tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!(
                        "select id, scan_id, repository_id, http_method, path, auth_required, auth_type, visibility, file_path, line_number, framework, operation_id, summary, tags, created_at \
                         from t_api_endpoint where repository_id in ({placeholders}) order by id asc"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    result.extend(rows.into_iter().map(|r| parse_api_endpoint_row!(r)));
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!(
                        "select id, scan_id, repository_id, http_method, path, auth_required, auth_type, visibility, file_path, line_number, framework, operation_id, summary, tags, created_at \
                         from t_api_endpoint where repository_id in ({placeholders}) order by id asc"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    result.extend(rows.into_iter().map(|r| parse_api_endpoint_row!(r)));
                }
            }
        }
        Ok(result)
    }

    pub async fn find_api_contracts_by_repos(db: &Db, repo_ids: &[i64]) -> Result<Vec<ApiContractRow>, StoreError> {
        if repo_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let mut result = Vec::new();
        for chunk in repo_ids.chunks(1000) {
            match &mut tx {
                Tx::MySql(conn) => {
                    let placeholders = vec!["?"; chunk.len()].join(",");
                    let sql = format!(
                        "select id, repository_id, scan_id, contract_path, format, title, version, endpoints_count, created_at \
                         from t_api_contract where repository_id in ({placeholders}) order by id asc"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    result.extend(rows.into_iter().map(|r| parse_api_contract_row!(r)));
                }
                Tx::PostgreSql(conn) => {
                    let placeholders = (1..=chunk.len()).map(|i| format!("${i}")).collect::<Vec<_>>().join(",");
                    let sql = format!(
                        "select id, repository_id, scan_id, contract_path, format, title, version, endpoints_count, created_at \
                         from t_api_contract where repository_id in ({placeholders}) order by id asc"
                    );
                    let mut q = sqlx::query(AssertSqlSafe(sql));
                    for id in chunk {
                        q = q.bind(id);
                    }
                    let rows = q.fetch_all(&mut **conn).await?;
                    result.extend(rows.into_iter().map(|r| parse_api_contract_row!(r)));
                }
            }
        }
        Ok(result)
    }

    pub async fn find_all_api_endpoints(db: &Db) -> Result<Vec<ApiEndpointRow>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = "select id, scan_id, repository_id, http_method, path, auth_required, auth_type, visibility, file_path, line_number, framework, operation_id, summary, tags, created_at from t_api_endpoint order by id asc";
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_api_endpoint_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_api_endpoint_row!(r)).collect())
            }
        }
    }

    pub async fn find_all_api_contracts(db: &Db) -> Result<Vec<ApiContractRow>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = "select id, repository_id, scan_id, contract_path, format, title, version, endpoints_count, created_at from t_api_contract order by id asc";
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_api_contract_row!(r)).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| parse_api_contract_row!(r)).collect())
            }
        }
    }

    pub async fn find_distinct_frameworks(db: &Db) -> Result<Vec<String>, StoreError> {
        let mut tx = db.begin(Mode::ReadOnly).await?;
        let sql = "select distinct framework from t_api_endpoint where framework is not null order by framework asc";
        match &mut tx {
            Tx::MySql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("framework")).collect())
            }
            Tx::PostgreSql(conn) => {
                let rows = sqlx::query(AssertSqlSafe(sql)).fetch_all(&mut **conn).await?;
                Ok(rows.into_iter().map(|r| r.get("framework")).collect())
            }
        }
    }
}
