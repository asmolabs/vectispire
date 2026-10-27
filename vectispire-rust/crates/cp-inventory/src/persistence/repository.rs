//! Persistence statements for the inventory's tables: `t_component`, `t_build_sbom`, `t_build_sbom_component`,
//! `t_license_policy`, `t_api_endpoint`, `t_api_contract`.
//!
//! **Built with SeaORM, run on the caller's [`Tx`]** (`vectispire_cp_db::orm`): each statement is written once, from the
//! entities in [`super::entities`], and rendered for the transaction's engine — where there were two hand-written copies
//! of each, and readers that turned a flag they could not decode into `false` (an endpoint read as open) or `None`.

use sea_orm::sea_query::{
    Alias, Condition, Expr, ExprTrait, Func, IntoColumnRef, OnConflict, Order, Query, SelectStatement,
};
use sea_orm::{
    ActiveValue::NotSet, ActiveValue::Set, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait,
};
use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, Tx, orm};

use super::entities::{api_contract, api_endpoint, build_sbom, build_sbom_component, component, license_policy};

use super::entities::api_contract::Column as ApiContractColumn;
use super::entities::api_contract::Entity as ApiContracts;
use super::entities::api_endpoint::Column as ApiEndpointColumn;
use super::entities::api_endpoint::Entity as ApiEndpoints;
use super::entities::build_sbom::Column as BuildSbomColumn;
use super::entities::build_sbom::Entity as BuildSboms;
use super::entities::build_sbom_component::Column as BuildSbomComponentColumn;
use super::entities::build_sbom_component::Entity as BuildSbomComponents;
use super::entities::component::Column as ComponentColumn;
use super::entities::component::Entity as Components;
use super::entities::license_policy::Column as LicensePolicyColumn;
use super::entities::license_policy::Entity as LicensePolicies;

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

/// How many identifiers one bound `IN` list carries — `LOOKUP_BATCH`: one parameter each, and both drivers refuse a
/// statement past 65,535.
const LOOKUP_BATCH: usize = 1_000;

/// Rows per multi-row insert: fourteen columns at most, so 7,000 parameters a statement.
const INSERT_BATCH: usize = 500;

/// Each identifier once, in order — two copies of one in two batches would read its rows twice.
fn distinct(ids: &[i64]) -> Vec<i64> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// A read for a caller holding no transaction: one of its own, read-only, closed when the read is done.
async fn reading<T>(db: &Db, read: impl AsyncFnOnce(&mut Tx) -> Result<T, StoreError>) -> Result<T, StoreError> {
    let mut tx = db.begin(Mode::ReadOnly).await?;
    let answer = read(&mut tx).await?;
    tx.commit().await?;
    Ok(answer)
}

/// A write for a caller holding no transaction: one of its own, committed.
async fn writing<T>(db: &Db, write: impl AsyncFnOnce(&mut Tx) -> Result<T, StoreError>) -> Result<T, StoreError> {
    let mut tx = db.begin(Mode::ReadWrite).await?;
    let answer = write(&mut tx).await?;
    tx.commit().await?;
    Ok(answer)
}

/// `lower(<column>) like <pattern>`; the pattern is the caller's, lowered already.
fn lower_like(column: impl IntoColumnRef, pattern: &str) -> Expr {
    Expr::expr(Func::lower(Expr::col(column))).like(pattern)
}

/// Java's `lower(c.name) like :name or lower(c.purl) like :name`: nobody remembers whether it is `log4j-core` or
/// `org.apache.logging.log4j:log4j-core`, and the purl says both.
fn names_or_purl(pattern: &str) -> Condition {
    Condition::any().add(lower_like(ComponentColumn::Name, pattern)).add(lower_like(ComponentColumn::Purl, pattern))
}

async fn components(tx: &mut Tx, select: SelectStatement) -> Result<Vec<ComponentRow>, StoreError> {
    let models: Vec<component::Model> = orm::fetch_all(tx, &select).await?;
    Ok(models.into_iter().map(ComponentRow::from).collect())
}

impl From<component::Model> for ComponentRow {
    fn from(model: component::Model) -> ComponentRow {
        ComponentRow {
            id: model.id,
            scan_id: model.scan_id,
            repo_id: model.repo_id,
            container_id: model.container_id,
            scan_created_at: model.scan_created_at,
            name: model.name,
            version: model.version,
            purl: model.purl,
            type_: model.type_,
            is_direct: model.is_direct,
            origin: model.origin,
            build_sbom_id: model.build_sbom_id,
            scanned_version: model.scanned_version,
            scanned_purl: model.scanned_purl,
            declared_license: model.declared_license,
        }
    }
}

impl From<build_sbom::Model> for BuildSbomRow {
    fn from(model: build_sbom::Model) -> BuildSbomRow {
        BuildSbomRow {
            id: model.id,
            source_id: model.source_id,
            source_slug: model.source_slug,
            repo_id: model.repo_id,
            spec_version: model.spec_version,
            tool: model.tool,
            components_count: model.components_count,
            commit_sha: model.commit_sha,
            branch_name: model.branch_name,
            document_sha256: model.document_sha256,
            imported_at: model.imported_at,
            imported_by: model.imported_by,
            api_key_id: model.api_key_id,
        }
    }
}

impl From<api_endpoint::Model> for ApiEndpointRow {
    fn from(model: api_endpoint::Model) -> ApiEndpointRow {
        ApiEndpointRow {
            id: model.id,
            scan_id: model.scan_id,
            repository_id: model.repository_id,
            http_method: model.http_method,
            path: model.path,
            auth_required: model.auth_required,
            auth_type: model.auth_type,
            visibility: model.visibility,
            file_path: model.file_path,
            line_number: model.line_number,
            framework: model.framework,
            operation_id: model.operation_id,
            summary: model.summary,
            tags: model.tags,
            created_at: model.created_at,
        }
    }
}

impl From<api_contract::Model> for ApiContractRow {
    fn from(model: api_contract::Model) -> ApiContractRow {
        ApiContractRow {
            id: model.id,
            repository_id: model.repository_id,
            scan_id: model.scan_id,
            contract_path: model.contract_path,
            format: model.format,
            title: model.title,
            version: model.version,
            endpoints_count: model.endpoints_count,
            created_at: model.created_at,
        }
    }
}

async fn endpoints(tx: &mut Tx, select: SelectStatement) -> Result<Vec<ApiEndpointRow>, StoreError> {
    let models: Vec<api_endpoint::Model> = orm::fetch_all(tx, &select).await?;
    Ok(models.into_iter().map(ApiEndpointRow::from).collect())
}

async fn contracts(tx: &mut Tx, select: SelectStatement) -> Result<Vec<ApiContractRow>, StoreError> {
    let models: Vec<api_contract::Model> = orm::fetch_all(tx, &select).await?;
    Ok(models.into_iter().map(ApiContractRow::from).collect())
}

#[derive(Debug, FromQueryResult)]
struct One<T: sea_orm::TryGetable> {
    value: T,
}

/// `select [distinct] <expression> as value …`, one column, each row's value.
async fn values<T: sea_orm::TryGetable>(tx: &mut Tx, select: SelectStatement) -> Result<Vec<T>, StoreError> {
    let rows: Vec<One<T>> = orm::fetch_all(tx, &select).await?;
    Ok(rows.into_iter().map(|row| row.value).collect())
}

fn select_value(expression: impl Into<Expr>) -> SelectStatement {
    Query::select().expr_as(expression.into(), Alias::new("value")).to_owned()
}

#[derive(Debug, Clone, Copy)]
pub struct InventoryRepository;

impl InventoryRepository {
    // -------------------------------------------------------------------------
    // t_component
    // -------------------------------------------------------------------------

    pub async fn delete_components_by_scan_id(tx: &mut Tx, scan_id: i64) -> Result<u64, StoreError> {
        let delete = Components::delete_many().filter(ComponentColumn::ScanId.eq(scan_id)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }

    pub async fn delete_components_by_scan_ids(tx: &mut Tx, scan_ids: &[i64]) -> Result<u64, StoreError> {
        let mut total = 0u64;
        for chunk in distinct(scan_ids).chunks(LOOKUP_BATCH) {
            let delete =
                Components::delete_many().filter(ComponentColumn::ScanId.is_in(chunk.iter().copied())).into_query();
            total = total.saturating_add(orm::execute(tx, &delete).await?);
        }
        Ok(total)
    }

    pub async fn delete_components_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
        let mut total = 0u64;
        for chunk in distinct(ids).chunks(LOOKUP_BATCH) {
            let delete =
                Components::delete_many().filter(ComponentColumn::Id.is_in(chunk.iter().copied())).into_query();
            total = total.saturating_add(orm::execute(tx, &delete).await?);
        }
        Ok(total)
    }

    pub async fn insert_components(tx: &mut Tx, rows: &[NewComponent]) -> Result<(), StoreError> {
        for chunk in rows.chunks(INSERT_BATCH) {
            let actives = chunk.iter().map(|row| component::ActiveModel {
                id: NotSet,
                scan_id: Set(row.scan_id),
                name: Set(row.name.clone()),
                version: Set(row.version.clone()),
                purl: Set(row.purl.clone()),
                type_: Set(row.type_.clone()),
                is_direct: Set(row.is_direct),
                repo_id: Set(row.repo_id),
                container_id: Set(row.container_id),
                scan_created_at: Set(row.scan_created_at),
                origin: Set(row.origin.clone()),
                build_sbom_id: Set(row.build_sbom_id),
                scanned_version: Set(row.scanned_version.clone()),
                scanned_purl: Set(row.scanned_purl.clone()),
                declared_license: Set(row.declared_license.clone()),
            });
            orm::execute(tx, &Components::insert_many(actives).into_query()).await?;
        }
        Ok(())
    }

    /// What completing a scan with a build SBOM changes of each row; one statement per row, as Hibernate wrote them.
    pub async fn update_components(tx: &mut Tx, rows: &[ComponentRow]) -> Result<(), StoreError> {
        for row in rows {
            let update = Components::update_many()
                .col_expr(ComponentColumn::Version, Expr::value(row.version.clone()))
                .col_expr(ComponentColumn::Purl, Expr::value(row.purl.clone()))
                .col_expr(ComponentColumn::Origin, Expr::value(row.origin.clone()))
                .col_expr(ComponentColumn::BuildSbomId, Expr::value(row.build_sbom_id))
                .col_expr(ComponentColumn::ScannedVersion, Expr::value(row.scanned_version.clone()))
                .col_expr(ComponentColumn::ScannedPurl, Expr::value(row.scanned_purl.clone()))
                .col_expr(ComponentColumn::DeclaredLicense, Expr::value(row.declared_license.clone()))
                .filter(ComponentColumn::Id.eq(row.id))
                .into_query();
            orm::execute(tx, &update).await?;
        }
        Ok(())
    }

    pub async fn find_components_by_scan_id(db: &Db, scan_id: i64) -> Result<Vec<ComponentRow>, StoreError> {
        reading(db, async |tx| Self::find_components_by_scan_id_tx(tx, scan_id).await).await
    }

    pub async fn find_components_by_scan_id_tx(tx: &mut Tx, scan_id: i64) -> Result<Vec<ComponentRow>, StoreError> {
        let select = Components::find().filter(ComponentColumn::ScanId.eq(scan_id)).order_by_asc(ComponentColumn::Id);
        components(tx, select.into_query()).await
    }

    /// Java's `lockScan`: a scan's rows, `for update`, in key order — two imports completing one scan at once would
    /// otherwise both add the build's components.
    pub async fn lock_scan_components(tx: &mut Tx, scan_id: i64) -> Result<Vec<ComponentRow>, StoreError> {
        let select = Components::find()
            .filter(ComponentColumn::ScanId.eq(scan_id))
            .order_by_asc(ComponentColumn::Id)
            .lock_exclusive();
        components(tx, select.into_query()).await
    }

    /// Java's `namesOfScans` and `findByScanIdIn`: `order by c.scanId, c.id` — of two rows naming one component of one
    /// target, the first decides the purl the licence inventory shows — and each scan read once.
    pub async fn find_components_by_scan_ids(db: &Db, scan_ids: &[i64]) -> Result<Vec<ComponentRow>, StoreError> {
        let ids = distinct(scan_ids);
        reading(db, async |tx| {
            let mut found = Vec::new();
            for chunk in ids.chunks(LOOKUP_BATCH) {
                let select = Components::find()
                    .filter(ComponentColumn::ScanId.is_in(chunk.iter().copied()))
                    .order_by_asc(ComponentColumn::ScanId)
                    .order_by_asc(ComponentColumn::Id);
                found.extend(components(tx, select.into_query()).await?);
            }
            Ok(found)
        })
        .await
    }

    pub async fn indexed_among(db: &Db, scan_ids: &[i64]) -> Result<Vec<i64>, StoreError> {
        let ids = distinct(scan_ids);
        reading(db, async |tx| {
            let mut found = Vec::new();
            for chunk in ids.chunks(LOOKUP_BATCH) {
                let select = select_value(Expr::col(ComponentColumn::ScanId))
                    .distinct()
                    .from(Components)
                    .and_where(Expr::col(ComponentColumn::ScanId).is_in(chunk.iter().copied()))
                    .to_owned();
                found.extend(values::<i64>(tx, select).await?);
            }
            Ok(found)
        })
        .await
    }

    pub async fn count_components_by_scan_ids(db: &Db, scan_ids: &[i64]) -> Result<i64, StoreError> {
        let ids = distinct(scan_ids);
        reading(db, async |tx| {
            let mut total = 0i64;
            for chunk in ids.chunks(LOOKUP_BATCH) {
                let select = select_value(Func::count(Expr::col(ComponentColumn::Id)))
                    .from(Components)
                    .and_where(Expr::col(ComponentColumn::ScanId).is_in(chunk.iter().copied()))
                    .to_owned();
                total = total.saturating_add(orm::fetch_count(tx, &select).await?);
            }
            Ok(total)
        })
        .await
    }

    /// Java's `search`: by name or purl, the version exactly — `2.14.1` is not `2.14.10`, a different release with a
    /// different verdict — newest scan first, then by name, bounded; the bound keeping the newest is why the order is
    /// the scan's instant and not the key, which is the order of writing.
    pub async fn search_components(
        db: &Db,
        name_like: &str,
        version: Option<&str>,
        limit: i64,
    ) -> Result<Vec<ComponentRow>, StoreError> {
        let mut select = Components::find().filter(names_or_purl(name_like));
        if let Some(version) = version {
            select = select.filter(ComponentColumn::Version.eq(version));
        }
        let select = select
            .order_by_desc(ComponentColumn::ScanCreatedAt)
            .order_by_asc(ComponentColumn::Name)
            .limit(u64::try_from(limit).unwrap_or(0));
        reading(db, async |tx| components(tx, select.into_query()).await).await
    }

    /// Java's `versionsOf`: each version and target once, by name or purl, newest version first, bounded — a row
    /// without a version is left out here rather than after the bound, where it took a place in it.
    pub async fn versions_of(
        db: &Db,
        name_like: &str,
        limit: i64,
    ) -> Result<Vec<(String, Option<i64>, Option<i64>)>, StoreError> {
        #[derive(Debug, FromQueryResult)]
        struct Version {
            version: String,
            repo_id: Option<i64>,
            container_id: Option<i64>,
        }
        let select = Query::select()
            .distinct()
            .columns([ComponentColumn::Version, ComponentColumn::RepoId, ComponentColumn::ContainerId])
            .from(Components)
            .cond_where(names_or_purl(name_like))
            .and_where(Expr::col(ComponentColumn::Version).is_not_null())
            .order_by(ComponentColumn::Version, Order::Desc)
            .limit(u64::try_from(limit).unwrap_or(0))
            .to_owned();
        let rows: Vec<Version> = reading(db, async |tx| Ok(orm::fetch_all(tx, &select).await?)).await?;
        Ok(rows.into_iter().map(|row| (row.version, row.repo_id, row.container_id)).collect())
    }

    pub async fn distinct_purls(db: &Db) -> Result<Vec<String>, StoreError> {
        let select = select_value(Expr::col(ComponentColumn::Purl))
            .distinct()
            .from(Components)
            .and_where(Expr::col(ComponentColumn::Purl).is_not_null())
            .order_by(ComponentColumn::Purl, Order::Asc)
            .to_owned();
        reading(db, async |tx| values::<String>(tx, select).await).await
    }

    /// Java's `distinctPurlsByTarget`: a row naming a repository and an image comes back with both, on both sides.
    pub async fn distinct_purls_by_target(db: &Db) -> Result<Vec<(Option<i64>, Option<i64>, String)>, StoreError> {
        #[derive(Debug, FromQueryResult)]
        struct Purl {
            repo_id: Option<i64>,
            container_id: Option<i64>,
            purl: String,
        }
        let select = Query::select()
            .distinct()
            .columns([ComponentColumn::RepoId, ComponentColumn::ContainerId, ComponentColumn::Purl])
            .from(Components)
            .and_where(Expr::col(ComponentColumn::Purl).is_not_null())
            .to_owned();
        let rows: Vec<Purl> = reading(db, async |tx| Ok(orm::fetch_all(tx, &select).await?)).await?;
        Ok(rows.into_iter().map(|row| (row.repo_id, row.container_id, row.purl)).collect())
    }

    pub async fn distinct_repositories_with_components(db: &Db) -> Result<Vec<i64>, StoreError> {
        Self::distinct_targets(db, ComponentColumn::RepoId).await
    }

    /// Java's `distinctContainersWithComponents`, which does not add `repo_id is null`: a row naming both counts the
    /// image as inventoried.
    pub async fn distinct_containers_with_components(db: &Db) -> Result<Vec<i64>, StoreError> {
        Self::distinct_targets(db, ComponentColumn::ContainerId).await
    }

    async fn distinct_targets(db: &Db, column: ComponentColumn) -> Result<Vec<i64>, StoreError> {
        let select = select_value(Expr::col(column))
            .distinct()
            .from(Components)
            .and_where(Expr::col(column).is_not_null())
            .to_owned();
        reading(db, async |tx| values::<i64>(tx, select).await).await
    }

    /// For each of these imports, the newest scan it completed.
    pub async fn newest_scan_completed_by(db: &Db, build_sbom_ids: &[i64]) -> Result<Vec<(i64, i64)>, StoreError> {
        #[derive(Debug, FromQueryResult)]
        struct Completed {
            build_sbom_id: i64,
            scan_id: i64,
        }
        let ids = distinct(build_sbom_ids);
        reading(db, async |tx| {
            let mut found = Vec::new();
            for chunk in ids.chunks(LOOKUP_BATCH) {
                let select = Query::select()
                    .column(ComponentColumn::BuildSbomId)
                    .expr_as(Func::max(Expr::col(ComponentColumn::ScanId)), Alias::new("scan_id"))
                    .from(Components)
                    .and_where(Expr::col(ComponentColumn::BuildSbomId).is_in(chunk.iter().copied()))
                    .group_by_col(ComponentColumn::BuildSbomId)
                    .to_owned();
                let rows: Vec<Completed> = orm::fetch_all(tx, &select).await?;
                found.extend(rows.into_iter().map(|row| (row.build_sbom_id, row.scan_id)));
            }
            Ok(found)
        })
        .await
    }

    // -------------------------------------------------------------------------
    // t_build_sbom, t_build_sbom_component
    // -------------------------------------------------------------------------

    pub async fn insert_build_sbom(tx: &mut Tx, row: &NewBuildSbom) -> Result<i64, StoreError> {
        let active = build_sbom::ActiveModel {
            id: NotSet,
            source_id: Set(row.source_id),
            source_slug: Set(row.source_slug.clone()),
            repo_id: Set(row.repo_id),
            spec_version: Set(row.spec_version.clone()),
            tool: Set(row.tool.clone()),
            components_count: Set(row.components_count),
            commit_sha: Set(row.commit_sha.clone()),
            branch_name: Set(row.branch_name.clone()),
            document_sha256: Set(row.document_sha256.clone()),
            imported_at: Set(row.imported_at),
            imported_by: Set(row.imported_by.clone()),
            api_key_id: Set(row.api_key_id.clone()),
        };
        Ok(orm::insert_returning_id::<BuildSboms>(tx, BuildSboms::insert(active).into_query()).await?)
    }

    /// In document order: the keys are handed out in the order of the `VALUES`, and the import's components are read
    /// back by key.
    pub async fn insert_build_sbom_components(tx: &mut Tx, rows: &[NewBuildSbomComponent]) -> Result<(), StoreError> {
        for chunk in rows.chunks(INSERT_BATCH) {
            let actives = chunk.iter().map(|row| build_sbom_component::ActiveModel {
                id: NotSet,
                import_id: Set(row.import_id),
                name: Set(row.name.clone()),
                version: Set(row.version.clone()),
                purl: Set(row.purl.clone()),
                type_: Set(row.type_.clone()),
                license: Set(row.license.clone()),
            });
            orm::execute(tx, &BuildSbomComponents::insert_many(actives).into_query()).await?;
        }
        Ok(())
    }

    /// Java's `newestFor`: the newest import of the repository stating the scan's branch, or stating none. A scan with
    /// no branch is spoken for by an import stating none — `branch = null` is unknown, never "any branch"; the
    /// hand-written `? is null or …` let another branch's SBOM complete it.
    pub async fn find_newest_build_sbom_for_repo(
        tx: &mut Tx,
        repo_id: i64,
        branch: Option<&str>,
    ) -> Result<Option<BuildSbomRow>, StoreError> {
        let mut branches = Condition::any().add(BuildSbomColumn::BranchName.is_null());
        if let Some(branch) = branch {
            branches = branches.add(BuildSbomColumn::BranchName.eq(branch));
        }
        let select = BuildSboms::find()
            .filter(BuildSbomColumn::RepoId.eq(repo_id))
            .filter(branches)
            .order_by_desc(BuildSbomColumn::Id)
            .limit(1)
            .into_query();
        let model: Option<build_sbom::Model> = orm::fetch_optional(tx, &select).await?;
        Ok(model.map(BuildSbomRow::from))
    }

    pub async fn find_build_sbom_components(
        tx: &mut Tx,
        import_id: i64,
    ) -> Result<Vec<BuildSbomComponentRow>, StoreError> {
        let select = BuildSbomComponents::find()
            .filter(BuildSbomComponentColumn::ImportId.eq(import_id))
            .order_by_asc(BuildSbomComponentColumn::Id)
            .into_query();
        let models: Vec<build_sbom_component::Model> = orm::fetch_all(tx, &select).await?;
        Ok(models
            .into_iter()
            .map(|model| BuildSbomComponentRow {
                id: model.id,
                import_id: model.import_id,
                name: model.name,
                version: model.version,
                purl: model.purl,
                type_: model.type_,
                license: model.license,
            })
            .collect())
    }

    pub async fn find_build_sboms_by_repo(db: &Db, repo_id: i64, limit: i64) -> Result<Vec<BuildSbomRow>, StoreError> {
        let select = BuildSboms::find()
            .filter(BuildSbomColumn::RepoId.eq(repo_id))
            .order_by_desc(BuildSbomColumn::Id)
            .limit(u64::try_from(limit).unwrap_or(0))
            .into_query();
        let models: Vec<build_sbom::Model> = reading(db, async |tx| Ok(orm::fetch_all(tx, &select).await?)).await?;
        Ok(models.into_iter().map(BuildSbomRow::from).collect())
    }

    pub async fn find_build_sbom_ids_by_repo(tx: &mut Tx, repo_id: i64) -> Result<Vec<i64>, StoreError> {
        let select = select_value(Expr::col(BuildSbomColumn::Id))
            .from(BuildSboms)
            .and_where(Expr::col(BuildSbomColumn::RepoId).eq(repo_id))
            .order_by(BuildSbomColumn::Id, Order::Asc)
            .to_owned();
        values::<i64>(tx, select).await
    }

    pub async fn find_build_sbom_ids_imported_before(
        tx: &mut Tx,
        cutoff: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<i64>, StoreError> {
        let select = select_value(Expr::col(BuildSbomColumn::Id))
            .from(BuildSboms)
            .and_where(Expr::col(BuildSbomColumn::ImportedAt).lt(cutoff))
            .order_by(BuildSbomColumn::Id, Order::Asc)
            .limit(u64::try_from(limit).unwrap_or(0))
            .to_owned();
        values::<i64>(tx, select).await
    }

    pub async fn delete_build_sbom_components_by_import_ids(
        tx: &mut Tx,
        import_ids: &[i64],
    ) -> Result<u64, StoreError> {
        let mut total = 0u64;
        for chunk in distinct(import_ids).chunks(LOOKUP_BATCH) {
            let delete = BuildSbomComponents::delete_many()
                .filter(BuildSbomComponentColumn::ImportId.is_in(chunk.iter().copied()))
                .into_query();
            total = total.saturating_add(orm::execute(tx, &delete).await?);
        }
        Ok(total)
    }

    pub async fn delete_build_sboms_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
        let mut total = 0u64;
        for chunk in distinct(ids).chunks(LOOKUP_BATCH) {
            let delete =
                BuildSboms::delete_many().filter(BuildSbomColumn::Id.is_in(chunk.iter().copied())).into_query();
            total = total.saturating_add(orm::execute(tx, &delete).await?);
        }
        Ok(total)
    }

    // -------------------------------------------------------------------------
    // t_license_policy
    // -------------------------------------------------------------------------

    pub async fn find_license_policy(db: &Db) -> Result<Option<LicensePolicyRow>, StoreError> {
        let select = LicensePolicies::find().filter(LicensePolicyColumn::Id.eq(1i64)).into_query();
        let model: Option<license_policy::Model> =
            reading(db, async |tx| Ok(orm::fetch_optional(tx, &select).await?)).await?;
        Ok(model.map(|model| LicensePolicyRow {
            id: model.id,
            disallowed_categories: model.disallowed_categories,
            allowed_licenses: model.allowed_licenses,
            disallowed_licenses: model.disallowed_licenses,
            updated_at: model.updated_at,
        }))
    }

    /// The singleton, replaced in one statement — an insert that updates on the key, so two writers cannot both find
    /// it missing — and stamped with `at`, the application's instant: Java's `clock.instant()`, where the hand-written
    /// statement took the database's `now()`, which is the session's time zone on MySQL.
    pub async fn upsert_license_policy(
        tx: &mut Tx,
        disallowed_categories: &str,
        allowed_licenses: Option<&str>,
        disallowed_licenses: Option<&str>,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let active = license_policy::ActiveModel {
            id: Set(1),
            disallowed_categories: Set(disallowed_categories.to_owned()),
            allowed_licenses: Set(allowed_licenses.map(str::to_owned)),
            disallowed_licenses: Set(disallowed_licenses.map(str::to_owned)),
            updated_at: Set(at),
        };
        let upsert = LicensePolicies::insert(active)
            .on_conflict(
                OnConflict::column(LicensePolicyColumn::Id)
                    .update_columns([
                        LicensePolicyColumn::DisallowedCategories,
                        LicensePolicyColumn::AllowedLicenses,
                        LicensePolicyColumn::DisallowedLicenses,
                        LicensePolicyColumn::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .into_query();
        orm::execute(tx, &upsert).await?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // t_api_endpoint, t_api_contract
    // -------------------------------------------------------------------------

    pub async fn delete_api_endpoints_by_scan_id(tx: &mut Tx, scan_id: i64) -> Result<u64, StoreError> {
        let delete = ApiEndpoints::delete_many().filter(ApiEndpointColumn::ScanId.eq(scan_id)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }

    pub async fn delete_api_contracts_by_scan_id(tx: &mut Tx, scan_id: i64) -> Result<u64, StoreError> {
        let delete = ApiContracts::delete_many().filter(ApiContractColumn::ScanId.eq(scan_id)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }

    pub async fn delete_all_api_endpoints(tx: &mut Tx) -> Result<u64, StoreError> {
        Ok(orm::execute(tx, &ApiEndpoints::delete_many().into_query()).await?)
    }

    pub async fn delete_all_api_contracts(tx: &mut Tx) -> Result<u64, StoreError> {
        Ok(orm::execute(tx, &ApiContracts::delete_many().into_query()).await?)
    }

    pub async fn delete_api_endpoints_by_repo_tx(tx: &mut Tx, repo_id: i64) -> Result<u64, StoreError> {
        let delete = ApiEndpoints::delete_many().filter(ApiEndpointColumn::RepositoryId.eq(repo_id)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }

    pub async fn delete_api_endpoints_by_repo(db: &Db, repo_id: i64) -> Result<u64, StoreError> {
        writing(db, async |tx| Self::delete_api_endpoints_by_repo_tx(tx, repo_id).await).await
    }

    pub async fn delete_api_contracts_by_repo_tx(tx: &mut Tx, repo_id: i64) -> Result<u64, StoreError> {
        let delete = ApiContracts::delete_many().filter(ApiContractColumn::RepositoryId.eq(repo_id)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }

    pub async fn delete_api_contracts_by_repo(db: &Db, repo_id: i64) -> Result<u64, StoreError> {
        writing(db, async |tx| Self::delete_api_contracts_by_repo_tx(tx, repo_id).await).await
    }

    pub async fn insert_api_endpoints(tx: &mut Tx, rows: &[NewApiEndpoint]) -> Result<(), StoreError> {
        for chunk in rows.chunks(INSERT_BATCH) {
            let actives = chunk.iter().map(|row| api_endpoint::ActiveModel {
                id: NotSet,
                scan_id: Set(row.scan_id),
                repository_id: Set(row.repository_id),
                http_method: Set(row.http_method.clone()),
                path: Set(row.path.clone()),
                auth_required: Set(row.auth_required),
                auth_type: Set(row.auth_type.clone()),
                visibility: Set(row.visibility.clone()),
                file_path: Set(row.file_path.clone()),
                line_number: Set(row.line_number),
                framework: Set(row.framework.clone()),
                operation_id: Set(row.operation_id.clone()),
                summary: Set(row.summary.clone()),
                tags: Set(row.tags.clone()),
                created_at: Set(row.created_at),
            });
            orm::execute(tx, &ApiEndpoints::insert_many(actives).into_query()).await?;
        }
        Ok(())
    }

    pub async fn insert_api_contracts(tx: &mut Tx, rows: &[NewApiContract]) -> Result<(), StoreError> {
        for chunk in rows.chunks(INSERT_BATCH) {
            let actives = chunk.iter().map(|row| api_contract::ActiveModel {
                id: NotSet,
                repository_id: Set(row.repository_id),
                scan_id: Set(row.scan_id),
                contract_path: Set(row.contract_path.clone()),
                format: Set(row.format.clone()),
                title: Set(row.title.clone()),
                version: Set(row.version.clone()),
                endpoints_count: Set(row.endpoints_count),
                created_at: Set(row.created_at),
            });
            orm::execute(tx, &ApiContracts::insert_many(actives).into_query()).await?;
        }
        Ok(())
    }

    /// Java's `findByRepositoryIdOrderByPathAsc`, the key breaking a tie.
    pub async fn find_api_endpoints_by_repo(db: &Db, repo_id: i64) -> Result<Vec<ApiEndpointRow>, StoreError> {
        let select = ApiEndpoints::find()
            .filter(ApiEndpointColumn::RepositoryId.eq(repo_id))
            .order_by_asc(ApiEndpointColumn::Path)
            .order_by_asc(ApiEndpointColumn::Id)
            .into_query();
        reading(db, async |tx| endpoints(tx, select).await).await
    }

    /// Java's `findByRepositoryIdOrderByCreatedAtDesc`: newest first — the hand-written read listed them oldest first.
    pub async fn find_api_contracts_by_repo(db: &Db, repo_id: i64) -> Result<Vec<ApiContractRow>, StoreError> {
        let select = ApiContracts::find()
            .filter(ApiContractColumn::RepositoryId.eq(repo_id))
            .order_by_desc(ApiContractColumn::CreatedAt)
            .order_by_desc(ApiContractColumn::Id)
            .into_query();
        reading(db, async |tx| contracts(tx, select).await).await
    }

    pub async fn find_api_endpoints_by_repos(db: &Db, repo_ids: &[i64]) -> Result<Vec<ApiEndpointRow>, StoreError> {
        let ids = distinct(repo_ids);
        reading(db, async |tx| {
            let mut found = Vec::new();
            for chunk in ids.chunks(LOOKUP_BATCH) {
                let select = ApiEndpoints::find()
                    .filter(ApiEndpointColumn::RepositoryId.is_in(chunk.iter().copied()))
                    .order_by_asc(ApiEndpointColumn::Id)
                    .into_query();
                found.extend(endpoints(tx, select).await?);
            }
            Ok(found)
        })
        .await
    }

    pub async fn find_api_contracts_by_repos(db: &Db, repo_ids: &[i64]) -> Result<Vec<ApiContractRow>, StoreError> {
        let ids = distinct(repo_ids);
        reading(db, async |tx| {
            let mut found = Vec::new();
            for chunk in ids.chunks(LOOKUP_BATCH) {
                let select = ApiContracts::find()
                    .filter(ApiContractColumn::RepositoryId.is_in(chunk.iter().copied()))
                    .order_by_asc(ApiContractColumn::Id)
                    .into_query();
                found.extend(contracts(tx, select).await?);
            }
            Ok(found)
        })
        .await
    }

    pub async fn find_all_api_endpoints(db: &Db) -> Result<Vec<ApiEndpointRow>, StoreError> {
        let select = ApiEndpoints::find().order_by_asc(ApiEndpointColumn::Id).into_query();
        reading(db, async |tx| endpoints(tx, select).await).await
    }

    pub async fn find_all_api_contracts(db: &Db) -> Result<Vec<ApiContractRow>, StoreError> {
        let select = ApiContracts::find().order_by_asc(ApiContractColumn::Id).into_query();
        reading(db, async |tx| contracts(tx, select).await).await
    }

    /// Every framework once. No visibility, as on the Java side: a restricted reader is told which frameworks the
    /// estate uses (a filter value, not an endpoint).
    pub async fn find_distinct_frameworks(db: &Db) -> Result<Vec<String>, StoreError> {
        let select = select_value(Expr::col(ApiEndpointColumn::Framework))
            .distinct()
            .from(ApiEndpoints)
            .and_where(Expr::col(ApiEndpointColumn::Framework).is_not_null())
            .order_by(ApiEndpointColumn::Framework, Order::Asc)
            .to_owned();
        reading(db, async |tx| values::<String>(tx, select).await).await
    }
}
