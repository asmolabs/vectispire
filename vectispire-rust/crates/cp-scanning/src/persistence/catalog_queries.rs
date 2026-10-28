//! Queries on `t_scan` and `t_finding` for `ScanCatalog` (inventory, blast radius, license governance, history).
//!
//! **Built with SeaORM, run on the caller's [`Tx`]** (`vectispire_cp_db::orm`): each statement is written once, from
//! the entities in [`super::entities`], and rendered for the transaction's engine — where there were two hand-written
//! copies per engine, a `?`-to-`$n` renumbering, and readers that tried three integer types before settling on
//! `false` or `0`. The scan lifecycle's fixed statements stay compile-checked `query!`s beside them.

use std::collections::BTreeMap;

use sea_orm::sea_query::{
    Alias, Condition, Expr, ExprTrait, Func, Order, Query, QueryStatementBuilder, SelectStatement,
};
use sea_orm::{ColumnTrait, EntityTrait, FromQueryResult, IdenStatic, Iterable, QueryFilter, QueryOrder, QueryTrait};
use time::OffsetDateTime;
use vectispire_cp_db::orm;
use vectispire_cp_db::query::rows_of;
use vectispire_cp_db::{ScanTarget, Tx, Visibility};

use super::entities::{FindingColumn, FindingModel, Findings, ScanColumn, Scans};
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

/// How many identifiers one bound `IN` list carries — `ScanCatalog.LOOKUP_BATCH`: one parameter each, and both drivers
/// refuse a statement past 65,535.
const LOOKUP_BATCH: usize = 1_000;

/// The scan columns a catalog read answers with — `ScanRow` and whether the SBOM is still held — never the payloads.
#[derive(Debug, FromQueryResult)]
struct ScanColumns {
    id: i64,
    branch: String,
    sub_path: Option<String>,
    status: String,
    duration_ms: Option<i64>,
    findings_count: i32,
    new_issues_count: i32,
    resolved_issues_count: i32,
    error: Option<String>,
    created_at: OffsetDateTime,
    version: Option<String>,
    project_type: Option<String>,
    repo_id: Option<i64>,
    container_id: Option<i64>,
    required_agent_label: Option<String>,
    claimed_by: Option<String>,
    claimed_at: Option<OffsetDateTime>,
    lease_expires_at: Option<OffsetDateTime>,
    attempts: i32,
    not_before: Option<OffsetDateTime>,
    plugin_steps: Option<String>,
    examined_types: Option<String>,
    detected_languages: Option<String>,
    sast_languages: Option<String>,
    has_sbom: i64,
}

const SCAN_COLUMNS: [ScanColumn; 24] = [
    ScanColumn::Id,
    ScanColumn::Branch,
    ScanColumn::SubPath,
    ScanColumn::Status,
    ScanColumn::DurationMs,
    ScanColumn::FindingsCount,
    ScanColumn::NewIssuesCount,
    ScanColumn::ResolvedIssuesCount,
    ScanColumn::Error,
    ScanColumn::CreatedAt,
    ScanColumn::Version,
    ScanColumn::ProjectType,
    ScanColumn::RepoId,
    ScanColumn::ContainerId,
    ScanColumn::RequiredAgentLabel,
    ScanColumn::ClaimedBy,
    ScanColumn::ClaimedAt,
    ScanColumn::LeaseExpiresAt,
    ScanColumn::Attempts,
    ScanColumn::NotBefore,
    ScanColumn::PluginSteps,
    ScanColumn::ExaminedTypes,
    ScanColumn::DetectedLanguages,
    ScanColumn::SastLanguages,
];

/// `1` when the scan still holds its SBOM, `0` otherwise. The two values are bound, so both engines type the `CASE`
/// as a `bigint` — written as literals it was an `int` on PostgreSQL and a `bigint` on MySQL, and the reader tried
/// three types before settling on `false`.
fn holds_sbom() -> Expr {
    Expr::case(Expr::col((Scans, ScanColumn::Sbom)).is_null(), 0i64).finally(1i64).into()
}

/// The scan columns under `prefix` — `s_` beside a finding's — and `has_sbom`.
fn select_scan_columns(select: &mut SelectStatement, prefix: &str) {
    for column in SCAN_COLUMNS {
        select.expr_as(Expr::col((Scans, column)), Alias::new(format!("{prefix}{}", column.as_str())));
    }
    select.expr_as(holds_sbom(), Alias::new(format!("{prefix}has_sbom")));
}

impl From<ScanColumns> for ScanRow {
    fn from(scan: ScanColumns) -> ScanRow {
        ScanRow {
            id: scan.id,
            branch: scan.branch,
            sub_path: scan.sub_path,
            status: scan.status,
            duration_ms: scan.duration_ms,
            findings_count: scan.findings_count,
            new_issues_count: scan.new_issues_count,
            resolved_issues_count: scan.resolved_issues_count,
            error: scan.error,
            created_at: scan.created_at,
            version: scan.version,
            project_type: scan.project_type,
            repo_id: scan.repo_id,
            container_id: scan.container_id,
            required_agent_label: scan.required_agent_label,
            claimed_by: scan.claimed_by,
            claimed_at: scan.claimed_at,
            lease_expires_at: scan.lease_expires_at,
            attempts: scan.attempts,
            not_before: scan.not_before,
            plugin_steps: scan.plugin_steps,
            examined_types: scan.examined_types,
            detected_languages: scan.detected_languages,
            sast_languages: scan.sast_languages,
            has_sbom: scan.has_sbom != 0,
        }
    }
}

impl From<FindingModel> for ScanFindingView {
    fn from(finding: FindingModel) -> ScanFindingView {
        ScanFindingView {
            id: finding.id,
            scan_id: finding.scan_id,
            type_: finding.type_,
            severity: finding.severity,
            identifier: finding.identifier,
            package_name: finding.package_name,
            package_version: finding.package_version,
            purl: finding.purl,
            file_path: finding.file_path,
            owasp_category: finding.owasp_category,
            source: Some(finding.source),
            tool: finding.tool,
            tool_name: finding.tool_name,
            tool_version: finding.tool_version,
            epss_score: finding.epss_score,
            is_kev: finding.is_kev,
            created_at: finding.created_at,
            cvss_score: finding.cvss_score,
            cvss_vector: finding.cvss_vector,
            fix_state: finding.fix_state,
            fix_versions: finding.fix_versions,
            link: finding.link,
            issue_id: finding.issue_id,
            is_direct_dependency: finding.is_direct_dependency,
            line: finding.line,
            description: finding.description,
        }
    }
}

async fn finding_views(tx: &mut Tx, select: SelectStatement) -> Result<Vec<ScanFindingView>, StoreError> {
    let models: Vec<FindingModel> = orm::fetch_all(tx, &select).await?;
    Ok(models.into_iter().map(ScanFindingView::from).collect())
}

/// `select f.*, s.<columns> as s_<column> from t_finding f join t_scan s on f.scan_id = s.id` — every finding column,
/// so that the finding decodes as its entity, and the scan's under `s_`.
fn findings_on_scans() -> SelectStatement {
    let mut select = Query::select();
    for column in FindingColumn::iter() {
        select.column((Findings, column));
    }
    select_scan_columns(&mut select, "s_");
    select
        .from(Findings)
        .inner_join(Scans, Expr::col((Findings, FindingColumn::ScanId)).equals((Scans, ScanColumn::Id)));
    select
}

async fn findings_with_scans(tx: &mut Tx, select: SelectStatement) -> Result<Vec<FindingOnScanRow>, StoreError> {
    let rows = orm::fetch_rows(tx, &select).await?;
    let decode = |row: &sea_orm::QueryResult| -> Result<FindingOnScanRow, sea_orm::DbErr> {
        let finding = FindingModel::from_query_result(row, "")?;
        let scan = ScanColumns::from_query_result(row, "s_")?;
        Ok(FindingOnScanRow { finding: finding.into(), scan: scan.into() })
    };
    rows.iter().map(|row| decode(row).map_err(|error| StoreError(Box::new(error)))).collect()
}

/// The scans a reader may see, applied to the **scan** — where a finding's target lives — by the rule every reader's
/// query keeps (`rows_of`): its repository when it names one, its image otherwise. The identifiers are written into
/// the statement, a thousand to a list, so a reader granted more than the 65,535 parameters a driver binds is
/// answered; bound one by one, both engines refused them (`WideAllowanceIntegrationTest`). `None` for a reader who
/// sees everything. The condition names `repo_id` and `container_id` unqualified: of the two tables joined here only
/// `t_scan` has them.
fn visible_scans(allowed: &Visibility) -> Option<Condition> {
    match allowed {
        Visibility::Everything => None,
        Visibility::Only(targets) => Some(rows_of::<vectispire_cp_db::query::Scans>(targets)),
    }
}

#[derive(Debug, FromQueryResult)]
struct SbomRow {
    id: i64,
    repo_id: Option<i64>,
    container_id: Option<i64>,
    sbom: Option<String>,
}

impl From<SbomRow> for ScanSbom {
    fn from(row: SbomRow) -> ScanSbom {
        ScanSbom { id: row.id, repo_id: row.repo_id, container_id: row.container_id, sbom: row.sbom }
    }
}

/// Java's `sbomsOfAll`: `select s.id, s.repoId, s.containerId, s.sbom` — **every** scan, its SBOM or none.
///
/// The hand-written reads kept only the scans holding one; the licence inventory then asked for the licence
/// findings of those alone, and a scan whose SBOM retention had cleared lost its licence scanner's findings with it.
fn sboms() -> SelectStatement {
    Query::select()
        .columns([ScanColumn::Id, ScanColumn::RepoId, ScanColumn::ContainerId, ScanColumn::Sbom])
        .from(Scans)
        .to_owned()
}

async fn sbom_rows(tx: &mut Tx, select: SelectStatement) -> Result<Vec<ScanSbom>, StoreError> {
    let rows: Vec<SbomRow> = orm::fetch_all(tx, &select).await?;
    Ok(rows.into_iter().map(ScanSbom::from).collect())
}

pub async fn sboms_of_all(tx: &mut Tx) -> Result<Vec<ScanSbom>, StoreError> {
    sbom_rows(tx, sboms()).await
}

pub async fn sboms_of_untargeted(tx: &mut Tx) -> Result<Vec<ScanSbom>, StoreError> {
    let select = sboms()
        .and_where(Expr::col(ScanColumn::RepoId).is_null())
        .and_where(Expr::col(ScanColumn::ContainerId).is_null())
        .to_owned();
    sbom_rows(tx, select).await
}

/// Java's `sbomsOfTargets`: the scans naming one of these repositories, then those naming one of these images — an
/// image's being **every** scan naming it, as Java's are; the inventory leaves out the SBOM of one that also names a
/// repository. A scan reached through both of its targets is read once.
pub async fn sboms_of_targets(tx: &mut Tx, targets: &[ScanTarget]) -> Result<Vec<ScanSbom>, StoreError> {
    let (repositories, images) = split(targets);
    let mut found: Vec<ScanSbom> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (column, ids) in [(ScanColumn::RepoId, &repositories), (ScanColumn::ContainerId, &images)] {
        for chunk in ids.chunks(LOOKUP_BATCH) {
            let select = sboms().and_where(Expr::col(column).is_in(chunk.iter().copied())).to_owned();
            for row in sbom_rows(tx, select).await? {
                if seen.insert(row.id) {
                    found.push(row);
                }
            }
        }
    }
    Ok(found)
}

/// The repositories and the images among `targets`, each once, in order.
fn split(targets: &[ScanTarget]) -> (Vec<i64>, Vec<i64>) {
    let mut repositories = Vec::new();
    let mut images = Vec::new();
    for target in targets {
        match target {
            ScanTarget::Repository(id) => repositories.push(*id),
            ScanTarget::Container(id) => images.push(*id),
        }
    }
    repositories.sort_unstable();
    repositories.dedup();
    images.sort_unstable();
    images.dedup();
    (repositories, images)
}

#[derive(Debug, FromQueryResult)]
struct NewestCompleted {
    repo_id: Option<i64>,
    container_id: Option<i64>,
    id: i64,
    created_at: OffsetDateTime,
    sbom_stored: i64,
}

/// `s.id = (select max(l.id) from t_scan l where l.<target> = s.<target> and l.status in (<statuses>))` — the newest
/// scan of the row's own target among those statuses, by key: Java's correlated subquery, written once.
fn is_newest_with_status(target: ScanColumn, statuses: &[&str]) -> Expr {
    let (s, l) = (Alias::new("s"), Alias::new("l"));
    let newest = Query::select()
        .expr(Func::max(Expr::col((l.clone(), ScanColumn::Id))))
        .from_as(Scans, l.clone())
        .and_where(Expr::col((l.clone(), target)).equals((s.clone(), target)))
        .and_where(Expr::col((l, ScanColumn::Status)).is_in(statuses.iter().copied()))
        .to_owned();
    Expr::col((s, ScanColumn::Id)).eq(Expr::SubQuery(None, Box::new(newest.into_sub_query_statement())))
}

/// Java's `findNewestWithStatusOfRepositories` and `…OfContainers`, for `completed`.
pub async fn newest_completed(
    tx: &mut Tx,
    targets: &[ScanTarget],
) -> Result<BTreeMap<ScanTarget, NewestCompletedScanRow>, StoreError> {
    let (repositories, images) = split(targets);
    let s = Alias::new("s");
    let mut result = BTreeMap::new();
    for (column, ids) in [(ScanColumn::RepoId, &repositories), (ScanColumn::ContainerId, &images)] {
        for chunk in ids.chunks(LOOKUP_BATCH) {
            let select = Query::select()
                .columns([
                    (s.clone(), ScanColumn::RepoId),
                    (s.clone(), ScanColumn::ContainerId),
                    (s.clone(), ScanColumn::Id),
                    (s.clone(), ScanColumn::CreatedAt),
                ])
                .expr_as(
                    Expr::case(Expr::col((s.clone(), ScanColumn::Sbom)).is_null(), 0i64).finally(1i64),
                    Alias::new("sbom_stored"),
                )
                .from_as(Scans, s.clone())
                .and_where(Expr::col((s.clone(), column)).is_in(chunk.iter().copied()))
                .and_where(is_newest_with_status(column, &["completed"]))
                .to_owned();
            let rows: Vec<NewestCompleted> = orm::fetch_all(tx, &select).await?;
            for row in rows {
                let row = NewestCompletedScanRow {
                    repository_id: row.repo_id,
                    container_id: row.container_id,
                    scan_id: row.id,
                    created_at: row.created_at,
                    sbom_stored: row.sbom_stored != 0,
                };
                // Keyed by the target asked for: a scan naming both, newest for the image, is the image's answer.
                let target = match column {
                    ScanColumn::RepoId => row.repository_id.map(ScanTarget::Repository),
                    _ => row.container_id.map(ScanTarget::Container),
                };
                if let Some(target) = target {
                    result.insert(target, row);
                }
            }
        }
    }
    Ok(result)
}

#[derive(Debug, FromQueryResult)]
struct Id {
    id: i64,
}

async fn ids(tx: &mut Tx, select: SelectStatement) -> Result<Vec<i64>, StoreError> {
    let rows: Vec<Id> = orm::fetch_all(tx, &select).await?;
    Ok(rows.into_iter().map(|row| row.id).collect())
}

fn target_column(target: ScanTarget) -> (ScanColumn, i64) {
    match target {
        ScanTarget::Repository(id) => (ScanColumn::RepoId, id),
        ScanTarget::Container(id) => (ScanColumn::ContainerId, id),
    }
}

fn bounded(limit: usize) -> u64 {
    u64::try_from(limit).unwrap_or(u64::MAX)
}

pub async fn recent_ids(tx: &mut Tx, target: ScanTarget, limit: usize) -> Result<Vec<i64>, StoreError> {
    let (column, id) = target_column(target);
    let select = Query::select()
        .column(ScanColumn::Id)
        .from(Scans)
        .and_where(Expr::col(column).eq(id))
        .order_by(ScanColumn::Id, Order::Desc)
        .limit(bounded(limit))
        .to_owned();
    ids(tx, select).await
}

pub async fn findings(tx: &mut Tx, scan_id: i64) -> Result<Vec<ScanFindingView>, StoreError> {
    let select =
        Findings::find().filter(FindingColumn::ScanId.eq(scan_id)).order_by_asc(FindingColumn::Id).into_query();
    finding_views(tx, select).await
}

/// Java's `findLicenseFindings`: of type `license`, **or from a source naming a licence scanner** — the second half
/// was missing, and the licence scanner's findings with it.
pub async fn license_findings(tx: &mut Tx, scan_ids: &[i64]) -> Result<Vec<ScanFindingView>, StoreError> {
    let mut distinct = scan_ids.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    let mut found = Vec::new();
    for chunk in distinct.chunks(LOOKUP_BATCH) {
        let select = Findings::find()
            .filter(FindingColumn::ScanId.is_in(chunk.iter().copied()))
            .filter(
                Condition::any()
                    .add(Expr::expr(Func::lower(Expr::col(FindingColumn::Type))).eq("license"))
                    .add(Expr::expr(Func::lower(Expr::col(FindingColumn::Source))).like("%license%")),
            )
            .order_by_asc(FindingColumn::Id)
            .into_query();
        found.extend(finding_views(tx, select).await?);
    }
    Ok(found)
}

/// A finding naming a package: not null, and not blank — `trim` rather than `<> ''`, as Java's `isBlank()`.
fn names_a_package() -> Condition {
    Condition::all()
        .add(Expr::col((Findings, FindingColumn::PackageName)).is_not_null())
        .add(Expr::expr(Func::cust("trim").arg(Expr::col((Findings, FindingColumn::PackageName)))).ne(""))
}

#[derive(Debug, FromQueryResult)]
struct ImpactRow {
    package_name: String,
    any_purl: Option<String>,
    repos: i64,
    containers: i64,
    direct: i64,
    total: i64,
    cves: i64,
    cvss: Option<f64>,
}

/// Java's `packageImpacts`.
///
/// **Every figure a `count`**, which both engines answer as a `bigint`: the direct usages were a `sum(case …)`, a
/// `DECIMAL` on MySQL, which the reader did not decode and counted as zero — every direct dependency read as
/// transitive. Counting the `CASE`'s non-null values is the same figure (a null flag is not direct, as in Java).
pub async fn package_impacts(tx: &mut Tx, allowed: &Visibility) -> Result<Vec<PackageImpact>, StoreError> {
    if allowed.is_empty() {
        return Ok(Vec::new());
    }
    let package = Expr::col((Findings, FindingColumn::PackageName));
    let mut select = Query::select();
    select
        .expr_as(package.clone(), Alias::new("package_name"))
        .expr_as(Func::min(Expr::col((Findings, FindingColumn::Purl))), Alias::new("any_purl"))
        .expr_as(Func::count_distinct(Expr::col((Scans, ScanColumn::RepoId))), Alias::new("repos"))
        // A scan's target is its repository, else its image: the image is counted where no repository is named, so
        // the two figures sum to the targets.
        .expr_as(
            Func::count_distinct(
                Expr::case(
                    Expr::col((Scans, ScanColumn::RepoId)).is_null(),
                    Expr::col((Scans, ScanColumn::ContainerId)),
                )
                .finally(Expr::null()),
            ),
            Alias::new("containers"),
        )
        .expr_as(
            Func::count(
                Expr::case(Expr::col((Findings, FindingColumn::IsDirectDependency)).eq(true), 1i64)
                    .finally(Expr::null()),
            ),
            Alias::new("direct"),
        )
        .expr_as(Func::count(Expr::col((Findings, FindingColumn::Id))), Alias::new("total"))
        .expr_as(
            Func::count_distinct(
                Expr::case(
                    Expr::expr(Func::lower(Expr::col((Findings, FindingColumn::Identifier)))).like("cve-%"),
                    Expr::col((Findings, FindingColumn::Identifier)),
                )
                .finally(Expr::null()),
            ),
            Alias::new("cves"),
        )
        .expr_as(Func::max(Expr::col((Findings, FindingColumn::CvssScore))), Alias::new("cvss"))
        .from(Findings)
        .inner_join(Scans, Expr::col((Findings, FindingColumn::ScanId)).equals((Scans, ScanColumn::Id)))
        .cond_where(names_a_package())
        .add_group_by([package]);
    if let Some(visible) = visible_scans(allowed) {
        select.cond_where(visible);
    }
    let rows: Vec<ImpactRow> = orm::fetch_all(tx, &select).await?;
    Ok(rows
        .into_iter()
        .map(|row| PackageImpact {
            package_name: row.package_name,
            any_purl: row.any_purl,
            distinct_repositories: row.repos,
            distinct_containers: row.containers,
            direct_usages: row.direct,
            transitive_usages: row.total.saturating_sub(row.direct),
            distinct_cves: row.cves,
            max_cvss: row.cvss,
        })
        .collect())
}

/// Java's `forGraph`.
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
    let mut select = findings_on_scans();
    select.cond_where(names_a_package());
    if exclude_secrets {
        select.cond_where(
            Condition::any()
                .add(Expr::col((Findings, FindingColumn::Type)).is_null())
                .add(Expr::expr(Func::lower(Expr::col((Findings, FindingColumn::Type)))).ne("secret")),
        );
    }
    let trimmed = query.trim();
    if !trimmed.is_empty() {
        let lowered = trimmed.to_lowercase();
        if is_cve_query {
            // Exactly: a substring would answer CVE-2021-4 with every identifier that contains it.
            select.cond_where(Expr::expr(Func::lower(Expr::col((Findings, FindingColumn::Identifier)))).eq(lowered));
        } else {
            let pattern = format!("%{lowered}%");
            select.cond_where(
                Condition::any()
                    .add(Expr::expr(Func::lower(Expr::col((Findings, FindingColumn::PackageName)))).like(&pattern))
                    .add(Expr::expr(Func::lower(Expr::col((Findings, FindingColumn::Purl)))).like(&pattern)),
            );
        }
    }
    if let Some(visible) = visible_scans(allowed) {
        select.cond_where(visible);
    }
    select.order_by((Findings, FindingColumn::Id), Order::Asc);
    findings_with_scans(tx, select).await
}

/// Identifiers of scans holding an SBOM strictly older than `before`, newest first.
pub async fn ids_with_sbom_before(tx: &mut Tx, before: i64, limit: i64) -> Result<Vec<i64>, StoreError> {
    let select = Query::select()
        .column(ScanColumn::Id)
        .from(Scans)
        .and_where(Expr::col(ScanColumn::Sbom).is_not_null())
        .and_where(Expr::col(ScanColumn::Id).lt(before))
        .order_by(ScanColumn::Id, Order::Desc)
        .limit(u64::try_from(limit).unwrap_or(0))
        .to_owned();
    ids(tx, select).await
}

#[derive(Debug, FromQueryResult)]
struct LastScan {
    repo_id: i64,
    last_scan: Option<OffsetDateTime>,
}

/// Every scan, whatever its status, as Java's `findLastScanInstantPerRepository`: the history's last scan is the newest
/// one started, and a target whose only scan failed still shows when it was last looked at.
pub async fn last_scan_at_per_repository(tx: &mut Tx) -> Result<BTreeMap<i64, OffsetDateTime>, StoreError> {
    let select = Query::select()
        .column(ScanColumn::RepoId)
        .expr_as(Func::max(Expr::col(ScanColumn::CreatedAt)), Alias::new("last_scan"))
        .from(Scans)
        .and_where(Expr::col(ScanColumn::RepoId).is_not_null())
        .group_by_col(ScanColumn::RepoId)
        .to_owned();
    let rows: Vec<LastScan> = orm::fetch_all(tx, &select).await?;
    Ok(rows.into_iter().filter_map(|row| row.last_scan.map(|at| (row.repo_id, at))).collect())
}

pub async fn history_of_repository(
    tx: &mut Tx,
    repo_id: i64,
    branch: Option<&str>,
    limit: usize,
) -> Result<Vec<ScanRow>, StoreError> {
    let mut select = Query::select();
    select_scan_columns(&mut select, "");
    select.from(Scans).and_where(Expr::col((Scans, ScanColumn::RepoId)).eq(repo_id));
    if let Some(branch) = branch {
        select.and_where(Expr::col((Scans, ScanColumn::Branch)).eq(branch));
    }
    select
        .order_by((Scans, ScanColumn::CreatedAt), Order::Desc)
        .order_by((Scans, ScanColumn::Id), Order::Desc)
        .limit(bounded(limit));
    let rows: Vec<ScanColumns> = orm::fetch_all(tx, &select).await?;
    Ok(rows.into_iter().map(ScanRow::from).collect())
}

pub async fn findings_of_scans(tx: &mut Tx, scan_ids: &[i64]) -> Result<Vec<ScanFindingView>, StoreError> {
    let mut found = Vec::new();
    for chunk in scan_ids.chunks(LOOKUP_BATCH) {
        let select = Findings::find()
            .filter(FindingColumn::ScanId.is_in(chunk.iter().copied()))
            .order_by_asc(FindingColumn::Id)
            .into_query();
        found.extend(finding_views(tx, select).await?);
    }
    Ok(found)
}

pub async fn sightings_of_issue(tx: &mut Tx, issue_id: i64, limit: usize) -> Result<Vec<FindingOnScanRow>, StoreError> {
    let mut select = findings_on_scans();
    select
        .and_where(Expr::col((Findings, FindingColumn::IssueId)).eq(issue_id))
        .order_by((Scans, ScanColumn::CreatedAt), Order::Desc)
        .order_by((Scans, ScanColumn::Id), Order::Desc)
        .limit(bounded(limit));
    findings_with_scans(tx, select).await
}

#[derive(Debug, FromQueryResult)]
struct Latest {
    target_id: i64,
    id: i64,
    status: String,
    created_at: OffsetDateTime,
    error: Option<String>,
}

impl From<Latest> for LatestRow {
    fn from(row: Latest) -> LatestRow {
        LatestRow {
            target_id: row.target_id,
            scan_id: row.id,
            status: row.status,
            created_at: row.created_at,
            error: row.error,
        }
    }
}

/// The statuses a scan ends in — Java's `FINISHED`, read off `ScanStatus::is_in_flight` so a status added later is
/// classified where its meaning is declared.
fn finished() -> Vec<&'static str> {
    vectispire_domain::ScanStatus::ALL
        .into_iter()
        .filter(|status| !status.is_in_flight())
        .map(|s| s.wire_name())
        .collect()
}

/// `select s.<target> as target_id, s.id, s.status, s.created_at, s.error from t_scan s`.
fn latest(target: ScanColumn) -> SelectStatement {
    let s = Alias::new("s");
    Query::select()
        .expr_as(Expr::col((s.clone(), target)), Alias::new("target_id"))
        .columns([
            (s.clone(), ScanColumn::Id),
            (s.clone(), ScanColumn::Status),
            (s.clone(), ScanColumn::CreatedAt),
            (s.clone(), ScanColumn::Error),
        ])
        .from_as(Scans, s)
        .to_owned()
}

async fn latest_finished_per(tx: &mut Tx, target: ScanColumn) -> Result<Vec<LatestRow>, StoreError> {
    let select = latest(target)
        .and_where(Expr::col((Alias::new("s"), target)).is_not_null())
        .and_where(is_newest_with_status(target, &finished()))
        .to_owned();
    let rows: Vec<Latest> = orm::fetch_all(tx, &select).await?;
    Ok(rows.into_iter().map(LatestRow::from).collect())
}

pub async fn latest_finished_per_repository(tx: &mut Tx) -> Result<Vec<LatestRow>, StoreError> {
    latest_finished_per(tx, ScanColumn::RepoId).await
}

pub async fn latest_finished_per_container(tx: &mut Tx) -> Result<Vec<LatestRow>, StoreError> {
    latest_finished_per(tx, ScanColumn::ContainerId).await
}

pub async fn latest_finished_of_target(tx: &mut Tx, target: ScanTarget) -> Result<Option<LatestRow>, StoreError> {
    let (column, id) = target_column(target);
    let select = latest(column)
        .and_where(Expr::col((Alias::new("s"), column)).eq(id))
        .and_where(Expr::col((Alias::new("s"), ScanColumn::Status)).is_in(finished()))
        .order_by((Alias::new("s"), ScanColumn::Id), Order::Desc)
        .limit(1)
        .to_owned();
    let row: Option<Latest> = orm::fetch_optional(tx, &select).await?;
    Ok(row.map(LatestRow::from))
}
