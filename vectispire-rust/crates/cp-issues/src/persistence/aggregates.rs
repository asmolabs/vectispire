//! The aggregates other modules read off the backlog — `IssueAggregateQueriesImpl` and the projections of
//! `IssueRows`, for the posture module's figures: grading counts, resolutions, the remediation distribution, the debt's
//! tallies and packages, the quality screen's counts, and the rows the series and the attack graph are drawn from.
//!
//! **One clause for the reader's criteria**: every statement starts from [`visible_issues`] narrowed by the backlog's
//! own [`criteria`], so a figure and the issues list it links to cannot disagree about which rows they cover. What
//! each adds is Java's `restrict(…, extra)` — written beside it.
//!
//! **Engine spellings** where the result type differs: MySQL's `avg` and `sum` of an integer column are `DECIMAL`, which
//! the driver does not decode into a number of Rust's; each is cast where it is selected — to a double for the
//! average, as JDBC's `getDouble` reads it, to a 64-bit integer for a sum of ones.

use sea_orm::sea_query::{Alias, Expr, ExprTrait, Func, Order, SelectStatement, SimpleExpr};
use sea_orm::{ColumnTrait, FromQueryResult, QueryFilter, QueryTrait};
use time::OffsetDateTime;
use vectispire_cp_db::{Engine, Tx, orm};
use vectispire_domain::owasp_coverage;

use super::entities::{IssueColumn, issues, visible_issues};
use super::filters::IssueFilters;
use super::lived;
use super::repository::{StoreError, criteria};

/// What a vulnerability without an identifier is counted under.
const UNNAMED: &str = "UNKNOWN-CVE";

/// A statement over the reader's rows, its selection cleared for the aggregate's own.
fn over(filters: &IssueFilters, extra: Option<sea_orm::Condition>) -> SelectStatement {
    let mut visible = visible_issues(&filters.visibility).filter(criteria(filters));
    if let Some(extra) = extra {
        visible = visible.filter(extra);
    }
    let mut statement = visible.statement().clone();
    statement.clear_selects().clear_order_by();
    statement
}

fn as_double(engine: Engine, expression: SimpleExpr) -> SimpleExpr {
    let to = match engine {
        Engine::MySql => "double",
        Engine::PostgreSql => "double precision",
    };
    Func::cast_as(expression, Alias::new(to)).into()
}

fn as_long(engine: Engine, expression: SimpleExpr) -> SimpleExpr {
    let to = match engine {
        Engine::MySql => "signed",
        Engine::PostgreSql => "bigint",
    };
    Func::cast_as(expression, Alias::new(to)).into()
}

/// `case when <condition> then 1 else 0 end`.
fn one_when(condition: SimpleExpr) -> SimpleExpr {
    Expr::case(condition, 1).finally(0).into()
}

/// `packageIsNamed`: a package name, not blank once trimmed of spaces.
fn package_is_named() -> SimpleExpr {
    IssueColumn::PackageName
        .is_not_null()
        .and(Expr::expr(Func::cust("trim").arg(Expr::col(IssueColumn::PackageName))).ne(""))
}

fn vulnerability_with_a_package() -> SimpleExpr {
    IssueColumn::Type.eq("vulnerability").and(package_is_named())
}

fn identifier_or_unnamed() -> SimpleExpr {
    Func::coalesce([Expr::col(IssueColumn::Identifier), Expr::val(UNNAMED)]).into()
}

/// `TargetGradingCount`: the open test is the reader's, in the service, as the scorecard always wrote it.
#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct TargetGradingCount {
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub severity: Option<String>,
    pub is_kev: bool,
    pub state: String,
    pub c: i64,
}

/// `TargetResolutions`: every closed issue counted; the average over those with a measured resolution only.
#[derive(Debug, Clone, PartialEq, FromQueryResult)]
pub struct TargetResolutions {
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub resolved: i64,
    pub average_seconds: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct ResolvedDuration {
    pub severity: Option<String>,
    pub resolution_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct OpenBacklog {
    pub severity: Option<String>,
    pub total: i64,
    pub oldest_first_seen: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct TypePackaging {
    #[sea_orm(from_alias = "type")]
    pub type_: String,
    pub package_named: i64,
    pub unnamed: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct SeverityTypeCount {
    pub severity: Option<String>,
    #[sea_orm(from_alias = "type")]
    pub type_: String,
    pub c: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct PackageWeight {
    pub package_name: String,
    pub version: Option<String>,
    pub distinct_identifiers: i64,
    pub critical_count: i64,
    pub high_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct PackageDetail {
    pub package_name: String,
    pub identifier: String,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub fix_versions: Option<String>,
}

/// `IssueRows.Lifespan` and `IssueRows.Observation` at once: the columns the series are drawn from.
#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct Observation {
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub severity: Option<String>,
    pub first_seen_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
}

/// `IssueRows.GraphNode`.
#[derive(Debug, Clone, PartialEq, FromQueryResult)]
pub struct GraphNode {
    pub id: i64,
    pub repo_id: Option<i64>,
    #[sea_orm(from_alias = "type")]
    pub type_: String,
    pub severity: Option<String>,
    pub identifier: Option<String>,
    pub description: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub file_path: Option<String>,
    pub cvss_score: Option<f64>,
    pub epss_score: Option<f64>,
    pub is_kev: bool,
}

/// The axis the quality screen counts along.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    Rule,
    File,
    Repository,
}

impl Axis {
    fn column(self) -> IssueColumn {
        match self {
            Axis::Rule => IssueColumn::Identifier,
            Axis::File => IssueColumn::FilePath,
            Axis::Repository => IssueColumn::RepoId,
        }
    }
}

#[derive(Debug, FromQueryResult)]
struct TextKey {
    key: Option<String>,
    total: i64,
}

#[derive(Debug, FromQueryResult)]
struct IdKey {
    key: Option<i64>,
    total: i64,
}

#[derive(Debug, FromQueryResult)]
struct Total {
    total: i64,
}

/// `OwaspCategoryCount`: open code-analysis issues per declared category.
#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct OwaspCategoryCount {
    pub owasp_category: String,
    pub c: i64,
}

/// `WeeklyFlow`: per week and per (type, category), the issues open at its end, opened, resolved and reopened in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeeklyFlow {
    pub week_start: OffsetDateTime,
    pub type_: String,
    pub owasp_category: Option<String>,
    pub open_at_end: i64,
    pub opened: i64,
    pub resolved: i64,
    pub reopened: i64,
}

/// `IssueRows.Resolution`: what the MTTR is computed from.
#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct Resolution {
    pub severity: Option<String>,
    pub first_seen_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
}

/// `IssueRows.Identified`: an issue and the identifier the OWASP report's links key it by.
#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct Identified {
    pub id: i64,
    pub identifier: Option<String>,
}

/// `TargetBreakdown`: one group of open, unsettled issues of the whole estate.
#[derive(Debug, Clone, PartialEq, Eq, FromQueryResult)]
pub struct TargetBreakdown {
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub severity: Option<String>,
    #[sea_orm(from_alias = "type")]
    pub type_: String,
    pub is_kev: bool,
    pub c: i64,
}

/// Weeks per statement — `WEEKS_PER_STATEMENT`. Each week is four conditional sums over two bound instants: thirteen
/// weeks, a quarter, keep the select list and the binds small on every engine, and a year is four reads.
pub const WEEKS_PER_STATEMENT: usize = 13;

/// The conditional sums of one week, in the order they are selected.
const FIGURES: usize = 4;

#[derive(Debug, Clone, Copy)]
pub struct IssueAggregates;

impl IssueAggregates {
    pub async fn count_for_grading_by_target(
        tx: &mut Tx,
        filters: &IssueFilters,
    ) -> Result<Vec<TargetGradingCount>, StoreError> {
        let mut statement = over(filters, None);
        let columns = [
            IssueColumn::RepoId,
            IssueColumn::ContainerId,
            IssueColumn::Severity,
            IssueColumn::IsKev,
            IssueColumn::State,
        ];
        for column in columns {
            statement.column(column).add_group_by([Expr::col(column)]);
        }
        statement.expr_as(Expr::col(IssueColumn::Id).count(), Alias::new("c"));
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    pub async fn count_resolved_by_target(
        tx: &mut Tx,
        filters: &IssueFilters,
    ) -> Result<Vec<TargetResolutions>, StoreError> {
        let engine = tx.engine();
        let mut statement = over(filters, Some(sea_orm::Condition::all().add(IssueColumn::ResolvedAt.is_not_null())));
        statement
            .column(IssueColumn::RepoId)
            .column(IssueColumn::ContainerId)
            .expr_as(Expr::col(IssueColumn::Id).count(), Alias::new("resolved"))
            .expr_as(
                as_double(engine, Func::avg(Expr::col(IssueColumn::ResolutionSeconds)).into()),
                Alias::new("average_seconds"),
            )
            .add_group_by([Expr::col(IssueColumn::RepoId), Expr::col(IssueColumn::ContainerId)]);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    pub async fn resolved_durations_since(
        tx: &mut Tx,
        filters: &IssueFilters,
        since: OffsetDateTime,
    ) -> Result<Vec<ResolvedDuration>, StoreError> {
        // An issue closed in the instant it was seen, or never seen, is unmeasured — not a resolution of zero.
        let extra = sea_orm::Condition::all()
            .add(IssueColumn::ResolutionSeconds.is_not_null())
            .add(IssueColumn::ResolvedAt.gte(since));
        let mut statement = over(filters, Some(extra));
        statement.column(IssueColumn::Severity).column(IssueColumn::ResolutionSeconds);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    pub async fn open_backlog_by_severity(tx: &mut Tx, filters: &IssueFilters) -> Result<Vec<OpenBacklog>, StoreError> {
        let mut statement = over(filters, Some(sea_orm::Condition::all().add(IssueColumn::ResolvedAt.is_null())));
        statement
            .column(IssueColumn::Severity)
            .expr_as(Expr::col(IssueColumn::Id).count(), Alias::new("total"))
            .expr_as(Func::min(Expr::col(IssueColumn::FirstSeenAt)), Alias::new("oldest_first_seen"))
            .add_group_by([Expr::col(IssueColumn::Severity)]);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    pub async fn count_open_by_type_and_packaging(
        tx: &mut Tx,
        filters: &IssueFilters,
    ) -> Result<Vec<TypePackaging>, StoreError> {
        let engine = tx.engine();
        let mut statement = over(filters, None);
        statement
            .column(IssueColumn::Type)
            .expr_as(as_long(engine, Func::sum(one_when(package_is_named())).into()), Alias::new("package_named"))
            .expr_as(as_long(engine, Func::sum(one_when(package_is_named().not())).into()), Alias::new("unnamed"))
            .add_group_by([Expr::col(IssueColumn::Type)]);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    pub async fn count_grouped_by_severity_and_type(
        tx: &mut Tx,
        filters: &IssueFilters,
    ) -> Result<Vec<SeverityTypeCount>, StoreError> {
        let mut statement = over(filters, None);
        statement
            .column(IssueColumn::Severity)
            .column(IssueColumn::Type)
            .expr_as(Expr::col(IssueColumn::Id).count(), Alias::new("c"))
            .add_group_by([Expr::col(IssueColumn::Severity), Expr::col(IssueColumn::Type)]);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `weighPackages`: per package, the smallest version, the distinct identifiers (an unnamed one counted once), and
    /// the criticals and highs — `severity = 'critical'` compared by the column's collation, as Java's statement does.
    pub async fn weigh_packages(tx: &mut Tx, filters: &IssueFilters) -> Result<Vec<PackageWeight>, StoreError> {
        let engine = tx.engine();
        let mut statement = over(filters, Some(sea_orm::Condition::all().add(vulnerability_with_a_package())));
        statement
            .column(IssueColumn::PackageName)
            .expr_as(Func::min(Expr::col(IssueColumn::PackageVersion)), Alias::new("version"))
            .expr_as(Func::count_distinct(identifier_or_unnamed()), Alias::new("distinct_identifiers"))
            .expr_as(
                as_long(engine, Func::sum(one_when(IssueColumn::Severity.eq("critical"))).into()),
                Alias::new("critical_count"),
            )
            .expr_as(
                as_long(engine, Func::sum(one_when(IssueColumn::Severity.eq("high"))).into()),
                Alias::new("high_count"),
            )
            .add_group_by([Expr::col(IssueColumn::PackageName)]);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `detailPackages`: distinct, since two findings of one CVE on one target are one line of the plan.
    pub async fn detail_packages(
        tx: &mut Tx,
        filters: &IssueFilters,
        package_names: &[String],
    ) -> Result<Vec<PackageDetail>, StoreError> {
        if package_names.is_empty() {
            return Ok(Vec::new());
        }
        let extra = sea_orm::Condition::all()
            .add(vulnerability_with_a_package())
            .add(IssueColumn::PackageName.is_in(package_names.iter().map(String::as_str)));
        let mut statement = over(filters, Some(extra));
        statement
            .distinct()
            .column(IssueColumn::PackageName)
            .expr_as(identifier_or_unnamed(), Alias::new("identifier"))
            .column(IssueColumn::RepoId)
            .column(IssueColumn::ContainerId)
            .column(IssueColumn::FixVersions);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `findAllAs(…, Lifespan / Observation)`: two instants per issue, and where it is.
    pub async fn observations(tx: &mut Tx, filters: &IssueFilters) -> Result<Vec<Observation>, StoreError> {
        let mut statement = over(filters, None);
        statement
            .column(IssueColumn::RepoId)
            .column(IssueColumn::ContainerId)
            .column(IssueColumn::Severity)
            .column(IssueColumn::FirstSeenAt)
            .column(IssueColumn::ResolvedAt);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `findByStateAndRepoIdInAndTriageStatusNotIn`: the open issues of these repositories a settled triage left in.
    /// No reader's visibility here: the caller passes the repositories it has already held to it.
    pub async fn unsettled_of_repositories(
        tx: &mut Tx,
        state: &str,
        repository_ids: &[i64],
        settled: &[&str],
    ) -> Result<Vec<GraphNode>, StoreError> {
        if repository_ids.is_empty() {
            return Ok(Vec::new());
        }
        let filters = IssueFilters { state: None, ..IssueFilters::new(vectispire_cp_db::Visibility::Everything) };
        let extra = sea_orm::Condition::all()
            .add(IssueColumn::State.eq(state))
            .add(IssueColumn::RepoId.is_in(repository_ids.iter().copied()))
            .add(IssueColumn::TriageStatus.is_not_in(settled.iter().copied()));
        let mut statement = over(&filters, Some(extra));
        statement
            .columns([
                IssueColumn::Id,
                IssueColumn::RepoId,
                IssueColumn::Type,
                IssueColumn::Severity,
                IssueColumn::Identifier,
                IssueColumn::Description,
                IssueColumn::PackageName,
                IssueColumn::PackageVersion,
                IssueColumn::FilePath,
                IssueColumn::CvssScore,
                IssueColumn::EpssScore,
                IssueColumn::IsKev,
            ])
            .order_by(IssueColumn::Id, Order::Asc);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `countDistinct(…, axis)`: the distinct values of the axis, a missing one not counted.
    pub async fn count_distinct(tx: &mut Tx, filters: &IssueFilters, axis: Axis) -> Result<i64, StoreError> {
        let mut statement = over(filters, None);
        statement.expr_as(Func::count_distinct(Expr::col(axis.column())), Alias::new("total"));
        let rows: Vec<Total> = orm::fetch_all(tx, &statement).await?;
        Ok(rows.first().map_or(0, |row| row.total))
    }

    /// `countGrouped(…, axis, limit)`: the most frequent values first; the repository axis leaves out the images'.
    pub async fn count_grouped_text(
        tx: &mut Tx,
        filters: &IssueFilters,
        axis: Axis,
        limit: u64,
    ) -> Result<Vec<(Option<String>, i64)>, StoreError> {
        let statement = Self::grouped(filters, axis, limit);
        let rows: Vec<TextKey> = orm::fetch_all(tx, &statement).await?;
        Ok(rows.into_iter().map(|row| (row.key, row.total)).collect())
    }

    pub async fn count_grouped_repository(
        tx: &mut Tx,
        filters: &IssueFilters,
        limit: u64,
    ) -> Result<Vec<(i64, i64)>, StoreError> {
        let statement = Self::grouped(filters, Axis::Repository, limit);
        let rows: Vec<IdKey> = orm::fetch_all(tx, &statement).await?;
        Ok(rows.into_iter().filter_map(|row| row.key.map(|key| (key, row.total))).collect())
    }

    /// `countOpenGroupedByTarget`: **every target's, whatever the reader may see** — Java's statement is target-scoped
    /// and its one caller, the compliance matrix, reads only the groups of targets it already holds visible.
    pub async fn count_open_grouped_by_target(
        tx: &mut Tx,
        state: &str,
        settled: &[&str],
    ) -> Result<Vec<TargetBreakdown>, StoreError> {
        let mut statement = issues()
            .filter(IssueColumn::State.eq(state))
            .filter(IssueColumn::TriageStatus.is_not_in(settled.iter().copied()))
            .into_query();
        statement.clear_selects();
        let columns = [
            IssueColumn::RepoId,
            IssueColumn::ContainerId,
            IssueColumn::Severity,
            IssueColumn::Type,
            IssueColumn::IsKev,
        ];
        for column in columns {
            statement.column(column).add_group_by([Expr::col(column)]);
        }
        statement.expr_as(Expr::col(IssueColumn::Id).count(), Alias::new("c"));
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `countOpenSastByOwaspCategory`: the type the grid reads the column of, named where the placement is
    /// (`owasp_coverage::DECLARES_ITS_CATEGORY`), so the backlog's filter and this count cannot name two.
    pub async fn count_open_sast_by_owasp_category(
        tx: &mut Tx,
        filters: &IssueFilters,
    ) -> Result<Vec<OwaspCategoryCount>, StoreError> {
        let extra = sea_orm::Condition::all()
            .add(IssueColumn::Type.eq(owasp_coverage::DECLARES_ITS_CATEGORY.wire_name()))
            .add(IssueColumn::OwaspCategory.is_not_null());
        let mut statement = over(filters, Some(extra));
        statement
            .column(IssueColumn::OwaspCategory)
            .expr_as(Expr::col(IssueColumn::Id).count(), Alias::new("c"))
            .add_group_by([Expr::col(IssueColumn::OwaspCategory)]);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `rows(filters, Resolution.class)`: in the engine's order — the caller averages them.
    pub async fn resolutions(tx: &mut Tx, filters: &IssueFilters) -> Result<Vec<Resolution>, StoreError> {
        let mut statement = over(filters, None);
        statement.column(IssueColumn::Severity).column(IssueColumn::FirstSeenAt).column(IssueColumn::ResolvedAt);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `rows(filters, Identified.class)`: in the engine's order — the caller keys them by identifier.
    pub async fn identified(tx: &mut Tx, filters: &IssueFilters) -> Result<Vec<Identified>, StoreError> {
        let mut statement = over(filters, None);
        statement.column(IssueColumn::Id).column(IssueColumn::Identifier);
        Ok(orm::fetch_all(tx, &statement).await?)
    }

    /// `weeklyFlows`: the weeks distinct and in order, thirteen per statement; a (type, category) group is listed for
    /// a week only where one of its four figures is not zero. The clauses are the backlog's own ([`lived`]), so a cell
    /// and the list it opens cannot disagree.
    pub async fn weekly_flows(
        tx: &mut Tx,
        filters: &IssueFilters,
        week_starts: &[OffsetDateTime],
    ) -> Result<Vec<WeeklyFlow>, StoreError> {
        let mut weeks = week_starts.to_vec();
        weeks.sort_unstable();
        weeks.dedup();
        let mut flows = Vec::new();
        for batch in weeks.chunks(WEEKS_PER_STATEMENT) {
            flows.extend(Self::weekly_flows_of(tx, filters, batch).await?);
        }
        Ok(flows)
    }

    async fn weekly_flows_of(
        tx: &mut Tx,
        filters: &IssueFilters,
        weeks: &[OffsetDateTime],
    ) -> Result<Vec<WeeklyFlow>, StoreError> {
        let (Some(first), Some(last)) = (weeks.first(), weeks.last()) else {
            return Ok(Vec::new());
        };
        let engine = tx.engine();
        let week = time::Duration::days(7);
        // Only the issues that can count in one of these weeks: seen before the last one ends, and not resolved before
        // the first one starts.
        let extra = sea_orm::Condition::all().add(IssueColumn::FirstSeenAt.lt(*last + week)).add(
            sea_orm::Condition::any().add(IssueColumn::ResolvedAt.is_null()).add(IssueColumn::ResolvedAt.gte(*first)),
        );
        let mut statement = over(filters, Some(extra));
        statement
            .expr_as(Expr::col(IssueColumn::Type), Alias::new("type"))
            .expr_as(Expr::col(IssueColumn::OwaspCategory), Alias::new("owasp_category"));
        for (index, start) in weeks.iter().enumerate() {
            let end = *start + week;
            let opened = sea_orm::Condition::all()
                .add(IssueColumn::FirstSeenAt.gte(*start))
                .add(IssueColumn::FirstSeenAt.lt(end));
            let figures = [
                lived::open_at(end),
                opened,
                lived::resolved_within(Some(*start), Some(end)),
                lived::reopened_within(Some(*start), Some(end)),
            ];
            for (figure, condition) in figures.into_iter().enumerate() {
                statement.expr_as(
                    as_long(engine, Func::sum(Expr::case(condition, 1).finally(0)).into()),
                    Alias::new(format!("w{index}_{figure}")),
                );
            }
        }
        statement.add_group_by([Expr::col(IssueColumn::Type), Expr::col(IssueColumn::OwaspCategory)]);

        let mut flows = Vec::new();
        for row in orm::fetch_rows(tx, &statement).await? {
            let type_: String = row.try_get("", "type").map_err(|e| StoreError::Other(e.to_string()))?;
            let owasp_category: Option<String> =
                row.try_get("", "owasp_category").map_err(|e| StoreError::Other(e.to_string()))?;
            for (index, start) in weeks.iter().enumerate() {
                let mut figures = [0_i64; FIGURES];
                for (figure, value) in figures.iter_mut().enumerate() {
                    let sum: Option<i64> =
                        row.try_get("", &format!("w{index}_{figure}")).map_err(|e| StoreError::Other(e.to_string()))?;
                    *value = sum.unwrap_or(0);
                }
                let [open_at_end, opened, resolved, reopened] = figures;
                if figures.iter().any(|figure| *figure > 0) {
                    flows.push(WeeklyFlow {
                        week_start: *start,
                        type_: type_.clone(),
                        owasp_category: owasp_category.clone(),
                        open_at_end,
                        opened,
                        resolved,
                        reopened,
                    });
                }
            }
        }
        Ok(flows)
    }

    fn grouped(filters: &IssueFilters, axis: Axis, limit: u64) -> SelectStatement {
        let column = axis.column();
        let extra = (axis == Axis::Repository).then(|| sea_orm::Condition::all().add(column.is_not_null()));
        let mut statement = over(filters, extra);
        statement
            .expr_as(Expr::col(column), Alias::new("key"))
            .expr_as(Expr::col(IssueColumn::Id).count(), Alias::new("total"))
            .add_group_by([Expr::col(column)])
            .order_by(Alias::new("total"), Order::Desc)
            .limit(limit);
        statement
    }
}
