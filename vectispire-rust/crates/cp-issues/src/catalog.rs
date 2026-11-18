//! `IssueCatalog`: issues as other modules read them.

use std::collections::BTreeSet;

use vectispire_cp_db::Db;
use vectispire_domain::triage_status::TriageStatus;

use crate::error::IssueError;
use crate::persistence::IssueFilters;
use crate::persistence::IssueRepository;
use crate::persistence::StoreError;
use crate::persistence::aggregates::{
    Axis, GraphNode, Identified, IssueAggregates, Observation, OpenBacklog, OwaspCategoryCount, PackageDetail,
    PackageWeight, Resolution, ResolvedDuration, SeverityTypeCount, TargetBreakdown, TargetGradingCount,
    TargetResolutions, TypePackaging, WeeklyFlow,
};
use crate::persistence::checked::{self, UnsettledScope};
use crate::views::IssueView;

/// How many repositories one count binds — Java's `FLAG_BATCH`: a project's repositories are sized by the data.
const FLAG_BATCH: usize = 1_000;

/// `ScopeCount`: issues of one repository, severity and state in one scope — the rows a checklist's figures add up.
/// Every state is answered as stored; the reader counts one it does not know as open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeCount {
    pub repository_id: i64,
    pub severity: Option<String>,
    pub state: String,
    pub count: i64,
}

#[derive(Clone)]
pub struct IssueCatalog {
    db: Db,
}

impl IssueCatalog {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn count(&self, filters: &IssueFilters) -> Result<i64, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let total = IssueRepository::count_issues(&mut tx, filters).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(total)
    }

    pub async fn issues(&self, filters: &IssueFilters) -> Result<Vec<IssueView>, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let (rows, _) = IssueRepository::page_issues(&mut tx, filters, 10_000, 0).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(rows.into_iter().map(|r| r.to_view()).collect())
    }

    pub async fn find_by_id(&self, id: i64) -> Result<Option<IssueView>, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let row = IssueRepository::find_by_id(&mut tx, id).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(row.map(|r| r.to_view()))
    }

    pub async fn find_by_ids(&self, ids: &[i64]) -> Result<Vec<IssueView>, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let rows = IssueRepository::find_by_ids(&mut tx, ids).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(rows.into_iter().map(|r| r.to_view()).collect())
    }

    // ------------------------------------------------------------------ the aggregates posture reads
    // Each one read-only transaction, each over the backlog's own criteria (`persistence::aggregates`).

    pub async fn count_for_grading_by_target(
        &self,
        filters: &IssueFilters,
    ) -> Result<Vec<TargetGradingCount>, IssueError> {
        self.read(async |tx| IssueAggregates::count_for_grading_by_target(tx, filters).await).await
    }

    pub async fn count_resolved_by_target(&self, filters: &IssueFilters) -> Result<Vec<TargetResolutions>, IssueError> {
        self.read(async |tx| IssueAggregates::count_resolved_by_target(tx, filters).await).await
    }

    pub async fn resolved_durations_since(
        &self,
        filters: &IssueFilters,
        since: time::OffsetDateTime,
    ) -> Result<Vec<ResolvedDuration>, IssueError> {
        self.read(async |tx| IssueAggregates::resolved_durations_since(tx, filters, since).await).await
    }

    pub async fn open_backlog_by_severity(&self, filters: &IssueFilters) -> Result<Vec<OpenBacklog>, IssueError> {
        self.read(async |tx| IssueAggregates::open_backlog_by_severity(tx, filters).await).await
    }

    pub async fn count_open_by_type_and_packaging(
        &self,
        filters: &IssueFilters,
    ) -> Result<Vec<TypePackaging>, IssueError> {
        self.read(async |tx| IssueAggregates::count_open_by_type_and_packaging(tx, filters).await).await
    }

    pub async fn count_grouped_by_severity_and_type(
        &self,
        filters: &IssueFilters,
    ) -> Result<Vec<SeverityTypeCount>, IssueError> {
        self.read(async |tx| IssueAggregates::count_grouped_by_severity_and_type(tx, filters).await).await
    }

    pub async fn weigh_packages(&self, filters: &IssueFilters) -> Result<Vec<PackageWeight>, IssueError> {
        self.read(async |tx| IssueAggregates::weigh_packages(tx, filters).await).await
    }

    pub async fn detail_packages(
        &self,
        filters: &IssueFilters,
        package_names: &[String],
    ) -> Result<Vec<PackageDetail>, IssueError> {
        self.read(async |tx| IssueAggregates::detail_packages(tx, filters, package_names).await).await
    }

    /// The criteria's rows as the series read them: where, how severe, first seen, resolved.
    pub async fn observations(&self, filters: &IssueFilters) -> Result<Vec<Observation>, IssueError> {
        self.read(async |tx| IssueAggregates::observations(tx, filters).await).await
    }

    /// The open issues of these repositories no settled triage took out, for the attack graph — a thousand
    /// repositories per statement, as Java's `Batches` cut them.
    pub async fn unsettled_of_repositories(
        &self,
        state: &str,
        repository_ids: &[i64],
        settled: &[&str],
    ) -> Result<Vec<GraphNode>, IssueError> {
        let mut distinct: Vec<i64> = Vec::new();
        for id in repository_ids {
            if !distinct.contains(id) {
                distinct.push(*id);
            }
        }
        let mut rows = Vec::new();
        for batch in distinct.chunks(1_000) {
            rows.extend(
                self.read(async |tx| IssueAggregates::unsettled_of_repositories(tx, state, batch, settled).await)
                    .await?,
            );
        }
        Ok(rows)
    }

    /// `countDistinct` along an axis of the quality screen.
    pub async fn count_distinct(&self, filters: &IssueFilters, axis: Axis) -> Result<i64, IssueError> {
        self.read(async |tx| IssueAggregates::count_distinct(tx, filters, axis).await).await
    }

    /// The most frequent rules or files, `limit` of them.
    pub async fn count_grouped(
        &self,
        filters: &IssueFilters,
        axis: Axis,
        limit: u64,
    ) -> Result<Vec<(Option<String>, i64)>, IssueError> {
        self.read(async |tx| IssueAggregates::count_grouped_text(tx, filters, axis, limit).await).await
    }

    /// The repositories holding the most, `limit` of them.
    pub async fn count_grouped_by_repository(
        &self,
        filters: &IssueFilters,
        limit: u64,
    ) -> Result<Vec<(i64, i64)>, IssueError> {
        self.read(async |tx| IssueAggregates::count_grouped_repository(tx, filters, limit).await).await
    }

    // ------------------------------------------------------------------ the reads compliance adds

    /// Every target's open, unsettled groups — see `IssueAggregates::count_open_grouped_by_target`: the caller narrows
    /// to the targets it holds visible.
    pub async fn count_open_grouped_by_target(
        &self,
        state: &str,
        settled: &[&str],
    ) -> Result<Vec<TargetBreakdown>, IssueError> {
        self.read(async |tx| IssueAggregates::count_open_grouped_by_target(tx, state, settled).await).await
    }

    pub async fn count_open_sast_by_owasp_category(
        &self,
        filters: &IssueFilters,
    ) -> Result<Vec<OwaspCategoryCount>, IssueError> {
        self.read(async |tx| IssueAggregates::count_open_sast_by_owasp_category(tx, filters).await).await
    }

    pub async fn resolutions(&self, filters: &IssueFilters) -> Result<Vec<Resolution>, IssueError> {
        self.read(async |tx| IssueAggregates::resolutions(tx, filters).await).await
    }

    pub async fn identified(&self, filters: &IssueFilters) -> Result<Vec<Identified>, IssueError> {
        self.read(async |tx| IssueAggregates::identified(tx, filters).await).await
    }

    /// Per week, the issues open at its end, opened, resolved and reopened in it — none read for no week.
    pub async fn weekly_flows(
        &self,
        filters: &IssueFilters,
        week_starts: &[time::OffsetDateTime],
    ) -> Result<Vec<WeeklyFlow>, IssueError> {
        if week_starts.is_empty() {
            return Ok(Vec::new());
        }
        self.read(async |tx| IssueAggregates::weekly_flows(tx, filters, week_starts).await).await
    }

    /// `ReopeningsRecord.recordedSince`: the instant from which every reopening has an entry — V68's installation, a
    /// day later — or nothing when that is not known (no V68 row in Flyway's history, or a failed one), in which case no
    /// figure of reopenings is a figure. **The day's margin** covers the zone Flyway stored the instant in: the
    /// server's on PostgreSQL, the session's on MySQL. A reader asking about whole weeks loses at most the week of the
    /// upgrade, whose first days were not recorded anyway.
    pub async fn reopenings_recorded_since(&self) -> Result<Option<time::OffsetDateTime>, IssueError> {
        let installed =
            self.read(async |tx| crate::persistence::checked::reopening_migration_installed_on(tx).await).await?;
        Ok(installed.into_iter().min().and_then(|at| at.checked_add(time::Duration::days(1))))
    }

    async fn read<T>(
        &self,
        work: impl AsyncFnOnce(&mut vectispire_cp_db::Tx) -> Result<T, crate::persistence::StoreError>,
    ) -> Result<T, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let value = work(&mut tx).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(value)
    }

    /// The issues in `state` of one target, as the gate weighs them — see `IssueRepository::find_by_state`.
    pub async fn gate_issues_of(
        &self,
        target: vectispire_cp_db::ScanTarget,
        state: &str,
    ) -> Result<Vec<IssueView>, IssueError> {
        self.in_state_of(state, Some(target)).await
    }

    /// Every issue in a state, across all targets.
    pub async fn in_state(&self, state: &str) -> Result<Vec<IssueView>, IssueError> {
        self.in_state_of(state, None).await
    }

    async fn in_state_of(
        &self,
        state: &str,
        target: Option<vectispire_cp_db::ScanTarget>,
    ) -> Result<Vec<IssueView>, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let rows = IssueRepository::find_by_state(&mut tx, state, target).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(rows.into_iter().map(|r| r.to_view()).collect())
    }
    /// `countUnsettledOfTypeWithin`: these repositories' issues of one built-in type (its wire name), per repository,
    /// severity and state, settled triage left out — a triage status this version does not know is counted (decision
    /// 0032 §6). The resolved ones are counted too: a resolved ratio needs both sides.
    pub async fn count_unsettled_of_type_within(
        &self,
        kind: &str,
        repository_ids: &[i64],
    ) -> Result<Vec<ScopeCount>, IssueError> {
        self.scope_counts(UnsettledScope::Type(kind), repository_ids).await
    }

    /// `countUnsettledOfToolWithin`: the same, for one tool's issues, by the fingerprint's tool key — `plugin:<id>`,
    /// `import:<source>/<tool>`.
    pub async fn count_unsettled_of_tool_within(
        &self,
        tool_key: &str,
        repository_ids: &[i64],
    ) -> Result<Vec<ScopeCount>, IssueError> {
        self.scope_counts(UnsettledScope::Tool(tool_key), repository_ids).await
    }

    async fn scope_counts(
        &self,
        scope: UnsettledScope<'_>,
        repository_ids: &[i64],
    ) -> Result<Vec<ScopeCount>, IssueError> {
        // Fixed at three by the statement's placeholders; a fourth settled status must widen the statement, and is
        // refused here until it does rather than counted as unsettled.
        let &[first, second, third] = TriageStatus::settled_wire_names() else {
            return Err(IssueError::from(StoreError::Other(
                "the settled triage statuses are not the three the count binds".to_owned(),
            )));
        };
        // Once each, as Java's `LinkedHashSet`: a repository named twice would be counted in two batches.
        let distinct: Vec<i64> = repository_ids.iter().copied().collect::<BTreeSet<i64>>().into_iter().collect();
        let mut tx = crate::persistence::read(&self.db).await?;
        let mut counts = Vec::new();
        for batch in distinct.chunks(FLAG_BATCH) {
            let rows = checked::count_unsettled_within(&mut tx, scope, batch, [first, second, third])
                .await
                .map_err(IssueError::from)?;
            counts.extend(rows.into_iter().map(|(repository_id, severity, state, count)| ScopeCount {
                repository_id,
                severity,
                state,
                count,
            }));
        }
        crate::persistence::commit(tx).await?;
        Ok(counts)
    }
}

opaque_debug!(IssueCatalog);
