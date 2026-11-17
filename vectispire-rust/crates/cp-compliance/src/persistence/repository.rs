//! The statements of compliance's four tables — Java's `ControlDeclarationRepository`, `ComplianceSnapshotRepository`,
//! `AiReviewResultRepository`, `OwaspWeeklyCoverageRepository` and `OwaspWeeklyCoverageQueriesImpl` — built with
//! SeaORM from [`super::entities`] and run on the caller's [`Tx`].

use sea_orm::sea_query::{Alias, Expr, ExprTrait, Func, Order};
use sea_orm::{
    ActiveValue::NotSet, ActiveValue::Set, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait,
};
use time::OffsetDateTime;
use vectispire_cp_db::{Engine, Tx, Visibility, orm};

use super::entities::{
    DeclarationActive, DeclarationColumn, DeclarationModel, Declarations, ReviewActive, ReviewColumn, ReviewModel,
    Reviews, SnapshotActive, SnapshotColumn, SnapshotModel, Snapshots, WeeklyActive, WeeklyColumn, delete_weekly,
    insert_weekly, visible_weekly, weekly,
};
use super::{DeclarationRow, NewReview, ReviewRow, SnapshotRow, StoreError, WeeklyRow, WeeklyStateCount, WeeklyTarget};

impl From<DeclarationModel> for DeclarationRow {
    fn from(model: DeclarationModel) -> DeclarationRow {
        DeclarationRow {
            id: model.id,
            framework: model.framework,
            control_id: model.control_id,
            applicability: model.applicability,
            justification: model.justification,
            implementation: model.implementation,
            evidence_source: model.evidence_source,
            external_evidence: model.external_evidence,
            control_owner: model.control_owner,
            decided_by: model.decided_by,
            decided_at: model.decided_at,
            reviewed_at: model.reviewed_at,
            review_due_at: model.review_due_at,
        }
    }
}

fn declaration_active(row: &DeclarationRow) -> DeclarationActive {
    DeclarationActive {
        id: Set(row.id.clone()),
        framework: Set(row.framework.clone()),
        control_id: Set(row.control_id.clone()),
        applicability: Set(row.applicability.clone()),
        justification: Set(row.justification.clone()),
        implementation: Set(row.implementation.clone()),
        evidence_source: Set(row.evidence_source.clone()),
        external_evidence: Set(row.external_evidence.clone()),
        control_owner: Set(row.control_owner.clone()),
        decided_by: Set(row.decided_by.clone()),
        decided_at: Set(row.decided_at),
        reviewed_at: Set(row.reviewed_at),
        review_due_at: Set(row.review_due_at),
    }
}

impl From<SnapshotModel> for SnapshotRow {
    fn from(model: SnapshotModel) -> SnapshotRow {
        SnapshotRow {
            id: model.id,
            period: model.period,
            framework: model.framework,
            score: model.score,
            status: model.status,
            targets: model.targets,
            observed_targets: model.observed_targets,
            fresh_targets: model.fresh_targets,
            freshness_days: model.freshness_days,
            eol_enabled: model.eol_enabled,
            code_analysis_reaches: model.code_analysis_reaches,
            controls_total: model.controls_total,
            controls_declared: model.controls_declared,
            soa_findings: model.soa_findings,
            captured_at: model.captured_at,
        }
    }
}

fn snapshot_active(row: &SnapshotRow) -> SnapshotActive {
    SnapshotActive {
        id: Set(row.id.clone()),
        period: Set(row.period.clone()),
        framework: Set(row.framework.clone()),
        score: Set(row.score),
        status: Set(row.status.clone()),
        targets: Set(row.targets),
        observed_targets: Set(row.observed_targets),
        fresh_targets: Set(row.fresh_targets),
        freshness_days: Set(row.freshness_days),
        eol_enabled: Set(row.eol_enabled),
        code_analysis_reaches: Set(row.code_analysis_reaches),
        controls_total: Set(row.controls_total),
        controls_declared: Set(row.controls_declared),
        soa_findings: Set(row.soa_findings),
        captured_at: Set(row.captured_at),
    }
}

impl From<ReviewModel> for ReviewRow {
    fn from(model: ReviewModel) -> ReviewRow {
        ReviewRow {
            id: model.id,
            scan_id: model.scan_id,
            model: model.model,
            prompt: model.prompt,
            response: model.response,
            status: model.status,
            error: model.error,
            created_at: model.created_at,
            inputs: model.inputs,
            deadline_at: model.deadline_at,
            repo_id: model.repo_id,
            evidence_identifiers: model.evidence_identifiers,
        }
    }
}

/// The declaration of applicability. **No visibility clause**: a declaration is about the management system, not a
/// target — the routes are gated on the role instead.
#[derive(Debug, Clone, Copy)]
pub struct DeclarationRepository;

impl DeclarationRepository {
    /// `findByFramework`, in the engine's order: the statement reconciles them by control.
    pub async fn by_framework(tx: &mut Tx, framework: &str) -> Result<Vec<DeclarationRow>, StoreError> {
        let select = Declarations::find().filter(DeclarationColumn::Framework.eq(framework)).into_query();
        let models: Vec<DeclarationModel> = orm::fetch_all(tx, &select).await?;
        Ok(models.into_iter().map(DeclarationRow::from).collect())
    }

    pub async fn find(tx: &mut Tx, framework: &str, control_id: &str) -> Result<Option<DeclarationRow>, StoreError> {
        let select = Declarations::find()
            .filter(DeclarationColumn::Framework.eq(framework))
            .filter(DeclarationColumn::ControlId.eq(control_id))
            .into_query();
        let model: Option<DeclarationModel> = orm::fetch_optional(tx, &select).await?;
        Ok(model.map(DeclarationRow::from))
    }

    /// `findReviewOverdue`: lines whose review has lapsed, across every framework, the most lapsed first.
    pub async fn review_overdue(tx: &mut Tx, now: OffsetDateTime) -> Result<Vec<DeclarationRow>, StoreError> {
        let select = Declarations::find()
            .filter(DeclarationColumn::ReviewDueAt.is_not_null())
            .filter(DeclarationColumn::ReviewDueAt.lt(now))
            .order_by(DeclarationColumn::ReviewDueAt, Order::Asc)
            .into_query();
        let models: Vec<DeclarationModel> = orm::fetch_all(tx, &select).await?;
        Ok(models.into_iter().map(DeclarationRow::from).collect())
    }

    pub async fn insert(tx: &mut Tx, row: &DeclarationRow) -> Result<(), StoreError> {
        orm::execute(tx, &Declarations::insert(declaration_active(row)).into_query()).await?;
        Ok(())
    }

    /// Rewrites the line in place, by its key — `save` of a found entity.
    pub async fn update(tx: &mut Tx, row: &DeclarationRow) -> Result<u64, StoreError> {
        let update = Declarations::update_many()
            .set(declaration_active(row))
            .filter(DeclarationColumn::Id.eq(row.id.as_str()))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }
}

/// The monthly captures. **No visibility clause**: a capture describes the whole estate, which is what makes two
/// months comparable; narrowed per reader it would be a different history for each and an audit trail for none.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotRepository;

impl SnapshotRepository {
    pub async fn find(tx: &mut Tx, period: &str, framework: &str) -> Result<Option<SnapshotRow>, StoreError> {
        let select = Snapshots::find()
            .filter(SnapshotColumn::Period.eq(period))
            .filter(SnapshotColumn::Framework.eq(framework))
            .into_query();
        let model: Option<SnapshotModel> = orm::fetch_optional(tx, &select).await?;
        Ok(model.map(SnapshotRow::from))
    }

    /// `findAllOrdered`: every capture, oldest first, then by framework — the order a progression is read in.
    pub async fn all_ordered(tx: &mut Tx) -> Result<Vec<SnapshotRow>, StoreError> {
        let select = Snapshots::find()
            .order_by(SnapshotColumn::Period, Order::Asc)
            .order_by(SnapshotColumn::Framework, Order::Asc)
            .into_query();
        let models: Vec<SnapshotModel> = orm::fetch_all(tx, &select).await?;
        Ok(models.into_iter().map(SnapshotRow::from).collect())
    }

    pub async fn insert(tx: &mut Tx, row: &SnapshotRow) -> Result<(), StoreError> {
        orm::execute(tx, &Snapshots::insert(snapshot_active(row)).into_query()).await?;
        Ok(())
    }

    pub async fn update(tx: &mut Tx, row: &SnapshotRow) -> Result<u64, StoreError> {
        let update = Snapshots::update_many()
            .set(snapshot_active(row))
            .filter(SnapshotColumn::Id.eq(row.id.as_str()))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    pub async fn delete(tx: &mut Tx, id: &str) -> Result<u64, StoreError> {
        Ok(orm::execute(tx, &Snapshots::delete_by_id(id.to_owned()).into_query()).await?)
    }

    /// `deleteBefore`: the captures older than the evidence window.
    pub async fn delete_before(tx: &mut Tx, cutoff: OffsetDateTime) -> Result<u64, StoreError> {
        let delete = Snapshots::delete_many().filter(SnapshotColumn::CapturedAt.lt(cutoff)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }
}

/// The OWASP reports. Read by repository once the route has settled that the reader may see it.
#[derive(Debug, Clone, Copy)]
pub struct ReviewRepository;

impl ReviewRepository {
    /// `latestForRepository`: the newest report about one repository, whichever scan it was built from — by
    /// creation, then by key, so two written in one instant still have one latest.
    pub async fn latest_for_repository(tx: &mut Tx, repo_id: i64) -> Result<Option<ReviewRow>, StoreError> {
        let select = Reviews::find()
            .filter(ReviewColumn::RepoId.eq(repo_id))
            .order_by(ReviewColumn::CreatedAt, Order::Desc)
            .order_by(ReviewColumn::Id, Order::Desc)
            .limit(1)
            .into_query();
        let model: Option<ReviewModel> = orm::fetch_optional(tx, &select).await?;
        Ok(model.map(ReviewRow::from))
    }

    pub async fn find_by_id(tx: &mut Tx, id: i64) -> Result<Option<ReviewRow>, StoreError> {
        let model: Option<ReviewModel> = orm::fetch_optional(tx, &Reviews::find_by_id(id).into_query()).await?;
        Ok(model.map(ReviewRow::from))
    }

    pub async fn insert(tx: &mut Tx, row: &NewReview) -> Result<i64, StoreError> {
        let active = ReviewActive {
            id: NotSet,
            scan_id: Set(row.scan_id),
            model: Set(row.model.clone()),
            prompt: Set(row.prompt.clone()),
            response: Set(None),
            status: Set(row.status.clone()),
            error: Set(None),
            created_at: Set(row.created_at),
            inputs: Set(row.inputs.clone()),
            deadline_at: Set(row.deadline_at),
            repo_id: Set(row.repo_id),
            evidence_identifiers: Set(row.evidence_identifiers.clone()),
        };
        Ok(orm::insert_returning_id::<Reviews>(tx, Reviews::insert(active).into_query()).await?)
    }

    /// The model's answer, or its failure, written on the row: the deadline goes, the status and its text come.
    pub async fn settle(
        tx: &mut Tx,
        id: i64,
        status: &str,
        response: Option<&str>,
        error: Option<&str>,
    ) -> Result<u64, StoreError> {
        let update = Reviews::update_many()
            .col_expr(ReviewColumn::Status, Expr::value(status))
            .col_expr(ReviewColumn::Response, Expr::value(response.map(str::to_owned)))
            .col_expr(ReviewColumn::Error, Expr::value(error.map(str::to_owned)))
            .col_expr(ReviewColumn::DeadlineAt, Expr::value(Option::<OffsetDateTime>::None))
            .filter(ReviewColumn::Id.eq(id))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `existsByStatusAndDeadlineAtAfter`: some review under way and still awaited. A running row past its deadline
    /// is one a stopped process left behind, and waiting for it would wait for nothing.
    pub async fn any_awaited(tx: &mut Tx, running: &str, now: OffsetDateTime) -> Result<bool, StoreError> {
        let select = Reviews::find()
            .filter(ReviewColumn::Status.eq(running))
            .filter(ReviewColumn::DeadlineAt.gt(now))
            .into_query();
        Ok(orm::fetch_count(tx, &count_of(select)).await? > 0)
    }

    /// `settleAbandoned`: conditional on the status in the `where`, so a review its own request settles at the same
    /// moment keeps what the model said — the sweep only ever turns a running row into a failed one.
    pub async fn settle_abandoned(
        tx: &mut Tx,
        running: &str,
        failed: &str,
        error: &str,
        now: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let update = Reviews::update_many()
            .col_expr(ReviewColumn::Status, Expr::value(failed))
            .col_expr(ReviewColumn::Error, Expr::value(error))
            .col_expr(ReviewColumn::DeadlineAt, Expr::value(Option::<OffsetDateTime>::None))
            .filter(ReviewColumn::Status.eq(running))
            .filter(ReviewColumn::DeadlineAt.lt(now))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `deleteByScanIdIn`: the purge's batch of a deleted target's scans.
    pub async fn delete_by_scan_ids(tx: &mut Tx, scan_ids: &[i64]) -> Result<u64, StoreError> {
        if scan_ids.is_empty() {
            return Ok(0);
        }
        let delete = Reviews::delete_many().filter(ReviewColumn::ScanId.is_in(scan_ids.iter().copied())).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }
}

/// `select count(*) from (<select>)`, the selection cleared — what `orm::fetch_count` reads.
fn count_of(mut select: sea_orm::sea_query::SelectStatement) -> sea_orm::sea_query::SelectStatement {
    select.clear_selects().expr_as(Expr::col(ReviewColumn::Id).count(), Alias::new("count"));
    select
}

#[derive(Debug, FromQueryResult)]
struct Newest {
    newest: Option<OffsetDateTime>,
}

#[derive(Debug, FromQueryResult)]
struct Summed {
    week_start: OffsetDateTime,
    category: String,
    state: String,
    targets: i64,
    open: Option<i64>,
    settled: Option<i64>,
    captured_at: OffsetDateTime,
}

#[derive(Debug, FromQueryResult)]
struct Named {
    target_kind: String,
    target_id: i64,
}

/// MySQL's `sum` of a `bigint` is a `DECIMAL`, which the driver does not decode into an integer of Rust's: cast where
/// it is selected, as the issues' aggregates do.
fn as_long(engine: Engine, expression: sea_orm::sea_query::SimpleExpr) -> sea_orm::sea_query::SimpleExpr {
    let to = match engine {
        Engine::MySql => "signed",
        Engine::PostgreSql => "bigint",
    };
    Func::cast_as(expression, Alias::new(to)).into()
}

/// The weekly OWASP record. **What writes and purges has no visibility clause** — the capture is of the whole estate;
/// a reader's read narrows by target, which is what the per-target rows exist for ([`Self::sum_by_week`]).
#[derive(Debug, Clone, Copy)]
pub struct WeeklyRepository;

impl WeeklyRepository {
    /// `newestCaptureOf`: when this week was last written, by any instance — the capture's gate.
    pub async fn newest_capture_of(tx: &mut Tx, week: OffsetDateTime) -> Result<Option<OffsetDateTime>, StoreError> {
        let select = weekly()
            .select_only()
            .expr_as(Func::max(Expr::col(WeeklyColumn::CapturedAt)), "newest")
            .filter(WeeklyColumn::WeekStart.eq(week))
            .into_query();
        let newest: Option<Newest> = orm::fetch_optional(tx, &select).await?;
        Ok(newest.and_then(|row| row.newest))
    }

    /// `deleteWeek`: the week's rows, before they are written again — never another week's.
    pub async fn delete_week(tx: &mut Tx, week: OffsetDateTime) -> Result<u64, StoreError> {
        Ok(orm::execute(tx, &delete_weekly().filter(WeeklyColumn::WeekStart.eq(week)).into_query()).await?)
    }

    /// `deleteWeeksBefore`: every week that starts before this Monday — the evidence window's purge.
    pub async fn delete_weeks_before(tx: &mut Tx, week: OffsetDateTime) -> Result<u64, StoreError> {
        Ok(orm::execute(tx, &delete_weekly().filter(WeeklyColumn::WeekStart.lt(week)).into_query()).await?)
    }

    /// `deleteByTarget`: a target's rows, every week — in the deleting transaction.
    pub async fn delete_by_target(tx: &mut Tx, kind: &str, id: i64) -> Result<u64, StoreError> {
        let delete = delete_weekly()
            .filter(WeeklyColumn::TargetKind.eq(kind))
            .filter(WeeklyColumn::TargetId.eq(id))
            .into_query();
        Ok(orm::execute(tx, &delete).await?)
    }

    /// `targets`: every target the record names, once each — sorted, where Java's `distinct` answered the engine's
    /// order; the sweep only asks which of them are gone.
    pub async fn targets(tx: &mut Tx) -> Result<Vec<WeeklyTarget>, StoreError> {
        let select = weekly()
            .select_only()
            .column(WeeklyColumn::TargetKind)
            .column(WeeklyColumn::TargetId)
            .distinct()
            .into_query();
        let rows: Vec<Named> = orm::fetch_all(tx, &select).await?;
        let mut targets: Vec<WeeklyTarget> =
            rows.into_iter().map(|row| WeeklyTarget { kind: row.target_kind, id: row.target_id }).collect();
        targets.sort();
        Ok(targets)
    }

    pub async fn insert_all(tx: &mut Tx, rows: &[WeeklyRow]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        let actives = rows
            .iter()
            .map(|row| WeeklyActive {
                id: NotSet,
                week_start: Set(row.week_start),
                target_kind: Set(row.target_kind.clone()),
                target_id: Set(row.target_id),
                category: Set(row.category.clone()),
                state: Set(row.state.clone()),
                open_count: Set(row.open_count),
                settled_count: Set(row.settled_count),
                captured_at: Set(row.captured_at),
            })
            .collect();
        orm::execute(tx, &insert_weekly(actives)).await?;
        Ok(())
    }

    /// `sumByWeekCategoryAndState`: every recorded week in `[from_week, to_week]`, narrowed to the targets the reader
    /// may see — each kind by its own column value, a reader who sees nothing reading no row. Grouped in the database:
    /// a year of weeks over a thousand targets is half a million rows, and per week, category and state at most two
    /// thousand. Weeks with no row for those targets are absent — not recorded, which the reader says.
    pub async fn sum_by_week(
        tx: &mut Tx,
        from_week: OffsetDateTime,
        to_week: OffsetDateTime,
        allowed: &Visibility,
    ) -> Result<Vec<WeeklyStateCount>, StoreError> {
        let engine = tx.engine();
        let visible = visible_weekly(allowed)
            .filter(WeeklyColumn::WeekStart.gte(from_week))
            .filter(WeeklyColumn::WeekStart.lte(to_week));
        let mut statement = visible.statement().clone();
        statement
            .clear_selects()
            .clear_order_by()
            .column(WeeklyColumn::WeekStart)
            .column(WeeklyColumn::Category)
            .column(WeeklyColumn::State)
            .expr_as(Expr::col(WeeklyColumn::Id).count(), Alias::new("targets"))
            .expr_as(as_long(engine, Func::sum(Expr::col(WeeklyColumn::OpenCount)).into()), Alias::new("open"))
            .expr_as(as_long(engine, Func::sum(Expr::col(WeeklyColumn::SettledCount)).into()), Alias::new("settled"))
            .expr_as(Func::max(Expr::col(WeeklyColumn::CapturedAt)), Alias::new("captured_at"))
            .add_group_by([
                Expr::col(WeeklyColumn::WeekStart),
                Expr::col(WeeklyColumn::Category),
                Expr::col(WeeklyColumn::State),
            ]);
        let rows: Vec<Summed> = orm::fetch_all(tx, &statement).await?;
        Ok(rows
            .into_iter()
            .map(|row| WeeklyStateCount {
                week_start: row.week_start,
                category: row.category,
                state: row.state,
                targets: row.targets,
                open: row.open.unwrap_or(0),
                settled: row.settled.unwrap_or(0),
                captured_at: row.captured_at,
            })
            .collect())
    }
}
