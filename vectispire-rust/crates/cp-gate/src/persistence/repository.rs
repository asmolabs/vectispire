//! Persistence operations for gate policies and verdicts: `t_gate_policy` and `t_gate_verdict`.
//!
//! **Built with SeaORM, run on the caller's [`Tx`]** (`vectispire_cp_db::orm`): each statement is written once, from
//! the entities in [`super::entities`], and rendered for the transaction's engine.

use sea_orm::sea_query::{Condition, Expr, Func, Order};
use sea_orm::{
    ActiveValue::NotSet, ActiveValue::Set, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait,
};
use time::OffsetDateTime;
use vectispire_cp_db::{Tx, Visibility, orm};

use super::entities::{
    Policies, PolicyActive, PolicyColumn, PolicyModel, VerdictActive, VerdictColumn, VerdictModel, delete_verdicts,
    insert_verdict, verdicts, visible_verdicts,
};
use super::{GatePolicyRow, GateVerdictRow, NewGatePolicyRow, StoreError};

impl From<PolicyModel> for GatePolicyRow {
    fn from(model: PolicyModel) -> GatePolicyRow {
        GatePolicyRow {
            id: model.id,
            target_kind: model.target_kind,
            target_id: model.target_id,
            version: model.version,
            is_active: model.is_active,
            fail_on_severity: model.fail_on_severity,
            fail_on_kev: model.fail_on_kev,
            fixable_only: model.fixable_only,
            include_triaged: model.include_triaged,
            include_ai_review: model.include_ai_review,
            fail_on_uncovered_languages: model.fail_on_uncovered_languages,
            include_plugins: model.include_plugins,
            note: model.note,
            created_by: model.created_by,
            created_at: model.created_at,
        }
    }
}

impl From<VerdictModel> for GateVerdictRow {
    fn from(model: VerdictModel) -> GateVerdictRow {
        GateVerdictRow {
            id: model.id,
            repo_id: model.repo_id,
            container_id: model.container_id,
            passed: model.passed,
            evaluated: model.evaluated,
            violations: model.violations,
            critical_count: model.critical_count,
            high_count: model.high_count,
            medium_count: model.medium_count,
            low_count: model.low_count,
            fail_on_severity: model.fail_on_severity,
            policy_source: model.policy_source,
            policy_version: model.policy_version,
            relaxations_ignored: model.relaxations_ignored,
            decided_at: model.decided_at,
            decided_by: model.decided_by,
            ip_address: model.ip_address,
        }
    }
}

/// A negative limit reads nothing, as an empty page — never an error from the engine.
fn bounded(limit: i32) -> u64 {
    u64::try_from(limit).unwrap_or(0)
}

fn scope(kind: &str, id: i64) -> Condition {
    Condition::all().add(PolicyColumn::TargetKind.eq(kind)).add(PolicyColumn::TargetId.eq(id))
}

#[derive(Debug, FromQueryResult)]
struct Highest {
    /// `max(version)` and not `coalesce(max(version), 0)`: the column is an `int`, and so is the coalesce on
    /// PostgreSQL, so the absent maximum is read as `None` rather than cast.
    max_v: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub struct GatePolicyRepository;

impl GatePolicyRepository {
    pub async fn find_active(tx: &mut Tx) -> Result<Vec<GatePolicyRow>, StoreError> {
        let select = Policies::find().filter(PolicyColumn::IsActive.eq(true)).into_query();
        let models: Vec<PolicyModel> = orm::fetch_all(tx, &select).await?;
        Ok(models.into_iter().map(GatePolicyRow::from).collect())
    }

    pub async fn highest_version(tx: &mut Tx, kind: &str, id: i64) -> Result<i32, StoreError> {
        let select = Policies::find()
            .select_only()
            .expr_as(Func::max(Expr::col(PolicyColumn::Version)), "max_v")
            .filter(scope(kind, id))
            .into_query();
        let highest: Option<Highest> = orm::fetch_optional(tx, &select).await?;
        Ok(highest.and_then(|row| row.max_v).unwrap_or(0))
    }

    /// Supersedes the active policy of one scope: `is_active` becomes null, never false, because the unique index
    /// holding "at most one active per scope" counts nulls as distinct (`GatePolicyRepository.java`).
    pub async fn supersede(tx: &mut Tx, kind: &str, id: i64) -> Result<u64, StoreError> {
        let update = Policies::update_many()
            .col_expr(PolicyColumn::IsActive, Expr::value(Option::<bool>::None))
            .filter(scope(kind, id))
            .filter(PolicyColumn::IsActive.eq(true))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    pub async fn insert(tx: &mut Tx, row: &NewGatePolicyRow) -> Result<i64, StoreError> {
        let active = PolicyActive {
            id: NotSet,
            target_kind: Set(row.target_kind.clone()),
            target_id: Set(row.target_id),
            version: Set(row.version),
            is_active: Set(row.is_active),
            fail_on_severity: Set(row.fail_on_severity.clone()),
            fail_on_kev: Set(row.fail_on_kev),
            fixable_only: Set(row.fixable_only),
            include_triaged: Set(row.include_triaged),
            include_ai_review: Set(row.include_ai_review),
            fail_on_uncovered_languages: Set(row.fail_on_uncovered_languages),
            include_plugins: Set(row.include_plugins),
            note: Set(row.note.clone()),
            created_by: Set(row.created_by.clone()),
            created_at: Set(row.created_at),
        };
        Ok(orm::insert_returning_id::<Policies>(tx, Policies::insert(active).into_query()).await?)
    }

    pub async fn delete_by_target(tx: &mut Tx, kind: &str, id: i64) -> Result<u64, StoreError> {
        let delete = Policies::delete_many().filter(scope(kind, id)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GateVerdictRepository;

impl GateVerdictRepository {
    pub async fn insert(tx: &mut Tx, row: &GateVerdictRow) -> Result<(), StoreError> {
        let active = VerdictActive {
            id: Set(row.id.clone()),
            repo_id: Set(row.repo_id),
            container_id: Set(row.container_id),
            passed: Set(row.passed),
            evaluated: Set(row.evaluated),
            violations: Set(row.violations),
            critical_count: Set(row.critical_count),
            high_count: Set(row.high_count),
            medium_count: Set(row.medium_count),
            low_count: Set(row.low_count),
            fail_on_severity: Set(row.fail_on_severity.clone()),
            policy_source: Set(row.policy_source.clone()),
            policy_version: Set(row.policy_version),
            relaxations_ignored: Set(row.relaxations_ignored),
            decided_at: Set(row.decided_at),
            decided_by: Set(row.decided_by.clone()),
            ip_address: Set(row.ip_address.clone()),
        };
        orm::execute(tx, &insert_verdict(active)).await?;
        Ok(())
    }

    /// One page of the register for `allowed`, after a cursor or from the newest: Java's `firstPage`, `pageAfter`
    /// and their `…Within`, in one statement.
    ///
    /// **Ordered by instant and id**, so that verdicts written in the same millisecond fall on one side of a cursor
    /// and none is skipped; and **read within the reader's targets**, so that every row read — and the cursor taken
    /// from the last of them — is one the reader may see (the audit of 10 October 2026).
    pub async fn page(
        tx: &mut Tx,
        allowed: &Visibility,
        after: Option<(OffsetDateTime, &str)>,
        limit: i32,
    ) -> Result<Vec<GateVerdictRow>, StoreError> {
        let mut page = visible_verdicts(allowed);
        if let Some((at, id)) = after {
            page = page.filter(
                Condition::any()
                    .add(VerdictColumn::DecidedAt.lt(at))
                    .add(Condition::all().add(VerdictColumn::DecidedAt.eq(at)).add(VerdictColumn::Id.lt(id))),
            );
        }
        let page = page
            .order_by(VerdictColumn::DecidedAt, Order::Desc)
            .order_by(VerdictColumn::Id, Order::Desc)
            .limit(bounded(limit));
        let models: Vec<VerdictModel> = orm::fetch_all(tx, page.statement()).await?;
        Ok(models.into_iter().map(GateVerdictRow::from).collect())
    }

    /// The newest verdicts, every target's — for the indicator, which answers no single reader's page.
    pub async fn newest(tx: &mut Tx, limit: i32) -> Result<Vec<GateVerdictRow>, StoreError> {
        let select = verdicts().order_by_desc(VerdictColumn::DecidedAt).limit(bounded(limit)).into_query();
        let models: Vec<VerdictModel> = orm::fetch_all(tx, &select).await?;
        Ok(models.into_iter().map(GateVerdictRow::from).collect())
    }

    pub async fn last_for_repository(
        tx: &mut Tx,
        repo_id: i64,
        from: OffsetDateTime,
        until: Option<OffsetDateTime>,
    ) -> Result<Option<GateVerdictRow>, StoreError> {
        Self::last_within(tx, VerdictColumn::RepoId.eq(repo_id), from, until).await
    }

    pub async fn last_for_container(
        tx: &mut Tx,
        container_id: i64,
        from: OffsetDateTime,
        until: Option<OffsetDateTime>,
    ) -> Result<Option<GateVerdictRow>, StoreError> {
        Self::last_within(tx, VerdictColumn::ContainerId.eq(container_id), from, until).await
    }

    /// The last verdict of one target from `from` on, before `until` when a later scan closes the window — no
    /// far-future bound for the open one, since `Instant.MAX` fits neither engine's timestamp.
    async fn last_within(
        tx: &mut Tx,
        target: impl sea_orm::sea_query::IntoCondition,
        from: OffsetDateTime,
        until: Option<OffsetDateTime>,
    ) -> Result<Option<GateVerdictRow>, StoreError> {
        let mut select = verdicts().filter(target).filter(VerdictColumn::DecidedAt.gte(from));
        if let Some(until) = until {
            select = select.filter(VerdictColumn::DecidedAt.lt(until));
        }
        let select = select.order_by_desc(VerdictColumn::DecidedAt).limit(1).into_query();
        let model: Option<VerdictModel> = orm::fetch_optional(tx, &select).await?;
        Ok(model.map(GateVerdictRow::from))
    }

    pub async fn delete_before(tx: &mut Tx, cutoff: OffsetDateTime) -> Result<u64, StoreError> {
        let delete = delete_verdicts().filter(VerdictColumn::DecidedAt.lt(cutoff)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }
}
