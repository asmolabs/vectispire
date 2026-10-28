//! Persistence operations for issues tables: `t_issue` and `t_issue_triage_event`.
//!
//! **Built with SeaORM, run on the caller's [`Tx`]** (`vectispire_cp_db::orm`): each statement is written once, from
//! the entities in [`super::entities`], and rendered for the transaction's engine. The fixed statements are
//! `sqlx::query!` in [`super::checked`], on the same transaction.

use sea_orm::sea_query::{BinOper, Condition, Expr, ExprTrait, Func, Order};
use sea_orm::{
    ActiveValue::NotSet, ActiveValue::Set, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, Select,
};
use time::OffsetDateTime;
use vectispire_cp_db::orm;
use vectispire_cp_db::query::{Issues, rows_of};
use vectispire_cp_db::{Engine, ScanTarget, Tx, Visibility};

use super::entities::{
    IssueActive, IssueColumn, IssueModel, TriageEventColumn, TriageEventModel, TriageEvents, delete_issues,
    insert_issue, issues, update_issues, visible_issues,
};
use super::filters::IssueFilters;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct IssueRow {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub fingerprint: String,
    pub type_: String,
    pub identifier: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
    pub file_path: Option<String>,
    pub owasp_category: Option<String>,
    pub source: Option<String>,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
    pub import_source: Option<String>,
    pub severity: String,
    pub epss_score: Option<f64>,
    pub is_kev: bool,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fix_state: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
    pub description: Option<String>,
    pub reachability: String,
    pub reachable_symbols: Option<String>,
    pub state: String,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
    pub resolution_seconds: Option<i64>,
    pub sla_breach_signalled_at: Option<OffsetDateTime>,
    pub first_seen_scan_id: Option<i64>,
    pub last_seen_scan_id: Option<i64>,
    pub times_seen: i32,
    pub triage_status: String,
    pub triage_justification: Option<String>,
    pub triage_comment: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<OffsetDateTime>,
    pub triage_expires_at: Option<OffsetDateTime>,
    pub triage_requested_status: Option<String>,
    pub is_direct_dependency: Option<bool>,
    pub line: Option<i32>,
    pub ticket_ref: Option<String>,
    pub ticket_url: Option<String>,
    pub ticket_attached_by: Option<String>,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewIssue {
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
    pub fingerprint: String,
    pub type_: String,
    pub identifier: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub purl: Option<String>,
    pub file_path: Option<String>,
    pub owasp_category: Option<String>,
    pub source: String,
    pub tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool_version: Option<String>,
    pub import_source: Option<String>,
    pub severity: String,
    pub epss_score: Option<f64>,
    pub is_kev: bool,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub fix_state: Option<String>,
    pub fix_versions: Option<String>,
    pub link: Option<String>,
    pub description: Option<String>,
    pub reachability: String,
    pub reachable_symbols: Option<String>,
    pub state: String,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
    pub resolution_seconds: Option<i64>,
    pub sla_breach_signalled_at: Option<OffsetDateTime>,
    pub first_seen_scan_id: Option<i64>,
    pub last_seen_scan_id: Option<i64>,
    pub times_seen: i32,
    pub triage_status: String,
    pub triage_justification: Option<String>,
    pub triage_comment: Option<String>,
    pub triaged_by: Option<String>,
    pub triaged_at: Option<OffsetDateTime>,
    pub triage_expires_at: Option<OffsetDateTime>,
    pub triage_requested_status: Option<String>,
    pub is_direct_dependency: Option<bool>,
    pub line: Option<i32>,
    pub ticket_ref: Option<String>,
    pub ticket_url: Option<String>,
    pub ticket_attached_by: Option<String>,
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TriageEventRow {
    pub id: i64,
    pub issue_id: i64,
    pub from_status: String,
    pub to_status: String,
    pub justification: Option<String>,
    pub comment: Option<String>,
    pub actor: Option<String>,
    pub origin: String,
    pub occurred_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub requested_status: Option<String>,
    pub scan_id: Option<i64>,
    pub previous_resolved_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewTriageEvent {
    pub issue_id: i64,
    pub from_status: String,
    pub to_status: String,
    pub justification: Option<String>,
    pub comment: Option<String>,
    pub actor: Option<String>,
    pub origin: String,
    pub occurred_at: OffsetDateTime,
    pub expires_at: Option<OffsetDateTime>,
    pub requested_status: Option<String>,
    pub scan_id: Option<i64>,
    pub previous_resolved_at: Option<OffsetDateTime>,
}

impl From<IssueModel> for IssueRow {
    /// `identifier` and `severity` may be null in the schema and have always been read here as text: an absent one is
    /// the empty string, as the hand-written reader made it. `source` stays absent — Java answers `null` for it, and
    /// the replay of `DualTargetVisibilityRoutesTest` caught the `""`.
    fn from(model: IssueModel) -> IssueRow {
        IssueRow {
            id: model.id,
            repo_id: model.repo_id,
            container_id: model.container_id,
            fingerprint: model.fingerprint,
            type_: model.type_,
            identifier: model.identifier.unwrap_or_default(),
            package_name: model.package_name,
            package_version: model.package_version,
            purl: model.purl,
            file_path: model.file_path,
            owasp_category: model.owasp_category,
            source: model.source,
            tool: model.tool,
            tool_name: model.tool_name,
            tool_version: model.tool_version,
            import_source: model.import_source,
            severity: model.severity.unwrap_or_default(),
            epss_score: model.epss_score,
            is_kev: model.is_kev,
            cvss_score: model.cvss_score,
            cvss_vector: model.cvss_vector,
            fix_state: model.fix_state,
            fix_versions: model.fix_versions,
            link: model.link,
            description: model.description,
            reachability: model.reachability,
            reachable_symbols: model.reachable_symbols,
            state: model.state,
            first_seen_at: model.first_seen_at,
            last_seen_at: model.last_seen_at,
            resolved_at: model.resolved_at,
            resolution_seconds: model.resolution_seconds,
            sla_breach_signalled_at: model.sla_breach_signalled_at,
            first_seen_scan_id: model.first_seen_scan_id,
            last_seen_scan_id: model.last_seen_scan_id,
            times_seen: model.times_seen,
            triage_status: model.triage_status,
            triage_justification: model.triage_justification,
            triage_comment: model.triage_comment,
            triaged_by: model.triaged_by,
            triaged_at: model.triaged_at,
            triage_expires_at: model.triage_expires_at,
            triage_requested_status: model.triage_requested_status,
            is_direct_dependency: model.is_direct_dependency,
            line: model.line,
            ticket_ref: model.ticket_ref,
            ticket_url: model.ticket_url,
            ticket_attached_by: model.ticket_attached_by,
            revision: model.revision,
        }
    }
}

impl From<TriageEventModel> for TriageEventRow {
    fn from(model: TriageEventModel) -> TriageEventRow {
        TriageEventRow {
            id: model.id,
            issue_id: model.issue_id,
            from_status: model.from_status,
            to_status: model.to_status,
            justification: model.justification,
            comment: model.comment,
            actor: model.actor,
            origin: model.origin,
            occurred_at: model.occurred_at,
            expires_at: model.expires_at,
            requested_status: model.requested_status,
            scan_id: model.scan_id,
            previous_resolved_at: model.previous_resolved_at,
        }
    }
}

/// Every column of an issue but its key, as written by an insert or an update — one list for both.
macro_rules! issue_columns {
    ($from:expr) => {{
        let from = $from;
        IssueActive {
            id: NotSet,
            repo_id: Set(from.repo_id),
            container_id: Set(from.container_id),
            fingerprint: Set(from.fingerprint.clone()),
            type_: Set(from.type_.clone()),
            identifier: Set(Some(from.identifier.clone())),
            package_name: Set(from.package_name.clone()),
            package_version: Set(from.package_version.clone()),
            purl: Set(from.purl.clone()),
            file_path: Set(from.file_path.clone()),
            owasp_category: Set(from.owasp_category.clone()),
            // A `NewIssue`'s source is text, an `IssueRow`'s may be null: `into` takes either.
            source: Set(from.source.clone().into()),
            tool: Set(from.tool.clone()),
            tool_name: Set(from.tool_name.clone()),
            tool_version: Set(from.tool_version.clone()),
            import_source: Set(from.import_source.clone()),
            severity: Set(Some(from.severity.clone())),
            epss_score: Set(from.epss_score),
            is_kev: Set(from.is_kev),
            cvss_score: Set(from.cvss_score),
            cvss_vector: Set(from.cvss_vector.clone()),
            fix_state: Set(from.fix_state.clone()),
            fix_versions: Set(from.fix_versions.clone()),
            link: Set(from.link.clone()),
            description: Set(from.description.clone()),
            reachability: Set(from.reachability.clone()),
            reachable_symbols: Set(from.reachable_symbols.clone()),
            state: Set(from.state.clone()),
            first_seen_at: Set(from.first_seen_at),
            last_seen_at: Set(from.last_seen_at),
            resolved_at: Set(from.resolved_at),
            resolution_seconds: Set(from.resolution_seconds),
            sla_breach_signalled_at: Set(from.sla_breach_signalled_at),
            first_seen_scan_id: Set(from.first_seen_scan_id),
            last_seen_scan_id: Set(from.last_seen_scan_id),
            times_seen: Set(from.times_seen),
            triage_status: Set(from.triage_status.clone()),
            triage_justification: Set(from.triage_justification.clone()),
            triage_comment: Set(from.triage_comment.clone()),
            triaged_by: Set(from.triaged_by.clone()),
            triaged_at: Set(from.triaged_at),
            triage_expires_at: Set(from.triage_expires_at),
            triage_requested_status: Set(from.triage_requested_status.clone()),
            is_direct_dependency: Set(from.is_direct_dependency),
            line: Set(from.line),
            ticket_ref: Set(from.ticket_ref.clone()),
            ticket_url: Set(from.ticket_url.clone()),
            ticket_attached_by: Set(from.ticket_attached_by.clone()),
            revision: Set(from.revision),
        }
    }};
}

/// How many identifiers one `IN` list binds — `IssueSpecifications.IN_LIST_BATCH`, under PostgreSQL's 65,535
/// parameters per statement.
const IN_LIST_BATCH: usize = 1_000;

/// The statuses a decision settles — `TriageStatus.isSettled()`.
const SETTLED: [&str; 3] = ["not_affected", "fixed", "will_not_fix"];

#[derive(Debug, FromQueryResult)]
struct Id {
    id: i64,
}

#[derive(Debug, FromQueryResult)]
struct CountBy {
    target: i64,
    c: i64,
}

#[derive(Debug, FromQueryResult)]
struct SeverityCount {
    repo_id: Option<i64>,
    container_id: Option<i64>,
    severity: Option<String>,
    c: i64,
}

async fn issue_rows(tx: &mut Tx, select: Select<impl EntityTrait>) -> Result<Vec<IssueRow>, StoreError> {
    let models: Vec<IssueModel> = orm::fetch_all(tx, &select.into_query()).await?;
    Ok(models.into_iter().map(IssueRow::from).collect())
}

async fn event_rows(tx: &mut Tx, select: Select<TriageEvents>) -> Result<Vec<TriageEventRow>, StoreError> {
    let models: Vec<TriageEventModel> = orm::fetch_all(tx, &select.into_query()).await?;
    Ok(models.into_iter().map(TriageEventRow::from).collect())
}

fn upper(column: IssueColumn) -> Expr {
    Expr::expr(Func::upper(Expr::col(column)))
}

fn lower_like(column: IssueColumn, pattern: &str) -> Expr {
    Expr::expr(Func::lower(Expr::col(column))).binary(BinOper::Like, Func::lower(Expr::val(pattern)))
}

#[derive(Debug, Clone, Copy)]
pub struct IssueRepository;

impl IssueRepository {
    // -------------------------------------------------------------------------
    // t_issue queries
    // -------------------------------------------------------------------------

    pub async fn find_by_id(tx: &mut Tx, id: i64) -> Result<Option<IssueRow>, StoreError> {
        let select = issues().filter(IssueColumn::Id.eq(id)).into_query();
        let model: Option<IssueModel> = orm::fetch_optional(tx, &select).await?;
        Ok(model.map(IssueRow::from))
    }

    /// The issues in `state` — of one target, or of all — in key order and whole, as the gate weighs them: Java's
    /// `findByStateAndRepoId`, `findByStateAndRepoIdIsNullAndContainerId` and `findByState`.
    ///
    /// **Not the backlog's page**, which these were read through: its order is the screen's (most severe first),
    /// it stops at a page's size, and its image filter is `container_id` alone — a row naming a repository and the
    /// image, which belongs to the repository, weighed on the image's gate and was listed, identifier and all, to a
    /// pipeline that may see only the image. A target here is [`rows_of`]'s, the rule every reader's query keeps.
    pub async fn find_by_state(
        tx: &mut Tx,
        state: &str,
        target: Option<ScanTarget>,
    ) -> Result<Vec<IssueRow>, StoreError> {
        let mut select = issues().filter(IssueColumn::State.eq(state));
        if let Some(target) = target {
            select = select.filter(rows_of::<Issues>(&std::collections::BTreeSet::from([target])));
        }
        issue_rows(tx, select.order_by_asc(IssueColumn::Id)).await
    }

    pub async fn find_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<Vec<IssueRow>, StoreError> {
        let mut results = Vec::new();
        for chunk in ids.chunks(IN_LIST_BATCH) {
            results.extend(issue_rows(tx, issues().filter(IssueColumn::Id.is_in(chunk.iter().copied()))).await?);
        }
        Ok(results)
    }

    pub async fn find_by_fingerprints(tx: &mut Tx, fingerprints: &[String]) -> Result<Vec<IssueRow>, StoreError> {
        let mut results = Vec::new();
        for chunk in fingerprints.chunks(IN_LIST_BATCH) {
            results
                .extend(issue_rows(tx, issues().filter(IssueColumn::Fingerprint.is_in(chunk.iter().cloned()))).await?);
        }
        Ok(results)
    }

    pub async fn find_open_by_target(
        tx: &mut Tx,
        state: &str,
        types: &[String],
        repo_id: Option<i64>,
        container_id: Option<i64>,
    ) -> Result<Vec<IssueRow>, StoreError> {
        Self::open_of_target(tx, state, types, None, repo_id, container_id).await
    }

    pub async fn find_open_by_target_and_tools(
        tx: &mut Tx,
        state: &str,
        types: &[String],
        tools: &[String],
        repo_id: Option<i64>,
        container_id: Option<i64>,
    ) -> Result<Vec<IssueRow>, StoreError> {
        Self::open_of_target(tx, state, types, Some(tools), repo_id, container_id).await
    }

    async fn open_of_target(
        tx: &mut Tx,
        state: &str,
        types: &[String],
        tools: Option<&[String]>,
        repo_id: Option<i64>,
        container_id: Option<i64>,
    ) -> Result<Vec<IssueRow>, StoreError> {
        if types.is_empty() || tools.is_some_and(<[String]>::is_empty) {
            return Ok(Vec::new());
        }
        let mut target = Condition::any();
        if let Some(repo_id) = repo_id {
            target = target.add(IssueColumn::RepoId.eq(repo_id));
        }
        if let Some(container_id) = container_id {
            target = target.add(IssueColumn::ContainerId.eq(container_id));
        }
        if target.is_empty() {
            return Ok(Vec::new());
        }
        let mut select = issues()
            .filter(IssueColumn::State.eq(state))
            .filter(IssueColumn::Type.is_in(types.iter().cloned()))
            .filter(target);
        if let Some(tools) = tools {
            select = select.filter(IssueColumn::Tool.is_in(tools.iter().cloned()));
        }
        issue_rows(tx, select).await
    }

    pub async fn insert_issue(tx: &mut Tx, issue: &NewIssue) -> Result<IssueRow, StoreError> {
        let id = insert_issue(tx, issue_columns!(issue)).await?;
        Self::find_by_id(tx, id).await?.ok_or_else(|| StoreError::Other("Inserted issue not found".to_owned()))
    }

    /// Optimistic, as `@Version` is: written only where the revision is still the one read, and moved by one.
    pub async fn update_issue(tx: &mut Tx, issue: &IssueRow) -> Result<bool, StoreError> {
        let mut columns = issue_columns!(issue);
        columns.revision = Set(issue.revision.saturating_add(1));
        let update = update_issues()
            .set(columns)
            .filter(IssueColumn::Id.eq(issue.id))
            .filter(IssueColumn::Revision.eq(issue.revision))
            .into_query();
        Ok(orm::execute(tx, &update).await? > 0)
    }

    pub async fn resolve_disappeared(tx: &mut Tx, ids: &[i64], moment: OffsetDateTime) -> Result<u64, StoreError> {
        // The one expression SeaORM cannot say for both engines: an age in seconds between two timestamps.
        let age = match tx.engine() {
            Engine::MySql => Expr::cust_with_values("TIMESTAMPDIFF(SECOND, first_seen_at, ?)", [moment]),
            Engine::PostgreSql => Expr::cust_with_values("EXTRACT(EPOCH FROM ($1 - first_seen_at))::bigint", [moment]),
        };
        let mut total: u64 = 0;
        for chunk in ids.chunks(IN_LIST_BATCH) {
            let update = update_issues()
                .col_expr(IssueColumn::State, Expr::val("resolved"))
                .col_expr(IssueColumn::ResolvedAt, Expr::val(moment))
                .col_expr(IssueColumn::ResolutionSeconds, age.clone())
                .col_expr(IssueColumn::Revision, Expr::col(IssueColumn::Revision).add(1))
                .filter(IssueColumn::Id.is_in(chunk.iter().copied()))
                .into_query();
            total = total.saturating_add(orm::execute(tx, &update).await?);
        }
        Ok(total)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn find_unsignalled_breaches(
        tx: &mut Tx,
        state: &str,
        severity: &str,
        before: OffsetDateTime,
        since: OffsetDateTime,
        settled: &[String],
        after_id: i64,
        limit: i64,
    ) -> Result<Vec<IssueRow>, StoreError> {
        let select = issues()
            .filter(IssueColumn::State.eq(state))
            .filter(IssueColumn::Severity.eq(severity))
            .filter(IssueColumn::FirstSeenAt.lt(before))
            .filter(IssueColumn::FirstSeenAt.gte(since))
            .filter(IssueColumn::SlaBreachSignalledAt.is_null())
            .filter(IssueColumn::TriageStatus.is_not_in(settled.iter().cloned()))
            .filter(IssueColumn::Id.gt(after_id))
            .order_by_asc(IssueColumn::Id)
            .limit(u64::try_from(limit).unwrap_or(0));
        issue_rows(tx, select).await
    }

    pub async fn mark_sla_breach_signalled(
        tx: &mut Tx,
        ids: &[i64],
        moment: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let mut total: u64 = 0;
        for chunk in ids.chunks(IN_LIST_BATCH) {
            let update = update_issues()
                .col_expr(IssueColumn::SlaBreachSignalledAt, Expr::val(moment))
                .filter(IssueColumn::Id.is_in(chunk.iter().copied()))
                .into_query();
            total = total.saturating_add(orm::execute(tx, &update).await?);
        }
        Ok(total)
    }

    pub async fn find_with_expired_triage(tx: &mut Tx, now: OffsetDateTime) -> Result<Vec<IssueRow>, StoreError> {
        issue_rows(
            tx,
            issues().filter(IssueColumn::TriageExpiresAt.is_not_null()).filter(IssueColumn::TriageExpiresAt.lte(now)),
        )
        .await
    }

    pub async fn count_open_by_repository(tx: &mut Tx, state: &str) -> Result<Vec<(i64, i64)>, StoreError> {
        Self::count_open_by(tx, state, IssueColumn::RepoId).await
    }

    pub async fn count_open_by_container(tx: &mut Tx, state: &str) -> Result<Vec<(i64, i64)>, StoreError> {
        Self::count_open_by(tx, state, IssueColumn::ContainerId).await
    }

    async fn count_open_by(tx: &mut Tx, state: &str, target: IssueColumn) -> Result<Vec<(i64, i64)>, StoreError> {
        let select = issues()
            .select_only()
            .column_as(target, "target")
            .column_as(IssueColumn::Id.count(), "c")
            .filter(IssueColumn::State.eq(state))
            .filter(target.is_not_null())
            .group_by(target)
            .into_query();
        let rows: Vec<CountBy> = orm::fetch_all(tx, &select).await?;
        Ok(rows.into_iter().map(|row| (row.target, row.c)).collect())
    }

    /// The open, unsettled issues by target and severity, of the targets `allowed` — one statement, each row once.
    pub async fn count_open_by_target_and_severity(
        tx: &mut Tx,
        allowed: &Visibility,
    ) -> Result<Vec<(Option<i64>, Option<i64>, String, i64)>, StoreError> {
        let grouped = visible_issues(allowed)
            .filter(IssueColumn::State.eq("open"))
            .filter(IssueColumn::TriageStatus.is_not_in(SETTLED))
            .grouped_count(&[IssueColumn::RepoId, IssueColumn::ContainerId, IssueColumn::Severity]);
        let rows: Vec<SeverityCount> = orm::fetch_all(tx, &grouped).await?;
        Ok(rows
            .into_iter()
            .map(|row| (row.repo_id, row.container_id, row.severity.unwrap_or_default(), row.c))
            .collect())
    }

    pub async fn find_ids_by_repo_id(tx: &mut Tx, repo_id: i64) -> Result<Vec<i64>, StoreError> {
        Self::ids_where(tx, IssueColumn::RepoId.eq(repo_id)).await
    }

    pub async fn find_ids_by_container_id(tx: &mut Tx, container_id: i64) -> Result<Vec<i64>, StoreError> {
        Self::ids_where(tx, IssueColumn::ContainerId.eq(container_id)).await
    }

    async fn ids_where(tx: &mut Tx, condition: Expr) -> Result<Vec<i64>, StoreError> {
        let select = issues().select_only().column(IssueColumn::Id).filter(condition).into_query();
        let rows: Vec<Id> = orm::fetch_all(tx, &select).await?;
        Ok(rows.into_iter().map(|row| row.id).collect())
    }

    /// `IssueRepository::find_orphaned_ids`: cross-module orphan sweep checked against `t_container` and `t_repository`.
    pub async fn find_orphaned_ids(tx: &mut Tx) -> Result<Vec<i64>, StoreError> {
        super::checked::find_orphaned_ids(tx).await
    }

    pub async fn delete_by_ids(tx: &mut Tx, ids: &[i64]) -> Result<u64, StoreError> {
        let mut total: u64 = 0;
        for chunk in ids.chunks(IN_LIST_BATCH) {
            let delete = delete_issues().filter(IssueColumn::Id.is_in(chunk.iter().copied())).into_query();
            total = total.saturating_add(orm::execute(tx, &delete).await?);
        }
        Ok(total)
    }

    // -------------------------------------------------------------------------
    // t_issue_triage_event queries
    // -------------------------------------------------------------------------

    pub async fn insert_triage_events(tx: &mut Tx, events: &[NewTriageEvent]) -> Result<(), StoreError> {
        for event in events {
            super::checked::insert_triage_event(tx, event).await?;
        }
        Ok(())
    }

    pub async fn find_triage_events_for_issues(
        tx: &mut Tx,
        issue_ids: &[i64],
    ) -> Result<Vec<TriageEventRow>, StoreError> {
        let mut results = Vec::new();
        for chunk in issue_ids.chunks(IN_LIST_BATCH) {
            let select = TriageEvents::find()
                .filter(TriageEventColumn::IssueId.is_in(chunk.iter().copied()))
                .order_by_desc(TriageEventColumn::OccurredAt)
                .order_by_desc(TriageEventColumn::Id);
            results.extend(event_rows(tx, select).await?);
        }
        Ok(results)
    }

    pub async fn find_triage_events_by_issue_id(tx: &mut Tx, issue_id: i64) -> Result<Vec<TriageEventRow>, StoreError> {
        let select = TriageEvents::find()
            .filter(TriageEventColumn::IssueId.eq(issue_id))
            .order_by_asc(TriageEventColumn::OccurredAt)
            .order_by_asc(TriageEventColumn::Id);
        event_rows(tx, select).await
    }

    pub async fn delete_triage_events_by_issue_ids(tx: &mut Tx, issue_ids: &[i64]) -> Result<u64, StoreError> {
        let mut total: u64 = 0;
        for chunk in issue_ids.chunks(IN_LIST_BATCH) {
            let delete = TriageEvents::delete_many()
                .filter(TriageEventColumn::IssueId.is_in(chunk.iter().copied()))
                .into_query();
            total = total.saturating_add(orm::execute(tx, &delete).await?);
        }
        Ok(total)
    }

    // -------------------------------------------------------------------------
    // Backlog Paging & Filters
    // -------------------------------------------------------------------------

    pub async fn page_issues(
        tx: &mut Tx,
        filters: &IssueFilters,
        limit: i32,
        offset: i32,
    ) -> Result<(Vec<IssueRow>, i64), StoreError> {
        let visible = visible_issues(&filters.visibility).filter(criteria(filters));
        let total = orm::fetch_count(tx, &visible.count()).await?;
        if total == 0 {
            return Ok((Vec::new(), 0));
        }
        // Most severe first, then the newest, as `IssueSpecifications.MOST_SEVERE_FIRST`.
        let page = visible
            .order_by_expr(
                Expr::cust("case upper(severity) when 'CRITICAL' then 1 when 'HIGH' then 2 when 'MEDIUM' then 3 when 'LOW' then 4 else 5 end"),
                Order::Asc,
            )
            .order_by(IssueColumn::FirstSeenAt, Order::Desc)
            .order_by(IssueColumn::Id, Order::Desc)
            .limit(u64::try_from(limit).unwrap_or(0))
            .offset(u64::try_from(offset).unwrap_or(0));
        let models: Vec<IssueModel> = orm::fetch_all(tx, page.statement()).await?;
        Ok((models.into_iter().map(IssueRow::from).collect(), total))
    }

    pub async fn count_issues(tx: &mut Tx, filters: &IssueFilters) -> Result<i64, StoreError> {
        let visible = visible_issues(&filters.visibility).filter(criteria(filters));
        Ok(orm::fetch_count(tx, &visible.count()).await?)
    }

    // -------------------------------------------------------------------------
    // Exceptions Register
    // -------------------------------------------------------------------------

    pub async fn register_exceptions(
        tx: &mut Tx,
        allowed: &Visibility,
        cursor: Option<(OffsetDateTime, i64)>,
        limit: usize,
    ) -> Result<Vec<IssueRow>, StoreError> {
        let mut register = visible_issues(allowed).filter(IssueColumn::TriageStatus.is_in([
            "not_affected",
            "will_not_fix",
            "pending_approval",
        ]));
        if let Some((at, id)) = cursor {
            register = register.filter(
                Condition::any()
                    .add(IssueColumn::TriagedAt.lt(at))
                    .add(Condition::all().add(IssueColumn::TriagedAt.eq(at)).add(IssueColumn::Id.lt(id))),
            );
        }
        let register = register
            .order_by(IssueColumn::TriagedAt, Order::Desc)
            .order_by(IssueColumn::Id, Order::Desc)
            .limit(u64::try_from(limit).unwrap_or(500));
        let models: Vec<IssueModel> = orm::fetch_all(tx, register.statement()).await?;
        Ok(models.into_iter().map(IssueRow::from).collect())
    }

    pub async fn find_page(
        tx: &mut Tx,
        filters: &IssueFilters,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<IssueRow>, i64), StoreError> {
        let l = i32::try_from(limit).unwrap_or(500);
        let o = i32::try_from(offset).unwrap_or(0);
        Self::page_issues(tx, filters, l, o).await
    }

    pub async fn count(tx: &mut Tx, filters: &IssueFilters) -> Result<i64, StoreError> {
        Self::count_issues(tx, filters).await
    }

    pub async fn count_by_state_and_repository(tx: &mut Tx, state: &str, repo_id: i64) -> Result<i64, StoreError> {
        super::checked::count_by_state_and_repository(tx, state, repo_id).await
    }

    pub async fn count_for_repository(tx: &mut Tx, repo_id: i64, not_a_decision: &str) -> Result<i64, StoreError> {
        super::checked::count_decisions_for_repository(tx, repo_id, not_a_decision).await
    }
}

pub struct TriageEventRepository;

impl TriageEventRepository {
    pub async fn find_for_issues(tx: &mut Tx, issue_ids: &[i64]) -> Result<Vec<TriageEventRow>, StoreError> {
        IssueRepository::find_triage_events_for_issues(tx, issue_ids).await
    }

    pub async fn count_for_repository(tx: &mut Tx, repo_id: i64, not_a_decision: &str) -> Result<i64, StoreError> {
        IssueRepository::count_for_repository(tx, repo_id, not_a_decision).await
    }
}

/// The backlog's criteria but the reader's visibility, which [`visible_issues`] writes first.
fn criteria(filters: &IssueFilters) -> Condition {
    let mut all = Condition::all();
    if let Some(state) = &filters.state {
        all = all.add(IssueColumn::State.eq(state.as_str()));
    }
    if let Some(severity) = &filters.severity {
        all = all.add(upper(IssueColumn::Severity).eq(Func::upper(Expr::val(severity.as_str()))));
    }
    if let Some(type_) = &filters.type_ {
        all = all.add(IssueColumn::Type.eq(type_.as_str()));
    }
    if let Some(triage) = &filters.triage_status {
        all = all.add(IssueColumn::TriageStatus.eq(triage.as_str()));
    }
    if let Some(repo_id) = filters.repo_id {
        all = all.add(IssueColumn::RepoId.eq(repo_id));
    }
    if let Some(container_id) = filters.container_id {
        all = all.add(IssueColumn::ContainerId.eq(container_id));
    }
    if filters.only_direct {
        all = all.add(IssueColumn::IsDirectDependency.eq(true));
    }
    if filters.only_kev {
        all = all.add(IssueColumn::IsKev.eq(true));
    }
    if filters.exclude_settled {
        all = all.add(IssueColumn::TriageStatus.is_not_in(SETTLED));
    }
    if filters.cve_only {
        all = all.add(upper(IssueColumn::Identifier).like("CVE-%"));
    }
    if let Some(search) = filters.search.as_deref().map(str::trim).filter(|search| !search.is_empty()) {
        let pattern = format!("%{search}%");
        all = all.add(
            Condition::any()
                .add(lower_like(IssueColumn::Identifier, &pattern))
                .add(lower_like(IssueColumn::PackageName, &pattern))
                .add(lower_like(IssueColumn::FilePath, &pattern)),
        );
    }
    if let Some(identifier) = filters.identifier.as_deref().map(str::trim).filter(|identifier| !identifier.is_empty()) {
        all =
            all.add(Expr::expr(Func::lower(Expr::col(IssueColumn::Identifier))).eq(Func::lower(Expr::val(identifier))));
    }
    if let Some(owasp) = &filters.owasp_category {
        all = all.add(if owasp.eq_ignore_ascii_case("any") {
            IssueColumn::OwaspCategory.is_not_null()
        } else {
            upper(IssueColumn::OwaspCategory).eq(Func::upper(Expr::val(owasp.as_str())))
        });
    }
    if let Some(touching) = filters.touching_since {
        all =
            all.add(Condition::any().add(IssueColumn::ResolvedAt.is_null()).add(IssueColumn::ResolvedAt.gte(touching)));
    }
    if !filters.overdue_before.is_empty() {
        all = all.add(filters.overdue_before.iter().fold(Condition::any(), |any, (severity, threshold)| {
            any.add(
                Condition::all()
                    .add(upper(IssueColumn::Severity).eq(Func::upper(Expr::val(severity.as_str()))))
                    .add(IssueColumn::FirstSeenAt.lt(*threshold)),
            )
        }));
    }
    if let Some(lifetime) = &filters.lifetime {
        if let Some(open_at) = lifetime.open_at {
            all = all
                .add(IssueColumn::FirstSeenAt.lte(open_at))
                .add(Condition::any().add(IssueColumn::ResolvedAt.is_null()).add(IssueColumn::ResolvedAt.gt(open_at)));
        }
        if let Some(from) = lifetime.first_seen_from {
            all = all.add(IssueColumn::FirstSeenAt.gte(from));
        }
        if let Some(before) = lifetime.first_seen_before {
            all = all.add(IssueColumn::FirstSeenAt.lt(before));
        }
        if let Some(from) = lifetime.resolved_from {
            all = all.add(IssueColumn::ResolvedAt.gte(from));
        }
        if let Some(before) = lifetime.resolved_before {
            all = all.add(IssueColumn::ResolvedAt.lt(before));
        }
    }
    if let Some(within) = &filters.targets_within {
        // A project's or a solution's targets, read as the reader's visibility is: a row naming both is its
        // repository's (`IssueSpecifications.within`).
        all = all.add(rows_of::<Issues>(within));
    }
    all
}

opaque_debug!(TriageEventRepository);
