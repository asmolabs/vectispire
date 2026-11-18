//! The tables forges owns — Java's `ForgeConnectionRepository`, `ForgeDiscoveryRepository`,
//! `ForgeRepositoryRepository`, `ForgeImportLinkRepository` and `ForgeReviewReadingRepository` — as SeaORM statements
//! run on the caller's [`Tx`].
//!
//! **Every write after a discovery's take names its owner** — the run's state and the instance that took it — so that
//! an instance whose lease lapsed writes nothing over another's progress: the conditional updates answer how many
//! rows they changed, and a caller reads `0` as "no longer mine".

pub(crate) mod entities;
#[cfg(test)]
mod tests;

use sea_orm::sea_query::{Expr, ExprTrait, Func, Order};
use sea_orm::{
    ActiveValue::NotSet, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect, QueryTrait,
};
use time::OffsetDateTime;
use vectispire_cp_db::{Db, Mode, Tx, orm};

use entities::{connection, discovery, link, reading, repository};

pub(crate) type ConnectionRow = connection::Model;
pub(crate) type DiscoveryRow = discovery::Model;
pub(crate) type RepositoryRow = repository::Model;
pub(crate) type LinkRow = link::Model;
pub(crate) type ReadingRow = reading::Model;

/// A statement the database refused or could not answer.
#[derive(Debug, thiserror::Error)]
#[error("the forge tables did not answer: {0}")]
pub struct StoreError(#[from] pub sqlx::Error);

impl StoreError {
    /// Whether the engine refused the statement on a unique key — `DataIntegrityViolationException`.
    pub fn is_unique_violation(&self) -> bool {
        match &self.0 {
            sqlx::Error::Database(error) => error.is_unique_violation(),
            _ => false,
        }
    }
}

pub(crate) async fn read(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadOnly).await?)
}

pub(crate) async fn write(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(Mode::ReadWrite).await?)
}

/// Namespaces or ids per statement: far under every bind limit.
pub(crate) const BATCH: usize = 1_000;

// ── t_forge_connection ───────────────────────────────────────────────────────────────────────────────────────────

/// `findAllByOrderByNameAsc`.
pub(crate) async fn connections(tx: &mut Tx) -> Result<Vec<ConnectionRow>, StoreError> {
    let statement = connection::Entity::find().order_by(connection::Column::Name, Order::Asc).into_query();
    Ok(orm::fetch_all(tx, &statement).await?)
}

pub(crate) async fn connection(tx: &mut Tx, id: &str) -> Result<Option<ConnectionRow>, StoreError> {
    let statement = connection::Entity::find().filter(connection::Column::Id.eq(id)).into_query();
    Ok(orm::fetch_optional(tx, &statement).await?)
}

/// `existsByNameIgnoreCase` and `existsByNameIgnoreCaseAndIdNot`: `upper(name) = upper(?)`, as Hibernate writes it.
pub(crate) async fn name_taken(tx: &mut Tx, name: &str, except: Option<&str>) -> Result<bool, StoreError> {
    let mut select = connection::Entity::find()
        .select_only()
        .column_as(Expr::col(connection::Column::Id).count(), "n")
        .filter(Expr::expr(Func::upper(Expr::col(connection::Column::Name))).eq(Func::upper(Expr::val(name))));
    if let Some(id) = except {
        select = select.filter(connection::Column::Id.ne(id));
    }
    Ok(orm::fetch_count(tx, &select.into_query()).await? > 0)
}

fn connection_active(row: &ConnectionRow) -> connection::ActiveModel {
    connection::ActiveModel {
        id: Set(row.id.clone()),
        name: Set(row.name.clone()),
        kind: Set(row.kind.clone()),
        edition: Set(row.edition.clone()),
        base_url: Set(row.base_url.clone()),
        owner: Set(row.owner.clone()),
        internal_network: Set(row.internal_network),
        ca_pem: Set(row.ca_pem.clone()),
        token: Set(row.token.clone()),
        credential_kind: Set(row.credential_kind.clone()),
        scopes: Set(row.scopes.clone()),
        can_write: Set(row.can_write),
        token_expires_at: Set(row.token_expires_at),
        forge_version: Set(row.forge_version.clone()),
        probed_at: Set(row.probed_at),
        created_at: Set(row.created_at),
        created_by: Set(row.created_by.clone()),
        updated_at: Set(row.updated_at),
        updated_by: Set(row.updated_by.clone()),
    }
}

pub(crate) async fn insert_connection(tx: &mut Tx, row: &ConnectionRow) -> Result<(), StoreError> {
    let statement = sea_orm::QueryTrait::into_query(connection::Entity::insert(connection_active(row)));
    orm::execute(tx, &statement).await?;
    Ok(())
}

pub(crate) async fn update_connection(tx: &mut Tx, row: &ConnectionRow) -> Result<(), StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        connection::Entity::update_many()
            .set(connection_active(row))
            .filter(connection::Column::Id.eq(row.id.as_str())),
    );
    orm::execute(tx, &statement).await?;
    Ok(())
}

pub(crate) async fn delete_connection(tx: &mut Tx, id: &str) -> Result<(), StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        connection::Entity::delete_many().filter(connection::Column::Id.eq(id)),
    );
    orm::execute(tx, &statement).await?;
    Ok(())
}

// ── t_forge_discovery ────────────────────────────────────────────────────────────────────────────────────────────

pub(crate) async fn insert_discovery(tx: &mut Tx, row: &DiscoveryRow) -> Result<i64, StoreError> {
    let active = discovery::ActiveModel {
        id: NotSet,
        connection_id: Set(row.connection_id.clone()),
        state: Set(row.state.clone()),
        reason: Set(row.reason.clone()),
        detail: Set(row.detail.clone()),
        active_key: Set(row.active_key.clone()),
        requested_at: Set(row.requested_at),
        requested_by: Set(row.requested_by.clone()),
        claimed_by: Set(row.claimed_by.clone()),
        lease_expires_at: Set(row.lease_expires_at),
        attempts: Set(row.attempts),
        started_at: Set(row.started_at),
        finished_at: Set(row.finished_at),
        namespaces_seen: Set(row.namespaces_seen),
        repositories_seen: Set(row.repositories_seen),
        repositories_skipped: Set(row.repositories_skipped),
        requests_made: Set(row.requests_made),
        rate_limit_wait_seconds: Set(row.rate_limit_wait_seconds),
        rate_limit_reset_at: Set(row.rate_limit_reset_at),
        new_count: Set(row.new_count),
        changed_count: Set(row.changed_count),
        gone_count: Set(row.gone_count),
        unreadable_namespaces: Set(row.unreadable_namespaces.clone()),
    };
    let statement = sea_orm::QueryTrait::into_query(discovery::Entity::insert(active));
    Ok(orm::insert_returning_id::<discovery::Entity>(tx, statement).await?)
}

pub(crate) async fn discovery(tx: &mut Tx, id: i64) -> Result<Option<DiscoveryRow>, StoreError> {
    let statement = discovery::Entity::find().filter(discovery::Column::Id.eq(id)).into_query();
    Ok(orm::fetch_optional(tx, &statement).await?)
}

/// `findByIdAndConnectionId`.
pub(crate) async fn discovery_of(tx: &mut Tx, id: i64, connection_id: &str) -> Result<Option<DiscoveryRow>, StoreError> {
    let statement = discovery::Entity::find()
        .filter(discovery::Column::Id.eq(id))
        .filter(discovery::Column::ConnectionId.eq(connection_id))
        .into_query();
    Ok(orm::fetch_optional(tx, &statement).await?)
}

pub(crate) async fn discovery_by_active_key(tx: &mut Tx, key: &str) -> Result<Option<DiscoveryRow>, StoreError> {
    let statement = discovery::Entity::find().filter(discovery::Column::ActiveKey.eq(key)).into_query();
    Ok(orm::fetch_optional(tx, &statement).await?)
}

/// `findByConnectionIdOrderByRequestedAtDescIdDesc(…, page)`; `findFirst…` is the page of one.
pub(crate) async fn discoveries_of(
    tx: &mut Tx,
    connection_id: &str,
    limit: u64,
    offset: u64,
) -> Result<Vec<DiscoveryRow>, StoreError> {
    let statement = discovery::Entity::find()
        .filter(discovery::Column::ConnectionId.eq(connection_id))
        .order_by(discovery::Column::RequestedAt, Order::Desc)
        .order_by(discovery::Column::Id, Order::Desc)
        .limit(limit)
        .offset(offset)
        .into_query();
    Ok(orm::fetch_all(tx, &statement).await?)
}

/// `findFirstByConnectionIdAndStateInOrderByRequestedAtDescIdDesc`.
pub(crate) async fn latest_discovery_in(
    tx: &mut Tx,
    connection_id: &str,
    states: &[&str],
) -> Result<Option<DiscoveryRow>, StoreError> {
    let statement = discovery::Entity::find()
        .filter(discovery::Column::ConnectionId.eq(connection_id))
        .filter(discovery::Column::State.is_in(states.iter().copied()))
        .order_by(discovery::Column::RequestedAt, Order::Desc)
        .order_by(discovery::Column::Id, Order::Desc)
        .limit(1)
        .into_query();
    Ok(orm::fetch_optional(tx, &statement).await?)
}

/// `waiting` and `waitingExcept`: the waiting runs oldest first, but those of connections of these kinds.
pub(crate) async fn waiting(
    tx: &mut Tx,
    pending: &str,
    suspended_kinds: &[&str],
    limit: u64,
) -> Result<Vec<i64>, StoreError> {
    let mut select = discovery::Entity::find().filter(discovery::Column::State.eq(pending));
    if !suspended_kinds.is_empty() {
        select = select.filter(discovery::Column::ConnectionId.not_in_subquery(suspended_connections(suspended_kinds)));
    }
    let statement = select
        .select_only()
        .column(discovery::Column::Id)
        .order_by(discovery::Column::RequestedAt, Order::Asc)
        .order_by(discovery::Column::Id, Order::Asc)
        .limit(limit)
        .into_query();
    let rows: Vec<IdRow> = orm::fetch_all(tx, &statement).await?;
    Ok(rows.into_iter().map(|row| row.id).collect())
}

fn suspended_connections(kinds: &[&str]) -> sea_orm::sea_query::SelectStatement {
    connection::Entity::find()
        .select_only()
        .column(connection::Column::Id)
        .filter(connection::Column::Kind.is_in(kinds.iter().copied()))
        .into_query()
}

#[derive(Debug, sea_orm::FromQueryResult)]
struct IdRow {
    id: i64,
}

/// `countWaitingOn`.
pub(crate) async fn count_waiting_on(tx: &mut Tx, pending: &str, kinds: &[&str]) -> Result<i64, StoreError> {
    let statement = discovery::Entity::find()
        .select_only()
        .column_as(Expr::col(discovery::Column::Id).count(), "n")
        .filter(discovery::Column::State.eq(pending))
        .filter(discovery::Column::ConnectionId.in_subquery(suspended_connections(kinds)))
        .into_query();
    Ok(orm::fetch_count(tx, &statement).await?)
}

fn update_discovery() -> sea_orm::UpdateMany<discovery::Entity> {
    discovery::Entity::update_many()
}

/// `giveBack`: a run its owner took back to waiting, its attempt not counted.
pub(crate) async fn give_back(tx: &mut Tx, id: i64, running: &str, pending: &str, owner: &str) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        update_discovery()
            .col_expr(discovery::Column::State, Expr::val(pending).into())
            .col_expr(discovery::Column::ClaimedBy, Expr::val(Option::<String>::None).into())
            .col_expr(discovery::Column::LeaseExpiresAt, Expr::val(Option::<OffsetDateTime>::None).into())
            .col_expr(discovery::Column::Attempts, Expr::col(discovery::Column::Attempts).sub(1))
            .filter(discovery::Column::Id.eq(id))
            .filter(discovery::Column::State.eq(running))
            .filter(discovery::Column::ClaimedBy.eq(owner)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

/// `take`: one waiting run, its attempt counted and its progress started afresh.
pub(crate) async fn take(
    tx: &mut Tx,
    id: i64,
    pending: &str,
    running: &str,
    owner: &str,
    started_at: OffsetDateTime,
    lease_expires_at: OffsetDateTime,
) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        update_discovery()
            .col_expr(discovery::Column::State, Expr::val(running).into())
            .col_expr(discovery::Column::ClaimedBy, Expr::val(owner).into())
            .col_expr(discovery::Column::LeaseExpiresAt, Expr::val(lease_expires_at).into())
            .col_expr(discovery::Column::StartedAt, Expr::val(started_at).into())
            .col_expr(discovery::Column::Attempts, Expr::col(discovery::Column::Attempts).add(1))
            .col_expr(discovery::Column::NamespacesSeen, Expr::val(0).into())
            .col_expr(discovery::Column::RepositoriesSeen, Expr::val(0).into())
            .col_expr(discovery::Column::RepositoriesSkipped, Expr::val(0).into())
            .col_expr(discovery::Column::RequestsMade, Expr::val(0).into())
            .col_expr(discovery::Column::RateLimitWaitSeconds, Expr::val(0i64).into())
            .filter(discovery::Column::Id.eq(id))
            .filter(discovery::Column::State.eq(pending)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

/// What a run has counted so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Progress {
    pub namespaces: i32,
    pub repositories: i32,
    pub skipped: i32,
    pub requests: i32,
    pub waited: i64,
}

fn with_progress(update: sea_orm::UpdateMany<discovery::Entity>, progress: Progress) -> sea_orm::UpdateMany<discovery::Entity> {
    update
        .col_expr(discovery::Column::NamespacesSeen, Expr::val(progress.namespaces).into())
        .col_expr(discovery::Column::RepositoriesSeen, Expr::val(progress.repositories).into())
        .col_expr(discovery::Column::RepositoriesSkipped, Expr::val(progress.skipped).into())
        .col_expr(discovery::Column::RequestsMade, Expr::val(progress.requests).into())
        .col_expr(discovery::Column::RateLimitWaitSeconds, Expr::val(progress.waited).into())
}

/// `renew`: the progress written and the lease extended, while the owner still holds the run.
pub(crate) async fn renew(
    tx: &mut Tx,
    id: i64,
    running: &str,
    owner: &str,
    lease_expires_at: OffsetDateTime,
    progress: Progress,
) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        with_progress(update_discovery(), progress)
            .col_expr(discovery::Column::LeaseExpiresAt, Expr::val(lease_expires_at).into())
            .filter(discovery::Column::Id.eq(id))
            .filter(discovery::Column::State.eq(running))
            .filter(discovery::Column::ClaimedBy.eq(owner)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

/// How a run ended, as `finish` writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ending {
    pub state: String,
    pub reason: Option<String>,
    pub detail: Option<String>,
    pub finished_at: OffsetDateTime,
    pub progress: Progress,
    pub reset_at: Option<OffsetDateTime>,
    pub new_count: Option<i32>,
    pub changed_count: Option<i32>,
    pub gone_count: Option<i32>,
    pub unreadable: Option<String>,
}

/// `finish`: a run its owner still holds ended, the active key going with the lease.
pub(crate) async fn finish(tx: &mut Tx, id: i64, running: &str, owner: &str, ending: &Ending) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        with_progress(update_discovery(), ending.progress)
            .col_expr(discovery::Column::State, Expr::val(ending.state.as_str()).into())
            .col_expr(discovery::Column::Reason, Expr::val(ending.reason.clone()).into())
            .col_expr(discovery::Column::Detail, Expr::val(ending.detail.clone()).into())
            .col_expr(discovery::Column::FinishedAt, Expr::val(ending.finished_at).into())
            .col_expr(discovery::Column::ActiveKey, Expr::val(Option::<String>::None).into())
            .col_expr(discovery::Column::ClaimedBy, Expr::val(Option::<String>::None).into())
            .col_expr(discovery::Column::LeaseExpiresAt, Expr::val(Option::<OffsetDateTime>::None).into())
            .col_expr(discovery::Column::RateLimitResetAt, Expr::val(ending.reset_at).into())
            .col_expr(discovery::Column::NewCount, Expr::val(ending.new_count).into())
            .col_expr(discovery::Column::ChangedCount, Expr::val(ending.changed_count).into())
            .col_expr(discovery::Column::GoneCount, Expr::val(ending.gone_count).into())
            .col_expr(discovery::Column::UnreadableNamespaces, Expr::val(ending.unreadable.clone()).into())
            .filter(discovery::Column::Id.eq(id))
            .filter(discovery::Column::State.eq(running))
            .filter(discovery::Column::ClaimedBy.eq(owner)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

/// `lapsed`: the runs whose instance stopped answering.
pub(crate) async fn lapsed(tx: &mut Tx, running: &str, as_of: OffsetDateTime) -> Result<Vec<i64>, StoreError> {
    let statement = discovery::Entity::find()
        .select_only()
        .column(discovery::Column::Id)
        .filter(discovery::Column::State.eq(running))
        .filter(discovery::Column::LeaseExpiresAt.lt(as_of))
        .order_by(discovery::Column::Id, Order::Asc)
        .into_query();
    let rows: Vec<IdRow> = orm::fetch_all(tx, &statement).await?;
    Ok(rows.into_iter().map(|row| row.id).collect())
}

/// `requeueLapsed`.
pub(crate) async fn requeue_lapsed(
    tx: &mut Tx,
    id: i64,
    running: &str,
    pending: &str,
    as_of: OffsetDateTime,
    max_attempts: i32,
) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        update_discovery()
            .col_expr(discovery::Column::State, Expr::val(pending).into())
            .col_expr(discovery::Column::ClaimedBy, Expr::val(Option::<String>::None).into())
            .col_expr(discovery::Column::LeaseExpiresAt, Expr::val(Option::<OffsetDateTime>::None).into())
            .filter(discovery::Column::Id.eq(id))
            .filter(discovery::Column::State.eq(running))
            .filter(discovery::Column::LeaseExpiresAt.lt(as_of))
            .filter(discovery::Column::Attempts.lt(max_attempts)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

/// `failLapsed`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fail_lapsed(
    tx: &mut Tx,
    id: i64,
    running: &str,
    failed: &str,
    reason: &str,
    detail: &str,
    as_of: OffsetDateTime,
    max_attempts: i32,
) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        update_discovery()
            .col_expr(discovery::Column::State, Expr::val(failed).into())
            .col_expr(discovery::Column::Reason, Expr::val(reason).into())
            .col_expr(discovery::Column::Detail, Expr::val(detail).into())
            .col_expr(discovery::Column::FinishedAt, Expr::val(as_of).into())
            .col_expr(discovery::Column::ActiveKey, Expr::val(Option::<String>::None).into())
            .col_expr(discovery::Column::ClaimedBy, Expr::val(Option::<String>::None).into())
            .col_expr(discovery::Column::LeaseExpiresAt, Expr::val(Option::<OffsetDateTime>::None).into())
            .filter(discovery::Column::Id.eq(id))
            .filter(discovery::Column::State.eq(running))
            .filter(discovery::Column::LeaseExpiresAt.lt(as_of))
            .filter(discovery::Column::Attempts.gte(max_attempts)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

pub(crate) async fn delete_discoveries_of(tx: &mut Tx, connection_id: &str) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        discovery::Entity::delete_many().filter(discovery::Column::ConnectionId.eq(connection_id)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

// ── t_forge_repository ───────────────────────────────────────────────────────────────────────────────────────────

/// `findByConnectionIdAndForgeIdIn`: one page's repositories, a hundred at most.
pub(crate) async fn snapshot_rows(
    tx: &mut Tx,
    connection_id: &str,
    forge_ids: &[String],
) -> Result<Vec<RepositoryRow>, StoreError> {
    let mut rows = Vec::new();
    for batch in forge_ids.chunks(BATCH) {
        let statement = repository::Entity::find()
            .filter(repository::Column::ConnectionId.eq(connection_id))
            .filter(repository::Column::ForgeId.is_in(batch.iter().map(String::as_str)))
            .into_query();
        rows.extend(orm::fetch_all::<RepositoryRow, _>(tx, &statement).await?);
    }
    Ok(rows)
}

/// Which run's column a count or a page reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeenBy {
    First,
    Last,
    Changed,
    Gone,
}

impl SeenBy {
    fn column(self) -> repository::Column {
        match self {
            SeenBy::First => repository::Column::FirstSeenBy,
            SeenBy::Last => repository::Column::LastSeenBy,
            SeenBy::Changed => repository::Column::ChangedBy,
            SeenBy::Gone => repository::Column::GoneBy,
        }
    }
}

/// `countByConnectionIdAndFirstSeenBy`, `…AndChangedBy`, and the totals of the pages.
pub(crate) async fn count_seen(tx: &mut Tx, connection_id: &str, by: SeenBy, discovery_id: i64) -> Result<i64, StoreError> {
    let statement = repository::Entity::find()
        .select_only()
        .column_as(Expr::col(repository::Column::Id).count(), "n")
        .filter(repository::Column::ConnectionId.eq(connection_id))
        .filter(by.column().eq(discovery_id))
        .into_query();
    Ok(orm::fetch_count(tx, &statement).await?)
}

/// `findByConnectionIdAnd…By(…, page)`, by full path then id.
pub(crate) async fn seen_page(
    tx: &mut Tx,
    connection_id: &str,
    by: SeenBy,
    discovery_id: i64,
    limit: u64,
    offset: u64,
) -> Result<Vec<RepositoryRow>, StoreError> {
    let statement = repository::Entity::find()
        .filter(repository::Column::ConnectionId.eq(connection_id))
        .filter(by.column().eq(discovery_id))
        .order_by(repository::Column::FullPath, Order::Asc)
        .order_by(repository::Column::Id, Order::Asc)
        .limit(limit)
        .offset(offset)
        .into_query();
    Ok(orm::fetch_all(tx, &statement).await?)
}

/// `listedBy`: every repository the discovery listed and no later completed run has marked gone.
pub(crate) async fn listed_by(tx: &mut Tx, connection_id: &str, discovery_id: i64) -> Result<Vec<RepositoryRow>, StoreError> {
    let statement = repository::Entity::find()
        .filter(repository::Column::ConnectionId.eq(connection_id))
        .filter(repository::Column::FirstSeenBy.lte(discovery_id))
        .filter(repository::Column::LastSeenBy.gte(discovery_id))
        .filter(repository::Column::GoneBy.is_null())
        .into_query();
    Ok(orm::fetch_all(tx, &statement).await?)
}

/// `currentUrls`: every repository of every snapshot no completed run marked gone, by its clone URLs.
#[derive(Debug, Clone, PartialEq, Eq, sea_orm::FromQueryResult)]
pub(crate) struct SnapshotUrls {
    pub connection_id: String,
    pub forge_id: String,
    pub http_url: Option<String>,
    pub ssh_url: Option<String>,
}

pub(crate) async fn current_urls(tx: &mut Tx) -> Result<Vec<SnapshotUrls>, StoreError> {
    let statement = repository::Entity::find()
        .select_only()
        .column(repository::Column::ConnectionId)
        .column(repository::Column::ForgeId)
        .column(repository::Column::HttpUrl)
        .column(repository::Column::SshUrl)
        .filter(repository::Column::GoneBy.is_null())
        .into_query();
    Ok(orm::fetch_all(tx, &statement).await?)
}

fn repository_active(row: &RepositoryRow) -> repository::ActiveModel {
    repository::ActiveModel {
        id: if row.id == 0 { NotSet } else { Set(row.id) },
        connection_id: Set(row.connection_id.clone()),
        forge_id: Set(row.forge_id.clone()),
        full_path: Set(row.full_path.clone()),
        namespace_path: Set(row.namespace_path.clone()),
        personal: Set(row.personal),
        name: Set(row.name.clone()),
        default_branch: Set(row.default_branch.clone()),
        archived: Set(row.archived),
        fork: Set(row.fork),
        visibility: Set(row.visibility.clone()),
        last_activity_at: Set(row.last_activity_at),
        language: Set(row.language.clone()),
        size_bytes: Set(row.size_bytes),
        http_url: Set(row.http_url.clone()),
        ssh_url: Set(row.ssh_url.clone()),
        web_url: Set(row.web_url.clone()),
        first_seen_by: Set(row.first_seen_by),
        first_seen_at: Set(row.first_seen_at),
        last_seen_by: Set(row.last_seen_by),
        last_seen_at: Set(row.last_seen_at),
        changed_by: Set(row.changed_by),
        change_summary: Set(row.change_summary.clone()),
        gone_by: Set(row.gone_by),
        gone_at: Set(row.gone_at),
    }
}

/// `saveAll`: a row with id 0 is inserted, any other updated.
pub(crate) async fn save_snapshot_rows(tx: &mut Tx, rows: &[RepositoryRow]) -> Result<(), StoreError> {
    for row in rows {
        if row.id == 0 {
            let statement = sea_orm::QueryTrait::into_query(repository::Entity::insert(repository_active(row)));
            orm::insert_returning_id::<repository::Entity>(tx, statement).await?;
        } else {
            let statement = sea_orm::QueryTrait::into_query(
                repository::Entity::update_many()
                    .set(repository_active(row))
                    .filter(repository::Column::Id.eq(row.id)),
            );
            orm::execute(tx, &statement).await?;
        }
    }
    Ok(())
}

/// `markGone`, or `markGoneWithin` these namespaces (lower case) when `within` is given.
pub(crate) async fn mark_gone(
    tx: &mut Tx,
    connection_id: &str,
    discovery_id: i64,
    at: OffsetDateTime,
    within: Option<&[String]>,
) -> Result<u64, StoreError> {
    let mut update = repository::Entity::update_many()
        .col_expr(repository::Column::GoneBy, Expr::val(discovery_id).into())
        .col_expr(repository::Column::GoneAt, Expr::val(at).into())
        .filter(repository::Column::ConnectionId.eq(connection_id))
        .filter(repository::Column::LastSeenBy.ne(discovery_id))
        .filter(repository::Column::GoneBy.is_null());
    if let Some(namespaces) = within {
        update = update.filter(
            Expr::expr(Func::lower(Expr::col(repository::Column::NamespacePath)))
                .is_in(namespaces.iter().map(String::as_str)),
        );
    }
    Ok(orm::execute(tx, &sea_orm::QueryTrait::into_query(update)).await?)
}

/// `unmarkGone`: this run's marks taken back in namespaces it could not read (lower case).
pub(crate) async fn unmark_gone(
    tx: &mut Tx,
    connection_id: &str,
    discovery_id: i64,
    namespaces: &[String],
) -> Result<u64, StoreError> {
    let update = repository::Entity::update_many()
        .col_expr(repository::Column::GoneBy, Expr::val(Option::<i64>::None).into())
        .col_expr(repository::Column::GoneAt, Expr::val(Option::<OffsetDateTime>::None).into())
        .filter(repository::Column::ConnectionId.eq(connection_id))
        .filter(repository::Column::GoneBy.eq(discovery_id))
        .filter(
            Expr::expr(Func::lower(Expr::col(repository::Column::NamespacePath)))
                .is_in(namespaces.iter().map(String::as_str)),
        );
    Ok(orm::execute(tx, &sea_orm::QueryTrait::into_query(update)).await?)
}

/// `setLanguage`.
pub(crate) async fn set_language(
    tx: &mut Tx,
    connection_id: &str,
    forge_id: &str,
    language: Option<&str>,
) -> Result<u64, StoreError> {
    let update = repository::Entity::update_many()
        .col_expr(repository::Column::Language, Expr::val(language.map(str::to_owned)).into())
        .filter(repository::Column::ConnectionId.eq(connection_id))
        .filter(repository::Column::ForgeId.eq(forge_id));
    Ok(orm::execute(tx, &sea_orm::QueryTrait::into_query(update)).await?)
}

pub(crate) async fn delete_snapshot_of(tx: &mut Tx, connection_id: &str) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        repository::Entity::delete_many().filter(repository::Column::ConnectionId.eq(connection_id)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

// ── t_forge_import_link ──────────────────────────────────────────────────────────────────────────────────────────

/// `findByConnectionId`, or `…AndForgeIdIn` when `forge_ids` is given.
pub(crate) async fn links_of(
    tx: &mut Tx,
    connection_id: &str,
    forge_ids: Option<&[String]>,
) -> Result<Vec<LinkRow>, StoreError> {
    let base = || link::Entity::find().filter(link::Column::ConnectionId.eq(connection_id));
    match forge_ids {
        None => Ok(orm::fetch_all(tx, &base().into_query()).await?),
        Some(ids) => {
            let mut rows = Vec::new();
            for batch in ids.chunks(BATCH) {
                let statement = base().filter(link::Column::ForgeId.is_in(batch.iter().map(String::as_str))).into_query();
                rows.extend(orm::fetch_all::<LinkRow, _>(tx, &statement).await?);
            }
            Ok(rows)
        }
    }
}

/// `findByRepositoryIdIn`.
pub(crate) async fn links_of_repositories(tx: &mut Tx, repository_ids: &[i64]) -> Result<Vec<LinkRow>, StoreError> {
    let mut rows = Vec::new();
    for batch in repository_ids.chunks(BATCH) {
        let statement =
            link::Entity::find().filter(link::Column::RepositoryId.is_in(batch.iter().copied())).into_query();
        rows.extend(orm::fetch_all::<LinkRow, _>(tx, &statement).await?);
    }
    Ok(rows)
}

/// `countByConnectionId`.
pub(crate) async fn count_links(tx: &mut Tx, connection_id: &str) -> Result<i64, StoreError> {
    let statement = link::Entity::find()
        .select_only()
        .column_as(Expr::col(link::Column::Id).count(), "n")
        .filter(link::Column::ConnectionId.eq(connection_id))
        .into_query();
    Ok(orm::fetch_count(tx, &statement).await?)
}

pub(crate) async fn insert_link(tx: &mut Tx, row: &LinkRow) -> Result<i64, StoreError> {
    let active = link::ActiveModel {
        id: NotSet,
        repository_id: Set(row.repository_id),
        connection_id: Set(row.connection_id.clone()),
        forge_id: Set(row.forge_id.clone()),
        discovery_id: Set(row.discovery_id),
        imported_at: Set(row.imported_at),
        imported_by: Set(row.imported_by.clone()),
    };
    let statement = sea_orm::QueryTrait::into_query(link::Entity::insert(active));
    Ok(orm::insert_returning_id::<link::Entity>(tx, statement).await?)
}

pub(crate) async fn delete_links_of_repository(tx: &mut Tx, repository_id: i64) -> Result<u64, StoreError> {
    let statement =
        sea_orm::QueryTrait::into_query(link::Entity::delete_many().filter(link::Column::RepositoryId.eq(repository_id)));
    Ok(orm::execute(tx, &statement).await?)
}

pub(crate) async fn delete_links_of(tx: &mut Tx, connection_id: &str) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        link::Entity::delete_many().filter(link::Column::ConnectionId.eq(connection_id)),
    );
    Ok(orm::execute(tx, &statement).await?)
}

// ── t_forge_review_reading ───────────────────────────────────────────────────────────────────────────────────────

/// `findByRepositoryIdAndWantedBranch`.
pub(crate) async fn reading(tx: &mut Tx, repository_id: i64, branch: &str) -> Result<Option<ReadingRow>, StoreError> {
    let statement = reading::Entity::find()
        .filter(reading::Column::RepositoryId.eq(repository_id))
        .filter(reading::Column::WantedBranch.eq(branch))
        .into_query();
    Ok(orm::fetch_optional(tx, &statement).await?)
}

/// `findByWantedBranchAndRepositoryIdIn`.
pub(crate) async fn readings_of(tx: &mut Tx, branch: &str, repository_ids: &[i64]) -> Result<Vec<ReadingRow>, StoreError> {
    let mut rows = Vec::new();
    for batch in repository_ids.chunks(BATCH) {
        let statement = reading::Entity::find()
            .filter(reading::Column::WantedBranch.eq(branch))
            .filter(reading::Column::RepositoryId.is_in(batch.iter().copied()))
            .into_query();
        rows.extend(orm::fetch_all::<ReadingRow, _>(tx, &statement).await?);
    }
    Ok(rows)
}

#[derive(Debug, sea_orm::FromQueryResult)]
struct RepositoryIdRow {
    repository_id: i64,
}

/// `repositoriesRead`.
pub(crate) async fn repositories_read(tx: &mut Tx) -> Result<Vec<i64>, StoreError> {
    let statement = reading::Entity::find()
        .select_only()
        .column(reading::Column::RepositoryId)
        .distinct()
        .into_query();
    let rows: Vec<RepositoryIdRow> = orm::fetch_all(tx, &statement).await?;
    Ok(rows.into_iter().map(|row| row.repository_id).collect())
}

/// `claim`: only when no other holds it and it is due.
pub(crate) async fn claim_reading(
    tx: &mut Tx,
    id: i64,
    now: OffsetDateTime,
    until: OffsetDateTime,
    stale_before: OffsetDateTime,
    window_days: i32,
) -> Result<u64, StoreError> {
    let update = reading::Entity::update_many()
        .col_expr(reading::Column::ClaimedUntil, Expr::val(until).into())
        .filter(reading::Column::Id.eq(id))
        .filter(
            sea_orm::Condition::any()
                .add(reading::Column::ClaimedUntil.is_null())
                .add(reading::Column::ClaimedUntil.lt(now)),
        )
        .filter(
            sea_orm::Condition::any()
                .add(reading::Column::ReadAt.is_null())
                .add(reading::Column::ReadAt.lt(stale_before))
                .add(reading::Column::WindowDays.lt(window_days)),
        );
    Ok(orm::execute(tx, &sea_orm::QueryTrait::into_query(update)).await?)
}

/// `release`.
pub(crate) async fn release_reading(tx: &mut Tx, id: i64) -> Result<u64, StoreError> {
    let update = reading::Entity::update_many()
        .col_expr(reading::Column::ClaimedUntil, Expr::val(Option::<OffsetDateTime>::None).into())
        .filter(reading::Column::Id.eq(id));
    Ok(orm::execute(tx, &sea_orm::QueryTrait::into_query(update)).await?)
}

fn reading_active(row: &ReadingRow) -> reading::ActiveModel {
    reading::ActiveModel {
        id: if row.id == 0 { NotSet } else { Set(row.id) },
        repository_id: Set(row.repository_id),
        wanted_branch: Set(row.wanted_branch.clone()),
        state: Set(row.state.clone()),
        connection_id: Set(row.connection_id.clone()),
        forge_id: Set(row.forge_id.clone()),
        window_days: Set(row.window_days),
        read_at: Set(row.read_at),
        reason: Set(row.reason.clone()),
        evidence: Set(row.evidence.clone()),
        evidence_sha256: Set(row.evidence_sha256.clone()),
        claimed_until: Set(row.claimed_until),
    }
}

/// `save`: a row with id 0 is inserted (its id answered), any other updated.
pub(crate) async fn save_reading(tx: &mut Tx, row: &ReadingRow) -> Result<i64, StoreError> {
    if row.id == 0 {
        let statement = sea_orm::QueryTrait::into_query(reading::Entity::insert(reading_active(row)));
        return Ok(orm::insert_returning_id::<reading::Entity>(tx, statement).await?);
    }
    let statement = sea_orm::QueryTrait::into_query(
        reading::Entity::update_many().set(reading_active(row)).filter(reading::Column::Id.eq(row.id)),
    );
    orm::execute(tx, &statement).await?;
    Ok(row.id)
}

pub(crate) async fn delete_readings_of_repositories(tx: &mut Tx, repository_ids: &[i64]) -> Result<u64, StoreError> {
    let mut deleted = 0;
    for batch in repository_ids.chunks(BATCH) {
        let statement = sea_orm::QueryTrait::into_query(
            reading::Entity::delete_many().filter(reading::Column::RepositoryId.is_in(batch.iter().copied())),
        );
        deleted += orm::execute(tx, &statement).await?;
    }
    Ok(deleted)
}

pub(crate) async fn delete_readings_of(tx: &mut Tx, connection_id: &str) -> Result<u64, StoreError> {
    let statement = sea_orm::QueryTrait::into_query(
        reading::Entity::delete_many().filter(reading::Column::ConnectionId.eq(connection_id)),
    );
    Ok(orm::execute(tx, &statement).await?)
}
