//! The statements of threat intelligence's three tables — Java's `ThreatIntelRepository`, `ThreatIntelBulkWrites`,
//! `ThreatIntelSyncRepository`, `EpssScoreRepository` and `EpssScoreBulkWrites` — built with SeaORM from
//! [`super::entities`] and run on the caller's [`Tx`].
//!
//! **The sync row's writes are conditional updates, and their count is the answer.** Every instance runs every
//! maintenance task: the update that matches is the election (`claim_*`), and an update that no longer matches is a
//! claim lost (`apply_epss`, `confirm_epss`, `fail_epss`) — the caller reads 0 as "someone else holds it", never as
//! an error to retry.

use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, ExprTrait, Func, Order, SimpleExpr};
use sea_orm::{ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder, QuerySelect, QueryTrait};
use time::OffsetDateTime;
use vectispire_cp_db::{Tx, orm};

use super::entities::{
    FeedActive, FeedColumn, FeedModel, Feeds, ScoreActive, ScoreColumn, ScoreModel, Scores, SyncActive, SyncColumn,
    SyncModel, Syncs,
};
use super::{FeedRow, KnownEpssScore, Listing, StoreError, SyncRow};

/// Rows per insert: 2,000 bind parameters, well under the ceiling — PostgreSQL's driver and a MySQL server-side
/// statement refuse one past 65,535. `ROWS_PER_STATEMENT` of both of Java's bulk writers.
pub const ROWS_PER_STATEMENT: usize = 500;

const SYNCED: &str = "SYNCED";
const FAILED: &str = "FAILED";

impl From<FeedModel> for FeedRow {
    fn from(model: FeedModel) -> FeedRow {
        FeedRow {
            cve_id: model.cve_id,
            is_kev: model.is_kev,
            date_added: model.date_added,
            updated_at: model.updated_at,
        }
    }
}

impl From<SyncModel> for SyncRow {
    fn from(model: SyncModel) -> SyncRow {
        SyncRow {
            id: model.id,
            last_synced_at: model.last_synced_at,
            cve_count: model.cve_count,
            kev_count: model.kev_count,
            status: model.status,
            kev_catalog_version: model.kev_catalog_version,
            kev_released_at: model.kev_released_at,
            last_attempt_at: model.last_attempt_at,
            last_error: model.last_error,
            epss_status: model.epss_status,
            epss_synced_at: model.epss_synced_at,
            epss_model_version: model.epss_model_version,
            epss_score_date: model.epss_score_date,
            epss_count: model.epss_count,
            epss_generation: model.epss_generation,
            epss_previous_generation: model.epss_previous_generation,
            epss_attempt_at: model.epss_attempt_at,
            epss_lease_until: model.epss_lease_until,
            epss_claim: model.epss_claim,
            epss_error: model.epss_error,
        }
    }
}

fn sync_active(row: &SyncRow) -> SyncActive {
    SyncActive {
        id: Set(row.id),
        last_synced_at: Set(row.last_synced_at),
        cve_count: Set(row.cve_count),
        kev_count: Set(row.kev_count),
        status: Set(row.status.clone()),
        kev_catalog_version: Set(row.kev_catalog_version.clone()),
        kev_released_at: Set(row.kev_released_at),
        last_attempt_at: Set(row.last_attempt_at),
        last_error: Set(row.last_error.clone()),
        epss_status: Set(row.epss_status.clone()),
        epss_synced_at: Set(row.epss_synced_at),
        epss_model_version: Set(row.epss_model_version.clone()),
        epss_score_date: Set(row.epss_score_date),
        epss_count: Set(row.epss_count),
        epss_generation: Set(row.epss_generation),
        epss_previous_generation: Set(row.epss_previous_generation),
        epss_attempt_at: Set(row.epss_attempt_at),
        epss_lease_until: Set(row.epss_lease_until),
        epss_claim: Set(row.epss_claim),
        epss_error: Set(row.epss_error.clone()),
    }
}

fn value<T: Into<sea_orm::Value>>(value: T) -> SimpleExpr {
    Expr::value(value)
}

/// `lower(cve_id) in (…)`: the identifiers the issues carry and the catalogue's do not agree on case.
fn lower_cve_in(ids: &[String]) -> SimpleExpr {
    Expr::expr(Func::lower(Expr::col(FeedColumn::CveId))).is_in(ids.iter().cloned())
}

#[derive(Debug, FromQueryResult)]
struct CveId {
    cve_id: String,
}

#[derive(Debug, FromQueryResult)]
struct Generation {
    generation: i64,
}

/// The stored KEV catalogue — `ThreatIntelRepository` and its bulk writes.
#[derive(Debug, Clone, Copy)]
pub struct IntelRepository;

impl IntelRepository {
    /// `findAll`, in key order.
    pub async fn all(tx: &mut Tx) -> Result<Vec<FeedRow>, StoreError> {
        let select = Feeds::find().order_by(FeedColumn::CveId, Order::Asc).into_query();
        let models: Vec<FeedModel> = orm::fetch_all(tx, &select).await?;
        Ok(models.into_iter().map(FeedRow::from).collect())
    }

    /// `findByCveIdInIgnoreCase`: `ids` lower-case; an empty list matches nothing and asks nothing.
    pub async fn by_ids_ignore_case(tx: &mut Tx, ids: &[String]) -> Result<Vec<FeedRow>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let select = Feeds::find().filter(lower_cve_in(ids)).into_query();
        let models: Vec<FeedModel> = orm::fetch_all(tx, &select).await?;
        Ok(models.into_iter().map(FeedRow::from).collect())
    }

    /// `exploitedAmong`: those of these lower-case identifiers the stored catalogue lists, as stored.
    pub async fn exploited_among(tx: &mut Tx, ids: &[String]) -> Result<Vec<String>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let select = Feeds::find()
            .select_only()
            .column(FeedColumn::CveId)
            .filter(FeedColumn::IsKev.eq(true))
            .filter(lower_cve_in(ids))
            .into_query();
        let rows: Vec<CveId> = orm::fetch_all(tx, &select).await?;
        Ok(rows.into_iter().map(|row| row.cve_id).collect())
    }

    /// `insertListed`: entries none of which is stored yet, as listed, [`ROWS_PER_STATEMENT`] to a statement — one
    /// `insert … values (…), (…)` where a save per entry was a select and an insert each, 3,000 round trips for an
    /// installation's first catalogue.
    pub async fn insert_listed(
        tx: &mut Tx,
        listings: &[Listing],
        updated_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        for batch in listings.chunks(ROWS_PER_STATEMENT) {
            let rows = batch.iter().map(|listing| FeedActive {
                cve_id: Set(listing.cve_id.clone()),
                is_kev: Set(true),
                date_added: Set(listing.date_added),
                updated_at: Set(updated_at),
            });
            orm::execute(tx, &Feeds::insert_many(rows).into_query()).await?;
        }
        Ok(())
    }

    /// The entity save of an entry already stored — flagged again, its day changed, or delisted.
    pub async fn update(tx: &mut Tx, row: &FeedRow) -> Result<u64, StoreError> {
        let update = Feeds::update_many()
            .col_expr(FeedColumn::IsKev, value(row.is_kev))
            .col_expr(FeedColumn::DateAdded, value(row.date_added))
            .col_expr(FeedColumn::UpdatedAt, value(row.updated_at))
            .filter(FeedColumn::CveId.eq(row.cve_id.as_str()))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }
}

/// The sync row — `ThreatIntelSyncRepository`.
#[derive(Debug, Clone, Copy)]
pub struct SyncRepository;

impl SyncRepository {
    pub async fn find(tx: &mut Tx, id: i64) -> Result<Option<SyncRow>, StoreError> {
        let model: Option<SyncModel> = orm::fetch_optional(tx, &Syncs::find_by_id(id).into_query()).await?;
        Ok(model.map(SyncRow::from))
    }

    /// The row created whole — `saveAndFlush` of a new entity. A key already stored is the engine's refusal, which
    /// [`StoreError::is_duplicate_key`] recognises.
    pub async fn insert(tx: &mut Tx, row: &SyncRow) -> Result<(), StoreError> {
        orm::execute(tx, &Syncs::insert(sync_active(row)).into_query()).await?;
        Ok(())
    }

    /// `save` of the row read under the lock: every column written back.
    pub async fn save(tx: &mut Tx, row: &SyncRow) -> Result<u64, StoreError> {
        let mut active = sync_active(row);
        active.id = sea_orm::ActiveValue::Unchanged(row.id);
        let update = Syncs::update(active).validate().map_err(|error| StoreError(Box::new(error)))?;
        Ok(orm::execute(tx, &update.into_query()).await?)
    }

    /// `markAttempt`: the attempt marked, and so the row's write lock taken until the transaction ends — an update
    /// rather than `select … for update` because it also records what the row exists to show. 0 when the row is
    /// missing, which the caller creates.
    pub async fn mark_attempt(tx: &mut Tx, id: i64, at: OffsetDateTime) -> Result<u64, StoreError> {
        let update = Syncs::update_many()
            .col_expr(SyncColumn::LastAttemptAt, value(at))
            .filter(SyncColumn::Id.eq(id))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `holdForReevaluation`: the row's write lock, nothing changed — the column set to itself, so the attempt the
    /// schedule's retry is timed from does not move. The first statement of each page of the KEV re-evaluation, so
    /// that a second synchronisation's page reads the flags the first one committed, and announces nothing twice.
    pub async fn hold_for_reevaluation(tx: &mut Tx, id: i64) -> Result<u64, StoreError> {
        let update = Syncs::update_many()
            .col_expr(SyncColumn::LastAttemptAt, Expr::col(SyncColumn::LastAttemptAt))
            .filter(SyncColumn::Id.eq(id))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `claimScheduled`: the catalogue's schedule claimed when the catalogue in use is older than `stale_before` — or
    /// there is none — **and** nobody tried since `retry_before`. 1 for the instance that won.
    pub async fn claim_scheduled(
        tx: &mut Tx,
        id: i64,
        now: OffsetDateTime,
        stale_before: OffsetDateTime,
        retry_before: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let update = Syncs::update_many()
            .col_expr(SyncColumn::LastAttemptAt, value(now))
            .filter(SyncColumn::Id.eq(id))
            .filter(SyncColumn::LastSyncedAt.is_null().or(SyncColumn::LastSyncedAt.lt(stale_before)))
            .filter(SyncColumn::LastAttemptAt.is_null().or(SyncColumn::LastAttemptAt.lt(retry_before)))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `claimEpss`: an EPSS synchronisation somebody asked for, unless one holds the lease. **A lease rather than the
    /// row lock**: the file is written in many short transactions, so exclusivity has to outlive one — the claimant
    /// writes its `generation` into `epss_claim` until `lease_until`, and every write after is conditional on it.
    pub async fn claim_epss(
        tx: &mut Tx,
        id: i64,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
        generation: i64,
    ) -> Result<u64, StoreError> {
        let update = Syncs::update_many()
            .col_expr(SyncColumn::EpssAttemptAt, value(now))
            .col_expr(SyncColumn::EpssLeaseUntil, value(lease_until))
            .col_expr(SyncColumn::EpssClaim, value(generation))
            .filter(SyncColumn::Id.eq(id))
            .filter(SyncColumn::EpssLeaseUntil.is_null().or(SyncColumn::EpssLeaseUntil.lt(now)))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `claimEpssScheduled`: the schedule's claim — the file in use older than `stale_before` or none, nobody tried
    /// since `retry_before`, and the lease free.
    #[allow(clippy::too_many_arguments)]
    pub async fn claim_epss_scheduled(
        tx: &mut Tx,
        id: i64,
        now: OffsetDateTime,
        lease_until: OffsetDateTime,
        generation: i64,
        stale_before: OffsetDateTime,
        retry_before: OffsetDateTime,
    ) -> Result<u64, StoreError> {
        let update = Syncs::update_many()
            .col_expr(SyncColumn::EpssAttemptAt, value(now))
            .col_expr(SyncColumn::EpssLeaseUntil, value(lease_until))
            .col_expr(SyncColumn::EpssClaim, value(generation))
            .filter(SyncColumn::Id.eq(id))
            .filter(SyncColumn::EpssSyncedAt.is_null().or(SyncColumn::EpssSyncedAt.lt(stale_before)))
            .filter(SyncColumn::EpssAttemptAt.is_null().or(SyncColumn::EpssAttemptAt.lt(retry_before)))
            .filter(SyncColumn::EpssLeaseUntil.is_null().or(SyncColumn::EpssLeaseUntil.lt(now)))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `applyEpss`: a whole, checked file put in use and the lease given back — only while this synchronisation holds
    /// the claim. `previous` is passed rather than copied from the column in the statement: MySQL assigns left to
    /// right with the values it has just set, the other engines with the old ones.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_epss(
        tx: &mut Tx,
        id: i64,
        generation: i64,
        previous: Option<i64>,
        now: OffsetDateTime,
        model_version: &str,
        score_date: OffsetDateTime,
        count: i64,
    ) -> Result<u64, StoreError> {
        let update = Syncs::update_many()
            .col_expr(SyncColumn::EpssGeneration, value(generation))
            .col_expr(SyncColumn::EpssPreviousGeneration, value(previous))
            .col_expr(SyncColumn::EpssStatus, value(SYNCED))
            .col_expr(SyncColumn::EpssSyncedAt, value(now))
            .col_expr(SyncColumn::EpssModelVersion, value(model_version))
            .col_expr(SyncColumn::EpssScoreDate, value(score_date))
            .col_expr(SyncColumn::EpssCount, value(count))
            .col_expr(SyncColumn::EpssError, value(Option::<String>::None))
            .col_expr(SyncColumn::EpssLeaseUntil, value(Option::<OffsetDateTime>::None))
            .col_expr(SyncColumn::EpssClaim, value(Option::<i64>::None))
            .filter(SyncColumn::Id.eq(id))
            .filter(SyncColumn::EpssClaim.eq(generation))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `confirmEpss`: the file read is the one in use — synchronised, nothing rewritten, the lease given back.
    pub async fn confirm_epss(tx: &mut Tx, id: i64, generation: i64, now: OffsetDateTime) -> Result<u64, StoreError> {
        let update = Syncs::update_many()
            .col_expr(SyncColumn::EpssStatus, value(SYNCED))
            .col_expr(SyncColumn::EpssSyncedAt, value(now))
            .col_expr(SyncColumn::EpssError, value(Option::<String>::None))
            .col_expr(SyncColumn::EpssLeaseUntil, value(Option::<OffsetDateTime>::None))
            .col_expr(SyncColumn::EpssClaim, value(Option::<i64>::None))
            .filter(SyncColumn::Id.eq(id))
            .filter(SyncColumn::EpssClaim.eq(generation))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }

    /// `failEpss`: a failed attempt recorded and the lease given back. The file in use, its generation and its date
    /// stay: an outage, or a refused file, is not a file without scores.
    pub async fn fail_epss(tx: &mut Tx, id: i64, generation: i64, error: &str) -> Result<u64, StoreError> {
        let update = Syncs::update_many()
            .col_expr(SyncColumn::EpssStatus, value(FAILED))
            .col_expr(SyncColumn::EpssError, value(error))
            .col_expr(SyncColumn::EpssLeaseUntil, value(Option::<OffsetDateTime>::None))
            .col_expr(SyncColumn::EpssClaim, value(Option::<i64>::None))
            .filter(SyncColumn::Id.eq(id))
            .filter(SyncColumn::EpssClaim.eq(generation))
            .into_query();
        Ok(orm::execute(tx, &update).await?)
    }
}

/// The stored EPSS scores, one generation at a time — `EpssScoreRepository` and its bulk writes. **Every read names
/// its generation**, the one the sync row says is in use, so a generation being written or refused is never seen.
#[derive(Debug, Clone, Copy)]
pub struct EpssScoreRepository;

impl EpssScoreRepository {
    /// `scoresOf`: `ids` upper-case, as stored — compared as given, so the key's index is used; a `lower(…)` on the
    /// column, as the KEV lookup has, would read the whole generation.
    pub async fn scores_of(tx: &mut Tx, generation: i64, ids: &[String]) -> Result<Vec<KnownEpssScore>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let select = Scores::find()
            .filter(ScoreColumn::Generation.eq(generation))
            .filter(ScoreColumn::CveId.is_in(ids.iter().cloned()))
            .into_query();
        let models: Vec<ScoreModel> = orm::fetch_all(tx, &select).await?;
        Ok(models
            .into_iter()
            .map(|model| KnownEpssScore { cve_id: model.cve_id, score: model.score, percentile: model.percentile })
            .collect())
    }

    /// `countByGeneration`.
    pub async fn count_by_generation(tx: &mut Tx, generation: i64) -> Result<i64, StoreError> {
        let select = Scores::find()
            .select_only()
            .expr_as(Expr::col(ScoreColumn::CveId).count(), "count")
            .filter(ScoreColumn::Generation.eq(generation))
            .into_query();
        Ok(orm::fetch_count(tx, &select).await?)
    }

    /// `generationsOtherThan`: those a refused or interrupted synchronisation left, and the one replaced two files ago.
    /// `keep` is never empty in Java's callers, where an empty `in` list is a syntax error on some engines; here an
    /// empty one keeps nothing.
    pub async fn generations_other_than(tx: &mut Tx, keep: &[i64]) -> Result<Vec<i64>, StoreError> {
        let mut select = Scores::find().select_only().column(ScoreColumn::Generation).distinct();
        if !keep.is_empty() {
            select = select.filter(ScoreColumn::Generation.is_not_in(keep.iter().copied()));
        }
        let rows: Vec<Generation> = orm::fetch_all(tx, &select.into_query()).await?;
        Ok(rows.into_iter().map(|row| row.generation).collect())
    }

    /// `cveIdsOf(generation, PageRequest.of(offset, 1))`: the identifier at this position in key order — the boundary
    /// of the next batch to delete.
    pub async fn cve_id_at(tx: &mut Tx, generation: i64, offset: u64) -> Result<Option<String>, StoreError> {
        let select = Scores::find()
            .select_only()
            .column(ScoreColumn::CveId)
            .filter(ScoreColumn::Generation.eq(generation))
            .order_by(ScoreColumn::CveId, Order::Asc)
            .offset(offset)
            .limit(1)
            .into_query();
        let row: Option<CveId> = orm::fetch_optional(tx, &select).await?;
        Ok(row.map(|row| row.cve_id))
    }

    /// `deleteUpTo`: one generation's rows up to a boundary, in key order — a range, because MySQL refuses a `limit`
    /// inside an `in` subquery and PostgreSQL has no `delete … limit`.
    pub async fn delete_up_to(tx: &mut Tx, generation: i64, up_to: &str) -> Result<u64, StoreError> {
        let delete = Scores::delete_many()
            .filter(ScoreColumn::Generation.eq(generation))
            .filter(ScoreColumn::CveId.lte(up_to))
            .into_query();
        Ok(orm::execute(tx, &delete).await?)
    }

    /// `deleteGeneration`: what is left of one generation.
    pub async fn delete_generation(tx: &mut Tx, generation: i64) -> Result<u64, StoreError> {
        let delete = Scores::delete_many().filter(ScoreColumn::Generation.eq(generation)).into_query();
        Ok(orm::execute(tx, &delete).await?)
    }

    /// `insertAll`: these scores under `generation`, [`ROWS_PER_STATEMENT`] to a statement, in the caller's
    /// transaction — the file's rows as the table spells them, the identifiers upper-case.
    pub async fn insert_all(tx: &mut Tx, generation: i64, scores: &[KnownEpssScore]) -> Result<(), StoreError> {
        for batch in scores.chunks(ROWS_PER_STATEMENT) {
            let rows = batch.iter().map(|score| ScoreActive {
                generation: Set(generation),
                cve_id: Set(score.cve_id.clone()),
                score: Set(score.score),
                percentile: Set(score.percentile),
            });
            orm::execute(tx, &Scores::insert_many(rows).into_query()).await?;
        }
        Ok(())
    }
}
