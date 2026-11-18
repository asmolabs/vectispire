//! `EpssFeed`: FIRST's EPSS file, synchronised and stored — the scores a scan and the backlog read, in place of a
//! question each scan asked `api.first.org`.
//!
//! **Written beside the scores in use, switched to in one statement.** A synchronisation claims the feed, writes the
//! whole file under a generation of its own in batches of [`WRITE_BATCH`] rows — each its own short transaction, so no
//! lock is held for the 380,000 rows — then checks it and points the sync row at it. Every reader reads the generation
//! the row names: until that update commits the previous scores are the ones in use, and a file refused half-way, or a
//! synchronisation that dies, leaves nothing a reader sees.
//!
//! **The generation replaced is kept until the next one is applied.** A reader reads the row, then the scores of the
//! generation it names — two statements, and a switch can fall between them; applying file N deletes N-2, not N-1.
//!
//! **The generation is random, not the next number.** It is also the claim's token: a synchronisation whose lease ran
//! out while it was still writing must not share a generation with the one that took the lease over.
//!
//! **Not audited here**: [`crate::sync::ThreatIntelFeedService`] alone calls [`EpssFeed::sync`] and
//! [`EpssFeed::sync_if_due`], and records each attempt. **Nothing here is ever silently replaced by less**: a file that
//! is not whole, is older than the one in use, or is markedly smaller than it is refused, recorded as failed with the
//! reason, and the scores in use stay.

use std::sync::Arc;

use rand_core::{OsRng, RngCore};
use time::Duration;
#[cfg(test)]
use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_issues::IssueCatalog;
use vectispire_cp_targets::Clock;
use vectispire_domain::java;

use crate::epss_file::{self, EpssReader, Header};
use crate::feeds::{EpssFeedStatus, FeedError, KnownEpssScore, ThreatIntel, scores_in};
use crate::persistence::repository::{EpssScoreRepository, SyncRepository};
use crate::persistence::{self, SINGLETON_ID, StoreError, SyncRow};
use crate::sources::EpssSource;
use crate::time_text::{java_string, of_instant, shifted};

/// How old the file in use may get before the schedule reads it again. FIRST publishes once a day; 23 hours rather
/// than 24 because the hourly turn drifts later each time, and a full day would slip a turn every day.
pub const REFRESH_AFTER: Duration = Duration::hours(23);

/// How long after an attempt a failed one is retried: every turn but one, under the hour for the same drift, above
/// zero so several instances ask once between them.
pub const RETRY_AFTER: Duration = Duration::minutes(50);

/// How long a claim holds: writing, applying and replacing FIRST's file takes seconds; half an hour covers a slow
/// mirror and a busy engine many times over, and bounds how long a crashed instance keeps the others from trying.
pub const LEASE: Duration = Duration::minutes(30);

/// Rows per write transaction.
pub const WRITE_BATCH: usize = 5_000;

/// Rows per delete statement, for the same reason.
pub const DELETE_BATCH: u64 = 5_000;

/// Open issues re-scored per page.
pub const BACKLOG_PAGE: u64 = 500;

/// `ERROR_MAX`: the column `epss_error` is 500.
const ERROR_MAX: usize = 500;

/// The states treated as settled: "still open" is every other one — the KEV re-evaluation's definition too.
pub(crate) fn closed() -> Vec<String> {
    vec!["closed".to_owned(), "resolved".to_owned()]
}

/// How an attempt ended, for the audit entry the caller writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A new file was written, checked and put in use.
    Applied,
    /// The file read is the one in use — same model, same score date — and nothing was rewritten.
    Unchanged,
    /// Nothing was replaced; the status says why.
    Failed,
    /// Another synchronisation holds the lease; this one did not run.
    Busy,
}

/// An attempt, and the state it left. `reason` is carried apart from the status, which a synchronisation that lost its
/// claim does not write: the feed then says what the one holding it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub outcome: Outcome,
    pub status: EpssFeedStatus,
    pub reason: Option<String>,
}

/// The feed.
#[derive(Clone)]
pub struct EpssFeed {
    db: Db,
    reads: ThreatIntel,
    issues: Arc<IssueCatalog>,
    source: Arc<dyn EpssSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for EpssFeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("EpssFeed").field("source", &self.source.location()).finish_non_exhaustive()
    }
}

/// Why a run stopped short of applying: the sentence the status keeps.
type Refusal = String;

impl EpssFeed {
    pub fn new(
        db: Db,
        reads: ThreatIntel,
        issues: Arc<IssueCatalog>,
        source: Arc<dyn EpssSource>,
        clock: Arc<dyn Clock>,
    ) -> EpssFeed {
        EpssFeed { db, reads, issues, source, clock }
    }

    /// `status()`: where the feed stands.
    pub async fn status(&self) -> Result<EpssFeedStatus, FeedError> {
        self.reads.epss_status().await
    }

    /// `sync()`: a synchronisation somebody asked for — unless one is running, in which case it is not run twice.
    pub async fn sync(&self) -> Result<Attempt, FeedError> {
        self.ensure_sync_row().await?;
        let generation = new_generation();
        let now = self.clock.now();
        let mut tx = persistence::write(&self.db).await?;
        let claimed = SyncRepository::claim_epss(&mut tx, SINGLETON_ID, now, shifted(now, LEASE), generation).await?;
        persistence::commit(tx).await?;
        if claimed == 0 {
            return Ok(Attempt { outcome: Outcome::Busy, status: self.status().await?, reason: None });
        }
        self.run(generation).await
    }

    /// `syncIfDue()`: the scheduled synchronisation, when one is due and this instance won it; none otherwise.
    pub async fn sync_if_due(&self) -> Result<Option<Attempt>, FeedError> {
        self.ensure_sync_row().await?;
        let generation = new_generation();
        let now = self.clock.now();
        let mut tx = persistence::write(&self.db).await?;
        let claimed = SyncRepository::claim_epss_scheduled(
            &mut tx,
            SINGLETON_ID,
            now,
            shifted(now, LEASE),
            generation,
            shifted(now, -REFRESH_AFTER),
            shifted(now, -RETRY_AFTER),
        )
        .await?;
        persistence::commit(tx).await?;
        if claimed == 0 {
            return Ok(None);
        }
        Ok(Some(self.run(generation).await?))
    }

    /// Under the claim: the file fetched, written, checked and applied, then the backlog re-scored.
    async fn run(&self, generation: i64) -> Result<Attempt, FeedError> {
        let before = self.sync_row().await?.ok_or_else(|| FeedError(Box::from("the sync row is missing")))?;
        let current = before.epss_generation;
        let previous = before.epss_previous_generation;

        let header = match self.write_and_apply(&before, generation).await {
            Ok(Some(header)) => header,
            Ok(None) => return Ok(Attempt { outcome: Outcome::Unchanged, status: self.status().await?, reason: None }),
            Err(refused) => {
                let reason = truncate(&refused);
                tracing::warn!("EPSS file not synchronised from {}: {reason}", self.source.location());
                let mut tx = persistence::write(&self.db).await?;
                let failed = SyncRepository::fail_epss(&mut tx, SINGLETON_ID, generation, &reason).await?;
                persistence::commit(tx).await?;
                if failed == 0 {
                    tracing::warn!(
                        "EPSS synchronisation had lost its claim; the failure is left to the one that holds it."
                    );
                }
                self.discard_quietly(generation).await;
                return Ok(Attempt { outcome: Outcome::Failed, status: self.status().await?, reason: Some(reason) });
            }
        };

        // Applied: what follows cannot un-apply it, and a failure below is logged and left to the next
        // synchronisation, which re-scores the backlog again.
        let rescored = match self.rescore_backlog(generation).await {
            Ok(rescored) => rescored,
            Err(failure) => {
                tracing::warn!("EPSS file applied, but the open issues were not all re-scored: {}", truncate(&failure));
                0
            }
        };
        // N-2, not the generation just replaced: a reader that read the row before the switch is still reading it.
        if let Some(previous) = previous
            && Some(previous) != current
        {
            self.discard_quietly(previous).await;
        }
        let model = &header.0.model_version;
        tracing::info!(
            "EPSS file {model} of {} synchronised: {} CVE scored, {rescored} open issue(s) re-scored.",
            header.0.score_date.to_java_string().unwrap_or_default(),
            header.1
        );
        let mut status = self.status().await?;
        status.backlog_updated_count = i64::try_from(rescored).unwrap_or(i64::MAX);
        Ok(Attempt { outcome: Outcome::Applied, status, reason: None })
    }

    /// The `try` of `run`: the file and its rows when applied, none when it is the one in use and was confirmed, the
    /// refusal otherwise — every failure of the store included, as Java's `catch (RuntimeException)` takes them.
    async fn write_and_apply(&self, before: &SyncRow, generation: i64) -> Result<Option<(Header, u64)>, Refusal> {
        let current = before.epss_generation;
        // Left by a synchronisation that was refused or died before it cleaned up.
        self.discard_all_but(generation, current, before.epss_previous_generation).await.map_err(text)?;
        // Fetched whole before anything is written: no transaction and no row wait on the network.
        let file = self.source.fetch().await?;
        let mut reader = EpssReader::open(&file).map_err(|unreadable| unreadable.0)?;
        if !proceed(before, reader.header())? {
            let mut tx = persistence::write(&self.db).await.map_err(text)?;
            let confirmed = SyncRepository::confirm_epss(&mut tx, SINGLETON_ID, generation, self.clock.now())
                .await
                .map_err(text)?;
            persistence::commit(tx).await.map_err(text)?;
            if confirmed == 0 {
                return Err("the claim on the EPSS feed ran out before the file was confirmed".to_owned());
            }
            return Ok(None);
        }
        while let Some(batch) = reader.next_batch(WRITE_BATCH).map_err(|unreadable| unreadable.0)? {
            let scores: Vec<KnownEpssScore> = batch
                .into_iter()
                .map(|score| KnownEpssScore { cve_id: score.cve, score: score.score, percentile: score.percentile })
                .collect();
            let mut tx = persistence::write(&self.db).await.map_err(text)?;
            EpssScoreRepository::insert_all(&mut tx, generation, &scores).await.map_err(text)?;
            persistence::commit(tx).await.map_err(text)?;
        }
        let rows = reader.rows();
        if current.is_some() {
            epss_file::require_comparable(u64::try_from(before.epss_count).unwrap_or(0), rows)
                .map_err(|unreadable| unreadable.0)?;
        }
        let header = reader.header().clone();
        let mut tx = persistence::write(&self.db).await.map_err(text)?;
        let written = EpssScoreRepository::count_by_generation(&mut tx, generation).await.map_err(text)?;
        if u64::try_from(written).ok() != Some(rows) {
            return Err(format!(
                "the file carries {rows} scores and {written} were stored: its rows were removed while it was written, \
                 by a synchronisation that took over an expired claim"
            ));
        }
        let score_date =
            of_instant(header.score_date).ok_or_else(|| "the file's score date is out of range".to_owned())?;
        let applied = SyncRepository::apply_epss(
            &mut tx,
            SINGLETON_ID,
            generation,
            current,
            self.clock.now(),
            &header.model_version,
            score_date,
            i64::try_from(rows).unwrap_or(i64::MAX),
        )
        .await
        .map_err(text)?;
        persistence::commit(tx).await.map_err(text)?;
        if applied == 0 {
            return Err("the claim on the EPSS feed ran out before the file was applied".to_owned());
        }
        Ok(Some((header, rows)))
    }

    /// `rescoreBacklog`: the open issues' scores from the file just applied, a page at a time, walked by id.
    ///
    /// **Only a known score replaces one**, as on a scan: a CVE the file no longer scores — a rejected one — keeps the
    /// figure it had rather than losing it to an unknown.
    async fn rescore_backlog(&self, generation: i64) -> Result<u64, String> {
        let closed = closed();
        let mut after = 0;
        let mut rescored: u64 = 0;
        loop {
            let page = self.issues.epss_candidates_after(after, &closed, BACKLOG_PAGE).await.map_err(text)?;
            let Some(last) = page.last() else {
                return Ok(rescored);
            };
            after = last.id;

            let mut tx = persistence::read(&self.db).await.map_err(text)?;
            let known = scores_in(&mut tx, generation, page.iter().map(|issue| issue.identifier.as_str()))
                .await
                .map_err(text)?;
            persistence::commit(tx).await.map_err(text)?;
            let mut changed: Vec<(i64, f64)> = Vec::new();
            for issue in &page {
                let Some(score) = known.get(&normalised(&issue.identifier)) else {
                    continue;
                };
                // `Objects.equals` on two `Double`s: the same bits.
                if issue.epss_score.map(f64::to_bits) != Some(score.score.to_bits()) {
                    changed.push((issue.id, score.score));
                }
            }
            rescored = rescored.saturating_add(self.issues.record_epss(&changed).await.map_err(text)?);
            if (page.len() as u64) < BACKLOG_PAGE {
                return Ok(rescored);
            }
        }
    }

    /// Every generation but the one being written, the one in use and the one it replaced.
    async fn discard_all_but(
        &self,
        writing: i64,
        current: Option<i64>,
        previous: Option<i64>,
    ) -> Result<(), StoreError> {
        let keep: Vec<i64> = [Some(writing), current, previous].into_iter().flatten().collect();
        let mut tx = persistence::read(&self.db).await?;
        let others = EpssScoreRepository::generations_other_than(&mut tx, &keep).await?;
        persistence::commit(tx).await?;
        for generation in others {
            self.discard(generation).await?;
        }
        Ok(())
    }

    async fn discard_quietly(&self, generation: i64) {
        if let Err(failure) = self.discard(generation).await {
            // Left for the next synchronisation, which discards every generation not in use first.
            tracing::warn!("EPSS generation {generation} not discarded: {}", truncate(&failure.to_string()));
        }
    }

    /// One generation deleted [`DELETE_BATCH`] rows at a time, in key order: the row at the batch's end is the
    /// boundary, and everything up to it goes in one statement.
    async fn discard(&self, generation: i64) -> Result<(), StoreError> {
        loop {
            let mut tx = persistence::write(&self.db).await?;
            match EpssScoreRepository::cve_id_at(&mut tx, generation, DELETE_BATCH - 1).await? {
                None => {
                    EpssScoreRepository::delete_generation(&mut tx, generation).await?;
                    persistence::commit(tx).await?;
                    return Ok(());
                }
                Some(boundary) => {
                    EpssScoreRepository::delete_up_to(&mut tx, generation, &boundary).await?;
                    persistence::commit(tx).await?;
                }
            }
        }
    }

    /// The row every attempt is recorded on; created when missing, by whichever instance gets there first.
    async fn ensure_sync_row(&self) -> Result<(), FeedError> {
        if self.sync_row().await?.is_some() {
            return Ok(());
        }
        let mut tx = persistence::write(&self.db).await?;
        match SyncRepository::insert(&mut tx, &SyncRow::fresh()).await {
            Ok(()) => persistence::commit(tx).await?,
            // Another instance, or the KEV synchronisation, created it: the claim reads it.
            Err(created_meanwhile) if created_meanwhile.is_duplicate_key() => {}
            Err(failure) => return Err(failure.into()),
        }
        Ok(())
    }

    async fn sync_row(&self) -> Result<Option<SyncRow>, StoreError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = SyncRepository::find(&mut tx, SINGLETON_ID).await?;
        persistence::commit(tx).await?;
        Ok(row)
    }
}

/// `Writer.header`: whether to write the file. **A file older than the one in use is refused** — a mirror restored
/// from last month's copy would otherwise put last month's probabilities back on every issue; **the same file again**
/// — a mirror not refreshed since — is confirmed, not rewritten.
fn proceed(in_use: &SyncRow, header: &Header) -> Result<bool, Refusal> {
    let Some(used) = in_use.epss_score_date.filter(|_| in_use.epss_generation.is_some()) else {
        return Ok(true);
    };
    let read = of_instant(header.score_date).ok_or_else(|| "the file's score date is out of range".to_owned())?;
    if read < used {
        return Err(format!(
            "the file read (scores of {}) is older than the one in use (scores of {}); kept the newer",
            header.score_date.to_java_string().unwrap_or_default(),
            java_string(used)
        ));
    }
    Ok(!(read == used && in_use.epss_model_version.as_deref() == Some(header.model_version.as_str())))
}

/// `ThreadLocalRandom.nextLong(1, Long.MAX_VALUE)`: a generation in `[1, i64::MAX)`.
fn new_generation() -> i64 {
    let span = u64::try_from(i64::MAX).unwrap_or(u64::MAX).saturating_sub(1);
    i64::try_from(OsRng.next_u64().checked_rem(span).unwrap_or(0)).unwrap_or(0).saturating_add(1)
}

fn normalised(identifier: &str) -> String {
    java::to_upper_root(java::trim(identifier))
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// `reason`: at most 500 characters, the last one an ellipsis.
pub(crate) fn truncate(message: &str) -> String {
    if message.chars().count() <= ERROR_MAX {
        return message.to_owned();
    }
    let mut kept: String = message.chars().take(ERROR_MAX - 1).collect();
    kept.push('…');
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use vectispire_domain::instant::Instant;

    fn row(generation: Option<i64>, date: Option<i64>, model: &str) -> SyncRow {
        SyncRow {
            epss_generation: generation,
            epss_score_date: date
                .map(|seconds| OffsetDateTime::from_unix_timestamp(seconds).unwrap_or(OffsetDateTime::UNIX_EPOCH)),
            epss_model_version: Some(model.to_owned()),
            ..SyncRow::fresh()
        }
    }

    fn header(seconds: i64, model: &str) -> Header {
        Header { model_version: model.to_owned(), score_date: Instant::of_epoch_second(seconds) }
    }

    #[test]
    fn the_first_file_and_a_newer_one_are_written() {
        assert_eq!(proceed(&row(None, Some(2_000), "v1"), &header(1_000, "v1")), Ok(true));
        assert_eq!(proceed(&row(Some(7), None, "v1"), &header(1_000, "v1")), Ok(true));
        assert_eq!(proceed(&row(Some(7), Some(1_000), "v1"), &header(1_001, "v1")), Ok(true));
        assert_eq!(proceed(&row(Some(7), Some(1_000), "v1"), &header(1_000, "v2")), Ok(true));
    }

    #[test]
    fn the_same_file_is_confirmed_and_an_older_one_refused() {
        assert_eq!(proceed(&row(Some(7), Some(1_000), "v1"), &header(1_000, "v1")), Ok(false));
        assert_eq!(
            proceed(&row(Some(7), Some(86_400), "v1"), &header(0, "v1")),
            Err("the file read (scores of 1970-01-01T00:00:00Z) is older than the one in use (scores of \
                 1970-01-02T00:00:00Z); kept the newer"
                .to_owned())
        );
    }

    #[test]
    fn a_generation_is_never_zero_nor_negative() {
        for _ in 0..1_000 {
            assert!(new_generation() >= 1);
        }
    }

    #[test]
    fn a_reason_keeps_five_hundred_characters() {
        assert_eq!(truncate("short"), "short");
        let long = "x".repeat(501);
        let kept = truncate(&long);
        assert_eq!(kept.chars().count(), 500);
        assert!(kept.ends_with("x…"));
        assert_eq!(truncate(&"y".repeat(500)), "y".repeat(500));
    }
}
