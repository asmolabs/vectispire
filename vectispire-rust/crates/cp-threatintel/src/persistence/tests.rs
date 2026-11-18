//! Threat intelligence's repositories on real servers: every statement, run once, its answer held to what Java's
//! `ThreatIntelRepository`, `ThreatIntelSyncRepository` and `EpssScoreRepository` answer — the elections and the
//! lease above all, whose count is the decision; the reads of [`crate::feeds`] over them; and the three entities held
//! to the migrated schema.
//!
//! Every check runs, and the failures are reported together.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use self::support::Migrated;
use crate::feeds::{EpssFeedStatus, ThreatIntel};
use crate::persistence::repository::{EpssScoreRepository, IntelRepository, ROWS_PER_STATEMENT, SyncRepository};
use crate::persistence::{FeedRow, KnownEpssScore, Listing, SINGLETON_ID, StoreError, SyncRow};
use crate::status::{Exploitation, KevListing, State};
use time::{Duration, OffsetDateTime};
use vectispire_cp_db::parity;
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Db, Engine, Mode, Tx};

#[test]
fn on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    run(Engine::MySql);
}

#[test]
fn on_postgresql() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    run(Engine::PostgreSql);
}

type Check = Result<(), String>;

macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($what:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!("{}: {:?} != {:?}", format!($($what)+), left, right));
        }
    }};
}

fn err(error: StoreError) -> String {
    error.to_string()
}

fn run(engine: Engine) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = Migrated::start(engine).await;
        let db = server.connect().await;
        let mut failures = Vec::new();
        macro_rules! each {
            ($($check:ident),* $(,)?) => {$(
                // Each check in a transaction of its own, rolled back: none sees another's rows.
                let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
                if let Err(failure) = $check(&mut tx).await {
                    failures.push(format!("{}: {failure}", stringify!($check)));
                }
                tx.rollback().await.unwrap();
            )*};
        }
        each!(
            the_migration_leaves_the_row_never_synchronised,
            the_catalogue_is_written_many_to_a_statement_and_read_whatever_the_case,
            a_missing_row_is_created_once_and_marks_nothing,
            the_lock_taking_update_moves_nothing,
            the_catalogue_s_schedule_is_claimed_when_stale_and_not_tried_since,
            the_epss_lease_is_held_by_one_and_its_writes_need_the_claim,
            the_scheduled_epss_claim_needs_all_three_conditions,
            the_row_is_saved_whole,
            a_generation_is_written_counted_read_and_discarded_by_ranges,
        );
        // Last: they commit.
        the_reads_say_unknown_until_each_feed_was_read(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("the_reads_say_unknown_until_each_feed_was_read: {failure}"));
        });
        the_entities_agree_with_the_schema(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("the_entities_agree_with_the_schema: {failure}"));
        });
        db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

/// A whole second: what V12's columns (`date_added`, `updated_at`, `last_synced_at`) keep on MySQL.
fn second(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_760_000_000 + seconds).unwrap()
}

fn at(seconds: i64) -> OffsetDateTime {
    to_microseconds(
        OffsetDateTime::from_unix_timestamp(1_760_000_000 + seconds).unwrap() + Duration::microseconds(123_456),
    )
}

async fn row(tx: &mut Tx) -> Result<SyncRow, String> {
    SyncRepository::find(tx, SINGLETON_ID).await.map_err(err)?.ok_or_else(|| "the sync row is missing".to_owned())
}

/// V43 writes the singleton back as never synchronised; V45 adds the EPSS columns at their defaults.
async fn the_migration_leaves_the_row_never_synchronised(tx: &mut Tx) -> Check {
    ensure_eq!(row(tx).await?, SyncRow::fresh(), "the row V43 and V45 leave");
    Ok(())
}

async fn the_catalogue_is_written_many_to_a_statement_and_read_whatever_the_case(tx: &mut Tx) -> Check {
    // More than two statements' worth, the last one partial.
    let listings: Vec<Listing> = (0..ROWS_PER_STATEMENT * 2 + 7)
        .map(|n| Listing {
            cve_id: format!("CVE-2024-{:05}", n),
            date_added: if n % 3 == 0 { None } else { Some(second(i64::try_from(n).unwrap())) },
        })
        .collect();
    IntelRepository::insert_listed(tx, &listings, second(-5)).await.map_err(err)?;
    let all = IntelRepository::all(tx).await.map_err(err)?;
    ensure_eq!(all.len(), listings.len(), "every entry written");
    ensure_eq!(
        all.get(1).cloned(),
        Some(FeedRow {
            cve_id: "CVE-2024-00001".to_owned(),
            is_kev: true,
            date_added: Some(second(1)),
            updated_at: second(-5)
        }),
        "an entry as listed"
    );
    ensure_eq!(all.first().and_then(|row| row.date_added), None, "the day unknown stays unknown");

    let mixed = vec!["cve-2024-00002".to_owned(), "cve-2024-00003".to_owned(), "cve-1999-0001".to_owned()];
    let mut found: Vec<String> =
        IntelRepository::by_ids_ignore_case(tx, &mixed).await.map_err(err)?.into_iter().map(|row| row.cve_id).collect();
    found.sort();
    ensure_eq!(found, vec!["CVE-2024-00002".to_owned(), "CVE-2024-00003".to_owned()], "lower-case ids match");

    let mut delisted = all.get(2).cloned().unwrap();
    delisted.is_kev = false;
    // A fraction the column cannot keep: MySQL rounds it away, as it does Java's instants.
    delisted.updated_at = at(50);
    ensure_eq!(IntelRepository::update(tx, &delisted).await.map_err(err)?, 1, "one row rewritten");
    let stored = IntelRepository::by_ids_ignore_case(tx, &["cve-2024-00002".to_owned()]).await.map_err(err)?;
    let expected = match tx_engine(tx) {
        Engine::MySql => second(50),
        Engine::PostgreSql => at(50),
    };
    ensure_eq!(stored.first().map(|row| row.updated_at), Some(expected), "the precision V12 gave the column");
    let mut exploited = IntelRepository::exploited_among(tx, &mixed).await.map_err(err)?;
    exploited.sort();
    ensure_eq!(exploited, vec!["CVE-2024-00003".to_owned()], "a delisted entry is no longer exploited, as stored");
    ensure_eq!(IntelRepository::exploited_among(tx, &[]).await.map_err(err)?, Vec::<String>::new(), "nothing asked");
    Ok(())
}

async fn a_missing_row_is_created_once_and_marks_nothing(tx: &mut Tx) -> Check {
    vectispire_cp_db::orm::execute(
        tx,
        &sea_orm::sea_query::Query::delete()
            .from_table(sea_orm::sea_query::Alias::new("t_threat_intel_sync"))
            .to_owned(),
    )
    .await
    .map_err(|e| e.to_string())?;
    ensure_eq!(SyncRepository::mark_attempt(tx, SINGLETON_ID, at(0)).await.map_err(err)?, 0, "no row to mark");
    ensure_eq!(SyncRepository::claim_epss(tx, SINGLETON_ID, at(0), at(10), 7).await.map_err(err)?, 0, "nor to claim");
    SyncRepository::insert(tx, &SyncRow::fresh()).await.map_err(err)?;
    // The second creation is refused as a duplicate: the instance that loses goes on with the row the winner made.
    // On PostgreSQL a refused statement aborts the transaction, which is why the Java side creates it in its own.
    if tx_engine(tx) == Engine::MySql {
        let again = SyncRepository::insert(tx, &SyncRow::fresh()).await;
        ensure_eq!(again.as_ref().map_err(StoreError::is_duplicate_key).err(), Some(true), "a duplicate key");
    }
    ensure_eq!(SyncRepository::mark_attempt(tx, SINGLETON_ID, at(3)).await.map_err(err)?, 1, "now marked");
    ensure_eq!(row(tx).await?.last_attempt_at, Some(at(3)), "the attempt");
    Ok(())
}

fn tx_engine(tx: &Tx) -> Engine {
    match tx {
        Tx::MySql(_) => Engine::MySql,
        Tx::PostgreSql(_) => Engine::PostgreSql,
    }
}

async fn the_lock_taking_update_moves_nothing(tx: &mut Tx) -> Check {
    SyncRepository::mark_attempt(tx, SINGLETON_ID, at(1)).await.map_err(err)?;
    let before = row(tx).await?;
    ensure_eq!(SyncRepository::hold_for_reevaluation(tx, SINGLETON_ID).await.map_err(err)?, 1, "the row matched");
    ensure_eq!(row(tx).await?, before, "nothing changed, the attempt above all");
    Ok(())
}

async fn the_catalogue_s_schedule_is_claimed_when_stale_and_not_tried_since(tx: &mut Tx) -> Check {
    // Never synchronised, never tried: due.
    ensure_eq!(
        SyncRepository::claim_scheduled(tx, SINGLETON_ID, at(100), at(40), at(70)).await.map_err(err)?,
        1,
        "due"
    );
    ensure_eq!(row(tx).await?.last_attempt_at, Some(at(100)), "the claim marks the attempt");
    // Tried at 100: not again before the retry window has passed it.
    ensure_eq!(
        SyncRepository::claim_scheduled(tx, SINGLETON_ID, at(110), at(50), at(80)).await.map_err(err)?,
        0,
        "tried"
    );
    ensure_eq!(
        SyncRepository::claim_scheduled(tx, SINGLETON_ID, at(200), at(150), at(101)).await.map_err(err)?,
        1,
        "retried"
    );
    // Synchronised at 300: not stale until the stale bound passes it.
    let mut synced = row(tx).await?;
    synced.last_synced_at = Some(second(300));
    SyncRepository::save(tx, &synced).await.map_err(err)?;
    ensure_eq!(
        SyncRepository::claim_scheduled(tx, SINGLETON_ID, at(400), second(300), at(350)).await.map_err(err)?,
        0,
        "fresh"
    );
    ensure_eq!(
        SyncRepository::claim_scheduled(tx, SINGLETON_ID, at(400), second(301), at(350)).await.map_err(err)?,
        1,
        "stale"
    );
    Ok(())
}

async fn the_epss_lease_is_held_by_one_and_its_writes_need_the_claim(tx: &mut Tx) -> Check {
    ensure_eq!(SyncRepository::claim_epss(tx, SINGLETON_ID, at(0), at(1800), 41).await.map_err(err)?, 1, "claimed");
    ensure_eq!(SyncRepository::claim_epss(tx, SINGLETON_ID, at(10), at(1810), 42).await.map_err(err)?, 0, "held");
    let claimed = row(tx).await?;
    ensure_eq!(
        (claimed.epss_attempt_at, claimed.epss_lease_until, claimed.epss_claim),
        (Some(at(0)), Some(at(1800)), Some(41)),
        "the claim"
    );
    // Not the holder: nothing written, whatever it says.
    ensure_eq!(
        SyncRepository::apply_epss(tx, SINGLETON_ID, 42, None, at(20), "v", at(0), 9).await.map_err(err)?,
        0,
        "x"
    );
    ensure_eq!(SyncRepository::confirm_epss(tx, SINGLETON_ID, 42, at(20)).await.map_err(err)?, 0, "not confirmed");
    ensure_eq!(SyncRepository::fail_epss(tx, SINGLETON_ID, 42, "no").await.map_err(err)?, 0, "not failed");
    ensure_eq!(row(tx).await?, claimed, "the holder's row untouched");

    ensure_eq!(
        SyncRepository::apply_epss(tx, SINGLETON_ID, 41, Some(7), at(30), "v2025.03.14", at(-86_400), 300_000)
            .await
            .map_err(err)?,
        1,
        "applied by the holder"
    );
    let applied = row(tx).await?;
    ensure_eq!(
        (
            applied.epss_generation,
            applied.epss_previous_generation,
            applied.epss_status.as_str(),
            applied.epss_synced_at,
            applied.epss_model_version.as_deref(),
            applied.epss_score_date,
            applied.epss_count,
            applied.epss_error.as_deref(),
            applied.epss_lease_until,
            applied.epss_claim
        ),
        (Some(41), Some(7), "SYNCED", Some(at(30)), Some("v2025.03.14"), Some(at(-86_400)), 300_000, None, None, None),
        "the file in use, the lease given back"
    );

    // A lease past its end is taken over; a failure keeps the file in use.
    ensure_eq!(SyncRepository::claim_epss(tx, SINGLETON_ID, at(40), at(1840), 43).await.map_err(err)?, 1, "free again");
    ensure_eq!(SyncRepository::fail_epss(tx, SINGLETON_ID, 43, "refused").await.map_err(err)?, 1, "failed");
    let failed = row(tx).await?;
    ensure_eq!(
        (failed.epss_status.as_str(), failed.epss_error.as_deref(), failed.epss_generation, failed.epss_claim),
        ("FAILED", Some("refused"), Some(41), None),
        "an outage is not a file without scores"
    );
    ensure_eq!(SyncRepository::claim_epss(tx, SINGLETON_ID, at(50), at(60), 44).await.map_err(err)?, 1, "short lease");
    ensure_eq!(SyncRepository::claim_epss(tx, SINGLETON_ID, at(61), at(1861), 45).await.map_err(err)?, 1, "expired");
    ensure_eq!(SyncRepository::confirm_epss(tx, SINGLETON_ID, 44, at(70)).await.map_err(err)?, 0, "the claim was lost");
    ensure_eq!(SyncRepository::confirm_epss(tx, SINGLETON_ID, 45, at(70)).await.map_err(err)?, 1, "confirmed");
    let confirmed = row(tx).await?;
    ensure_eq!(
        (confirmed.epss_status.as_str(), confirmed.epss_synced_at, confirmed.epss_error, confirmed.epss_generation),
        ("SYNCED", Some(at(70)), None, Some(41)),
        "the same file, nothing rewritten"
    );
    Ok(())
}

async fn claim(tx: &mut Tx, now: i64, generation: i64, stale: i64, retry: i64) -> Result<u64, StoreError> {
    SyncRepository::claim_epss_scheduled(tx, SINGLETON_ID, at(now), at(now + 1800), generation, at(stale), at(retry))
        .await
}

async fn the_scheduled_epss_claim_needs_all_three_conditions(tx: &mut Tx) -> Check {
    ensure_eq!(claim(tx, 100, 1, 0, 0).await.map_err(err)?, 1, "never synchronised, never tried, free");
    ensure_eq!(claim(tx, 2000, 2, 1000, 50).await.map_err(err)?, 0, "tried since the retry bound");
    ensure_eq!(claim(tx, 1000, 2, 1000, 1000).await.map_err(err)?, 0, "the lease runs until 1900");
    ensure_eq!(claim(tx, 2000, 2, 1000, 1000).await.map_err(err)?, 1, "the lease ran out");
    SyncRepository::apply_epss(tx, SINGLETON_ID, 2, None, at(2100), "v", at(0), 1).await.map_err(err)?;
    ensure_eq!(claim(tx, 3000, 3, 2100, 2500).await.map_err(err)?, 0, "the file in use is not stale");
    ensure_eq!(claim(tx, 3000, 3, 2101, 2500).await.map_err(err)?, 1, "stale");
    Ok(())
}

async fn the_row_is_saved_whole(tx: &mut Tx) -> Check {
    let mut every = SyncRow {
        id: SINGLETON_ID,
        last_synced_at: Some(second(1)),
        cve_count: 1_512,
        kev_count: 1_498,
        status: "SYNCED".to_owned(),
        kev_catalog_version: Some("2025.03.14".to_owned()),
        kev_released_at: Some(at(-3)),
        last_attempt_at: Some(at(1)),
        last_error: Some("é".repeat(500)),
        epss_status: "FAILED".to_owned(),
        epss_synced_at: Some(at(2)),
        epss_model_version: Some("v2025.03.14".to_owned()),
        epss_score_date: Some(at(-86_400)),
        epss_count: 312_000,
        epss_generation: Some(i64::MAX),
        epss_previous_generation: Some(1),
        epss_attempt_at: Some(at(4)),
        epss_lease_until: Some(at(5)),
        epss_claim: Some(9),
        epss_error: Some("x".repeat(500)),
    };
    ensure_eq!(SyncRepository::save(tx, &every).await.map_err(err)?, 1, "saved");
    ensure_eq!(row(tx).await?, every, "read back as written, 500 characters of error included");
    every.last_error = None;
    every.epss_generation = None;
    SyncRepository::save(tx, &every).await.map_err(err)?;
    ensure_eq!(row(tx).await?, every, "nulls written back");
    Ok(())
}

fn scores(count: usize) -> Vec<KnownEpssScore> {
    (0..count)
        .map(|n| {
            let fraction = f64::from(u32::try_from(n).unwrap()) / 3_000.0;
            KnownEpssScore { cve_id: format!("CVE-2023-{:05}", n), score: fraction, percentile: 1.0 - fraction }
        })
        .collect()
}

async fn a_generation_is_written_counted_read_and_discarded_by_ranges(tx: &mut Tx) -> Check {
    let file = scores(ROWS_PER_STATEMENT * 3 + 1);
    EpssScoreRepository::insert_all(tx, 11, &file).await.map_err(err)?;
    EpssScoreRepository::insert_all(tx, 12, &file[..3]).await.map_err(err)?;
    EpssScoreRepository::insert_all(tx, 13, &[]).await.map_err(err)?;
    ensure_eq!(EpssScoreRepository::count_by_generation(tx, 11).await.map_err(err)?, 1_501, "every row");
    ensure_eq!(EpssScoreRepository::count_by_generation(tx, 13).await.map_err(err)?, 0, "nothing written");

    let asked = vec!["CVE-2023-00001".to_owned(), "CVE-2023-01500".to_owned(), "cve-2023-00002".to_owned()];
    let mut found: Vec<String> = EpssScoreRepository::scores_of(tx, 11, &asked)
        .await
        .map_err(err)?
        .into_iter()
        .map(|score| format!("{} {} {}", score.cve_id, score.score, score.percentile))
        .collect();
    found.sort();
    // Compared as given, which MySQL's collation reads without case, as it does Java's statement — the callers
    // upper-case first, so the difference never shows.
    let mut expected =
        vec![format!("CVE-2023-00001 {} {}", 1.0 / 3_000.0, 1.0 - 1.0 / 3_000.0), "CVE-2023-01500 0.5 0.5".to_owned()];
    if tx_engine(tx) == Engine::MySql {
        expected.insert(1, format!("CVE-2023-00002 {} {}", 2.0 / 3_000.0, 1.0 - 2.0 / 3_000.0));
    }
    ensure_eq!(found, expected, "as stored, the doubles exact");

    let mut others = EpssScoreRepository::generations_other_than(tx, &[11]).await.map_err(err)?;
    others.sort_unstable();
    ensure_eq!(others, vec![12], "every generation but those kept");

    // `discard`: the boundary of each batch, then everything up to it; what is left at the end.
    ensure_eq!(EpssScoreRepository::cve_id_at(tx, 11, 499).await.map_err(err)?, Some("CVE-2023-00499".to_owned()), "b");
    ensure_eq!(EpssScoreRepository::delete_up_to(tx, 11, "CVE-2023-00499").await.map_err(err)?, 500, "a batch");
    ensure_eq!(
        EpssScoreRepository::cve_id_at(tx, 11, 1_000).await.map_err(err)?,
        Some("CVE-2023-01500".to_owned()),
        "c"
    );
    ensure_eq!(EpssScoreRepository::cve_id_at(tx, 11, 1_001).await.map_err(err)?, None, "past the end");
    ensure_eq!(EpssScoreRepository::delete_generation(tx, 11).await.map_err(err)?, 1_001, "the rest");
    ensure_eq!(EpssScoreRepository::count_by_generation(tx, 12).await.map_err(err)?, 3, "another generation untouched");
    Ok(())
}

#[derive(Debug)]
struct FixedClock(OffsetDateTime);

impl vectispire_cp_targets::Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

/// `getStatus`, `exploitationOf` and `lookupCves` over committed rows, before and after each feed is read.
async fn the_reads_say_unknown_until_each_feed_was_read(db: &Db) -> Check {
    let feeds = ThreatIntel::new(db.clone(), Arc::new(FixedClock(at(1_000))));
    let fail = |e: crate::feeds::FeedError| e.to_string();

    let status = feeds.status().await.map_err(fail)?;
    ensure_eq!((status.status, status.epss.clone()), (State::NeverSynced, EpssFeedStatus::never()), "nothing read");
    ensure_eq!(feeds.lookup_cves(["CVE-2024-0001"]).await.map_err(fail)?.len(), 0, "nothing recorded");
    ensure_eq!(feeds.exploitation_of(Some(" cve-2024-0001 ")).await.map_err(fail)?, Exploitation::unknown(), "unknown");

    // A catalogue entry stored but the catalogue never marked read (a row written by hand): its own word, KEV unknown.
    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    let listed = Listing { cve_id: "CVE-2024-0001".to_owned(), date_added: Some(second(-10)) };
    IntelRepository::insert_listed(&mut tx, &[listed], second(0)).await.map_err(err)?;
    EpssScoreRepository::insert_all(
        &mut tx,
        77,
        &[
            KnownEpssScore { cve_id: "CVE-2024-0001".to_owned(), score: 0.97, percentile: 0.999 },
            KnownEpssScore { cve_id: "CVE-2024-0002".to_owned(), score: 0.01, percentile: 0.2 },
        ],
    )
    .await
    .map_err(err)?;
    // A count with no generation in use counts nothing: the column is the file's, not yet any file's.
    let mut counted = SyncRepository::find(&mut tx, SINGLETON_ID).await.map_err(err)?.unwrap();
    counted.epss_count = 5;
    SyncRepository::save(&mut tx, &counted).await.map_err(err)?;
    tx.commit().await.map_err(|e| e.to_string())?;
    ensure_eq!(feeds.epss_status().await.map_err(fail)?.total_scored, 0, "no file in use, nothing scored");
    ensure_eq!(feeds.epss_synchronised().await.map_err(fail)?, false, "no file applied");
    let before = feeds.lookup_cves(["cve-2024-0001", "CVE-2024-0002", " ", "CVE-2024-0003"]).await.map_err(fail)?;
    ensure_eq!(before.len(), 1, "a score not in use is not read: generation 77 is not applied");
    ensure_eq!(
        before.get("cve-2024-0001").map(|record| (record.is_kev, record.epss_score, record.notes.as_str())),
        Some((true, None, "Listed in the CISA KEV catalogue")),
        "the KEV row's word"
    );

    // The file applied as generation 77, the catalogue still never read: a score, and nobody asked CISA yet.
    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    SyncRepository::claim_epss(&mut tx, SINGLETON_ID, at(0), at(10), 77).await.map_err(err)?;
    SyncRepository::apply_epss(&mut tx, SINGLETON_ID, 77, None, at(950), "v2025", at(-86_400), 2).await.map_err(err)?;
    tx.commit().await.map_err(|e| e.to_string())?;
    let scored = feeds.lookup_cves(["CVE-2024-0002"]).await.map_err(fail)?;
    ensure_eq!(
        scored.get("cve-2024-0002").map(|record| (record.is_kev, record.notes.as_str())),
        Some((false, "CISA KEV catalogue never synchronised")),
        "a score with no KEV row, the catalogue never read"
    );
    ensure_eq!(
        feeds.exploitation_of(Some("CVE-2024-0002")).await.map_err(fail)?,
        Exploitation { kev: KevListing::Unknown, epss_score: Some(0.01) },
        "scored, the listing unknown"
    );

    // Then the catalogue, read at 900, and another synchronisation's lease running past now.
    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    let mut sync = SyncRepository::find(&mut tx, SINGLETON_ID).await.map_err(err)?.unwrap();
    sync.last_synced_at = Some(second(900));
    sync.status = "SYNCED".to_owned();
    sync.cve_count = 1;
    sync.kev_count = 1;
    SyncRepository::save(&mut tx, &sync).await.map_err(err)?;
    SyncRepository::claim_epss(&mut tx, SINGLETON_ID, at(990), at(2_000), 78).await.map_err(err)?;
    tx.commit().await.map_err(|e| e.to_string())?;

    let status = feeds.status().await.map_err(fail)?;
    ensure_eq!(
        (status.status, status.last_synced_at, status.total_kev),
        (State::Synced, Some(second(900)), 1),
        "the catalogue's state"
    );
    ensure_eq!(
        (status.epss.status, status.epss.total_scored, status.epss.in_progress, status.epss.model_version.as_deref()),
        (State::Synced, 2, true, Some("v2025")),
        "the file's, in progress while the lease runs"
    );
    ensure_eq!(feeds.epss_synchronised().await.map_err(fail)?, true, "a file applied");
    let later = ThreatIntel::new(db.clone(), Arc::new(FixedClock(at(2_001))));
    ensure_eq!(later.epss_status().await.map_err(fail)?.in_progress, false, "a lease past its end holds nothing");

    let after = feeds.lookup_cves(["cve-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]).await.map_err(fail)?;
    ensure_eq!(
        after.get("cve-2024-0002").map(|record| (
            record.cve_id.as_str(),
            record.is_kev,
            record.epss_score,
            record.notes.as_str()
        )),
        Some(("CVE-2024-0002", false, Some(0.01), "Not listed in the CISA KEV catalogue")),
        "a score with no KEV row, the catalogue read"
    );
    ensure_eq!(after.get("cve-2024-0001").and_then(|record| record.epss_percentile), Some(0.999), "both feeds");
    ensure_eq!(after.contains_key("cve-2024-0003"), false, "neither recorded anything");
    ensure_eq!(
        feeds.exploitation_of(Some("cve-2024-0001")).await.map_err(fail)?,
        Exploitation { kev: KevListing::Listed, epss_score: Some(0.97) },
        "listed and scored"
    );
    ensure_eq!(
        feeds.exploitation_of(Some("CVE-2024-0002")).await.map_err(fail)?,
        Exploitation { kev: KevListing::NotListed, epss_score: Some(0.01) },
        "not listed, once the catalogue was read"
    );
    ensure_eq!(feeds.exploitation_of(Some("GHSA-xxxx")).await.map_err(fail)?, Exploitation::unknown(), "not a CVE");
    ensure_eq!(
        feeds.lookup_cve(Some(" CVE-2024-0001 ")).await.map_err(fail)?.map(|record| record.date_added),
        Some(Some(second(-10))),
        "one CVE, keyed as asked"
    );
    ensure_eq!(feeds.lookup_cve(Some("  ")).await.map_err(fail)?, None, "a blank id asks nothing");
    Ok(())
}

async fn the_entities_agree_with_the_schema(db: &Db) -> Check {
    let tables = crate::persistence::entities::tables()?;
    parity::check_entities(db, &tables).await.map_err(|error| error.to_string())
}
