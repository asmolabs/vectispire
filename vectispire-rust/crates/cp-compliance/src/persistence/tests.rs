//! Compliance's repositories on real servers: every statement, run once, its answer held to what the Java side's
//! `ControlDeclarationRepository`, `ComplianceSnapshotRepository`, `AiReviewResultRepository`,
//! `OwaspWeeklyCoverageRepository` and `OwaspWeeklyCoverageQueriesImpl` answer; and the four entities held to the
//! migrated schema.
//!
//! Every check runs, and the failures are reported together.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use self::support::Migrated;
use crate::persistence::repository::{DeclarationRepository, ReviewRepository, SnapshotRepository, WeeklyRepository};
use crate::persistence::{DeclarationRow, NewReview, SnapshotRow, WeeklyRow, WeeklyStateCount, WeeklyTarget};
use time::{Duration, OffsetDateTime};
use vectispire_cp_db::parity;
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Db, Engine, Mode, ScanTarget, Tx, Visibility};

const REPO_A: i64 = 101;
const REPO_B: i64 = 102;
const IMAGE_A: i64 = 201;
const SCAN_A: i64 = 301;

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

fn run(engine: Engine) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = Migrated::start(engine).await;
        seed_targets(&server);
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
            a_declaration_reads_back_and_is_rewritten_in_place,
            the_lapsed_reviews_come_most_lapsed_first,
            a_snapshot_reads_back_in_the_progression_s_order_and_is_purged_by_age,
            the_latest_report_of_a_repository_is_its_newest_then_highest,
            a_report_is_settled_once_and_the_abandoned_ones_by_the_sweep,
            the_weekly_record_is_gated_rewritten_and_purged_by_week,
            a_reader_sums_only_the_weeks_of_its_own_targets,
        );
        // Last: they commit.
        the_purges_and_the_tasks_take_their_rows(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("the_purges_and_the_tasks_take_their_rows: {failure}"));
        });
        the_entities_agree_with_the_schema(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("the_entities_agree_with_the_schema: {failure}"));
        });
        db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

/// Two repositories, an image and a scan, fixed ids, for the reports' foreign key.
fn seed_targets(server: &Migrated) {
    let overriding = match server.engine {
        Engine::MySql => "",
        Engine::PostgreSql => " overriding system value",
    };
    for id in [REPO_A, REPO_B] {
        server.sql_as_admin(&format!(
            "insert into t_repository (id, url, branch){overriding} values ({id}, 'https://forge.example/r{id}.git', 'main')"
        ));
    }
    server.sql_as_admin(&format!(
        "insert into t_container (id, image_name, tag){overriding} values ({IMAGE_A}, 'registry.example/i', 'v1')"
    ));
    server.sql_as_admin(&format!(
        "insert into t_scan (id, branch, status, created_at, repo_id, container_id){overriding} \
         values ({SCAN_A}, 'main', 'completed', '2026-01-01 00:00:00', {REPO_A}, null)"
    ));
}

fn at(seconds: i64) -> OffsetDateTime {
    to_microseconds(
        OffsetDateTime::from_unix_timestamp(1_760_000_000 + seconds).unwrap() + Duration::microseconds(123_456),
    )
}

fn declaration(id: &str, framework: &str, control: &str) -> DeclarationRow {
    DeclarationRow {
        id: id.to_owned(),
        framework: framework.to_owned(),
        control_id: control.to_owned(),
        applicability: "APPLICABLE".to_owned(),
        justification: None,
        implementation: Some("IMPLEMENTED".to_owned()),
        evidence_source: "VECTISPIRE".to_owned(),
        external_evidence: None,
        control_owner: Some("é — owner ✓".to_owned()),
        decided_by: Some("alice".to_owned()),
        decided_at: at(0),
        reviewed_at: Some(at(0)),
        review_due_at: None,
    }
}

async fn a_declaration_reads_back_and_is_rewritten_in_place(tx: &mut Tx) -> Check {
    let err = |e: crate::persistence::StoreError| e.to_string();
    let first = declaration("00000000-0000-4000-8000-000000000001", "ISO_27001", "A.8.28");
    DeclarationRepository::insert(tx, &first).await.map_err(err)?;
    DeclarationRepository::insert(tx, &declaration("00000000-0000-4000-8000-000000000002", "ISO_27001", "A.8.8"))
        .await
        .map_err(err)?;
    DeclarationRepository::insert(
        tx,
        &declaration("00000000-0000-4000-8000-000000000003", "EU_CRA", "CRA-ANNEX1-SBOM"),
    )
    .await
    .map_err(err)?;
    ensure_eq!(
        DeclarationRepository::find(tx, "ISO_27001", "A.8.28").await.map_err(err)?,
        Some(first.clone()),
        "found by framework and control"
    );
    ensure_eq!(DeclarationRepository::find(tx, "ISO_27001", "A.5.1").await.map_err(err)?, None, "an absent control");
    let mut iso: Vec<String> = DeclarationRepository::by_framework(tx, "ISO_27001")
        .await
        .map_err(err)?
        .into_iter()
        .map(|row| row.control_id)
        .collect();
    iso.sort();
    ensure_eq!(iso, vec!["A.8.28".to_owned(), "A.8.8".to_owned()], "a framework's lines");

    let excluded = DeclarationRow {
        applicability: "EXCLUDED".into(),
        justification: Some("No software is developed here.".into()),
        implementation: None,
        evidence_source: "EXTERNAL".into(),
        external_evidence: Some("Register R-12".into()),
        decided_at: at(50),
        reviewed_at: Some(at(50)),
        review_due_at: Some(at(1_000)),
        ..first.clone()
    };
    ensure_eq!(DeclarationRepository::update(tx, &excluded).await.map_err(err)?, 1, "one line rewritten");
    ensure_eq!(
        DeclarationRepository::find(tx, "ISO_27001", "A.8.28").await.map_err(err)?,
        Some(excluded),
        "the line as rewritten"
    );
    Ok(())
}

async fn the_lapsed_reviews_come_most_lapsed_first(tx: &mut Tx) -> Check {
    let err = |e: crate::persistence::StoreError| e.to_string();
    for (n, due) in [(1, Some(30)), (2, Some(10)), (3, None), (4, Some(100)), (5, Some(50))] {
        let row = DeclarationRow {
            review_due_at: due.map(at),
            ..declaration(&format!("00000000-0000-4000-8000-00000000001{n}"), "SOC2", &format!("CC{n}"))
        };
        DeclarationRepository::insert(tx, &row).await.map_err(err)?;
    }
    let lapsed: Vec<String> = DeclarationRepository::review_overdue(tx, at(50))
        .await
        .map_err(err)?
        .into_iter()
        .map(|row| row.control_id)
        .collect();
    ensure_eq!(lapsed, vec!["CC2".to_owned(), "CC1".to_owned()], "lapsed before now, the due date excluded");
    Ok(())
}

fn snapshot(id: &str, period: &str, framework: &str, captured: i64) -> SnapshotRow {
    SnapshotRow {
        id: id.to_owned(),
        period: period.to_owned(),
        framework: framework.to_owned(),
        score: 87,
        status: "PARTIAL".to_owned(),
        targets: 12,
        observed_targets: 10,
        fresh_targets: 9,
        freshness_days: 30,
        eol_enabled: true,
        code_analysis_reaches: false,
        controls_total: 14,
        controls_declared: 11,
        soa_findings: 2,
        captured_at: at(captured),
    }
}

async fn a_snapshot_reads_back_in_the_progression_s_order_and_is_purged_by_age(tx: &mut Tx) -> Check {
    let err = |e: crate::persistence::StoreError| e.to_string();
    let rows = [
        snapshot("00000000-0000-4000-8000-000000000021", "2026-10", "SOC2", 300),
        snapshot("00000000-0000-4000-8000-000000000022", "2026-09", "SOC2", 200),
        snapshot("00000000-0000-4000-8000-000000000023", "2026-10", "ISO_27001", 300),
        snapshot("00000000-0000-4000-8000-000000000024", "2026-08", "SOC2", 100),
    ];
    for row in &rows {
        SnapshotRepository::insert(tx, row).await.map_err(err)?;
    }
    let order: Vec<(String, String)> = SnapshotRepository::all_ordered(tx)
        .await
        .map_err(err)?
        .into_iter()
        .map(|row| (row.period, row.framework))
        .collect();
    ensure_eq!(
        order,
        vec![
            ("2026-08".to_owned(), "SOC2".to_owned()),
            ("2026-09".to_owned(), "SOC2".to_owned()),
            ("2026-10".to_owned(), "ISO_27001".to_owned()),
            ("2026-10".to_owned(), "SOC2".to_owned()),
        ],
        "period, then framework"
    );
    let first = rows.first().unwrap();
    ensure_eq!(SnapshotRepository::find(tx, "2026-10", "SOC2").await.map_err(err)?, Some(first.clone()), "found");
    let rewritten = SnapshotRow { score: 100, status: "COMPLIANT".into(), captured_at: at(400), ..first.clone() };
    ensure_eq!(SnapshotRepository::update(tx, &rewritten).await.map_err(err)?, 1, "one rewritten");
    ensure_eq!(SnapshotRepository::find(tx, "2026-10", "SOC2").await.map_err(err)?, Some(rewritten), "as rewritten");
    ensure_eq!(SnapshotRepository::delete_before(tx, at(200)).await.map_err(err)?, 1, "older than the window");
    ensure_eq!(
        SnapshotRepository::delete(tx, "00000000-0000-4000-8000-000000000023").await.map_err(err)?,
        1,
        "one deleted"
    );
    ensure_eq!(SnapshotRepository::all_ordered(tx).await.map_err(err)?.len(), 2, "what is left");
    Ok(())
}

fn review(created: i64, status: &str, deadline: Option<i64>) -> NewReview {
    NewReview {
        scan_id: SCAN_A,
        model: "a-model".to_owned(),
        prompt: "the prompt".to_owned(),
        status: status.to_owned(),
        created_at: at(created),
        inputs: Some("é ✓ the inputs".to_owned()),
        deadline_at: deadline.map(at),
        repo_id: Some(REPO_A),
        evidence_identifiers: Some("[\"CVE-1\"]".to_owned()),
    }
}

async fn the_latest_report_of_a_repository_is_its_newest_then_highest(tx: &mut Tx) -> Check {
    let err = |e: crate::persistence::StoreError| e.to_string();
    ensure_eq!(ReviewRepository::latest_for_repository(tx, REPO_A).await.map_err(err)?, None, "none yet");
    ReviewRepository::insert(tx, &review(10, "completed", None)).await.map_err(err)?;
    let first_of_two = ReviewRepository::insert(tx, &review(20, "completed", None)).await.map_err(err)?;
    let second_of_two = ReviewRepository::insert(tx, &review(20, "failed", None)).await.map_err(err)?;
    ensure_eq!(second_of_two > first_of_two, true, "keys ascend");
    let latest = ReviewRepository::latest_for_repository(tx, REPO_A).await.map_err(err)?.unwrap();
    ensure_eq!(latest.id, second_of_two, "the newest, then the highest key");
    ensure_eq!(latest.inputs.as_deref(), Some("é ✓ the inputs"), "the inputs read back");
    ensure_eq!(latest.response, None, "no answer yet");
    ensure_eq!(ReviewRepository::latest_for_repository(tx, REPO_B).await.map_err(err)?, None, "another repository's");
    Ok(())
}

async fn a_report_is_settled_once_and_the_abandoned_ones_by_the_sweep(tx: &mut Tx) -> Check {
    let err = |e: crate::persistence::StoreError| e.to_string();
    let awaited = ReviewRepository::insert(tx, &review(0, "running", Some(100))).await.map_err(err)?;
    let abandoned = ReviewRepository::insert(tx, &review(0, "running", Some(40))).await.map_err(err)?;
    // Answered, its deadline still written: the sweep turns only a running row into a failed one.
    let answered = ReviewRepository::insert(tx, &review(0, "completed", Some(40))).await.map_err(err)?;
    ensure_eq!(ReviewRepository::any_awaited(tx, "running", at(50)).await.map_err(err)?, true, "one still awaited");
    ensure_eq!(ReviewRepository::any_awaited(tx, "running", at(100)).await.map_err(err)?, false, "none past 100");

    ensure_eq!(
        ReviewRepository::settle_abandoned(tx, "running", "failed", "abandoned", at(50)).await.map_err(err)?,
        1,
        "the one past its deadline"
    );
    ensure_eq!(
        ReviewRepository::find_by_id(tx, answered).await.map_err(err)?.unwrap().status,
        "completed",
        "an answered report is not swept"
    );
    let swept = ReviewRepository::find_by_id(tx, abandoned).await.map_err(err)?.unwrap();
    ensure_eq!(
        (swept.status.as_str(), swept.error.as_deref(), swept.deadline_at),
        ("failed", Some("abandoned"), None),
        "settled by the sweep"
    );

    ReviewRepository::settle(tx, awaited, "completed", Some("## A01"), None).await.map_err(err)?;
    let settled = ReviewRepository::find_by_id(tx, awaited).await.map_err(err)?.unwrap();
    ensure_eq!(
        (settled.status.as_str(), settled.response.as_deref(), settled.deadline_at),
        ("completed", Some("## A01"), None),
        "settled by its request"
    );
    ensure_eq!(
        ReviewRepository::settle_abandoned(tx, "running", "failed", "abandoned", at(1_000)).await.map_err(err)?,
        0,
        "a settled report is not swept"
    );
    ensure_eq!(ReviewRepository::delete_by_scan_ids(tx, &[]).await.map_err(err)?, 0, "no scan");
    ensure_eq!(ReviewRepository::delete_by_scan_ids(tx, &[SCAN_A]).await.map_err(err)?, 3, "the scan's reports");
    Ok(())
}

fn week_row(week: i64, kind: &str, id: i64, category: &str, state: &str, open: i64, captured: i64) -> WeeklyRow {
    WeeklyRow {
        week_start: at(week),
        target_kind: kind.to_owned(),
        target_id: id,
        category: category.to_owned(),
        state: state.to_owned(),
        open_count: open,
        settled_count: 1,
        captured_at: at(captured),
    }
}

async fn the_weekly_record_is_gated_rewritten_and_purged_by_week(tx: &mut Tx) -> Check {
    let err = |e: crate::persistence::StoreError| e.to_string();
    ensure_eq!(WeeklyRepository::newest_capture_of(tx, at(0)).await.map_err(err)?, None, "an unwritten week");
    WeeklyRepository::insert_all(
        tx,
        &[
            week_row(0, "repository", REPO_A, "A06", "FINDINGS", 3, 5),
            week_row(0, "container", IMAGE_A, "A06", "NO_FINDING", 0, 7),
            week_row(100, "repository", REPO_A, "A06", "FINDINGS", 2, 105),
            week_row(200, "repository", REPO_B, "A03", "NOT_MEASURED", 0, 205),
        ],
    )
    .await
    .map_err(err)?;
    WeeklyRepository::insert_all(tx, &[]).await.map_err(err)?;
    ensure_eq!(WeeklyRepository::newest_capture_of(tx, at(0)).await.map_err(err)?, Some(at(7)), "the week's newest");
    ensure_eq!(
        WeeklyRepository::targets(tx).await.map_err(err)?,
        vec![
            WeeklyTarget { kind: "container".into(), id: IMAGE_A },
            WeeklyTarget { kind: "repository".into(), id: REPO_A },
            WeeklyTarget { kind: "repository".into(), id: REPO_B },
        ],
        "every target once"
    );
    ensure_eq!(WeeklyRepository::delete_week(tx, at(100)).await.map_err(err)?, 1, "one week, never another's");
    ensure_eq!(WeeklyRepository::delete_by_target(tx, "repository", REPO_B).await.map_err(err)?, 1, "a target's rows");
    ensure_eq!(WeeklyRepository::delete_by_target(tx, "container", REPO_A).await.map_err(err)?, 0, "kind and id");
    ensure_eq!(WeeklyRepository::delete_weeks_before(tx, at(0)).await.map_err(err)?, 0, "the boundary week stays");
    ensure_eq!(WeeklyRepository::delete_weeks_before(tx, at(1)).await.map_err(err)?, 2, "weeks before");
    Ok(())
}

async fn a_reader_sums_only_the_weeks_of_its_own_targets(tx: &mut Tx) -> Check {
    let err = |e: crate::persistence::StoreError| e.to_string();
    WeeklyRepository::insert_all(
        tx,
        &[
            week_row(0, "repository", REPO_A, "A06", "FINDINGS", 3, 5),
            week_row(0, "repository", REPO_B, "A06", "FINDINGS", 4, 9),
            week_row(0, "container", IMAGE_A, "A06", "FINDINGS", 5, 6),
            // An image carrying a repository's number: matched by its own kind only.
            week_row(0, "container", REPO_A, "A06", "FINDINGS", 100, 6),
            week_row(0, "repository", REPO_A, "A03", "NO_FINDING", 0, 5),
            week_row(100, "repository", REPO_A, "A06", "FINDINGS", 2, 105),
            week_row(300, "repository", REPO_A, "A06", "FINDINGS", 2, 305),
        ],
    )
    .await
    .map_err(err)?;
    let sum = |week: i64, category: &str, state: &str, targets: i64, open: i64, captured: i64| WeeklyStateCount {
        week_start: at(week),
        category: category.to_owned(),
        state: state.to_owned(),
        targets,
        open,
        settled: targets,
        captured_at: at(captured),
    };
    let sorted = |mut rows: Vec<WeeklyStateCount>| {
        rows.sort_by(|a, b| (a.week_start, &a.category).cmp(&(b.week_start, &b.category)));
        rows
    };
    let reader = Visibility::only([ScanTarget::Repository(REPO_A), ScanTarget::Container(IMAGE_A)]);
    ensure_eq!(
        sorted(WeeklyRepository::sum_by_week(tx, at(0), at(100), &reader).await.map_err(err)?),
        vec![
            sum(0, "A03", "NO_FINDING", 1, 0, 5),
            sum(0, "A06", "FINDINGS", 2, 8, 6),
            sum(100, "A06", "FINDINGS", 1, 2, 105)
        ],
        "a reader's two targets, both ends of the range included"
    );
    ensure_eq!(
        sorted(WeeklyRepository::sum_by_week(tx, at(0), at(0), &Visibility::everything()).await.map_err(err)?),
        vec![sum(0, "A03", "NO_FINDING", 1, 0, 5), sum(0, "A06", "FINDINGS", 4, 112, 9)],
        "the estate"
    );
    ensure_eq!(
        WeeklyRepository::sum_by_week(tx, at(0), at(300), &Visibility::only([])).await.map_err(err)?,
        vec![],
        "a reader who sees nothing reads no row"
    );
    Ok(())
}

/// The three purge listeners in a deletion's transaction, and what the two retention tasks run: the weekly record cut
/// at the Monday of the cutoff's week, the abandoned reports settled. Committed, so last.
async fn the_purges_and_the_tasks_take_their_rows(db: &Db) -> Check {
    use crate::internal::tasks::{ABANDONED, purge_weeks_ended_before, settle_abandoned};
    use crate::purge::{ReviewPurge, WeeklyCoveragePurge, WeeklyCoverageSweep};
    use vectispire_cp_targets::{PurgeListener, TargetPurge};
    let err = |e: crate::persistence::StoreError| e.to_string();
    const MONDAY: i64 = 1_767_571_200; // 2026-01-05, 00:00 UTC
    const WEEK: i64 = 7 * 24 * 3600;
    let monday = |weeks: i64| OffsetDateTime::from_unix_timestamp(MONDAY + weeks * WEEK).unwrap();
    let row = |weeks: i64, kind: &str, id: i64| WeeklyRow {
        week_start: monday(weeks),
        target_kind: kind.to_owned(),
        target_id: id,
        category: "A06".to_owned(),
        state: "FINDINGS".to_owned(),
        open_count: 1,
        settled_count: 0,
        captured_at: monday(weeks),
    };

    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    WeeklyRepository::insert_all(
        &mut tx,
        &[
            row(0, "repository", REPO_A),
            row(0, "repository", REPO_B),
            row(0, "container", IMAGE_A),
            row(0, "repository", 999),
            row(0, "galaxy", 7),
            row(1, "repository", REPO_A),
            row(2, "repository", REPO_A),
        ],
    )
    .await
    .map_err(err)?;
    let report = ReviewRepository::insert(&mut tx, &review(0, "completed", None)).await.map_err(err)?;
    tx.commit().await.map_err(|e| e.to_string())?;

    let names = |rows: Vec<WeeklyTarget>| rows.into_iter().map(|t| (t.kind, t.id)).collect::<Vec<_>>();
    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    WeeklyCoveragePurge
        .purge(&mut tx, &TargetPurge::Deleted(ScanTarget::Repository(REPO_B)))
        .await
        .map_err(|e| e.to_string())?;
    WeeklyCoveragePurge.purge(&mut tx, &TargetPurge::Orphans).await.map_err(|e| e.to_string())?;
    WeeklyCoverageSweep
        .purge(&mut tx, &TargetPurge::Deleted(ScanTarget::Repository(REPO_A)))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(
        names(WeeklyRepository::targets(&mut tx).await.map_err(err)?),
        vec![
            ("container".to_owned(), IMAGE_A),
            ("galaxy".to_owned(), 7),
            ("repository".to_owned(), REPO_A),
            ("repository".to_owned(), 999),
        ],
        "a deleted target's rows, and only on its deletion"
    );
    WeeklyCoverageSweep.purge(&mut tx, &TargetPurge::Orphans).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        names(WeeklyRepository::targets(&mut tx).await.map_err(err)?),
        vec![("container".to_owned(), IMAGE_A), ("galaxy".to_owned(), 7), ("repository".to_owned(), REPO_A)],
        "the sweep: a missing target's rows; an unknown kind left alone"
    );
    ReviewPurge
        .purge(&mut tx, &TargetPurge::Deleted(ScanTarget::Repository(REPO_B)))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(ReviewRepository::find_by_id(&mut tx, report).await.map_err(err)?.is_some(), true, "another's scans");
    ReviewPurge
        .purge(&mut tx, &TargetPurge::Deleted(ScanTarget::Repository(REPO_A)))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(ReviewRepository::find_by_id(&mut tx, report).await.map_err(err)?, None, "the target's scans' reports");
    tx.commit().await.map_err(|e| e.to_string())?;

    // A cutoff on the Wednesday of week 1: week 0 goes, week 1 stays whole.
    let wednesday = monday(1) + Duration::days(2) + Duration::hours(5);
    ensure_eq!(purge_weeks_ended_before(db, wednesday).await.map_err(err)?, 3, "the weeks before the cutoff's");
    let mut tx = db.begin(Mode::ReadOnly).await.map_err(|e| e.to_string())?;
    ensure_eq!(WeeklyRepository::newest_capture_of(&mut tx, monday(1)).await.map_err(err)?, Some(monday(1)), "kept");
    tx.commit().await.map_err(|e| e.to_string())?;
    ensure_eq!(purge_weeks_ended_before(db, monday(2)).await.map_err(err)?, 1, "a Monday is its own week");

    let mut tx = db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())?;
    let stale = ReviewRepository::insert(&mut tx, &review(0, "running", Some(10))).await.map_err(err)?;
    tx.commit().await.map_err(|e| e.to_string())?;
    ensure_eq!(settle_abandoned(db, at(20)).await.map_err(err)?, 1, "settled");
    let mut tx = db.begin(Mode::ReadOnly).await.map_err(|e| e.to_string())?;
    let swept = ReviewRepository::find_by_id(&mut tx, stale).await.map_err(err)?.unwrap();
    tx.commit().await.map_err(|e| e.to_string())?;
    ensure_eq!((swept.status.as_str(), swept.error.as_deref()), ("failed", Some(ABANDONED)), "with Java's sentence");
    Ok(())
}

async fn the_entities_agree_with_the_schema(db: &Db) -> Check {
    let tables = crate::persistence::entities::tables()?;
    parity::check_entities(db, &tables).await.map_err(|error| error.to_string())
}
