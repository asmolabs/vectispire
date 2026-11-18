//! What `checklists` measures with, read through [`ScanCatalog`] itself — Java's `ScanCatalog.newestExamining`,
//! `completedWithin`, `pluginRunsWithin`, `namingPluginBefore` and `languagesOf` — on a database of its own, since the
//! catalogue reads in a transaction of its own and the persistence suite rolls its rows back. Here rather than beside
//! the statements: the persistence layer reaches nothing above it, and these are the catalogue's answers.
//!
//! The scans are laid out in three time bands so that one reading never counts another's rows: the plugin runs from
//! 10 s, the languages at 50 s, the examined types from 100 s.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_scanning::catalog::{ExaminingScanRow, RecordedLanguages, ScansWithin};
use vectispire_cp_scanning::{ScanCatalog, StoreError};
use vectispire_cp_targets::SystemClock;
use vectispire_domain::FindingType;
use vectispire_domain::language::Language;

use support::{Migrated, count, exec, literal, repository};

type Check = Result<(), String>;

macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($what:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!("{}: {:?} != {:?}", format!($($what)+), left, right));
        }
    }};
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_each_engine() {
    for engine in Engine::ALL.into_iter().filter(|engine| vectispire_cp_db::testing::runs_on(*engine)) {
        let database = Migrated::start(engine).await;
        let db = database.connect().await;
        let outcome = the_checklist_readings_answer_as_java_does(&db).await;
        db.close().await;
        if let Err(failure) = outcome {
            panic!("{engine}: {failure}");
        }
    }
}

fn at(seconds: i64) -> OffsetDateTime {
    to_microseconds(
        OffsetDateTime::from_unix_timestamp(1_760_000_000 + seconds).unwrap() + Duration::microseconds(123_456),
    )
}

/// A scan of `repo` in `status`, with the recorded columns a result writes — inserted whole: the scans' own statements
/// are the persistence suite's to judge, not this one's.
#[allow(clippy::too_many_arguments)]
async fn scan(
    db: &Db,
    repo: i64,
    status: &str,
    seconds: i64,
    sbom: Option<&str>,
    examined: Option<&str>,
    plugin_steps: Option<&str>,
    detected: Option<&str>,
) -> i64 {
    let text = |value: Option<&str>| value.map_or("null".to_owned(), |value| format!("'{value}'"));
    exec(
        db,
        &format!(
            "insert into t_scan (branch, status, created_at, repo_id, attempts, findings_count, new_issues_count, \
             resolved_issues_count, duration_ms, sbom, examined_types, plugin_steps, detected_languages) values \
             ('main', '{status}', {}, {repo}, 0, 0, 0, 0, 1000, {}, {}, {}, {})",
            literal(at(seconds)),
            text(sbom),
            text(examined),
            text(plugin_steps),
            text(detected)
        ),
    )
    .await;
    count(db, "select max(id) from t_scan").await
}

/// `recordSastLanguages`: the languages the Semgrep rules of a scan's task read.
async fn sast_languages(db: &Db, id: i64, column: &str) {
    exec(db, &format!("update t_scan set sast_languages = '{column}' where id = {id}")).await;
}

/// A run as the check compares it: the scan, then the outcome's state, refusal and manifest digest.
type RunSummary = (i64, Option<String>, Option<String>, Option<String>);

fn languages(names: &[&str]) -> BTreeSet<Language> {
    names.iter().filter_map(|name| Language::from_wire_name(name)).collect()
}

#[allow(clippy::too_many_lines)]
async fn the_checklist_readings_answer_as_java_does(db: &Db) -> Check {
    let (a, b) = (repository(db, "checklist-a").await, repository(db, "checklist-b").await);

    // The plugin runs. `java-arch` must not answer for `java`; an id inside another field is no outcome of it.
    let java = |state: &str, extra: &str| {
        format!(r#"[{{"pluginId":"java","manifestDigest":"sha256:j","state":"{state}"{extra}}}]"#)
    };
    scan(db, a, "completed", 10, None, None, Some(&java("produced", "")), None).await;
    let produced = scan(db, a, "completed", 11, None, None, Some(&java("produced", r#","findings":3"#)), None).await;
    scan(db, a, "completed", 12, None, None, Some(r#"[{"pluginId":"java-arch","state":"absent"}]"#), None).await;
    let refused =
        scan(db, a, "completed", 13, None, None, Some(&java("refused", r#","refusal":"unsigned""#)), None).await;
    let accidental = r#"[{"pluginId":"other","state":"produced","note":{"pluginId":"java"}}]"#;
    scan(db, a, "completed", 14, None, None, Some(accidental), None).await;
    scan(db, a, "failed", 15, None, None, Some(&java("absent", "")), None).await;
    scan(db, a, "completed", 16, None, None, Some(r#"[{"pluginId":"kotlin","state":"produced"},null]"#), None).await;
    let skipped =
        scan(db, b, "completed", 12, None, None, Some(&java("not_applicable", r#","languages":["java"]"#)), None).await;

    // The languages: recorded, recorded and none, never recorded, and a name this version does not know.
    let both = scan(db, a, "completed", 50, None, None, None, Some("java,python")).await;
    sast_languages(db, both, "java").await;
    let census_empty = scan(db, a, "completed", 50, None, None, None, Some("")).await;
    let unrecorded = scan(db, a, "completed", 50, None, None, None, None).await;
    let unknown = scan(db, a, "completed", 50, None, None, None, Some(" Java ,cobol")).await;
    sast_languages(db, unknown, "").await;

    // The examined types: `sast` in a list, a failed scan, an unrecorded one, and `sastx`, which is not `sast`.
    scan(db, a, "completed", 101, Some("{}"), Some("iac,sast"), None, None).await;
    let a_sast = scan(db, a, "completed", 102, None, Some("sast,secret"), None, None).await;
    scan(db, a, "completed", 103, None, None, None, None).await;
    scan(db, a, "failed", 104, None, Some("sast"), None, None).await;
    let a_iac = scan(db, a, "completed", 105, None, Some("iac"), None, None).await;
    let b_old = scan(db, b, "completed", 100, Some("{}"), Some("sast"), None, None).await;
    scan(db, b, "completed", 106, None, Some(""), None, None).await;
    scan(db, b, "completed", 107, None, Some("sastx"), None, None).await;

    let catalog = ScanCatalog::new(db.clone(), Arc::new(SystemClock));
    let fail = |e: StoreError| e.to_string();

    // newestExamining
    let read = catalog.newest_examining(&[a, b, a], FindingType::Sast, at(101)).await.map_err(fail)?;
    let row = |repository_id, scan_id, seconds, sbom_stored| ExaminingScanRow {
        repository_id,
        scan_id,
        created_at: at(seconds),
        sbom_stored,
    };
    ensure_eq!(
        read,
        BTreeMap::from([(a, row(a, a_sast, 102, false))]),
        "the newest completed scan recording sast; a failed, an unrecorded and a `sastx` one are not it"
    );
    let read = catalog.newest_examining(&[a, b], FindingType::Sast, at(100)).await.map_err(fail)?;
    ensure_eq!(
        read,
        BTreeMap::from([(a, row(a, a_sast, 102, false)), (b, row(b, b_old, 100, true))]),
        "`since` is inclusive, and the SBOM's presence is read"
    );
    let read = catalog.newest_examining(&[a, b], FindingType::Iac, at(101)).await.map_err(fail)?;
    ensure_eq!(read, BTreeMap::from([(a, row(a, a_iac, 105, false))]), "another type, another scan");
    let read = catalog.newest_examining(&[], FindingType::Sast, at(0)).await.map_err(fail)?;
    ensure_eq!(read.len(), 0, "no repository, no statement and no answer");
    for refused_type in [FindingType::Plugin, FindingType::Imported, FindingType::AiReview] {
        let refused = catalog.newest_examining(&[a], refused_type, at(0)).await;
        ensure_eq!(refused.is_err(), true, "{} is examined by no built-in step: refused", refused_type.wire_name());
    }

    // completedWithin
    let read = catalog.completed_within(&[a, b, b], at(101)).await.map_err(fail)?;
    ensure_eq!(
        read,
        BTreeMap::from([
            (a, ScansWithin { repository_id: a, completed: 4, unrecorded: 1 }),
            (b, ScansWithin { repository_id: b, completed: 2, unrecorded: 0 }),
        ]),
        "completed scans within the age, the unrecorded apart; the empty set is recorded"
    );
    let read = catalog.completed_within(&[a, b], at(108)).await.map_err(fail)?;
    ensure_eq!(read.len(), 0, "a repository with no scan within the age is absent, not zero");

    // pluginRunsWithin
    let read = catalog.plugin_runs_within(&[a, b], "java", at(11)).await.map_err(fail)?;
    let summary: BTreeMap<i64, Vec<RunSummary>> = read
        .iter()
        .map(|(repository, runs)| {
            let runs = runs
                .iter()
                .map(|run| {
                    (
                        run.scan_id,
                        run.outcome.state.clone(),
                        run.outcome.refusal.clone(),
                        run.outcome.manifest_digest.clone(),
                    )
                })
                .collect();
            (*repository, runs)
        })
        .collect();
    let some = |text: &str| Some(text.to_owned());
    ensure_eq!(
        summary,
        BTreeMap::from([
            (
                a,
                vec![
                    (refused, some("refused"), some("unsigned"), some("sha256:j")),
                    (produced, some("produced"), None, some("sha256:j")),
                ]
            ),
            (b, vec![(skipped, some("not_applicable"), None, some("sha256:j"))]),
        ]),
        "newest first; `java-arch`, an accidental match, a failed scan and an older one are left out"
    );
    let first = read.get(&a).and_then(|runs| runs.first()).map(|run| (run.repository_id, run.created_at));
    ensure_eq!(first, Some((a, at(13))), "a run carries its repository and its scan's instant");
    // Past one batch, a repository named at both ends still has each run once: the list is made distinct first.
    let wide: Vec<i64> = std::iter::once(b).chain(1_000_000..1_001_000).chain(std::iter::once(b)).collect();
    let read = catalog.plugin_runs_within(&wide, "java", at(11)).await.map_err(fail)?;
    ensure_eq!(read.get(&b).map(Vec::len), Some(1), "a repository in two batches, its run read once");
    let read = catalog.plugin_runs_within(&[a, b], "absent-plugin", at(0)).await.map_err(fail)?;
    ensure_eq!(read.len(), 0, "a plugin no scan names: every repository absent");
    let null = catalog.plugin_runs_within(&[a], "kotlin", at(0)).await;
    ensure_eq!(null.is_err(), true, "a null outcome fails the reading, as Java's List.copyOf does");
    for id in ["", "Java", "a%b", "a_b", "x\"y"] {
        let refused = catalog.plugin_runs_within(&[a], id, at(0)).await;
        ensure_eq!(refused.is_err(), true, "{id:?} is not a plugin id: refused before any statement");
    }

    // namingPluginBefore
    let read = catalog.naming_plugin_before(&[a, b], "java", at(11)).await.map_err(fail)?;
    ensure_eq!(read, BTreeSet::from([a]), "a completed scan strictly before, naming the plugin");
    let read = catalog.naming_plugin_before(&[a, b], "java", at(10)).await.map_err(fail)?;
    ensure_eq!(read, BTreeSet::new(), "strictly before: the scan at the instant itself is not");
    let read = catalog.naming_plugin_before(&[a, b], "java", at(13)).await.map_err(fail)?;
    ensure_eq!(read, BTreeSet::from([a, b]), "each repository once");
    ensure_eq!(catalog.naming_plugin_before(&[a], "J", at(13)).await.is_err(), true, "an id with a capital: refused");

    // languagesOf
    let gone = unknown.saturating_add(1_000_000);
    let read = catalog.languages_of(&[both, census_empty, unrecorded, unknown, gone, both]).await.map_err(fail)?;
    ensure_eq!(
        read,
        BTreeMap::from([
            (
                both,
                RecordedLanguages {
                    detected: Some(languages(&["java", "python"])),
                    sast_rules: Some(languages(&["java"]))
                }
            ),
            (census_empty, RecordedLanguages { detected: Some(BTreeSet::new()), sast_rules: None }),
            (unrecorded, RecordedLanguages { detected: None, sast_rules: None }),
            (unknown, RecordedLanguages { detected: Some(languages(&["java"])), sast_rules: Some(BTreeSet::new()) }),
        ]),
        "absent and empty kept apart; a name this version does not know left out; a scan that does not exist absent"
    );
    Ok(())
}
