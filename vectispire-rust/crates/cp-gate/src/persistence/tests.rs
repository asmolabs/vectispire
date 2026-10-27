//! The gate's repositories on real servers, both engines: every statement they write, run once, its answer held to
//! what the Java side's `GatePolicyRepository` and `GateVerdictRepository` answer.
//!
//! **Written before the repositories were rewritten on SeaORM** (2026-10-27), so that one suite judges both
//! versions: until then the module's twelve statements were run by nothing but the route tests. The register's
//! reads change signature in the port — a [`Visibility`] instead of two id lists — so the checks reach them through
//! [`register`], and only that adapter differs between the two versions.
//!
//! Every check runs, and the failures are reported together.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;

use self::support::Migrated;
use crate::persistence::repository::{GatePolicyRepository, GateVerdictRepository};
use crate::persistence::{GatePolicyRow, GateVerdictRow, NewGatePolicyRow};
use time::{Duration, OffsetDateTime};
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Engine, Mode, ScanTarget, Tx, Visibility};

const REPO_A: i64 = 101;
const REPO_B: i64 = 102;
const IMAGE_A: i64 = 201;
const IMAGE_B: i64 = 202;

#[test]
fn on_mysql() {
    run(Engine::MySql);
}

#[test]
fn on_postgresql() {
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
            a_policy_reads_back_every_flag_it_was_written_with,
            a_new_version_supersedes_the_active_one_and_keeps_the_old,
            a_scope_s_policies_are_deleted_with_it_and_only_its,
            a_verdict_reads_back_what_was_written,
            the_register_pages_by_instant_then_id_and_loses_no_tie,
            a_restricted_reader_pages_only_through_its_own_targets,
            the_newest_verdicts_come_first_and_bounded,
            a_target_s_last_verdict_is_found_inside_its_window,
            the_purge_drops_only_what_is_older_than_the_cutoff,
        );
        db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

/// Two repositories and two images, fixed ids, for PostgreSQL's foreign keys.
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
    for id in [IMAGE_A, IMAGE_B] {
        server.sql_as_admin(&format!(
            "insert into t_container (id, image_name, tag){overriding} values ({id}, 'registry.example/i{id}', 'v1')"
        ));
    }
}

fn at(seconds: i64) -> OffsetDateTime {
    to_microseconds(
        OffsetDateTime::from_unix_timestamp(1_760_000_000 + seconds).unwrap() + Duration::microseconds(123_456),
    )
}

/// The register as the service reads it: everything, or a restricted reader's targets — the one place the two
/// versions of the repository differ.
async fn register(
    tx: &mut Tx,
    visibility: &Visibility,
    after: Option<(OffsetDateTime, &str)>,
    limit: i32,
) -> Result<Vec<GateVerdictRow>, String> {
    let read = match visibility {
        Visibility::Everything => match after {
            Some((at, id)) => GateVerdictRepository::page_after(tx, at, id, limit).await,
            None => GateVerdictRepository::first_page(tx, limit).await,
        },
        Visibility::Only(targets) => {
            let mut repo_ids = vec![-1i64];
            let mut container_ids = vec![-1i64];
            for target in targets {
                match target {
                    ScanTarget::Repository(id) => repo_ids.push(*id),
                    ScanTarget::Container(id) => container_ids.push(*id),
                }
            }
            match after {
                Some((at, id)) => {
                    GateVerdictRepository::page_after_within(tx, &repo_ids, &container_ids, at, id, limit).await
                }
                None => GateVerdictRepository::first_page_within(tx, &repo_ids, &container_ids, limit).await,
            }
        }
    };
    read.map_err(|error| error.to_string())
}

fn policy(kind: &str, target_id: i64, version: i32, flags: bool) -> NewGatePolicyRow {
    NewGatePolicyRow {
        target_kind: kind.into(),
        target_id,
        version,
        is_active: Some(true),
        fail_on_severity: flags.then(|| "HIGH".to_owned()),
        fail_on_kev: flags,
        fixable_only: flags,
        include_triaged: flags,
        include_ai_review: flags,
        fail_on_uncovered_languages: flags,
        include_plugins: flags,
        note: flags.then(|| "kept for the audit".to_owned()),
        created_by: flags.then(|| "alice".to_owned()),
        created_at: at(version.into()),
    }
}

/// A verdict on `repo` or `image` (or both, or neither), decided at `seconds`, its id chosen so that ties order.
fn verdict(id: &str, repo: Option<i64>, image: Option<i64>, seconds: i64) -> GateVerdictRow {
    GateVerdictRow {
        id: id.into(),
        repo_id: repo,
        container_id: image,
        passed: seconds % 2 == 0,
        evaluated: 12,
        violations: 3,
        critical_count: 1,
        high_count: 2,
        medium_count: 0,
        low_count: 4,
        fail_on_severity: Some("HIGH".into()),
        policy_source: "global".into(),
        policy_version: Some(7),
        relaxations_ignored: seconds % 3 == 0,
        decided_at: at(seconds),
        decided_by: Some("ci-bot".into()),
        ip_address: Some("192.0.2.7".into()),
    }
}

/// Every id is a UUID's shape, as the gate writes them; the leading digits give the order inside one instant.
fn uuid(n: u8) -> String {
    format!("{n:08x}-0000-4000-8000-000000000000")
}

async fn insert_verdicts(tx: &mut Tx, rows: &[GateVerdictRow]) -> Check {
    for row in rows {
        GateVerdictRepository::insert(tx, row).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn ids(rows: &[GateVerdictRow]) -> Vec<String> {
    rows.iter().map(|row| row.id.clone()).collect()
}

async fn active(tx: &mut Tx) -> Result<Vec<GatePolicyRow>, String> {
    let mut rows = GatePolicyRepository::find_active(tx).await.map_err(|e| e.to_string())?;
    rows.sort_by(|a, b| (&a.target_kind, a.target_id).cmp(&(&b.target_kind, b.target_id)));
    Ok(rows)
}

/// MySQL keeps four of these flags as `bit(1)` and three as `tinyint(1)`: every one read back true, and every one
/// false, so that a flag decoded as "false whatever it holds" cannot pass — that is a gate relaxed in silence.
async fn a_policy_reads_back_every_flag_it_was_written_with(tx: &mut Tx) -> Check {
    for (target_id, flags) in [(REPO_A, true), (REPO_B, false)] {
        let new = policy("repository", target_id, 1, flags);
        let id = GatePolicyRepository::insert(tx, &new).await.map_err(|e| e.to_string())?;
        if id <= 0 {
            return Err(format!("a generated key: {id}"));
        }
        let read = active(tx).await?;
        let row = read.iter().find(|row| row.id == id).ok_or(format!("policy {id} is not active"))?;
        let expected = GatePolicyRow {
            id,
            target_kind: new.target_kind.clone(),
            target_id: new.target_id,
            version: new.version,
            is_active: new.is_active,
            fail_on_severity: new.fail_on_severity.clone(),
            fail_on_kev: new.fail_on_kev,
            fixable_only: new.fixable_only,
            include_triaged: new.include_triaged,
            include_ai_review: new.include_ai_review,
            fail_on_uncovered_languages: new.fail_on_uncovered_languages,
            include_plugins: new.include_plugins,
            note: new.note.clone(),
            created_by: new.created_by.clone(),
            created_at: new.created_at,
        };
        ensure_eq!(*row, expected, "the policy written with every flag {flags}");
    }
    Ok(())
}

async fn a_new_version_supersedes_the_active_one_and_keeps_the_old(tx: &mut Tx) -> Check {
    let highest = GatePolicyRepository::highest_version(tx, "repository", REPO_A).await.map_err(|e| e.to_string())?;
    ensure_eq!(highest, 0, "the highest version of a scope that has none");

    GatePolicyRepository::insert(tx, &policy("repository", REPO_A, 1, true)).await.map_err(|e| e.to_string())?;
    GatePolicyRepository::insert(tx, &policy("container", REPO_A, 1, false)).await.map_err(|e| e.to_string())?;
    let superseded = GatePolicyRepository::supersede(tx, "repository", REPO_A).await.map_err(|e| e.to_string())?;
    ensure_eq!(superseded, 1, "the rows supersede touched");
    let again = GatePolicyRepository::supersede(tx, "repository", REPO_A).await.map_err(|e| e.to_string())?;
    ensure_eq!(again, 0, "a scope with nothing active supersedes nothing");
    let second =
        GatePolicyRepository::insert(tx, &policy("repository", REPO_A, 2, false)).await.map_err(|e| e.to_string())?;

    let highest = GatePolicyRepository::highest_version(tx, "repository", REPO_A).await.map_err(|e| e.to_string())?;
    ensure_eq!(highest, 2, "the highest version counts the superseded one");
    let read = active(tx).await?;
    let scopes: Vec<(String, i64, i32)> =
        read.iter().map(|row| (row.target_kind.clone(), row.target_id, row.version)).collect();
    // The same target id under the other kind is another scope, untouched.
    ensure_eq!(
        scopes,
        vec![("container".to_owned(), REPO_A, 1), ("repository".to_owned(), REPO_A, 2)],
        "the active policies"
    );
    ensure_eq!(read[1].id, second, "the active repository policy is the new one");
    Ok(())
}

async fn a_scope_s_policies_are_deleted_with_it_and_only_its(tx: &mut Tx) -> Check {
    GatePolicyRepository::insert(tx, &policy("repository", REPO_B, 1, true)).await.map_err(|e| e.to_string())?;
    GatePolicyRepository::supersede(tx, "repository", REPO_B).await.map_err(|e| e.to_string())?;
    GatePolicyRepository::insert(tx, &policy("repository", REPO_B, 2, true)).await.map_err(|e| e.to_string())?;
    GatePolicyRepository::insert(tx, &policy("container", IMAGE_B, 1, true)).await.map_err(|e| e.to_string())?;
    let deleted = GatePolicyRepository::delete_by_target(tx, "repository", REPO_B).await.map_err(|e| e.to_string())?;
    ensure_eq!(deleted, 2, "both versions of the repository's policy, the superseded one too");
    let left = GatePolicyRepository::highest_version(tx, "repository", REPO_B).await.map_err(|e| e.to_string())?;
    ensure_eq!(left, 0, "nothing left of the repository's scope");
    let read = active(tx).await?;
    ensure_eq!(read.len(), 1, "the image's policy stays");
    Ok(())
}

async fn a_verdict_reads_back_what_was_written(tx: &mut Tx) -> Check {
    let mut refused = verdict(&uuid(1), Some(REPO_A), None, 3);
    refused.passed = false;
    refused.relaxations_ignored = true;
    let mut passed = verdict(&uuid(2), None, Some(IMAGE_A), 4);
    passed.passed = true;
    passed.relaxations_ignored = false;
    passed.fail_on_severity = None;
    passed.policy_version = None;
    passed.decided_by = None;
    passed.ip_address = None;
    insert_verdicts(tx, &[refused.clone(), passed.clone()]).await?;
    let read = register(tx, &Visibility::Everything, None, 10).await?;
    ensure_eq!(read, vec![passed, refused], "the verdicts, newest first, every column");
    Ok(())
}

/// Seven verdicts, three of them in one instant: walked two by two, every row comes back once, in
/// `decided_at desc, id desc` — Java's `firstPage` and `pageAfter`.
async fn the_register_pages_by_instant_then_id_and_loses_no_tie(tx: &mut Tx) -> Check {
    let rows = vec![
        verdict(&uuid(1), Some(REPO_A), None, 10),
        verdict(&uuid(2), Some(REPO_A), None, 20),
        verdict(&uuid(3), None, Some(IMAGE_A), 20),
        verdict(&uuid(4), Some(REPO_B), None, 20),
        verdict(&uuid(5), Some(REPO_B), None, 30),
        verdict(&uuid(6), None, Some(IMAGE_B), 5),
        verdict(&uuid(7), None, None, 40),
    ];
    insert_verdicts(tx, &rows).await?;
    let expected: Vec<String> = [7, 5, 4, 3, 2, 1, 6].into_iter().map(uuid).collect();
    let mut walked = Vec::new();
    let mut cursor: Option<(OffsetDateTime, String)> = None;
    for _ in 0..10 {
        let page = register(tx, &Visibility::Everything, cursor.as_ref().map(|(at, id)| (*at, id.as_str())), 2).await?;
        let Some(last) = page.last() else { break };
        cursor = Some((last.decided_at, last.id.clone()));
        walked.extend(ids(&page));
    }
    ensure_eq!(walked, expected, "the register walked two by two");
    Ok(())
}

/// Java's `WITHIN`: a row's target is its repository when it names one, its image otherwise. A row naming both
/// belongs to the repository — a reader of the image does not see it, and no cursor of theirs names it.
async fn a_restricted_reader_pages_only_through_its_own_targets(tx: &mut Tx) -> Check {
    let rows = vec![
        verdict(&uuid(1), Some(REPO_A), None, 10),
        verdict(&uuid(2), None, Some(IMAGE_A), 20),
        verdict(&uuid(3), Some(REPO_B), Some(IMAGE_A), 30),
        verdict(&uuid(4), None, Some(IMAGE_A), 30),
        verdict(&uuid(5), None, None, 40),
        verdict(&uuid(6), Some(REPO_A), None, 50),
    ];
    insert_verdicts(tx, &rows).await?;
    let only = |targets: &[ScanTarget]| Visibility::Only(targets.iter().copied().collect::<BTreeSet<_>>());

    let cases = [
        (only(&[ScanTarget::Container(IMAGE_A)]), vec![4, 2]),
        (only(&[ScanTarget::Repository(REPO_B)]), vec![3]),
        (only(&[ScanTarget::Repository(REPO_A), ScanTarget::Container(IMAGE_A)]), vec![6, 4, 2, 1]),
        (only(&[ScanTarget::Container(IMAGE_B)]), vec![]),
        (only(&[]), vec![]),
    ];
    for (visibility, expected) in cases {
        let expected: Vec<String> = expected.into_iter().map(uuid).collect();
        let first = register(tx, &visibility, None, 100).await?;
        ensure_eq!(ids(&first), expected, "{visibility:?}: one page");
        // One by one: every cursor names a row the reader may see, and the walk ends with them.
        let mut walked = Vec::new();
        let mut cursor: Option<(OffsetDateTime, String)> = None;
        for _ in 0..10 {
            let page = register(tx, &visibility, cursor.as_ref().map(|(at, id)| (*at, id.as_str())), 1).await?;
            let Some(last) = page.last() else { break };
            cursor = Some((last.decided_at, last.id.clone()));
            walked.extend(ids(&page));
        }
        ensure_eq!(walked, expected, "{visibility:?}: walked one by one");
    }
    Ok(())
}

async fn the_newest_verdicts_come_first_and_bounded(tx: &mut Tx) -> Check {
    insert_verdicts(
        tx,
        &[
            verdict(&uuid(1), Some(REPO_A), None, 10),
            verdict(&uuid(2), None, Some(IMAGE_A), 30),
            verdict(&uuid(3), Some(REPO_B), None, 20),
        ],
    )
    .await?;
    let read = GateVerdictRepository::newest(tx, 2).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&read), vec![uuid(2), uuid(3)], "the two newest");
    Ok(())
}

/// The verdict that judged a scan's backlog: the last one from the scan on, before the next scan if there is one —
/// `from` included, `until` excluded, and another target's verdicts never.
async fn a_target_s_last_verdict_is_found_inside_its_window(tx: &mut Tx) -> Check {
    insert_verdicts(
        tx,
        &[
            verdict(&uuid(1), Some(REPO_A), None, 10),
            verdict(&uuid(2), Some(REPO_A), None, 20),
            verdict(&uuid(3), Some(REPO_A), None, 30),
            verdict(&uuid(4), Some(REPO_B), None, 25),
            verdict(&uuid(5), None, Some(IMAGE_A), 20),
            verdict(&uuid(6), None, Some(IMAGE_A), 40),
        ],
    )
    .await?;
    let found = GateVerdictRepository::last_for_repository(tx, REPO_A, at(10), Some(at(30)))
        .await
        .map_err(|e| e.to_string())?
        .map(|row| row.id);
    ensure_eq!(found, Some(uuid(2)), "until is excluded");
    let found = GateVerdictRepository::last_for_repository(tx, REPO_A, at(20), None)
        .await
        .map_err(|e| e.to_string())?
        .map(|row| row.id);
    ensure_eq!(found, Some(uuid(3)), "no later scan: the newest from the scan on");
    let found = GateVerdictRepository::last_for_repository(tx, REPO_A, at(30), Some(at(31)))
        .await
        .map_err(|e| e.to_string())?
        .map(|row| row.id);
    ensure_eq!(found, Some(uuid(3)), "from is included");
    let found = GateVerdictRepository::last_for_repository(tx, REPO_A, at(31), None)
        .await
        .map_err(|e| e.to_string())?
        .map(|row| row.id);
    ensure_eq!(found, None, "nothing after the last verdict");
    let found = GateVerdictRepository::last_for_container(tx, IMAGE_A, at(0), Some(at(40)))
        .await
        .map_err(|e| e.to_string())?
        .map(|row| row.id);
    ensure_eq!(found, Some(uuid(5)), "the image's, inside its window");
    let found = GateVerdictRepository::last_for_container(tx, IMAGE_A, at(0), None)
        .await
        .map_err(|e| e.to_string())?
        .map(|row| row.id);
    ensure_eq!(found, Some(uuid(6)), "the image's newest");
    Ok(())
}

async fn the_purge_drops_only_what_is_older_than_the_cutoff(tx: &mut Tx) -> Check {
    insert_verdicts(
        tx,
        &[
            verdict(&uuid(1), Some(REPO_A), None, 10),
            verdict(&uuid(2), Some(REPO_A), None, 20),
            verdict(&uuid(3), None, Some(IMAGE_A), 30),
        ],
    )
    .await?;
    let deleted = GateVerdictRepository::delete_before(tx, at(20)).await.map_err(|e| e.to_string())?;
    ensure_eq!(deleted, 1, "strictly older than the cutoff");
    let read = register(tx, &Visibility::Everything, None, 10).await?;
    ensure_eq!(ids(&read), vec![uuid(3), uuid(2)], "what the purge kept");
    Ok(())
}
