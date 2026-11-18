//! Forges' statements on a real server: the five entities held to the migrated schema, the name's case-insensitive
//! uniqueness, the discovery queue's conditional updates (a take matches once, a write after it names its owner, a
//! lapsed run goes back or fails on its attempts), the snapshot's gone marks and their taking back, and a reading's
//! claim. Every check runs, and the failures are reported together.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use time::{Duration, OffsetDateTime};
use vectispire_cp_db::testing::TestDatabase as Migrated;
use vectispire_cp_db::{Engine, Mode, Tx, parity};

use super::*;

type Check = Result<(), String>;

macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($what:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!("{}: {:?} != {:?}", format!($($what)+), left, right));
        }
    }};
}

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

fn err(error: StoreError) -> String {
    error.to_string()
}

fn at(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000 + seconds).unwrap()
}

const CONNECTION: &str = "11111111-2222-3333-4444-555555555555";

fn connection_row(id: &str, name: &str) -> ConnectionRow {
    ConnectionRow {
        id: id.to_owned(),
        name: name.to_owned(),
        kind: "gitlab".into(),
        edition: "gitlab_self_managed".into(),
        base_url: "https://gitlab.example.org".into(),
        owner: None,
        internal_network: true,
        ca_pem: None,
        token: "sealed".into(),
        credential_kind: "gitlab_bot".into(),
        scopes: Some("read_api".into()),
        can_write: Some(false),
        token_expires_at: None,
        forge_version: Some("17.4.1".into()),
        probed_at: at(0),
        created_at: at(0),
        created_by: "admin".into(),
        updated_at: at(0),
        updated_by: "admin".into(),
    }
}

fn pending(requested: i64) -> DiscoveryRow {
    DiscoveryRow {
        id: 0,
        connection_id: CONNECTION.into(),
        state: "pending".into(),
        reason: None,
        detail: None,
        active_key: None,
        requested_at: at(requested),
        requested_by: "admin".into(),
        claimed_by: None,
        lease_expires_at: None,
        attempts: 0,
        started_at: None,
        finished_at: None,
        namespaces_seen: 0,
        repositories_seen: 0,
        repositories_skipped: 0,
        requests_made: 0,
        rate_limit_wait_seconds: 0,
        rate_limit_reset_at: None,
        new_count: None,
        changed_count: None,
        gone_count: None,
        unreadable_namespaces: None,
    }
}

fn listed(forge_id: &str, namespace: &str, by: i64) -> RepositoryRow {
    RepositoryRow {
        id: 0,
        connection_id: CONNECTION.into(),
        forge_id: forge_id.into(),
        full_path: format!("{namespace}/{forge_id}"),
        namespace_path: namespace.into(),
        personal: false,
        name: forge_id.into(),
        default_branch: Some("main".into()),
        archived: None,
        fork: None,
        visibility: None,
        last_activity_at: None,
        language: None,
        size_bytes: None,
        http_url: Some(format!("https://gitlab.example.org/{namespace}/{forge_id}.git")),
        ssh_url: None,
        web_url: None,
        first_seen_by: by,
        first_seen_at: at(0),
        last_seen_by: by,
        last_seen_at: at(0),
        changed_by: None,
        change_summary: None,
        gone_by: None,
        gone_at: None,
    }
}

fn run(engine: Engine) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = Migrated::start(engine).await;
        let db = server.connect().await;
        let mut failures = Vec::new();
        if let Err(failure) = parity::check_entities(&db, &entities::tables().unwrap()).await {
            failures.push(format!("the entities agree with the schema: {failure}"));
        }
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
            a_connection_reads_back_and_its_name_is_unique_case_aside,
            the_queue_takes_once_and_every_later_write_names_its_owner,
            a_lapsed_run_goes_back_until_its_attempts_are_spent,
            gone_is_marked_on_what_the_run_did_not_list_and_taken_back_where_it_could_not_read,
            a_reading_is_claimed_once_while_it_is_due,
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}

async fn a_connection_reads_back_and_its_name_is_unique_case_aside(tx: &mut Tx) -> Check {
    let row = connection_row(CONNECTION, "Internal GitLab");
    insert_connection(tx, &row).await.map_err(err)?;
    ensure_eq!(connection(tx, CONNECTION).await.map_err(err)?, Some(row.clone()), "read back");
    ensure_eq!(name_taken(tx, "INTERNAL gitlab", None).await.map_err(err)?, true, "taken, case aside");
    ensure_eq!(name_taken(tx, "internal gitlab", Some(CONNECTION)).await.map_err(err)?, false, "but by itself");
    ensure_eq!(name_taken(tx, "Other", None).await.map_err(err)?, false, "another name");
    let mut renamed = row.clone();
    renamed.name = "Renamed".into();
    update_connection(tx, &renamed).await.map_err(err)?;
    ensure_eq!(connections(tx).await.map_err(err)?, vec![renamed], "updated in place");
    ensure_eq!(count_links(tx, CONNECTION).await.map_err(err)?, 0, "no import yet");
    delete_connection(tx, CONNECTION).await.map_err(err)?;
    ensure_eq!(connection(tx, CONNECTION).await.map_err(err)?, None, "deleted");
    Ok(())
}

async fn the_queue_takes_once_and_every_later_write_names_its_owner(tx: &mut Tx) -> Check {
    insert_connection(tx, &connection_row(CONNECTION, "c")).await.map_err(err)?;
    let older = insert_discovery(tx, &pending(10)).await.map_err(err)?;
    let newer = insert_discovery(tx, &pending(20)).await.map_err(err)?;
    ensure_eq!(waiting(tx, "pending", &[], 8).await.map_err(err)?, vec![older, newer], "oldest first");
    ensure_eq!(waiting(tx, "pending", &["gitlab"], 8).await.map_err(err)?, Vec::<i64>::new(), "a suspended kind waits");
    ensure_eq!(count_waiting_on(tx, "pending", &["gitlab"]).await.map_err(err)?, 2, "counted on its kind");
    ensure_eq!(take(tx, older, "pending", "running", "a", at(30), at(210)).await.map_err(err)?, 1, "taken");
    ensure_eq!(take(tx, older, "pending", "running", "b", at(30), at(210)).await.map_err(err)?, 0, "once");
    let progress = Progress { namespaces: 2, repositories: 5, skipped: 1, requests: 9, waited: 3 };
    ensure_eq!(renew(tx, older, "running", "b", at(400), progress).await.map_err(err)?, 0, "not b's to renew");
    ensure_eq!(renew(tx, older, "running", "a", at(400), progress).await.map_err(err)?, 1, "a's");
    let ending = Ending {
        state: "completed".into(),
        reason: None,
        detail: None,
        finished_at: at(50),
        progress,
        reset_at: None,
        new_count: Some(5),
        changed_count: Some(0),
        gone_count: Some(0),
        unreadable: None,
    };
    ensure_eq!(finish(tx, older, "running", "b", &ending).await.map_err(err)?, 0, "not b's to finish");
    ensure_eq!(finish(tx, older, "running", "a", &ending).await.map_err(err)?, 1, "a's");
    let ended = discovery(tx, older).await.map_err(err)?.unwrap();
    ensure_eq!(
        (ended.state.as_str(), ended.attempts, ended.claimed_by, ended.repositories_seen, ended.new_count),
        ("completed", 1, None, 5, Some(5)),
        "ended with what it learnt"
    );
    ensure_eq!(
        discoveries_of(tx, CONNECTION, 1, 0).await.map_err(err)?.first().map(|run| run.id),
        Some(newer),
        "newest"
    );
    ensure_eq!(
        latest_discovery_in(tx, CONNECTION, &["completed", "partial"]).await.map_err(err)?.map(|run| run.id),
        Some(older),
        "the latest ended"
    );
    ensure_eq!(take(tx, newer, "pending", "running", "a", at(60), at(240)).await.map_err(err)?, 1, "taken");
    ensure_eq!(give_back(tx, newer, "running", "pending", "a").await.map_err(err)?, 1, "given back");
    ensure_eq!(discovery(tx, newer).await.map_err(err)?.unwrap().attempts, 0, "its attempt not counted");
    ensure_eq!(delete_discoveries_of(tx, CONNECTION).await.map_err(err)?, 2, "a deleted connection's runs");
    Ok(())
}

async fn a_lapsed_run_goes_back_until_its_attempts_are_spent(tx: &mut Tx) -> Check {
    let run = insert_discovery(tx, &pending(0)).await.map_err(err)?;
    for attempt in 1..=3 {
        ensure_eq!(take(tx, run, "pending", "running", "a", at(0), at(10)).await.map_err(err)?, 1, "take {attempt}");
        ensure_eq!(lapsed(tx, "running", at(5)).await.map_err(err)?, Vec::<i64>::new(), "not lapsed yet");
        ensure_eq!(lapsed(tx, "running", at(11)).await.map_err(err)?, vec![run], "lapsed");
        let back = requeue_lapsed(tx, run, "running", "pending", at(11), 3).await.map_err(err)?;
        let failed =
            fail_lapsed(tx, run, "running", "failed", "executor_lost", "lost", at(11), 3).await.map_err(err)?;
        ensure_eq!((back, failed), if attempt < 3 { (1, 0) } else { (0, 1) }, "attempt {attempt}");
    }
    let ended = discovery(tx, run).await.map_err(err)?.unwrap();
    ensure_eq!((ended.state.as_str(), ended.reason.as_deref()), ("failed", Some("executor_lost")), "failed at last");
    Ok(())
}

async fn gone_is_marked_on_what_the_run_did_not_list_and_taken_back_where_it_could_not_read(tx: &mut Tx) -> Check {
    save_snapshot_rows(tx, &[listed("1", "Acme", 1), listed("2", "acme/sub", 1), listed("3", "other", 1)])
        .await
        .map_err(err)?;
    let mut seen = snapshot_rows(tx, CONNECTION, &["1".to_owned()]).await.map_err(err)?;
    seen[0].last_seen_by = 2;
    save_snapshot_rows(tx, &seen).await.map_err(err)?;
    let within = vec!["acme".to_owned()];
    ensure_eq!(mark_gone(tx, CONNECTION, 2, at(1), Some(&within)).await.map_err(err)?, 0, "only within, lower case");
    ensure_eq!(mark_gone(tx, CONNECTION, 2, at(1), None).await.map_err(err)?, 2, "what run 2 did not list");
    let refused = vec!["other".to_owned()];
    ensure_eq!(unmark_gone(tx, CONNECTION, 2, &refused).await.map_err(err)?, 1, "taken back where it could not read");
    ensure_eq!(count_seen(tx, CONNECTION, SeenBy::Gone, 2).await.map_err(err)?, 1, "gone by run 2");
    let page = seen_page(tx, CONNECTION, SeenBy::First, 1, 2, 0).await.map_err(err)?;
    ensure_eq!(page.iter().map(|row| row.forge_id.as_str()).collect::<Vec<_>>(), vec!["1", "2"], "by full path");
    ensure_eq!(listed_by(tx, CONNECTION, 2).await.map_err(err)?.len(), 1, "listed by run 2 and not gone");
    ensure_eq!(set_language(tx, CONNECTION, "1", Some("Rust")).await.map_err(err)?, 1, "a language");
    ensure_eq!(current_urls(tx).await.map_err(err)?.len(), 2, "the snapshot's current URLs");
    Ok(())
}

async fn a_reading_is_claimed_once_while_it_is_due(tx: &mut Tx) -> Check {
    let id = save_reading(
        tx,
        &ReadingRow {
            id: 0,
            repository_id: 7,
            wanted_branch: "main".into(),
            state: "pending".into(),
            connection_id: None,
            forge_id: None,
            window_days: 30,
            read_at: None,
            reason: None,
            evidence: None,
            evidence_sha256: None,
            claimed_until: None,
        },
    )
    .await
    .map_err(err)?;
    let now = at(100);
    let until = now + Duration::minutes(10);
    ensure_eq!(claim_reading(tx, id, now, until, at(0), 30).await.map_err(err)?, 1, "never read: due");
    ensure_eq!(claim_reading(tx, id, now, until, at(0), 30).await.map_err(err)?, 0, "held");
    ensure_eq!(release_reading(tx, id).await.map_err(err)?, 1, "released");
    let mut read = reading(tx, 7, "main").await.map_err(err)?.unwrap();
    read.read_at = Some(at(50));
    save_reading(tx, &read).await.map_err(err)?;
    ensure_eq!(claim_reading(tx, id, now, until, at(0), 30).await.map_err(err)?, 0, "read since the stale cut");
    ensure_eq!(claim_reading(tx, id, now, until, at(0), 60).await.map_err(err)?, 1, "a wider window is due");
    ensure_eq!(readings_of(tx, "main", &[7, 8]).await.map_err(err)?.len(), 1, "by branch and repository");
    ensure_eq!(repositories_read(tx).await.map_err(err)?, vec![7], "every repository read");
    ensure_eq!(delete_readings_of_repositories(tx, &[7]).await.map_err(err)?, 1, "a gone target's");
    Ok(())
}
