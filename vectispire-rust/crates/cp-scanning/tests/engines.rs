//! The module against real servers, MySQL 9.4 and PostgreSQL 17, each migrated by `vectispire-migrate` — Java's
//! `ScanQueueIntegrationTest`, `ScanLabelsIntegrationTest`, `LeaderElectionIntegrationTest`, `SchedulerDatabaseTest` and
//! `RetentionDatabaseTest`, case for case, and the races the claim exists for.
//!
//! **This is the suite the claim's design answers to.** A claim that hands one scan to two workers is invisible with a
//! mock, on one thread, and on the one engine a developer runs; so is a claim that never double-serves because it
//! serves almost nothing. Both are asserted here, on both engines, with claimants racing — `SKIP LOCKED` was dropped
//! for what it did on MySQL, and a wider window starved PostgreSQL: each was seen only on a real server.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::print_stdout
)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::{Db, Engine, ScanTarget, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_scanning::ports::PortError;
use vectispire_cp_scanning::{ClaimingAgent, Exclusion, NoExclusion, PAGE};
use vectispire_cp_settings::Setting;
use vectispire_domain::FailureKind;
use vectispire_domain::scan_queue::{LEASE_EXHAUSTED_MESSAGE, Policy};
use vectispire_protocol::ScanArtifacts;

use support::{Composed, Migrated, compose, count, exec, literal, numbers, system_clock, text};

fn now() -> OffsetDateTime {
    vectispire_cp_targets::clock::microseconds(OffsetDateTime::now_utc())
}

fn base() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_786_615_200).unwrap() // 2026-08-13T10:00:00Z
}

async fn clean(db: &Db) {
    for table in ["t_finding", "t_scan", "t_agent", "t_repository", "t_container", "t_leader_lease", "t_ssh_key"] {
        exec(db, &format!("delete from {table}")).await;
    }
    exec(db, &format!("delete from t_setting where {} in ('retention_keep_per_target', 'retention_max_age_days', 'scan_default_interval_days')", key(db))).await;
}

/// `count` waiting scans requiring `label`, none of a target — what the claim alone looks at.
async fn enqueue(db: &Db, count: i64, label: Option<&str>) -> Vec<i64> {
    let mut ids = Vec::new();
    for i in 0..count {
        ids.push(support::scan(db, None, None, label, base() + Duration::from_secs(i as u64)).await);
    }
    ids
}

/// `count` scans of one repository, queued after everything already waiting.
async fn enqueue_for(db: &Db, repo: i64, count: i64, label: Option<&str>) -> Vec<i64> {
    let already = support::count(db, "select count(*) from t_scan").await;
    let mut ids = Vec::new();
    for i in 0..count {
        let at = base() + Duration::from_secs(3_600 + (already + i) as u64);
        ids.push(support::scan(db, Some(repo), None, label, at).await);
    }
    ids
}

fn labels(label: Option<&str>) -> Vec<String> {
    label.map(|label| vec![label.to_owned()]).unwrap_or_default()
}

struct Excluding(BTreeSet<i64>, Arc<Mutex<Vec<usize>>>);

impl Excluding {
    fn of(ids: impl IntoIterator<Item = i64>) -> Excluding {
        Excluding(ids.into_iter().collect(), Arc::new(Mutex::new(Vec::new())))
    }
}

impl Exclusion for Excluding {
    fn among<'a>(&'a self, repositories: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<BTreeSet<i64>, PortError>> {
        self.1.lock().unwrap().push(repositories.len());
        let excluded = repositories.intersection(&self.0).copied().collect();
        Box::pin(async move { Ok(excluded) })
    }
}

async fn status(db: &Db, id: i64) -> String {
    text(db, &format!("select status from t_scan where id = {id}")).await.unwrap()
}

async fn attempts(db: &Db, id: i64) -> i64 {
    count(db, &format!("select cast(attempts as bigint) from t_scan where id = {id}").replace("bigint", bigint(db)))
        .await
}

fn bigint(db: &Db) -> &'static str {
    match db {
        Db::MySql(_) => "signed",
        Db::PostgreSql(_) => "bigint",
    }
}

async fn wait_served(db: &Db, id: i64) {
    exec(db, &format!("update t_scan set not_before = {} where id = {id}", literal(now() - Duration::from_secs(1))))
        .await;
}

async fn wait_until(db: &Db, id: i64, at: OffsetDateTime) {
    exec(db, &format!("update t_scan set not_before = {} where id = {id}", literal(at))).await;
}

async fn lapse(db: &Db, id: i64) {
    exec(
        db,
        &format!("update t_scan set lease_expires_at = {} where id = {id}", literal(now() - Duration::from_secs(60))),
    )
    .await;
}

fn reason(text: &'static str) -> impl Fn(&vectispire_cp_scanning::Abandoned) -> String + Send + Sync {
    move |_| text.to_owned()
}

/// One case of the suite, run on a cleaned database.
type Case = fn(Db) -> BoxFuture<'static, ()>;

async fn suite(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = database.connect().await;
    let cases: Vec<(&str, Case)> = vec![
        ("never serves the same scan twice, and the queue drains", |db| Box::pin(never_serves_twice(db))),
        ("the routing label is inside the selection", |db| Box::pin(respects_the_label(db))),
        ("a claim marks what it took", |db| Box::pin(marks_what_it_took(db))),
        ("an empty queue, and a claim of zero", |db| Box::pin(empty_and_zero(db))),
        ("concurrent polls of one agent never pass its limit", |db| Box::pin(concurrent_polls(db))),
        ("the count waits for a concurrent take", |db| Box::pin(the_count_waits(db))),
        ("a lapsed lease does not count", |db| Box::pin(lapsed_does_not_count(db))),
        ("an exclusion leaves the scans where they are", |db| Box::pin(exclusion_leaves(db))),
        ("the exclusion is asked a page at a time", |db| Box::pin(exclusion_paged(db))),
        ("a refund gives back the claim's attempt", |db| Box::pin(refund(db))),
        ("exclusions under concurrency", |db| Box::pin(exclusions_racing(db))),
        ("a scan in backoff is skipped by every selection", |db| Box::pin(backoff_skipped(db))),
        ("the next page skips the backoff too", |db| Box::pin(backoff_next_page(db))),
        ("a permanent failure fails at its first attempt", |db| Box::pin(permanent(db))),
        ("a long reason is kept within its column", |db| Box::pin(a_long_reason(db))),
        ("a transient failure reaches the limit across the delays", |db| Box::pin(across_the_delays(db))),
        ("a lapse waits too", |db| Box::pin(a_lapse_waits(db))),
        ("two executors and one scan in backoff", |db| Box::pin(two_executors_backoff(db))),
        ("the take repeats the wait", |db| Box::pin(take_repeats_wait(db))),
        ("a failure report ends its attempt only", |db| Box::pin(report_ends_its_attempt(db))),
        ("a deposed worker cannot fail its successor", |db| Box::pin(deposed(db))),
        ("a renewal beats a stale reclaim", |db| Box::pin(renewal_beats_reclaim(db))),
        ("the write fences the reclaim", |db| Box::pin(write_fences_reclaim(db))),
        ("N claimants racing: each scan once, the queue drains", |db| Box::pin(claimants_racing(db))),
        ("each scan's label, past every engine's bind limit", |db| Box::pin(labels_of(db))),
        ("leader election", |db| Box::pin(leader_election(db))),
        ("the scheduler on a database", |db| Box::pin(scheduler(db))),
        ("retention on a database", |db| Box::pin(retention(db))),
        ("the trigger, the latest scan, the languages and the purge", |db| Box::pin(targets_side(db))),
        ("a result written, whichever executor", |db| Box::pin(results(db))),
        ("the built-in worker", |db| Box::pin(built_in_worker(db))),
        ("one long purl, path and link no longer lose the scan", |db| Box::pin(long_findings(db))),
        ("the licence blocklist is read at each scan", |db| Box::pin(license_blocklist_per_scan(db))),
    ];
    for (name, case) in cases {
        clean(&db).await;
        println!("{engine}: {name}");
        case(db.clone()).await;
    }
    db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn on_mysql() {
    suite(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn on_postgresql() {
    suite(Engine::PostgreSql).await;
}

fn composed(db: &Db) -> Composed {
    compose(db, system_clock(), Policy::default())
}

// ── ScanQueueIntegrationTest ─────────────────────────────────────────────────────────────────

async fn never_serves_twice(db: Db) {
    enqueue(&db, 20, None).await;
    let queue = composed(&db).scanning.queue().clone();
    let mut served = Vec::new();
    for _ in 0..20 {
        if served.len() >= 20 {
            break;
        }
        let mut claims = Vec::new();
        for worker in 0..8 {
            let queue = queue.clone();
            claims.push(tokio::spawn(async move {
                queue
                    .claim(5, &format!("worker-{worker}"), &[])
                    .await
                    .unwrap()
                    .iter()
                    .map(|scan| scan.id)
                    .collect::<Vec<_>>()
            }));
        }
        for claim in claims {
            served.extend(claim.await.unwrap());
        }
    }
    let distinct: BTreeSet<i64> = served.iter().copied().collect();
    assert_eq!(distinct.len(), served.len(), "a scan served twice is a repository scanned twice: {served:?}");
    assert_eq!(served.len(), 20, "everything queued must eventually be claimed");
    assert_eq!(count(&db, "select count(*) from t_scan where status = 'pending'").await, 0);
}

async fn respects_the_label(db: Db) {
    enqueue(&db, 3, Some("production")).await;
    enqueue(&db, 2, None).await;
    let queue = composed(&db).scanning.queue().clone();
    // No label: only the unrouted work — an agent with no label does not match everything.
    assert_eq!(queue.claim(10, "plain", &[]).await.unwrap().len(), 2);
    assert_eq!(queue.claim(10, "prod", &labels(Some("production"))).await.unwrap().len(), 3);
}

async fn marks_what_it_took(db: Db) {
    enqueue(&db, 2, None).await;
    let claimed = composed(&db).scanning.queue().claim(2, "worker", &[]).await.unwrap();
    assert_eq!(claimed.len(), 2);
    for scan in claimed {
        assert_eq!(scan.status, "scanning");
        assert_eq!(scan.claimed_by.as_deref(), Some("worker"));
        assert!(scan.lease_expires_at.is_some());
        assert_eq!(scan.attempts, 1);
    }
    assert_eq!(count(&db, "select count(*) from t_scan where status = 'pending'").await, 0);
}

async fn empty_and_zero(db: Db) {
    let queue = composed(&db).scanning.queue().clone();
    assert!(queue.claim(5, "worker", &[]).await.unwrap().is_empty());
    enqueue(&db, 1, None).await;
    assert!(queue.claim(0, "worker", &[]).await.unwrap().is_empty());
    assert_eq!(count(&db, "select count(*) from t_scan where status = 'pending'").await, 1);
}

async fn concurrent_polls(db: Db) {
    enqueue(&db, 20, None).await;
    let edge = support::agent(&db, "edge").await;
    let other = support::agent(&db, "other").await;
    let queue = composed(&db).scanning.queue().clone();
    for round in 0..5 {
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut polls = Vec::new();
        for _ in 0..8 {
            let (queue, barrier) = (queue.clone(), barrier.clone());
            polls.push(tokio::spawn(async move {
                barrier.wait().await;
                queue.claim_within(edge, 2, &[], &NoExclusion).await.unwrap()
            }));
        }
        for poll in polls {
            poll.await.unwrap();
        }
        assert_eq!(
            count(&db, &format!("select count(*) from t_scan where status = 'scanning' and claimed_by = '{edge}'"))
                .await,
            2,
            "scans held by an agent whose limit is 2, after round {round}"
        );
    }
    // The limit is the agent's, not the queue's.
    assert!(queue.claim_within(other, 1, &[], &NoExclusion).await.unwrap().scan.is_some());
}

async fn the_count_waits(db: Db) {
    let ids = enqueue(&db, 2, None).await;
    let edge = support::agent(&db, "edge").await;
    let queue = composed(&db).scanning.queue().clone();
    let newest = ids[1];
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let competitor = {
        let db = db.clone();
        tokio::spawn(async move {
            let mut tx = db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
            let at = now();
            let lock = format!("update t_agent set last_seen_at = {} where id = '{edge}'", literal(at));
            let take = format!(
                "update t_scan set status = 'scanning', claimed_by = '{edge}', claimed_at = {}, lease_expires_at = {}, \
                 attempts = attempts + 1 where id = {newest} and status = 'pending'",
                literal(at),
                literal(at + Duration::from_secs(600))
            );
            let took = match &mut tx {
                vectispire_cp_db::Tx::MySql(tx) => {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(lock)).execute(&mut **tx).await.unwrap();
                    sqlx::raw_sql(sqlx::AssertSqlSafe(take)).execute(&mut **tx).await.unwrap().rows_affected()
                }
                vectispire_cp_db::Tx::PostgreSql(tx) => {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(lock)).execute(&mut **tx).await.unwrap();
                    sqlx::raw_sql(sqlx::AssertSqlSafe(take)).execute(&mut **tx).await.unwrap().rows_affected()
                }
            };
            held_tx.send(()).unwrap();
            // Uncommitted while the claim below counts, reads its candidate and reaches the agent's row.
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            tx.commit().await.unwrap();
            took == 1
        })
    };
    held_rx.await.unwrap();
    let claim = queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap();
    assert!(competitor.await.unwrap());
    assert!(claim.scan.is_none(), "a claim past a limit of one");
    assert_eq!(
        count(&db, &format!("select count(*) from t_scan where status = 'scanning' and claimed_by = '{edge}'")).await,
        1
    );
}

async fn lapsed_does_not_count(db: Db) {
    enqueue(&db, 3, None).await;
    let edge = support::agent(&db, "edge").await;
    let queue = composed(&db).scanning.queue().clone();
    let held = queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap().id;
    assert!(
        queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.is_none(),
        "a live lease fills a limit of one"
    );
    lapse(&db, held).await;
    assert!(queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.is_some());
}

async fn exclusion_leaves(db: Db) {
    let queue = composed(&db).scanning.queue().clone();
    for label in [None, Some("dmz")] {
        exec(&db, "delete from t_scan").await;
        let suffix = label.unwrap_or("none");
        let keyed = support::repository(&db, &format!("keyed-{suffix}")).await;
        let open = support::repository(&db, &format!("open-{suffix}")).await;
        enqueue_for(&db, keyed, 2, label).await;
        let unrouted = enqueue(&db, 1, label).await;
        exec(
            &db,
            &format!(
                "update t_scan set created_at = {} where id = {}",
                literal(base() + Duration::from_secs(3_600 + 2)),
                unrouted[0]
            ),
        )
        .await;
        enqueue_for(&db, open, 1, label).await;
        let routed = support::repository(&db, &format!("routed-{suffix}")).await;
        enqueue_for(&db, routed, 1, Some("elsewhere")).await;
        let edge = support::agent(&db, &format!("edge-{suffix}")).await;
        let exclusion = Excluding::of([keyed]);
        let asked = Arc::new(Mutex::new(BTreeSet::new()));
        let recording = Recording(exclusion, asked.clone());
        let mut taken = Vec::new();
        for _ in 0..4 {
            if let Some(scan) = queue.claim_within(edge, 16, &labels(label), &recording).await.unwrap().scan {
                taken.push(scan);
            }
        }
        assert!(asked.lock().unwrap().is_subset(&[keyed, open].into_iter().collect()), "{label:?}");
        assert_eq!(taken.len(), 2, "{label:?}");
        assert!(taken.iter().all(|scan| scan.repo_id != Some(keyed)));
        assert_eq!(
            count(&db, &format!("select count(*) from t_scan where repo_id = {keyed} and status = 'pending' and claimed_by is null and attempts = 0")).await,
            2
        );
        // Nothing excluded: the same agent takes them.
        assert_eq!(
            queue.claim_within(edge, 16, &labels(label), &NoExclusion).await.unwrap().scan.unwrap().repo_id,
            Some(keyed)
        );
    }
}

struct Recording(Excluding, Arc<Mutex<BTreeSet<i64>>>);

impl Exclusion for Recording {
    fn among<'a>(&'a self, repositories: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<BTreeSet<i64>, PortError>> {
        self.1.lock().unwrap().extend(repositories.iter().copied());
        self.0.among(repositories)
    }
}

async fn exclusion_paged(db: Db) {
    let mut keyed = BTreeSet::new();
    let excluded_repositories = 2 * PAGE + 10;
    let mut statements = String::new();
    for i in 0..excluded_repositories {
        statements.push_str(&format!("insert into t_repository (url, branch, name) values ('https://example.invalid/k{i}.git', 'main', 'keyed-{i}');"));
    }
    exec(&db, &statements).await;
    let repositories = numbers(&db, "select id from t_repository order by id").await;
    let mut scans = String::new();
    for (i, id) in repositories.iter().enumerate() {
        keyed.insert(*id);
        scans.push_str(&format!(
            "insert into t_scan (branch, status, created_at, repo_id, attempts, findings_count, new_issues_count, resolved_issues_count) values ('main', 'pending', {}, {id}, 0, 0, 0, 0);",
            literal(base() + Duration::from_secs(i as u64))
        ));
    }
    exec(&db, &scans).await;
    let open = support::repository(&db, "open").await;
    enqueue_for(&db, open, 1, None).await;
    exec(
        &db,
        &format!(
            "update t_scan set created_at = {} where repo_id = {open}",
            literal(base() + Duration::from_secs(100_000))
        ),
    )
    .await;
    let edge = support::agent(&db, "edge").await;
    let queue = composed(&db).scanning.queue().clone();
    let exclusion = Excluding::of(keyed.iter().copied());
    let claim = queue.claim_within(edge, 16, &[], &exclusion).await.unwrap();
    assert_eq!(claim.scan.unwrap().repo_id, Some(open));
    assert!(claim.kept, "the scans it walked past were left for another executor");
    let sizes = exclusion.1.lock().unwrap().clone();
    assert!(sizes.len() > 2 && sizes.iter().all(|size| *size <= PAGE), "{sizes:?}");
    assert_eq!(
        count(&db, &format!("select count(*) from t_scan where status <> 'pending' and repo_id <> {open}")).await,
        0
    );
    let nothing = queue.claim_within(edge, 16, &[], &exclusion).await.unwrap();
    assert!(nothing.scan.is_none());
    assert!(nothing.kept);
}

async fn refund(db: Db) {
    enqueue(&db, 1, None).await;
    let edge = support::agent(&db, "edge").await;
    let queue = composed(&db).scanning.queue().clone();
    let id = queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap().id;
    assert_eq!(attempts(&db, id).await, 1);
    assert!(!queue.requeue_refunded(id, "somebody-else").await.unwrap());
    assert_eq!(attempts(&db, id).await, 1);
    assert!(queue.requeue_refunded(id, &edge.to_string()).await.unwrap());
    assert_eq!(status(&db, id).await, "pending");
    assert_eq!(text(&db, &format!("select claimed_by from t_scan where id = {id}")).await, None);
    assert_eq!(
        count(&db, &format!("select count(*) from t_scan where id = {id} and lease_expires_at is null")).await,
        1
    );
    assert_eq!(attempts(&db, id).await, 0);
    // The plain requeue keeps the attempt.
    queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap();
    assert!(queue.requeue(id, &edge.to_string()).await.unwrap());
    assert_eq!(attempts(&db, id).await, 1);
}

async fn exclusions_racing(db: Db) {
    let keyed = support::repository(&db, "keyed").await;
    let open = support::repository(&db, "open").await;
    enqueue_for(&db, keyed, 10, None).await;
    enqueue_for(&db, open, 5, None).await;
    enqueue(&db, 5, None).await;
    let mut withholding = Vec::new();
    let mut capable = Vec::new();
    for i in 0..4 {
        withholding.push(support::agent(&db, &format!("unverified-{i}")).await);
        capable.push(support::agent(&db, &format!("verified-{i}")).await);
    }
    let queue = composed(&db).scanning.queue().clone();
    let mut served: Vec<(bool, i64, Option<i64>)> = Vec::new();
    for _ in 0..20 {
        if served.len() >= 20 {
            break;
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut polls = Vec::new();
        for (agent, excluding) in withholding.iter().map(|a| (*a, true)).chain(capable.iter().map(|a| (*a, false))) {
            let (queue, barrier) = (queue.clone(), barrier.clone());
            polls.push(tokio::spawn(async move {
                barrier.wait().await;
                let claim = if excluding {
                    queue.claim_within(agent, 16, &[], &Excluding::of([keyed])).await.unwrap()
                } else {
                    queue.claim_within(agent, 16, &[], &NoExclusion).await.unwrap()
                };
                claim.scan.map(|scan| (excluding, scan.id, scan.repo_id))
            }));
        }
        for poll in polls {
            served.extend(poll.await.unwrap());
        }
    }
    let distinct: BTreeSet<i64> = served.iter().map(|(_, id, _)| *id).collect();
    assert_eq!(distinct.len(), served.len());
    assert_eq!(served.len(), 20);
    assert!(served.iter().filter(|(excluding, _, _)| *excluding).all(|(_, _, repo)| *repo != Some(keyed)));
    assert_eq!(count(&db, "select count(*) from t_scan where status <> 'scanning' or attempts <> 1").await, 0);
}

/// The oldest scan waiting out a retry, a due one behind it.
async fn backoff_before_a_due_scan(db: &Db, label: Option<&str>, tag: &str) -> (i64, i64) {
    exec(db, "delete from t_scan").await;
    let backoff = support::repository(db, &format!("backoff-{tag}")).await;
    let due = support::repository(db, &format!("due-{tag}")).await;
    let waiting = enqueue_for(db, backoff, 1, label).await[0];
    enqueue_for(db, due, 1, label).await;
    wait_until(db, waiting, now() + Duration::from_secs(600)).await;
    (waiting, due)
}

async fn backoff_skipped(db: Db) {
    let queue = composed(&db).scanning.queue().clone();
    for label in [None, Some("dmz")] {
        let tag = label.unwrap_or("none");
        let edge = support::agent(&db, &format!("edge-{tag}")).await;
        let (_, due) = backoff_before_a_due_scan(&db, label, &format!("w{tag}")).await;
        let claimed = queue.claim(5, "worker", &labels(label)).await.unwrap();
        assert_eq!(claimed.iter().map(|scan| scan.repo_id).collect::<Vec<_>>(), vec![Some(due)], "{label:?}");

        let (_, due) = backoff_before_a_due_scan(&db, label, &format!("a{tag}")).await;
        assert_eq!(
            queue.claim_within(edge, 16, &labels(label), &NoExclusion).await.unwrap().scan.unwrap().repo_id,
            Some(due)
        );
        assert!(queue.claim_within(edge, 16, &labels(label), &NoExclusion).await.unwrap().scan.is_none());

        let (waiting, due) = backoff_before_a_due_scan(&db, label, &format!("e{tag}")).await;
        let nothing = Excluding::of([]);
        assert_eq!(
            queue.claim_within(edge, 16, &labels(label), &nothing).await.unwrap().scan.unwrap().repo_id,
            Some(due)
        );
        assert_eq!(status(&db, waiting).await, "pending");
        assert_eq!(attempts(&db, waiting).await, 0, "a skipped scan costs no attempt");
        wait_served(&db, waiting).await;
        assert_eq!(queue.claim_within(edge, 16, &labels(label), &nothing).await.unwrap().scan.unwrap().id, waiting);
        assert_eq!(
            count(&db, &format!("select count(*) from t_scan where id = {waiting} and not_before is null")).await,
            1,
            "a running scan waits for nothing"
        );
    }
}

async fn backoff_next_page(db: Db) {
    let queue = composed(&db).scanning.queue().clone();
    for label in [None, Some("dmz")] {
        exec(&db, "delete from t_scan").await;
        let tag = label.unwrap_or("none");
        let keyed = support::repository(&db, &format!("keyed-{tag}")).await;
        let mut scans = String::new();
        for i in 0..PAGE {
            let required = label.map_or("null".to_owned(), |label| format!("'{label}'"));
            scans.push_str(&format!(
                "insert into t_scan (branch, status, created_at, repo_id, required_agent_label, attempts, findings_count, new_issues_count, resolved_issues_count) values ('main', 'pending', {}, {keyed}, {required}, 0, 0, 0, 0);",
                literal(base() + Duration::from_secs(i as u64))
            ));
        }
        exec(&db, &scans).await;
        let backoff = support::repository(&db, &format!("backoff-{tag}")).await;
        let waiting = enqueue_for(&db, backoff, 1, label).await[0];
        exec(
            &db,
            &format!(
                "update t_scan set created_at = {} where id = {waiting}",
                literal(base() + Duration::from_secs(10_000))
            ),
        )
        .await;
        wait_until(&db, waiting, now() + Duration::from_secs(600)).await;
        let due = support::repository(&db, &format!("due-{tag}")).await;
        let due_scan = enqueue_for(&db, due, 1, label).await[0];
        exec(
            &db,
            &format!(
                "update t_scan set created_at = {} where id = {due_scan}",
                literal(base() + Duration::from_secs(10_001))
            ),
        )
        .await;
        let edge = support::agent(&db, &format!("edge-{tag}")).await;
        let claim = queue.claim_within(edge, 16, &labels(label), &Excluding::of([keyed])).await.unwrap();
        assert_eq!(claim.scan.unwrap().repo_id, Some(due), "{label:?}");
    }
}

async fn permanent(db: Db) {
    enqueue(&db, 1, None).await;
    let edge = support::agent(&db, "edge").await;
    let queue = composed(&db).scanning.queue().clone();
    let id = queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap().id;
    let done = queue
        .abandon(id, &edge.to_string(), 1, FailureKind::Permanent, &reason("host key changed"))
        .await
        .unwrap()
        .unwrap();
    assert!(!done.retried());
    assert!(done.permanent());
    assert!(done.not_before().is_none());
    assert_eq!(status(&db, id).await, "failed");
    assert_eq!(attempts(&db, id).await, 1);
    assert_eq!(
        text(&db, &format!("select error from t_scan where id = {id}")).await.as_deref(),
        Some("host key changed")
    );
    assert_eq!(
        count(
            &db,
            &format!("select count(*) from t_scan where id = {id} and not_before is null and claimed_by is null")
        )
        .await,
        1
    );
}

/// A scanner's stack trace runs to tens of kilobytes: the reason is kept within the column.
async fn a_long_reason(db: Db) {
    enqueue(&db, 1, None).await;
    let queue = composed(&db).scanning.queue().clone();
    let id = queue.claim(1, "worker", &[]).await.unwrap()[0].id;
    let long = "x".repeat(3_000);
    queue
        .abandon(id, "worker", 1, FailureKind::Permanent, &move |_: &vectispire_cp_scanning::Abandoned| long.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        count(&db, &format!("select cast(length(error) as {}) from t_scan where id = {id}", bigint(&db))).await,
        2_000
    );
}

async fn across_the_delays(db: Db) {
    let policy = Policy::default();
    assert_eq!(policy.retry_delays, vec![Duration::from_secs(60), Duration::from_secs(300), Duration::from_secs(900)]);
    // Whole seconds: the comparison below is to the instant.
    let start = now().replace_nanosecond(0).unwrap();
    let clock = support::MovingClock::at(start);
    let composed = compose(&db, clock.clone(), policy);
    let queue = composed.scanning.queue().clone();
    enqueue(&db, 1, None).await;
    let edge = support::agent(&db, "edge").await;
    let worker = edge.to_string();

    let id = queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap().id;
    let first = clock.now_at();
    let done =
        queue.abandon(id, &worker, 1, FailureKind::Transient, &reason("connection reset")).await.unwrap().unwrap();
    assert_eq!(done.not_before(), Some(first + Duration::from_secs(60)));

    clock.advance(Duration::from_secs(59));
    assert!(queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.is_none(), "a second early");
    assert!(queue.claim(1, "worker", &[]).await.unwrap().is_empty());
    clock.advance(Duration::from_secs(1));
    // Taken by the built-in worker this time: the scan's fate does not depend on the executor.
    let taken = queue.claim(1, "worker", &[]).await.unwrap();
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].attempts, 2);

    let second = clock.now_at();
    let done =
        queue.abandon(id, "worker", 2, FailureKind::Transient, &reason("daemon unreachable")).await.unwrap().unwrap();
    assert_eq!(done.not_before(), Some(second + Duration::from_secs(300)));
    clock.advance(Duration::from_secs(299));
    assert!(queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.is_none(), "a second early");
    clock.advance(Duration::from_secs(1));
    assert_eq!(queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap().attempts, 3);

    let done = queue.abandon(id, &worker, 3, FailureKind::Transient, &reason("the last")).await.unwrap().unwrap();
    assert!(!done.retried());
    assert!(!done.permanent());
    assert_eq!(status(&db, id).await, "failed");
    assert_eq!(count(&db, &format!("select count(*) from t_scan where id = {id} and not_before is null")).await, 1);
    clock.advance(Duration::from_secs(3_600));
    assert!(queue.claim(1, "worker", &[]).await.unwrap().is_empty(), "failed for good is not waiting");
}

trait At {
    fn now_at(&self) -> OffsetDateTime;
}

impl At for Arc<support::MovingClock> {
    fn now_at(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

async fn claimed_then_lapsed(db: &Db, queue: &vectispire_cp_scanning::ScanQueue, worker: &str) -> i64 {
    enqueue(db, 1, None).await;
    let id = queue.claim(1, worker, &[]).await.unwrap()[0].id;
    lapse(db, id).await;
    id
}

async fn a_lapse_waits(db: Db) {
    let queue = composed(&db).scanning.queue().clone();
    let id = claimed_then_lapsed(&db, &queue, "worker-a").await;
    let before = now();
    assert_eq!(queue.reclaim_lapsed_leases().await.unwrap().requeued, vec![id]);
    let not_before = queue.by_id(id).await.unwrap().unwrap().not_before.unwrap();
    assert!(not_before >= before + Duration::from_secs(59) && not_before <= now() + Duration::from_secs(61));
    assert!(queue.claim(1, "worker-b", &[]).await.unwrap().is_empty(), "a lone worker does not take it back at once");
    for _ in 2..=3 {
        wait_served(&db, id).await;
        assert_eq!(queue.claim(1, "worker-b", &[]).await.unwrap().len(), 1);
        lapse(&db, id).await;
        queue.reclaim_lapsed_leases().await.unwrap();
    }
    assert_eq!(status(&db, id).await, "failed");
    assert_eq!(
        text(&db, &format!("select error from t_scan where id = {id}")).await.as_deref(),
        Some(LEASE_EXHAUSTED_MESSAGE)
    );
    assert_eq!(count(&db, &format!("select count(*) from t_scan where id = {id} and not_before is null")).await, 1);
}

async fn two_executors_backoff(db: Db) {
    let id = enqueue(&db, 1, None).await[0];
    wait_until(&db, id, now() + Duration::from_secs(600)).await;
    let edge = support::agent(&db, "edge").await;
    let queue = composed(&db).scanning.queue().clone();
    for round in 0..4 {
        if round == 3 {
            wait_served(&db, id).await;
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let worker = {
            let (queue, barrier) = (queue.clone(), barrier.clone());
            tokio::spawn(async move {
                barrier.wait().await;
                queue.claim(1, "worker", &[]).await.unwrap().len()
            })
        };
        let agent = {
            let (queue, barrier) = (queue.clone(), barrier.clone());
            tokio::spawn(async move {
                barrier.wait().await;
                usize::from(queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.is_some())
            })
        };
        let taken = worker.await.unwrap() + agent.await.unwrap();
        assert_eq!(taken, usize::from(round == 3), "round {round}");
    }
    assert_eq!(status(&db, id).await, "scanning");
    assert_eq!(attempts(&db, id).await, 1);
}

async fn take_repeats_wait(db: Db) {
    let id = enqueue(&db, 1, None).await[0];
    let other = support::agent(&db, "other").await;
    let queue = composed(&db).scanning.queue().clone();
    assert_eq!(queue.claim_within(other, 1, &[], &NoExclusion).await.unwrap().scan.unwrap().id, id);
    assert!(
        queue
            .abandon(id, &other.to_string(), 1, FailureKind::Transient, &reason("connection reset"))
            .await
            .unwrap()
            .is_some()
    );
    // The take a claimant that read the scan while it was due issues now: pending again, and not due.
    let at = now();
    exec(&db, &format!(
        "update t_scan set status = 'scanning', claimed_by = 'worker' where id = {id} and status = 'pending' and (not_before is null or not_before <= {})",
        literal(at)
    )).await;
    assert_eq!(status(&db, id).await, "pending");
    // And the queue's own take, through a claim: it reads nothing due.
    assert!(queue.claim(1, "worker", &[]).await.unwrap().is_empty());
}

async fn report_ends_its_attempt(db: Db) {
    enqueue(&db, 1, None).await;
    let edge = support::agent(&db, "edge").await;
    let worker = edge.to_string();
    let queue = composed(&db).scanning.queue().clone();
    let id = queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap().id;
    assert!(
        queue.abandon(id, "somebody-else", 1, FailureKind::Transient, &reason("not mine")).await.unwrap().is_none()
    );
    assert!(
        queue.abandon(id, &worker, 2, FailureKind::Transient, &reason("not this attempt")).await.unwrap().is_none()
    );
    let done = queue
        .abandon(id, &worker, 1, FailureKind::Transient, &|done: &vectispire_cp_scanning::Abandoned| {
            format!("attempt {}: clone refused", done.attempt)
        })
        .await
        .unwrap()
        .unwrap();
    assert!(done.retried());
    assert_eq!(status(&db, id).await, "pending");
    assert_eq!(
        text(&db, &format!("select error from t_scan where id = {id}")).await.as_deref(),
        Some("attempt 1: clone refused")
    );
    assert!(
        queue.by_id(id).await.unwrap().unwrap().not_before.unwrap() > now() + Duration::from_secs(50),
        "a minute's wait"
    );
    assert!(queue.abandon(id, &worker, 1, FailureKind::Transient, &reason("again")).await.unwrap().is_none());

    wait_served(&db, id).await;
    queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap();
    // A report about attempt 1 arriving now — the statement's own condition is what turns it away.
    exec(&db, &format!("update t_scan set status = 'pending', error = 'stale' where id = {id} and status = 'scanning' and claimed_by = '{worker}' and attempts = 1")).await;
    assert_eq!(status(&db, id).await, "scanning");

    assert!(queue.abandon(id, &worker, 2, FailureKind::Transient, &reason("clone refused")).await.unwrap().is_some());
    wait_served(&db, id).await;
    queue.claim_within(edge, 1, &[], &NoExclusion).await.unwrap().scan.unwrap();
    let done = queue.abandon(id, &worker, 3, FailureKind::Transient, &reason("the last")).await.unwrap().unwrap();
    assert!(!done.retried());
    assert_eq!(status(&db, id).await, "failed");
    assert_eq!(text(&db, &format!("select error from t_scan where id = {id}")).await.as_deref(), Some("the last"));
    assert_eq!(
        count(
            &db,
            &format!("select count(*) from t_scan where id = {id} and lease_expires_at is null and not_before is null")
        )
        .await,
        1
    );
}

async fn deposed(db: Db) {
    let queue = composed(&db).scanning.queue().clone();
    let id = claimed_then_lapsed(&db, &queue, "worker-a").await;
    assert_eq!(queue.reclaim_lapsed_leases().await.unwrap().requeued, vec![id]);
    wait_served(&db, id).await;
    assert_eq!(queue.claim(1, "worker-b", &[]).await.unwrap().iter().map(|scan| scan.id).collect::<Vec<_>>(), vec![id]);
    assert!(
        queue.abandon(id, "worker-a", 1, FailureKind::Permanent, &reason("runner crashed")).await.unwrap().is_none()
    );
    assert!(
        queue.abandon(id, "worker-a", 2, FailureKind::Permanent, &reason("runner crashed")).await.unwrap().is_none()
    );
    assert!(!queue.requeue(id, "worker-a").await.unwrap());
    let after = queue.by_id(id).await.unwrap().unwrap();
    assert_eq!(after.status, "scanning");
    assert_eq!(after.claimed_by.as_deref(), Some("worker-b"));
    assert!(after.lease_expires_at.is_some());
}

async fn renewal_beats_reclaim(db: Db) {
    let queue = composed(&db).scanning.queue().clone();
    let id = claimed_then_lapsed(&db, &queue, "worker-a").await;
    let (renewed_tx, renewed_rx) = tokio::sync::oneshot::channel();
    let renewal = {
        let db = db.clone();
        tokio::spawn(async move {
            let mut tx = db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
            let renewed = format!(
                "update t_scan set lease_expires_at = {} where id = {id} and status = 'scanning' and claimed_by = 'worker-a'",
                literal(now() + Duration::from_secs(1_200))
            );
            let rows = match &mut tx {
                vectispire_cp_db::Tx::MySql(tx) => {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(renewed)).execute(&mut **tx).await.unwrap().rows_affected()
                }
                vectispire_cp_db::Tx::PostgreSql(tx) => {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(renewed)).execute(&mut **tx).await.unwrap().rows_affected()
                }
            };
            renewed_tx.send(()).unwrap();
            // Uncommitted while the reclaim reads the old, lapsed lease and then blocks on the row.
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            tx.commit().await.unwrap();
            rows == 1
        })
    };
    renewed_rx.await.unwrap();
    let reclaimed = queue.reclaim_lapsed_leases().await.unwrap();
    assert!(renewal.await.unwrap());
    assert!(reclaimed.requeued.is_empty());
    let after = queue.by_id(id).await.unwrap().unwrap();
    assert_eq!(after.status, "scanning");
    assert_eq!(after.claimed_by.as_deref(), Some("worker-a"));
}

async fn write_fences_reclaim(db: Db) {
    let queue = composed(&db).scanning.queue().clone();
    let id = claimed_then_lapsed(&db, &queue, "worker-a").await;
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let write = {
        let (db, queue) = (db.clone(), queue.clone());
        tokio::spawn(async move {
            let mut tx = db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
            if !queue.hold_for_write(&mut tx, id, "worker-a").await.unwrap() {
                return false;
            }
            held_tx.send(()).unwrap();
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            let done = format!(
                "update t_scan set status = 'completed', claimed_by = null, lease_expires_at = null where id = {id}"
            );
            match &mut tx {
                vectispire_cp_db::Tx::MySql(tx) => {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(done)).execute(&mut **tx).await.unwrap().rows_affected()
                }
                vectispire_cp_db::Tx::PostgreSql(tx) => {
                    sqlx::raw_sql(sqlx::AssertSqlSafe(done)).execute(&mut **tx).await.unwrap().rows_affected()
                }
            };
            tx.commit().await.unwrap();
            true
        })
    };
    held_rx.await.unwrap();
    let reclaimed = queue.reclaim_lapsed_leases().await.unwrap();
    assert!(write.await.unwrap());
    assert!(reclaimed.requeued.is_empty());
    assert_eq!(status(&db, id).await, "completed");
}

/// Sixteen claimants — eight agents with a limit of four, eight built-in workers claiming three at a time — round
/// after round over two hundred scans: every scan claimed exactly once, no round coming back empty while scans wait,
/// and the queue drained.
///
/// **Not "every claimant served", and that is not the test being lenient.** It used to assert that, and failed now and
/// then on both engines — more often under load — with an agent served nothing across every round while a hundred
/// scans waited. Nothing had gone wrong: every claimant reads the same oldest row, an agent's attempt tries that one
/// candidate behind its own row's lock, and an attempt lost means somebody else took it; after
/// [`Policy::claim_attempts`] losses in a row the poll comes back empty, as Java's `claimWithin` does, and the agent
/// polls again a second later. Fifteen competitors at the head, round after round with no pause, can beat one agent
/// every time — seen with no error and no deadlock, twelve races lost per empty poll. Java's
/// `neverServesTheSameScanTwice` asserts what the claim promises, which is the queue's progress and not any one
/// claimant's share. A claim that starves the queue still fails here, and without a timing to rely on: a lost race
/// always has a winner, so a round that took nothing while scans waited, or sixty rounds that did not drain two
/// hundred, is the claim turning everybody away.
async fn claimants_racing(db: Db) {
    let mut statements = String::new();
    for i in 0..200 {
        statements.push_str(&format!(
            "insert into t_scan (branch, status, created_at, attempts, findings_count, new_issues_count, resolved_issues_count) values ('main', 'pending', {}, 0, 0, 0, 0);",
            literal(base() + Duration::from_secs(i))
        ));
    }
    exec(&db, &statements).await;
    let mut agents = Vec::new();
    for i in 0..8 {
        agents.push(support::agent(&db, &format!("racer-{i}")).await);
    }
    let queue = composed(&db).scanning.queue().clone();
    let mut served: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    for _round in 0..60 {
        if served.values().map(Vec::len).sum::<usize>() >= 200 {
            break;
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut claims = Vec::new();
        for agent in &agents {
            let (queue, barrier, agent) = (queue.clone(), barrier.clone(), *agent);
            claims.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut ids = Vec::new();
                // A poll that took one polls again at once while it has room, as a long poll does.
                while let Some(scan) = queue.claim_within(agent, 4, &[], &NoExclusion).await.unwrap().scan {
                    ids.push(scan.id);
                }
                (agent.to_string(), ids)
            }));
        }
        for worker in 0..8 {
            let (queue, barrier) = (queue.clone(), barrier.clone());
            claims.push(tokio::spawn(async move {
                barrier.wait().await;
                let name = format!("worker-{worker}");
                let ids: Vec<i64> = queue.claim(3, &name, &[]).await.unwrap().iter().map(|scan| scan.id).collect();
                (name, ids)
            }));
        }
        let mut round_ids = Vec::new();
        for claim in claims {
            let (who, ids) = claim.await.unwrap();
            round_ids.extend(ids.iter().copied());
            served.entry(who).or_default().extend(ids);
        }
        let distinct: BTreeSet<i64> = round_ids.iter().copied().collect();
        assert_eq!(distinct.len(), round_ids.len(), "a scan handed to two claimants in one round");
        assert!(!round_ids.is_empty(), "a round took nothing while scans waited");
        // What the agents took goes back as finished, so the next round finds only what nobody holds.
        let taken: Vec<String> = round_ids.iter().map(i64::to_string).collect();
        if !taken.is_empty() {
            exec(
                &db,
                &format!("update t_scan set status = 'completed', claimed_by = null where id in ({})", taken.join(",")),
            )
            .await;
        }
    }
    let all: Vec<i64> = served.values().flatten().copied().collect();
    let distinct: BTreeSet<i64> = all.iter().copied().collect();
    assert_eq!(distinct.len(), all.len(), "each scan claimed exactly once");
    assert_eq!(all.len(), 200, "the queue drained");
    assert_eq!(count(&db, "select count(*) from t_scan where status = 'pending'").await, 0, "nothing left waiting");
    assert_eq!(count(&db, "select count(*) from t_scan where attempts <> 1").await, 0, "one attempt each");
}

// ── ScanLabelsIntegrationTest ────────────────────────────────────────────────────────────────

async fn labels_of(db: Db) {
    let repository = support::repository(&db, "labels").await;
    exec(&db, &format!("insert into t_scan (repo_id, branch, version, status, created_at, attempts, findings_count, new_issues_count, resolved_issues_count) values ({repository}, 'main', '1.17.6', 'completed', {}, 1, 0, 0, 0)", literal(now()))).await;
    let released = count(&db, "select max(id) from t_scan").await;
    exec(&db, &format!("insert into t_scan (repo_id, branch, status, created_at, attempts, findings_count, new_issues_count, resolved_issues_count) values ({repository}, 'feature/x', 'completed', {}, 1, 0, 0, 0)", literal(now()))).await;
    let unversioned = count(&db, "select max(id) from t_scan").await;
    let mut ids = vec![released];
    ids.extend(3_000_000..=3_070_000);
    ids.push(unversioned);
    let labels = composed(&db).scanning.catalog().labels_of(&ids).await.unwrap();
    assert_eq!(labels.keys().copied().collect::<Vec<_>>(), vec![released, unversioned]);
    assert_eq!(labels[&released].branch, "main");
    assert_eq!(labels[&released].version.as_deref(), Some("1.17.6"));
    assert_eq!(labels[&unversioned].branch, "feature/x");
    assert_eq!(labels[&unversioned].version, None);
}

// ── LeaderElectionIntegrationTest ────────────────────────────────────────────────────────────

async fn winners(composed: &Composed, at: OffsetDateTime) -> usize {
    let mut claims = Vec::new();
    for index in 0..8 {
        let scanning = composed.scanning.clone();
        claims.push(tokio::spawn(async move {
            scanning.election().acquire("scheduler", &format!("instance-{index}"), at).await.unwrap()
        }));
    }
    let mut held = 0;
    for claim in claims {
        held += usize::from(claim.await.unwrap());
    }
    held
}

async fn leader_election(db: Db) {
    let composed = composed(&db);
    let election = composed.scanning.election();
    let at = now();
    // Eight start together, and the primary key arbitrates the first acquisition.
    assert_eq!(winners(&composed, at).await, 1);
    assert_eq!(count(&db, "select count(*) from t_leader_lease").await, 1);

    exec(&db, "delete from t_leader_lease").await;
    assert!(election.acquire("scheduler", "holder", at).await.unwrap());
    assert!(election.acquire("scheduler", "holder", at + Duration::from_secs(1)).await.unwrap(), "the holder renews");
    assert_eq!(winners(&composed, at + Duration::from_secs(2)).await, 0, "a live lease is not stolen");
    assert_eq!(
        election.current_holder("scheduler", at + Duration::from_secs(2)).await.unwrap().as_deref(),
        Some("holder")
    );

    exec(&db, "delete from t_leader_lease").await;
    assert!(election.acquire("scheduler", "the-dead-one", at).await.unwrap());
    let after_expiry = at + Duration::from_secs(3_600);
    assert_eq!(winners(&composed, after_expiry).await, 1, "exactly one takes over an expired lease");
    let holder = election.current_holder("scheduler", after_expiry).await.unwrap().unwrap();
    assert_ne!(holder, "the-dead-one");

    exec(&db, "delete from t_leader_lease").await;
    election.acquire("scheduler", "holder", at).await.unwrap();
    assert!(election.release("scheduler", "holder").await.unwrap());
    assert_eq!(winners(&composed, at + Duration::from_secs(1)).await, 1, "a released lease, to one taker");

    exec(&db, "delete from t_leader_lease").await;
    election.acquire("scheduler", "holder", at).await.unwrap();
    assert!(!election.release("scheduler", "an-impostor").await.unwrap());
    assert_eq!(
        election.current_holder("scheduler", at + Duration::from_secs(1)).await.unwrap().as_deref(),
        Some("holder")
    );
    assert!(election.is_leader("scheduler", "holder", at + Duration::from_secs(1)).await.unwrap());
    assert!(!election.is_leader("scheduler", "holder", at + Duration::from_secs(181)).await.unwrap(), "past the lease");

    // A lease is expired at its expiry's own instant — `!expiresAt.isAfter(at)`.
    exec(&db, "delete from t_leader_lease").await;
    assert!(election.acquire("scheduler", "holder", at).await.unwrap());
    assert!(election.acquire("scheduler", "successor", at + Duration::from_secs(180)).await.unwrap());
}

// ── SchedulerDatabaseTest ────────────────────────────────────────────────────────────────────

async fn due(db: &Db, tag: &str) -> i64 {
    exec(db, &format!(
        "insert into t_repository (url, branch, name, scan_interval_minutes, last_scheduled_scan_at) values ('https://example.invalid/due-{tag}.git', 'main', 'due-{tag}', 60, {})",
        literal(now() - Duration::from_secs(7_200))
    )).await;
    count(db, &format!("select id from t_repository where name = 'due-{tag}'")).await
}

async fn pending_for(db: &Db, repo: i64) -> i64 {
    count(db, &format!("select count(*) from t_scan where repo_id = {repo} and status = 'pending'")).await
}

async fn scheduler(db: Db) {
    let composed = composed(&db);
    let scanning = composed.scanning.clone();
    // A second tick does not stack.
    let id = due(&db, "a").await;
    assert_eq!(scanning.schedule_at(now()).await, 1);
    assert_eq!(scanning.schedule_at(now()).await, 0);
    assert_eq!(pending_for(&db, id).await, 1);

    // The stamp is written even when nothing was queued.
    clean(&db).await;
    let id = due(&db, "b").await;
    scanning.schedule_at(now()).await;
    let first = text(
        &db,
        &format!("select cast(last_scheduled_scan_at as char) from t_repository where id = {id}")
            .replace("as char", if matches!(db, Db::PostgreSql(_)) { "as text" } else { "as char" }),
    )
    .await;
    scanning.schedule_at(now() + Duration::from_secs(7_200)).await;
    let second = text(
        &db,
        &format!("select cast(last_scheduled_scan_at as char) from t_repository where id = {id}")
            .replace("as char", if matches!(db, Db::PostgreSql(_)) { "as text" } else { "as char" }),
    )
    .await;
    assert_ne!(first, second);
    assert!(second > first);

    // An undue target is left alone.
    clean(&db).await;
    exec(&db, &format!("insert into t_repository (url, branch, name, scan_interval_minutes, last_scheduled_scan_at) values ('https://example.invalid/slow.git', 'main', 'slow', 1440, {})", literal(now()))).await;
    let slow = count(&db, "select id from t_repository where name = 'slow'").await;
    assert_eq!(scanning.schedule_at(now()).await, 0);
    assert_eq!(pending_for(&db, slow).await, 0);

    // The queued row carries the branch and the required label.
    clean(&db).await;
    exec(&db, &format!("insert into t_repository (url, branch, name, scan_interval_minutes, required_agent_label, last_scheduled_scan_at) values ('https://example.invalid/labelled.git', 'develop', 'labelled', 60, 'production', {})", literal(now() - Duration::from_secs(7_200)))).await;
    let labelled = count(&db, "select id from t_repository where name = 'labelled'").await;
    scanning.schedule_at(now()).await;
    assert_eq!(pending_for(&db, labelled).await, 1);
    assert_eq!(
        text(&db, &format!("select branch from t_scan where repo_id = {labelled}")).await.as_deref(),
        Some("develop")
    );
    assert_eq!(
        text(&db, &format!("select required_agent_label from t_scan where repo_id = {labelled}")).await.as_deref(),
        Some("production")
    );

    // No schedule is the default; manual only is not scheduled, nor stamped.
    clean(&db).await;
    let defaulted = support::repository(&db, "unscheduled").await;
    exec(&db, "insert into t_repository (url, branch, name, scan_manual_only) values ('https://example.invalid/manual.git', 'main', 'manual', true)".replace("true", if matches!(db, Db::MySql(_)) { "1" } else { "true" }).as_str()).await;
    let manual = count(&db, "select id from t_repository where name = 'manual'").await;
    assert_eq!(scanning.schedule_at(now()).await, 1);
    assert_eq!(pending_for(&db, defaulted).await, 1);
    assert_eq!(pending_for(&db, manual).await, 0);
    assert_eq!(
        count(
            &db,
            &format!("select count(*) from t_repository where id = {manual} and last_scheduled_scan_at is null")
        )
        .await,
        1
    );

    // A running scan is not doubled, and the target is stamped.
    clean(&db).await;
    let id = due(&db, "c").await;
    exec(&db, &format!("insert into t_scan (repo_id, branch, status, created_at, attempts, findings_count, new_issues_count, resolved_issues_count) values ({id}, 'main', 'scanning', {}, 1, 0, 0, 0)", literal(now() - Duration::from_secs(3_600)))).await;
    assert_eq!(scanning.schedule_at(now()).await, 0);
    assert_eq!(pending_for(&db, id).await, 0);
    assert_eq!(
        count(
            &db,
            &format!(
                "select count(*) from t_repository where id = {id} and last_scheduled_scan_at > {}",
                literal(now() - Duration::from_secs(60))
            )
        )
        .await,
        1
    );

    // Another instance holding the lease: this one schedules nothing.
    clean(&db).await;
    due(&db, "d").await;
    assert!(scanning.election().acquire("scheduler", "another-instance", now()).await.unwrap());
    assert_eq!(scanning.schedule_at(now()).await, 0, "leader-only");

    // Under the default interval, a target scanned ten minutes ago is due only if its weekly slot fell in those ten
    // minutes — the default read in days, not minutes; an image is scheduled as a repository is.
    clean(&db).await;
    exec(&db, &format!("insert into t_repository (url, branch, name, last_scheduled_scan_at) values ('https://example.invalid/weekly.git', 'main', 'weekly', {})", literal(now() - Duration::from_secs(600)))).await;
    let weekly = count(&db, "select id from t_repository where name = 'weekly'").await;
    let stamped = text(
        &db,
        &format!(
            "select cast(last_scheduled_scan_at as {}) from t_repository where id = {weekly}",
            if matches!(db, Db::PostgreSql(_)) { "text" } else { "char" }
        ),
    )
    .await;
    exec(&db, &format!("insert into t_container (image_name, tag, scan_interval_minutes, last_scheduled_scan_at) values ('due-image', '1.0', 60, {})", literal(now() - Duration::from_secs(7_200)))).await;
    let image = count(&db, "select id from t_container where image_name = 'due-image'").await;
    let at = now();
    let expected = vectispire_domain::schedules::default_due(
        vectispire_domain::ScanTarget::Repository(weekly),
        7 * 86_400,
        Some(instant_of(at - Duration::from_secs(600))),
        instant_of(at),
    );
    assert_eq!(scanning.schedule_at(at).await, 1 + usize::from(expected), "{stamped:?}");
    assert_eq!(pending_for(&db, weekly).await, i64::from(expected));
    assert_eq!(
        count(
            &db,
            &format!(
                "select count(*) from t_scan where container_id = {image} and status = 'pending' and branch = 'n/a'"
            )
        )
        .await,
        1
    );

    // The lease table unreachable while the rest answers: the tick fails closed.
    clean(&db).await;
    let id = due(&db, "e").await;
    exec(&db, "alter table t_leader_lease rename to t_leader_lease_away").await;
    let skipped = scanning.schedule_at(now()).await;
    exec(&db, "alter table t_leader_lease_away rename to t_leader_lease").await;
    assert_eq!(skipped, 0, "an instance that cannot reach the lease is not entitled to assume it is alone");
    assert_eq!(pending_for(&db, id).await, 0);
}

// ── RetentionDatabaseTest ────────────────────────────────────────────────────────────────────

async fn with_payload(db: &Db, repo: i64, days_ago: u64) -> i64 {
    exec(db, &format!(
        "insert into t_scan (repo_id, branch, status, created_at, sbom, attempts, findings_count, new_issues_count, resolved_issues_count) values ({repo}, 'main', 'completed', {}, '{{\"artifacts\":[]}}', 0, 0, 0, 0)",
        literal(now() - Duration::from_secs(days_ago * 86_400))
    )).await;
    count(db, "select max(id) from t_scan").await
}

async fn set(db: &Db, keep: &str, days: &str) {
    let key = key(db);
    exec(db, &format!("delete from t_setting where {key} in ('retention_keep_per_target', 'retention_max_age_days')"))
        .await;
    exec(db, &format!("insert into t_setting ({key}, value) values ('retention_keep_per_target', '{keep}'), ('retention_max_age_days', '{days}')")).await;
}

/// `t_setting.key`, a reserved word on MySQL.
fn key(db: &Db) -> &'static str {
    match db {
        Db::MySql(_) => "`key`",
        Db::PostgreSql(_) => "key",
    }
}

async fn retention(db: Db) {
    let scanning = composed(&db).scanning;
    let repo = support::repository(&db, "kept").await;
    let has_sbom = |id: i64| format!("select count(*) from t_scan where id = {id} and sbom is not null");

    set(&db, "2", "30").await;
    let oldest = with_payload(&db, repo, 200).await;
    let middle = with_payload(&db, repo, 100).await;
    let newest = with_payload(&db, repo, 1).await;
    let second = with_payload(&db, repo, 2).await;
    assert_eq!(scanning.prune().await.unwrap(), 2);
    assert_eq!(count(&db, &has_sbom(newest)).await, 1);
    assert_eq!(count(&db, &has_sbom(second)).await, 1);
    assert_eq!(count(&db, &has_sbom(middle)).await, 0);
    assert_eq!(count(&db, &has_sbom(oldest)).await, 0);
    // The JSON-null trap: a purged row is not selected again.
    assert_eq!(scanning.prune().await.unwrap(), 0);
    assert_eq!(scanning.payload_count().await.unwrap(), 2);

    // Both axes must agree.
    exec(&db, "delete from t_scan").await;
    for days in 1..=3 {
        with_payload(&db, repo, days).await;
    }
    assert_eq!(scanning.prune().await.unwrap(), 0);

    // Zero on both disables purging.
    exec(&db, "delete from t_scan").await;
    set(&db, "0", "0").await;
    with_payload(&db, repo, 500).await;
    assert_eq!(scanning.prune().await.unwrap(), 0);
    let _ = Setting::RetentionKeepPerTarget;

    // The keep window protects what the age would purge: two old scans, both within the last two.
    exec(&db, "delete from t_scan").await;
    set(&db, "2", "30").await;
    with_payload(&db, repo, 200).await;
    with_payload(&db, repo, 100).await;
    assert_eq!(scanning.prune().await.unwrap(), 0);
}

// ── what targets reads of scans, and the purge ───────────────────────────────────────────────

async fn targets_side(db: Db) {
    let composed = composed(&db);
    let repo = support::repository(&db, "triggered").await;
    let image = support::container(&db, "service").await;
    let figures = vectispire_cp_scanning::target_scans(db.clone(), system_clock());
    let view = composed.targets.catalog_repository(repo).await.unwrap().unwrap();
    let queued = figures.queue_repository(&view, None).await.unwrap();
    assert_eq!(queued.status, "pending");
    match figures.queue_repository(&view, None).await {
        Err(vectispire_cp_targets::ports::QueueError::AlreadyQueued(message)) => {
            assert_eq!(message, "A scan of this target is already queued.");
        }
        other => panic!("{other:?}"),
    }
    let container = composed.targets.catalog_container(image).await.unwrap().unwrap();
    figures.queue_container(&container).await.unwrap();
    assert_eq!(
        text(&db, &format!("select branch from t_scan where container_id = {image}")).await.as_deref(),
        Some("n/a")
    );
    let latest = figures.latest_per_repository().await.unwrap();
    assert_eq!(latest[&repo].id, queued.id);
    assert_eq!(figures.latest_per_container().await.unwrap().len(), 1);

    // Languages: the newest completed scan's, unknown when it recorded none.
    exec(
        &db,
        &format!("update t_scan set status = 'completed', detected_languages = 'java,python' where id = {}", queued.id),
    )
    .await;
    let other = support::repository(&db, "never").await;
    let languages = figures.detected_languages(&[repo, other]).await.unwrap();
    assert_eq!(
        languages.get(&repo).map(|set| set.iter().cloned().collect::<Vec<_>>()),
        Some(vec!["java".to_owned(), "python".to_owned()])
    );
    assert!(!languages.contains_key(&other), "no completed scan is unknown, never none");
    // A newest completed scan that recorded no census is unknown too, never the empty set.
    exec(&db, &format!("insert into t_scan (repo_id, branch, status, created_at, attempts, findings_count, new_issues_count, resolved_issues_count) values ({other}, 'main', 'completed', {}, 1, 0, 0, 0)", literal(now()))).await;
    assert!(!figures.detected_languages(&[other]).await.unwrap().contains_key(&other));

    // A deletion takes the scans and their findings, through scanning's listeners in its transaction.
    exec(&db, &format!(
        "insert into t_finding (scan_id, type, source, is_kev, created_at, reachability) values ({}, 'secret', 'gitleaks', {}, {}, 'UNKNOWN')",
        queued.id,
        if matches!(db, Db::MySql(_)) { "0" } else { "false" },
        literal(now())
    )).await;
    let actor =
        vectispire_cp_audit::RequestActor { username: Some("admin".to_owned()), ip_address: None, user_agent: None };
    composed.targets.delete_repository(repo, &Visibility::Everything, &actor).await.unwrap();
    assert_eq!(count(&db, &format!("select count(*) from t_scan where repo_id = {repo}")).await, 0);
    assert_eq!(count(&db, "select count(*) from t_finding").await, 0);
    let names: Vec<String> = composed
        .targets
        .purge_registry()
        .names()
        .iter()
        .filter(|(name, _)| name.module == "scanning")
        .map(|(name, _)| name.listener.to_owned())
        .collect();
    assert_eq!(names, vec!["ScanPurge.purgeFindings", "ScanPurge.purgeScans"]);
    let _ = ScanTarget::Repository(0);
}

// ── the result ───────────────────────────────────────────────────────────────────────────────

async fn results(db: Db) {
    let composed = composed(&db);
    let scanning = composed.scanning.clone();
    let edge = support::agent(&db, "edge").await;
    let agent = ClaimingAgent {
        id: edge,
        name: Some("edge".to_owned()),
        labels: None,
        max_concurrent: Some(4),
        credentials_mode: Some("local".to_owned()),
        sealing_public_key: None,
        signing_public_key: None,
    };
    let image = support::container(&db, "service").await;
    async fn write(
        db: &Db,
        scanning: &vectispire_cp_scanning::Scanning,
        agent: &ClaimingAgent,
        image: i64,
        body: &'static str,
    ) -> i64 {
        exec(db, "delete from t_scan").await;
        support::scan(db, None, Some(image), None, base()).await;
        let task = scanning.dispatcher().claim_for_agent(agent).await.unwrap().unwrap();
        let artifacts = ScanArtifacts::read(body.as_bytes()).unwrap();
        assert!(scanning.dispatcher().accept_agent_result(task.scan_id, agent, &artifacts, None).await.unwrap());
        task.scan_id
    }
    // Every step absent and something broken: failed, never a clean scan.
    let id = write(
        &db,
        &scanning,
        &agent,
        image,
        r#"{"failures":[{"step":"dependencies","reason":"pull access denied for temurin"}],"duration":2.0}"#,
    )
    .await;
    assert_eq!(status(&db, id).await, "failed");
    assert_eq!(
        text(&db, &format!("select error from t_scan where id = {id}")).await.as_deref(),
        Some("dependencies: pull access denied for temurin")
    );
    // No duration is unknown, not a crash; a step that ran and found nothing stays completed.
    let id = write(&db, &scanning, &agent, image, r#"{"secrets":[],"sbom":{"b" : 1.0, "a":[ 1e2 ,"é"]},"project":{"type":"maven","version":"1.2"},"languages":["Java","cobol"]}"#).await;
    assert_eq!(status(&db, id).await, "completed");
    assert_eq!(count(&db, &format!("select count(*) from t_scan where id = {id} and duration_ms is null and claimed_by is null and lease_expires_at is null")).await, 1);
    // The SBOM as Jackson's tree writes it back, not the bytes as sent.
    assert_eq!(
        text(&db, &format!("select sbom from t_scan where id = {id}")).await.as_deref(),
        Some(r#"{"b":1.0,"a":[100.0,"é"]}"#)
    );
    assert_eq!(text(&db, &format!("select project_type from t_scan where id = {id}")).await.as_deref(), Some("maven"));
    assert_eq!(
        text(&db, &format!("select detected_languages from t_scan where id = {id}")).await.as_deref(),
        Some("java")
    );
    assert_eq!(text(&db, &format!("select error from t_scan where id = {id}")).await, None);
    // A result without a project leaves what an earlier one read.
    exec(&db, "delete from t_scan").await;
    support::scan(&db, None, Some(image), None, base()).await;
    let task = scanning.dispatcher().claim_for_agent(&agent).await.unwrap().unwrap();
    exec(&db, &format!("update t_scan set project_type = 'gradle', version = '9' where id = {}", task.scan_id)).await;
    let artifacts = ScanArtifacts::read(br#"{"secrets":[]}"#).unwrap();
    assert!(scanning.dispatcher().accept_agent_result(task.scan_id, &agent, &artifacts, None).await.unwrap());
    assert_eq!(
        text(&db, &format!("select project_type from t_scan where id = {}", task.scan_id)).await.as_deref(),
        Some("gradle")
    );
    // A result for a scan taken over meanwhile is discarded.
    exec(&db, "delete from t_scan").await;
    support::scan(&db, None, Some(image), None, base()).await;
    let task = scanning.dispatcher().claim_for_agent(&agent).await.unwrap().unwrap();
    exec(&db, &format!("update t_scan set claimed_by = 'somebody-else' where id = {}", task.scan_id)).await;
    let artifacts = ScanArtifacts::read(br#"{"secrets":[]}"#).unwrap();
    assert!(!scanning.dispatcher().accept_agent_result(task.scan_id, &agent, &artifacts, None).await.unwrap());
    assert_eq!(status(&db, task.scan_id).await, "scanning");
    // An agent's failure report, through the dispatcher: the sentence on the row.
    exec(&db, &format!("update t_scan set claimed_by = '{edge}' where id = {}", task.scan_id)).await;
    let failure = scanning
        .dispatcher()
        .report_agent_failure(task.scan_id, &agent, 1, FailureKind::Transient, "clone refused")
        .await
        .unwrap()
        .unwrap();
    assert!(failure.retried);
    let error = text(&db, &format!("select error from t_scan where id = {}", task.scan_id)).await.unwrap();
    assert!(
        error.starts_with("Attempt 1 of 3 could not run on agent \"edge\"; the scan is back in the queue, not before "),
        "{error}"
    );
    assert!(error.ends_with(": clone refused"), "{error}");

    let _ = Uuid::nil();
}

// ── the built-in worker (ScanDispatcherTest's cases with a runner) ────────────────────────────

/// A runner that answers what it is told, and remembers the tasks it ran.
struct Runner {
    tasks: Mutex<Vec<vectispire_protocol::ScanTask>>,
    answer: Box<dyn Fn(usize) -> Result<&'static str, vectispire_cp_scanning::ports::RunFailure> + Send + Sync>,
    during: Mutex<Option<String>>,
    db: Db,
}

impl vectispire_cp_scanning::ports::ScanRunner for Runner {
    fn run<'a>(
        &'a self,
        task: &'a vectispire_protocol::ScanTask,
    ) -> BoxFuture<'a, Result<vectispire_protocol::Received<'static>, vectispire_cp_scanning::ports::RunFailure>> {
        Box::pin(async move {
            let index = {
                let mut tasks = self.tasks.lock().unwrap();
                tasks.push(task.clone());
                tasks.len()
            };
            let during = self.during.lock().unwrap().take();
            if let Some(statement) = during {
                exec(&self.db, &statement).await;
            }
            let body = (self.answer)(index)?;
            Ok(ScanArtifacts::read(body.as_bytes()).unwrap().into_owned())
        })
    }
}

fn runner(
    db: &Db,
    answer: impl Fn(usize) -> Result<&'static str, vectispire_cp_scanning::ports::RunFailure> + Send + Sync + 'static,
) -> Arc<Runner> {
    Arc::new(Runner {
        tasks: Mutex::new(Vec::new()),
        answer: Box::new(answer),
        during: Mutex::new(None),
        db: db.clone(),
    })
}

const PRIVATE_KEY: &str = "test-ssh-private-key-material";

async fn built_in_worker(db: Db) {
    use vectispire_cp_scanning::ports::RunFailure;
    // Without a runner the round claims nothing: a claim it cannot honour would burn an attempt per round.
    let idle = composed(&db);
    let image = support::container(&db, "service").await;
    let waiting = support::scan(&db, None, Some(image), None, base()).await;
    assert_eq!(idle.scanning.dispatcher().dispatch("worker-1", 4, &[]).await.unwrap(), Default::default());
    assert_eq!(status(&db, waiting).await, "pending");

    // A repository with a deployment key: the worker receives the whole task in the clear.
    let encryption = support::encryption();
    let key_id = Uuid::new_v4();
    let ciphertext =
        encryption.encrypt(PRIVATE_KEY, &vectispire_cp_crypto::private_key_context(&key_id.to_string())).await.unwrap();
    exec(&db, &format!("insert into t_ssh_key (id, name, private_key, created_at) values ('{key_id}', 'deploy', '{ciphertext}', {})", literal(now()))).await;
    let repo = support::repository(&db, "keyed").await;
    exec(&db, &format!("update t_repository set ssh_key_id = '{key_id}', sub_path = 'services/api' where id = {repo}"))
        .await;
    exec(&db, "delete from t_scan").await;
    let clean_scan = support::scan(&db, Some(repo), None, None, base()).await;
    let running = runner(&db, |_| Ok(r#"{"secrets":[],"duration":1.0}"#));
    let worker = compose_running(&db, running.clone());
    let scan_worker = vectispire_cp_scanning::ScanWorker::with_identity(
        worker.scanning.dispatcher_arc(),
        vectispire_cp_scanning::WorkerProperties { enabled: true, max_concurrent: 2, labels: String::new() },
        "worker-1".to_owned(),
    );
    let round = scan_worker.round().await.unwrap();
    assert_eq!((round.claimed, round.completed, round.failed), (1, 1, 0));
    assert_eq!(status(&db, clean_scan).await, "completed");

    let tick_scan = support::scan(&db, Some(repo), None, None, base()).await;
    assert!(scan_worker.tick());
    for _ in 0..100 {
        if status(&db, tick_scan).await == "completed" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status(&db, tick_scan).await, "completed");
    let task = running.tasks.lock().unwrap()[0].clone();
    match &task.target {
        vectispire_protocol::Target::Repository(repository) => {
            assert_eq!(
                repository.private_key.as_ref().map(|key| key.expose().to_owned()).as_deref(),
                Some(PRIVATE_KEY)
            );
            assert_eq!(repository.sub_path.as_deref(), Some("services/api"));
        }
        vectispire_protocol::Target::Image(_) => panic!("a repository's task"),
    }

    // The room is this worker's limit less its own scans, whatever the agents hold.
    exec(&db, "delete from t_scan").await;
    for _ in 0..3 {
        support::scan(&db, Some(repo), None, None, base()).await;
    }
    exec(&db, &format!("update t_scan set status = 'scanning', claimed_by = 'some-agent', lease_expires_at = {} where id = (select max(id) from t_scan)", literal(now() + Duration::from_secs(600))).replace("(select max(id) from t_scan)", &count(&db, "select max(id) from t_scan").await.to_string())).await;
    let round = worker.scanning.dispatcher().dispatch("worker-1", 2, &[]).await.unwrap();
    assert_eq!(round.claimed, 2, "the agents' scans leave this worker's room alone");

    // A transient failure retries as an agent's would, scrubbed of the task's secrets.
    exec(&db, "delete from t_scan").await;
    let failing_scan = support::scan(&db, Some(repo), None, None, base()).await;
    let failing = runner(&db, |_| {
        Err(RunFailure {
            message: format!("Cannot connect to the Docker daemon while cloning with {PRIVATE_KEY} token=abc123def"),
            kind: FailureKind::Transient,
        })
    });
    let worker = compose_running(&db, failing);
    let round = worker.scanning.dispatcher().dispatch("worker-1", 2, &[]).await.unwrap();
    assert_eq!((round.claimed, round.completed, round.failed), (1, 0, 1));
    let error = text(&db, &format!("select error from t_scan where id = {failing_scan}")).await.unwrap();
    assert!(error.contains("Attempt 1 of 3 could not run on the built-in worker"), "{error}");
    assert!(error.contains("back in the queue"), "{error}");
    assert!(error.contains("Cannot connect to the Docker daemon"), "{error}");
    assert!(!error.contains(PRIVATE_KEY) && !error.contains("abc123def"), "{error}");
    assert_eq!(status(&db, failing_scan).await, "pending");

    // A permanent one fails at once.
    exec(&db, "delete from t_scan").await;
    let refused_scan = support::scan(&db, Some(repo), None, None, base()).await;
    let refusing = runner(&db, |_| {
        Err(RunFailure { message: "The host key has changed.".to_owned(), kind: FailureKind::Permanent })
    });
    compose_running(&db, refusing).scanning.dispatcher().dispatch("worker-1", 2, &[]).await.unwrap();
    assert_eq!(status(&db, refused_scan).await, "failed");
    let error = text(&db, &format!("select error from t_scan where id = {refused_scan}")).await.unwrap();
    assert!(
        error.contains("another attempt would meet the same refusal") && error.contains("The host key has changed."),
        "{error}"
    );

    // Results the worker could not write retry, as an undelivered upload would: a null failure is Java's NPE.
    exec(&db, "delete from t_scan").await;
    let unwritten = support::scan(&db, Some(repo), None, None, base()).await;
    let broken = runner(&db, |_| Ok(r#"{"secrets":[],"failures":[null]}"#));
    let round = compose_running(&db, broken).scanning.dispatcher().dispatch("worker-1", 2, &[]).await.unwrap();
    assert_eq!(round.failed, 1);
    assert_eq!(status(&db, unwritten).await, "pending");
    assert!(
        text(&db, &format!("select error from t_scan where id = {unwritten}"))
            .await
            .unwrap()
            .contains("Attempt 1 of 3 could not run on the built-in worker")
    );

    // A scan taken over before its turn in the round is not run.
    exec(&db, "delete from t_scan").await;
    let first = support::scan(&db, Some(repo), None, None, base()).await;
    let second = support::scan(&db, Some(repo), None, None, base() + Duration::from_secs(1)).await;
    let watching = runner(&db, |_| Ok(r#"{"secrets":[]}"#));
    *watching.during.lock().unwrap() =
        Some(format!("update t_scan set claimed_by = 'another-instance' where id = {second}"));
    let round =
        compose_running(&db, watching.clone()).scanning.dispatcher().dispatch("worker-1", 2, &[]).await.unwrap();
    assert_eq!(watching.tasks.lock().unwrap().len(), 1, "the second scan, taken over meanwhile, is not run");
    assert_eq!((round.claimed, round.completed, round.failed), (2, 1, 1));
    assert_eq!(status(&db, first).await, "completed");
    assert_eq!(status(&db, second).await, "scanning");
}

fn compose_running(db: &Db, runner: Arc<Runner>) -> Composed {
    support::compose_running(
        db,
        system_clock(),
        Policy::default(),
        vectispire_domain::git_host_allowlist::GitHostAllowlist::default(),
        Some(runner),
    )
}

/// An instant as the module's rules read it.
fn instant_of(at: OffsetDateTime) -> vectispire_domain::instant::Instant {
    vectispire_domain::instant::Instant { epoch_second: at.unix_timestamp(), nano: at.nanosecond() }
}

// ── LongFindingIntegrationTest ───────────────────────────────────────────────────────────────

async fn long_findings(db: Db) {
    exec(
        &db,
        "insert into t_repository (url, branch, name) values ('ssh://git@example.com/team/long.git', 'main', 'long')",
    )
    .await;
    let repo = count(&db, "select id from t_repository where name = 'long'").await;
    let scan_id = support::scan(&db, Some(repo), None, None, base()).await;

    let path = format!("src/{}index.js", "d/".repeat(400));
    let dep_id = format!("GHSA-{}", "x".repeat(300));
    let fix_v = format!("1.{}", "0".repeat(400));
    let link = format!("https://advisories.example/{}", "l".repeat(600));
    let purl = format!("pkg:npm/{}", "p".repeat(600));
    let body = serde_json::json!({
        "dependencies": [{
            "identifier": dep_id,
            "severity": "HIGH",
            "packageName": "left-pad",
            "installedVersion": "1.0.0",
            "fixVersions": fix_v,
            "referenceUrl": link,
            "purl": purl
        }],
        "secrets": [{
            "rule": "aws-key",
            "description": "AWS token",
            "file": path,
            "line": 12,
            "fingerprint": "abc"
        }]
    });

    let bytes = serde_json::to_vec(&body).unwrap();
    let artifacts = ScanArtifacts::read(&bytes).unwrap();
    let mut tx = db.begin(vectispire_cp_db::Mode::ReadWrite).await.unwrap();
    let scan_view = composed(&db).scanning.queue().by_id_in(&mut tx, scan_id).await.unwrap().unwrap();
    let ingestor = vectispire_cp_scanning::ingestion::ScanIngestor::new(
        Arc::new(vectispire_cp_scanning::ingestion::NoBacklog),
        Arc::new(vectispire_cp_scanning::ingestion::NoInventory),
        None,
        None,
        None,
        system_clock(),
    );
    let prepared = ingestor.prepare(&scan_view, &artifacts).await;
    let _result = ingestor.ingest(&mut tx, &scan_view, &artifacts, &prepared).await.unwrap();
    tx.commit().await.unwrap();

    let findings_count = count(&db, "select count(*) from t_finding").await;
    assert_eq!(findings_count, 2);

    let b = bigint(&db);
    let purl_len = count(&db, &format!("select cast(length(purl) as {b}) from t_finding where purl is not null")).await;
    assert_eq!(purl_len, 255);
    let link_len = count(&db, &format!("select cast(length(link) as {b}) from t_finding where link is not null")).await;
    assert_eq!(link_len, 500);
    let path_len =
        count(&db, &format!("select cast(length(file_path) as {b}) from t_finding where file_path is not null")).await;
    assert_eq!(path_len, 500);
}

// ── LicenseService reads LICENSE_BLOCKLIST per scan ─────────────────────────────────────────────

/// Java's `LicenseService.blocklist()` reads the setting on every call, so an administrator's change applies to the
/// next scan. The Rust service was built with a list fixed at start — and the binary composed none at all, so no
/// licence was ever checked. Held here on a database, through the settings store the binary hands it.
async fn license_blocklist_per_scan(db: Db) {
    use vectispire_cp_scanning::ingestion::{LicenseService, LicenseSource};

    let sbom = serde_json::json!({
        "artifacts": [{
            "name": "copyleft-lib",
            "version": "1.0.0",
            "purl": "pkg:npm/copyleft-lib@1.0.0",
            "licenses": [{"value": "GPL-3.0-only"}]
        }]
    });
    let service = LicenseService::from_settings(vectispire_cp_settings::Settings::new(db.clone()));
    let k = key(&db);

    assert!(service.findings(&sbom).await.unwrap().is_empty(), "no list configured, nothing is forbidden");

    exec(&db, &format!("insert into t_setting ({k}, value) values ('license_blocklist', 'GPL-3.0-only')")).await;
    let found = service.findings(&sbom).await.unwrap();
    assert_eq!(found.len(), 1, "the list stored after the service was built applies");
    assert_eq!(found[0].identifier.as_deref(), Some("GPL-3.0-only"));

    exec(&db, &format!("update t_setting set value = 'AGPL-3.0-only' where {k} = 'license_blocklist'")).await;
    assert!(service.findings(&sbom).await.unwrap().is_empty(), "a change applies to the next scan");

    exec(&db, &format!("delete from t_setting where {k} = 'license_blocklist'")).await;
}
