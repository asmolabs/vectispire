//! The two failure fates of a clone on the built-in worker: `CloneFailureFateTest`'s port.
//!
//! A repository its server does not have fails at its first attempt, says so, and is not retried.
//! A host that cannot be reached waits a minute, then five, and fails as the last of three.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_scanning::BuiltInScanRunner;
use vectispire_cp_scanning::ports::BundledRules;
use vectispire_cp_targets::Clock;
use vectispire_domain::git_host_allowlist::GitHostAllowlist;
use vectispire_domain::scan_queue::Policy;
use vectispire_runner::{Images, Places};

use support::{Migrated, MovingClock, compose_running, count, exec, text};

/// What `git daemon` answers for a path it does not serve: one pkt-line, `ERR` and its
/// sentence, as git 2.55's daemon sends it (`CloneFailureFateTest.GitDaemonRefusing`).
struct GitDaemonRefusing {
    port: u16,
    requests: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl GitDaemonRefusing {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        let reqs = requests.clone();
        let stop = shutdown.clone();

        let handle = std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        reqs.fetch_add(1, Ordering::SeqCst);
                        let mut len_bytes = [0u8; 4];
                        if stream.read_exact(&mut len_bytes).is_ok()
                            && let Ok(len_str) = std::str::from_utf8(&len_bytes)
                            && let Ok(len) = usize::from_str_radix(len_str, 16)
                            && len >= 4
                        {
                            let mut body = vec![0u8; len - 4];
                            let _ = stream.read_exact(&mut body);
                            let body_str = String::from_utf8_lossy(&body);
                            // "git-upload-pack /path\0host=...\0"
                            let path = body_str
                                .split_whitespace()
                                .nth(1)
                                .unwrap_or("missing.git")
                                .split('\0')
                                .next()
                                .unwrap_or("missing.git");
                            let refusal = format!("ERR access denied or repository not exported: {path}");
                            let response = format!("{:04x}{refusal}", refusal.len() + 4);
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.flush();
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self { port, requests, shutdown, handle: Some(handle) }
    }

    fn url(&self, path: &str) -> String {
        format!("git://127.0.0.1:{}/{}", self.port, path)
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for GitDaemonRefusing {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn base_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_786_615_200).unwrap() // 2026-08-13T10:00:00Z
}

fn bigint(db: &Db) -> &'static str {
    match db {
        Db::MySql(_) => "signed",
        Db::PostgreSql(_) => "bigint",
    }
}

async fn custom_repository(db: &Db, name: &str, url: &str) -> i64 {
    exec(db, &format!("insert into t_repository (url, branch, name) values ('{url}', 'main', '{name}')")).await;
    count(db, &format!("select max(id) from t_repository where name = '{name}'")).await
}

async fn run_fate_suite(engine: Engine) {
    let database = Migrated::start(engine).await;
    let db = database.connect().await;

    // Set up temp directories for the runner
    let work_dir = std::env::temp_dir().join(format!("clone-fate-{}", Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&work_dir);
    let places = Places { work: work_dir.clone(), home: work_dir.join("home") };

    let runner = Arc::new(
        BuiltInScanRunner::new(
            Arc::new(BundledRules),
            Images::from_lookup(|_| None),
            places,
            None,
            vectispire_tls::TlsTrust::BuiltIn,
        )
        .expect("BuiltInScanRunner creation"),
    );

    let clock = MovingClock::at(base_time());
    let policy = Policy::default();
    let hosts = GitHostAllowlist::default();
    let composed = compose_running(&db, clock.clone(), policy, hosts, Some(runner));

    // ──────────────────────────────────────────────────────────────────────────────────────────
    // 1. A repository its server does not have fails at its first attempt, says so, and is not retried
    // ──────────────────────────────────────────────────────────────────────────────────────────
    let daemon = GitDaemonRefusing::new();
    let missing_url = daemon.url("missing.git");
    let repo_id = custom_repository(&db, "missing-repo", &missing_url).await;
    let scan_id = support::scan(&db, Some(repo_id), None, None, clock.now()).await;

    let round = composed.scanning.dispatcher().dispatch("built-in-clone-fate", 1, &[]).await.unwrap();
    assert_eq!((round.claimed, round.completed, round.failed), (1, 0, 1));

    let scan_status = text(&db, &format!("select status from t_scan where id = {scan_id}")).await.unwrap();
    let scan_attempts = count(
        &db,
        &format!("select cast(attempts as bigint) from t_scan where id = {scan_id}").replace("bigint", bigint(&db)),
    )
    .await;
    let scan_not_before = text(&db, &format!("select not_before from t_scan where id = {scan_id}")).await;
    let scan_error = text(&db, &format!("select error from t_scan where id = {scan_id}")).await.unwrap();

    assert_eq!(scan_status, "failed");
    assert_eq!(scan_attempts, 1);
    assert!(scan_not_before.is_none(), "no retry scheduled for permanent failure");
    assert!(
        scan_error.starts_with(
            "Attempt 1 of 3 could not run on the built-in worker, and another attempt would meet the same refusal: "
        ),
        "expected permanent error prefix, got: {scan_error}"
    );
    assert!(
        scan_error.ends_with(&format!("{missing_url} could not be found.")),
        "expected 'could not be found.' suffix, got: {scan_error}"
    );
    assert_eq!(daemon.requests(), 1, "one clone, one refusal");

    // Advance clock by 1 hour: a failed scan is never taken again
    clock.advance(Duration::from_secs(3600));
    let next_round = composed.scanning.dispatcher().dispatch("built-in-clone-fate", 1, &[]).await.unwrap();
    assert_eq!(next_round.claimed, 0, "a failed scan is never taken again");
    assert_eq!(daemon.requests(), 1);

    // ──────────────────────────────────────────────────────────────────────────────────────────
    // 2. A host that cannot be reached waits a minute, then five, and fails as the last of three
    // ──────────────────────────────────────────────────────────────────────────────────────────
    // `.invalid` never resolves (RFC 6761), here or on any runner.
    let unreachable_url = "git://forge.vectispire.invalid/team/repo.git";
    let failed_at = clock.now();
    let repo_2 = custom_repository(&db, "unreachable-repo", unreachable_url).await;
    let scan_2 = support::scan(&db, Some(repo_2), None, None, failed_at).await;

    // Attempt 1
    let round1 = composed.scanning.dispatcher().dispatch("built-in-clone-fate", 1, &[]).await.unwrap();
    assert_eq!((round1.claimed, round1.completed, round1.failed), (1, 0, 1));

    let scan2_status = text(&db, &format!("select status from t_scan where id = {scan_2}")).await.unwrap();
    let scan2_attempts = count(
        &db,
        &format!("select cast(attempts as bigint) from t_scan where id = {scan_2}").replace("bigint", bigint(&db)),
    )
    .await;
    let scan2_error = text(&db, &format!("select error from t_scan where id = {scan_2}")).await.unwrap();

    assert_eq!(scan2_status, "pending");
    assert_eq!(scan2_attempts, 1);
    assert!(scan2_error.contains("Attempt 1 of 3 could not run on the built-in worker; the scan is back in the queue"));
    assert!(scan2_error.contains("could not reach its host. Is the repository reachable from this machine?"));

    // Advance 59 seconds: a second before its minute, the scan waits
    clock.advance(Duration::from_secs(59));
    let wait_round = composed.scanning.dispatcher().dispatch("built-in-clone-fate", 1, &[]).await.unwrap();
    assert_eq!(wait_round.claimed, 0, "a second before its minute, the scan waits");

    // Advance 1 second (total 60s): at its minute, it is taken again
    clock.advance(Duration::from_secs(1));
    let round2 = composed.scanning.dispatcher().dispatch("built-in-clone-fate", 1, &[]).await.unwrap();
    assert_eq!((round2.claimed, round2.completed, round2.failed), (1, 0, 1));

    let scan2_status_2 = text(&db, &format!("select status from t_scan where id = {scan_2}")).await.unwrap();
    let scan2_attempts_2 = count(
        &db,
        &format!("select cast(attempts as bigint) from t_scan where id = {scan_2}").replace("bigint", bigint(&db)),
    )
    .await;
    assert_eq!(scan2_status_2, "pending");
    assert_eq!(scan2_attempts_2, 2);

    // Advance 4 minutes 59 seconds: waits
    clock.advance(Duration::from_secs(299));
    let wait_round_2 = composed.scanning.dispatcher().dispatch("built-in-clone-fate", 1, &[]).await.unwrap();
    assert_eq!(wait_round_2.claimed, 0);

    // Advance 1 second (total 5m): third round runs and fails as the last
    clock.advance(Duration::from_secs(1));
    let round3 = composed.scanning.dispatcher().dispatch("built-in-clone-fate", 1, &[]).await.unwrap();
    assert_eq!((round3.claimed, round3.completed, round3.failed), (1, 0, 1));

    let scan2_status_3 = text(&db, &format!("select status from t_scan where id = {scan_2}")).await.unwrap();
    let scan2_attempts_3 = count(
        &db,
        &format!("select cast(attempts as bigint) from t_scan where id = {scan_2}").replace("bigint", bigint(&db)),
    )
    .await;
    let scan2_not_before_3 = text(&db, &format!("select not_before from t_scan where id = {scan_2}")).await;
    let scan2_error_3 = text(&db, &format!("select error from t_scan where id = {scan_2}")).await.unwrap();

    assert_eq!(scan2_status_3, "failed");
    assert_eq!(scan2_attempts_3, 3);
    assert!(scan2_not_before_3.is_none());
    assert!(scan2_error_3.starts_with("Attempt 3 of 3 could not run on the built-in worker, and it was the last: "));

    let _ = std::fs::remove_dir_all(&work_dir);
    db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clone_failure_fates_on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    run_fate_suite(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clone_failure_fates_on_postgres() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    run_fate_suite(Engine::PostgreSql).await;
}
