//! `t_one_shot_job` on real servers, both engines: the claim that commits with its work, the one that rolls back
//! with it, and two instances starting together — the case the table exists for, which no reading of the code can
//! settle, because the second insert's wait on the first's uncommitted row is the engine's behaviour.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use support::Migrated;
use time::OffsetDateTime;
use vectispire_cp_db::{Engine, Mode};
use vectispire_cp_maintenance::{Clock, OneShotJobs, SystemClock};

#[derive(Debug)]
struct Fixed(OffsetDateTime);

impl Clock for Fixed {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

async fn a_claim_commits_with_its_work_and_is_refused_after(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    // Nanoseconds the column cannot keep: the row holds the microsecond, as Java's microsecond clock writes it.
    let at = OffsetDateTime::from_unix_timestamp_nanos(1_790_000_000_123_456_789).unwrap();
    let jobs = OneShotJobs::new(db.clone(), Arc::new(Fixed(at)));
    assert!(!jobs.has_run("repair-withheld-claims").await.unwrap());

    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    jobs.claim(&mut tx, "repair-withheld-claims").await.unwrap();
    // Not yet committed: another connection does not see it — the read is on its own connection.
    assert!(!jobs.has_run("repair-withheld-claims").await.unwrap());
    tx.commit().await.unwrap();
    assert!(jobs.has_run("repair-withheld-claims").await.unwrap());
    let stored = server.sql_as_admin(match engine {
        Engine::MySql => "select date_format(ran_at, '%Y-%m-%d %H:%i:%s.%f') from t_one_shot_job",
        Engine::PostgreSql => {
            "select to_char(ran_at at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') from t_one_shot_job"
        }
    });
    assert_eq!(stored.trim(), "2026-09-21 14:13:20.123456", "the instant, at the microsecond, in UTC");

    // Run again, it is refused, and the refusal is not mistaken for anything else: the row says it ran.
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    assert!(jobs.claim(&mut tx, "repair-withheld-claims").await.is_err());
    tx.rollback().await.unwrap();
    assert!(jobs.has_run("repair-withheld-claims").await.unwrap());
    // Another job is its own row.
    assert!(!jobs.has_run("resume-target-deletions").await.unwrap());
}

async fn a_claim_rolled_back_with_its_work_leaves_the_job_to_the_next_start(engine: Engine) {
    let server = Migrated::start(engine).await;
    let db = server.connect().await;
    let jobs = OneShotJobs::new(db.clone(), Arc::new(SystemClock));
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    jobs.claim(&mut tx, "half-way").await.unwrap();
    tx.rollback().await.unwrap();
    assert!(!jobs.has_run("half-way").await.unwrap(), "a job that failed half-way is not recorded as run");
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    jobs.claim(&mut tx, "half-way").await.unwrap();
    tx.commit().await.unwrap();
    assert!(jobs.has_run("half-way").await.unwrap());
}

/// Two instances starting together: the second insert waits on the first's uncommitted row, then fails once it
/// commits — and `has_run`, asked after the loser's rollback, says the job is held, which is how the loser knows it
/// lost rather than failed.
async fn of_two_instances_starting_together_one_runs(engine: Engine) {
    let server = Migrated::start(engine).await;
    let first = OneShotJobs::new(server.connect().await, Arc::new(SystemClock));
    let second_db = server.connect().await;
    let second = OneShotJobs::new(second_db.clone(), Arc::new(SystemClock));
    let first_db = server.connect().await;

    let mut winner = first_db.begin(Mode::ReadWrite).await.unwrap();
    first.claim(&mut winner, "repair").await.unwrap();

    let racer = tokio::spawn(async move {
        let mut tx = second_db.begin(Mode::ReadWrite).await.unwrap();
        let claimed = second.claim(&mut tx, "repair").await;
        tx.rollback().await.unwrap();
        (claimed.is_ok(), second.has_run("repair").await.unwrap())
    });
    // The second insert is blocked on the first's row, not refused at once: it is still running.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(!racer.is_finished(), "{engine}: the second claim waits for the first transaction to end");
    winner.commit().await.unwrap();
    let (claimed, held) = racer.await.unwrap();
    assert!(!claimed, "{engine}: the second instance's claim fails");
    assert!(held, "{engine}: and the row tells it the job is held elsewhere");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_claim_commits_with_its_work_and_is_refused_after_on_mysql() {
    a_claim_commits_with_its_work_and_is_refused_after(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_claim_commits_with_its_work_and_is_refused_after_on_postgresql() {
    a_claim_commits_with_its_work_and_is_refused_after(Engine::PostgreSql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_claim_rolled_back_leaves_the_job_on_mysql() {
    a_claim_rolled_back_with_its_work_leaves_the_job_to_the_next_start(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_claim_rolled_back_leaves_the_job_on_postgresql() {
    a_claim_rolled_back_with_its_work_leaves_the_job_to_the_next_start(Engine::PostgreSql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn of_two_instances_one_runs_on_mysql() {
    of_two_instances_starting_together_one_runs(Engine::MySql).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn of_two_instances_one_runs_on_postgresql() {
    of_two_instances_starting_together_one_runs(Engine::PostgreSql).await;
}
