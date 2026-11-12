//! Multi-engine integration tests against MySQL 9.4 and PostgreSQL 17:
//! `AgentSealingKeyIntegrationTest`, `WithheldClaimRepairIntegrationTest`, `AgentDirectory`, and `AgentRowLock`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::print_stdout
)]

mod support;

use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_access::credentials::AgentDirectory;
use vectispire_cp_audit::{AuditLogQuery, AuditOperation, Record};
use vectispire_cp_db::{Db, Engine, Mode};
use vectispire_cp_maintenance::OneShotJobs;
use vectispire_cp_scanning::ports::AgentClaimLock;
use vectispire_crypto::SealingKeyPair;

use support::{
    Migrated, accept_sealing_key, agent, attempts, clean, compose, container, count, forget_sealing_key, repository,
    scan, ssh_key, status, system_clock, text,
};
use vectispire_cp_agents::{AgentDirectoryImpl, AgentRowLock, RepairOutcome, WithheldClaimRepair};

/// 2026-09-26 in epoch milliseconds: larger than a 32-bit int, testing width and comparison.
const NOW: i64 = 1_790_380_800_000;

#[tokio::test]
async fn sealing_keys_on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    let migrated = Migrated::start(Engine::MySql).await;
    let db = migrated.connect().await;
    clean(&db).await;
    test_sealing_keys(&db).await;
    db.close().await;
}

#[tokio::test]
async fn sealing_keys_on_postgres() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    let migrated = Migrated::start(Engine::PostgreSql).await;
    let db = migrated.connect().await;
    clean(&db).await;
    test_sealing_keys(&db).await;
    db.close().await;
}

async fn test_sealing_keys(db: &Db) {
    // 1. only_forwards
    let id = agent(db, &format!("sealing-{}", Uuid::new_v4()), "delegated").await;
    let first = SealingKeyPair::generate().public_key();
    let second = SealingKeyPair::generate().public_key();

    assert_eq!(accept_sealing_key(db, id, &first, NOW).await, 1, "first key accepted");
    assert_eq!(accept_sealing_key(db, id, &first, NOW).await, 1, "the same key repeated");
    assert_eq!(accept_sealing_key(db, id, &second, NOW).await, 0, "another key, same generation");
    assert_eq!(accept_sealing_key(db, id, &second, NOW - 1).await, 0, "an older generation");
    assert_eq!(accept_sealing_key(db, id, &second, NOW + 1).await, 1, "a newer generation");

    let row_key = text(db, &format!("select sealing_public_key from t_agent where id = '{id}'")).await.unwrap();
    assert_eq!(row_key, second);

    let cast = match db {
        Db::MySql(_) => "cast(sealing_key_generation as signed)",
        Db::PostgreSql(_) => "cast(sealing_key_generation as bigint)",
    };
    let row_gen = count(db, &format!("select {cast} from t_agent where id = '{id}'")).await;
    assert_eq!(row_gen, NOW + 1);

    // 2. a_reset_starts_over
    let id2 = agent(db, &format!("sealing-reset-{}", Uuid::new_v4()), "delegated").await;
    accept_sealing_key(db, id2, &SealingKeyPair::generate().public_key(), NOW).await;

    assert_eq!(forget_sealing_key(db, id2).await, 1, "forget returns 1");
    let forgotten_key = text(db, &format!("select sealing_public_key from t_agent where id = '{id2}'")).await;
    assert!(forgotten_key.is_none(), "public key cleared");

    let third = SealingKeyPair::generate().public_key();
    assert_eq!(accept_sealing_key(db, id2, &third, NOW - 60_000).await, 1, "older generation accepted after reset");
    assert_eq!(forget_sealing_key(db, Uuid::new_v4()).await, 0, "unknown agent returns 0");
}

#[tokio::test]
async fn withheld_claim_repair_on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    let migrated = Migrated::start(Engine::MySql).await;
    let db = migrated.connect().await;
    clean(&db).await;
    test_withheld_claim_repair(&db).await;
    db.close().await;
}

#[tokio::test]
async fn withheld_claim_repair_on_postgres() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    let migrated = Migrated::start(Engine::PostgreSql).await;
    let db = migrated.connect().await;
    clean(&db).await;
    test_withheld_claim_repair(&db).await;
    db.close().await;
}

async fn test_withheld_claim_repair(db: &Db) {
    let composed = compose(db, system_clock());

    let key_id = ssh_key(db, "deploy").await;
    let keyed = repository(db, "keyed", Some(key_id)).await;
    let open = repository(db, "open", None).await;

    // Delegated agent
    agent(db, "delegated-worker", "delegated").await;

    let inflated = scan(db, Some(keyed), None, "pending", 7).await;
    let delivered = scan(db, Some(keyed), None, "pending", 2).await;

    // Record delivery in audit log
    composed
        .audit
        .record(Record::of(
            AuditOperation::AgentCredentialSent,
            &delivered.to_string(),
            "Deployment key delegated.",
            Some("edge"),
        ))
        .await;

    let without_credential = scan(db, Some(open), None, "pending", 2).await;
    let running = scan(db, Some(keyed), None, "scanning", 1).await;
    let exhausted = scan(db, Some(keyed), None, "failed", 3).await;
    let image = scan(db, None, Some(container(db, "img").await), "pending", 1).await;
    let fresh = scan(db, Some(keyed), None, "pending", 0).await;

    let repair = WithheldClaimRepair::new(
        db.clone(),
        composed.scanning.catalog().clone(),
        composed.targets.clone(),
        Arc::new(AuditLogQuery::new((*composed.audit).clone(), Arc::new(vectispire_cp_audit::SystemClock), Vec::new())),
        composed.audit.clone(),
        Arc::new(OneShotJobs::new(db.clone(), Arc::new(vectispire_cp_maintenance::SystemClock))),
    );

    let outcome = repair.repair_once().await.expect("repair succeeds");
    assert_eq!(outcome, RepairOutcome::Repaired(vec![inflated]), "only inflated was repaired");

    assert_eq!(attempts(db, inflated).await, 0, "inflated reset to 0");
    assert_eq!(attempts(db, delivered).await, 2, "delivered untouched");
    assert_eq!(attempts(db, without_credential).await, 2, "without_credential untouched");
    assert_eq!(attempts(db, running).await, 1, "running untouched");
    assert_eq!(attempts(db, exhausted).await, 3, "exhausted untouched");
    assert_eq!(status(db, exhausted).await, "failed", "exhausted still failed");
    assert_eq!(attempts(db, image).await, 1, "image untouched");
    assert_eq!(attempts(db, fresh).await, 0, "fresh untouched");

    // Second run is AlreadyDone
    let second_run = repair.repair_once().await.expect("second repair succeeds");
    assert_eq!(second_run, RepairOutcome::AlreadyDone, "second run is AlreadyDone");
}

#[tokio::test]
async fn directory_and_claim_lock_on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    let migrated = Migrated::start(Engine::MySql).await;
    let db = migrated.connect().await;
    clean(&db).await;
    test_directory_and_claim_lock(&db).await;
    db.close().await;
}

#[tokio::test]
async fn directory_and_claim_lock_on_postgres() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    let migrated = Migrated::start(Engine::PostgreSql).await;
    let db = migrated.connect().await;
    clean(&db).await;
    test_directory_and_claim_lock(&db).await;
    db.close().await;
}

async fn test_directory_and_claim_lock(db: &Db) {
    let agent_id = agent(db, "lock-agent", "local").await;

    // Test AgentRowLock
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    let lock = AgentRowLock;
    let locked = lock.lock_for_claim(&mut tx, agent_id, OffsetDateTime::now_utc()).await.unwrap();
    assert!(locked, "agent row was locked for claim");
    tx.commit().await.unwrap();

    // Non-existent agent on a new transaction
    let mut tx2 = db.begin(Mode::ReadWrite).await.unwrap();
    let locked2 = lock.lock_for_claim(&mut tx2, Uuid::new_v4(), OffsetDateTime::now_utc()).await.unwrap();
    assert!(!locked2, "unknown agent cannot be locked");
    tx2.rollback().await.unwrap();

    // Test AgentDirectoryImpl
    let directory = AgentDirectoryImpl::new(db.clone());
    let missing = directory.by_api_key(Uuid::new_v4()).await.unwrap();
    assert!(missing.is_none(), "missing api key gives None");
}
