//! Multi-engine integration tests against MySQL 9.4 and PostgreSQL 17:
//! `SemgrepRuleSetRepository` operations, unique active constraint, and `RuleSetsForScans` port.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::print_stdout
)]

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;
use time::OffsetDateTime;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_scanning::ports::ScanRuleSets;
use vectispire_protocol::StoredFile;

use support::{Migrated, clean};
use vectispire_cp_rules::{NewSemgrepRuleSet, RuleSetsForScans, SemgrepRuleSetRepository};

#[tokio::test]
async fn semgrep_rule_sets_on_mysql() {
    if !vectispire_cp_db::testing::runs_on(Engine::MySql) {
        return;
    }
    let migrated = Migrated::start(Engine::MySql).await;
    let db = migrated.connect().await;
    clean(&db).await;
    test_rule_set_lifecycle(&db, Engine::MySql).await;
    db.close().await;
}

#[tokio::test]
async fn semgrep_rule_sets_on_postgres() {
    if !vectispire_cp_db::testing::runs_on(Engine::PostgreSql) {
        return;
    }
    let migrated = Migrated::start(Engine::PostgreSql).await;
    let db = migrated.connect().await;
    clean(&db).await;
    test_rule_set_lifecycle(&db, Engine::PostgreSql).await;
    db.close().await;
}

async fn test_rule_set_lifecycle(db: &Db, _engine: Engine) {
    let repo = Arc::new(SemgrepRuleSetRepository::new(db.clone()));
    let for_scans = RuleSetsForScans::new(repo.clone());

    // 1. Initially no active rule set
    assert!(repo.find_active().await.unwrap().is_none());
    assert!(for_scans.active_hash().await.unwrap().is_none());
    assert_eq!(for_scans.languages_read(None).await.unwrap(), BTreeSet::from(["python"]));

    // 2. Insert rule set 1 (Java rules)
    let files1 = vec![StoredFile {
        path: "rule-0001.yaml".to_owned(),
        original_name: Some("java/security/sql.yaml".to_owned()),
        content: "rules:\n  - id: sql-injection\n".to_owned(),
    }];
    let files1_json = serde_json::to_string(&files1).unwrap();
    let hash1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let id1 = repo
        .insert(&NewSemgrepRuleSet {
            name: "OWASP Java".to_owned(),
            files: files1_json.clone(),
            content_hash: hash1.to_owned(),
            rule_count: 1,
            file_count: 1,
            size_bytes: files1_json.len() as i64,
            is_active: None, // Inactive is NULL, never false
            uploaded_by: Some("alice".to_owned()),
            uploaded_at: OffsetDateTime::now_utc(),
            activation_note: None,
        })
        .await
        .unwrap();

    // 3. Insert rule set 2 (Python rules)
    let files2 = vec![StoredFile {
        path: "rule-0001.yaml".to_owned(),
        original_name: Some("python/security/eval.yaml".to_owned()),
        content: "rules:\n  - id: py-eval\n".to_owned(),
    }];
    let files2_json = serde_json::to_string(&files2).unwrap();
    let hash2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let id2 = repo
        .insert(&NewSemgrepRuleSet {
            name: "Python Security".to_owned(),
            files: files2_json.clone(),
            content_hash: hash2.to_owned(),
            rule_count: 1,
            file_count: 1,
            size_bytes: files2_json.len() as i64,
            is_active: None,
            uploaded_by: Some("bob".to_owned()),
            uploaded_at: OffsetDateTime::now_utc(),
            activation_note: None,
        })
        .await
        .unwrap();

    // Both can coexist inactive (NULL unique constraint semantics)
    let summaries = repo.summaries().await.unwrap();
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].id, id2); // Ordered by uploaded_at desc, id desc
    assert_eq!(summaries[1].id, id1);

    // Find by ID and content hash
    let found1 = repo.find_by_id(id1).await.unwrap().expect("should find id1");
    assert_eq!(found1.name, "OWASP Java");
    assert_eq!(found1.is_active, None);

    let by_hash = repo.find_first_by_content_hash_order_by_id_asc(hash1).await.unwrap().expect("should find by hash");
    assert_eq!(by_hash.id, id1);

    // 4. Activate rule set 1
    let affected = repo.activate(id1, Some("Approved for production")).await.unwrap();
    assert_eq!(affected, 1);

    let active = repo.find_active().await.unwrap().expect("id1 should be active");
    assert_eq!(active.id, id1);
    assert_eq!(active.is_active, Some(true));
    assert_eq!(active.activation_note.as_deref(), Some("Approved for production"));

    // Check through ScanRuleSets port
    assert_eq!(for_scans.active_hash().await.unwrap().as_deref(), Some(hash1));
    let read_files = for_scans.files_of(hash1).await.unwrap();
    assert_eq!(read_files.len(), 1);
    assert_eq!(read_files[0].original_name.as_deref(), Some("java/security/sql.yaml"));

    let langs = for_scans.languages_read(Some(hash1)).await.unwrap();
    assert!(langs.contains(&"java"));
    assert!(langs.contains(&"python")); // Bundled python always present

    // 5. Activate rule set 2: automatically deactivates rule set 1
    let affected2 = repo.activate(id2, Some("Switched to python")).await.unwrap();
    assert_eq!(affected2, 1);

    let active2 = repo.find_active().await.unwrap().expect("id2 should be active");
    assert_eq!(active2.id, id2);

    // Rule set 1 is now inactive (is_active is NULL)
    let prev = repo.find_by_id(id1).await.unwrap().unwrap();
    assert_eq!(prev.is_active, None);

    // 6. Deactivate all
    let deactivated = repo.deactivate_all().await.unwrap();
    assert_eq!(deactivated, 1);

    assert!(repo.find_active().await.unwrap().is_none());
    assert!(for_scans.active_hash().await.unwrap().is_none());

    // Both rows still exist and have is_active = NULL
    let r1 = repo.find_by_id(id1).await.unwrap().unwrap();
    let r2 = repo.find_by_id(id2).await.unwrap().unwrap();
    assert_eq!(r1.is_active, None);
    assert_eq!(r2.is_active, None);
}
