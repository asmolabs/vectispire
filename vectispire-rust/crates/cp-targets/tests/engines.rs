//! The module on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`: `TargetDeletionIntegrationTest`,
//! `TargetDeletionTest` and `TargetPurgeOrderTest` for what Phase 2 owns of a deletion, `RepositoryDuplicateIntegrationTest`
//! (the raced twin and the keying of rows filed twice before V73), and the clone credentials stored encrypted.
//!
//! **What a deletion covers in this phase**: the target's row, the grants and restricted keys `access` revokes before
//! the first phase, and the listeners in phase order. The issues, triage history, findings and scans go by the
//! foreign keys' cascade on both engines until their owners' listeners are ported (issues, Phase 3; scanning, 2.7) —
//! the plan's "a target deletion in full" is deferred, and this suite holds what is not.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use vectispire_cp_audit::{AuditOperation, RequestActor};
use vectispire_cp_crypto::{git_token_context, private_key_context};
use vectispire_cp_db::{Db, Engine, ScanTarget, Tx, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_targets::deletion::{ListenerName, Phase, PurgeError, PurgeListener, PurgeRegistry, TargetPurge};
use vectispire_cp_targets::repositories::Changes;
use vectispire_cp_targets::{RepositoryIdentityTask, TargetError};

use support::{Migrated, count, exec, text};

fn actor() -> RequestActor {
    RequestActor { username: Some("race-test".to_owned()), ip_address: None, user_agent: None }
}

fn changes(url: &str) -> Changes {
    Changes { url: Some(url.to_owned()), branch: Some("main".to_owned()), ..Changes::default() }
}

fn bool_literal(db: &Db, value: bool) -> &'static str {
    match (db, value) {
        (Db::MySql(_), true) => "b'1'",
        (Db::MySql(_), false) => "b'0'",
        (Db::PostgreSql(_), true) => "true",
        (Db::PostgreSql(_), false) => "false",
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_both_engines() {
    for engine in [Engine::MySql, Engine::PostgreSql] {
        let database = Migrated::start(engine).await;
        let db = database.connect().await;
        deletion_takes_the_rows_and_nobody_elses(&db, "repository").await;
        deletion_takes_the_rows_and_nobody_elses(&db, "container").await;
        the_purge_runs_children_before_parents(&db).await;
        a_listener_that_fails_rolls_the_deletion_back(&db).await;
        issues_past_the_bind_limit_all_go(&db).await;
        one_twin_wins_the_other_is_told(&database, &db).await;
        twins_found_by_the_upgrade_keep_their_rows(&db).await;
        credentials_are_stored_encrypted_under_their_contexts(&db).await;
        println!("{engine}: the targets' suite passed");
        db.close().await;
    }
}

/// A target with a scan, a finding, an issue with its triage history, a grant to an account and an integration key
/// restricted to it.
async fn populate(db: &Db, kind: &str, id: i64, owner: i64, tag: &str) {
    let column = if kind == "repository" { "repo_id" } else { "container_id" };
    let at = "'2026-09-01 10:00:00'";
    exec(
        db,
        &format!("insert into t_scan ({column}, branch, status, created_at) values ({id}, 'main', 'completed', {at})"),
    )
    .await;
    let scan = count(db, &format!("select max(id) from t_scan where {column} = {id}")).await;
    exec(
        db,
        &format!(
            "insert into t_issue ({column}, fingerprint, type, severity, state, triage_status, first_seen_at, last_seen_at, \
             times_seen) values ({id}, 'fp-{tag}', 'vulnerability', 'high', 'open', 'not_affected', {at}, {at}, 1)"
        ),
    )
    .await;
    let issue = count(db, &format!("select max(id) from t_issue where {column} = {id}")).await;
    exec(
        db,
        &format!(
            "insert into t_issue_triage_event (issue_id, from_status, to_status, origin, occurred_at) values \
             ({issue}, 'under_review', 'not_affected', 'user', {at})"
        ),
    )
    .await;
    exec(
        db,
        &format!(
            "insert into t_finding (scan_id, issue_id, type, source, is_kev, created_at) values ({scan}, {issue}, \
             'vulnerability', 'grype', {}, {at})",
            bool_literal(db, false)
        ),
    )
    .await;
    exec(db, &format!("insert into t_user_target (user_id, target_kind, target_id) values ({owner}, '{kind}', {id})"))
        .await;
    let key = uuid::Uuid::new_v4();
    exec(
        db,
        &format!(
            "insert into t_api_key (id, name, key_hash, created_at, owner_user_id, target_kind, target_id, scopes) values \
             ('{key}', 'pipeline-{tag}', 'not-a-hash', {at}, {owner}, '{kind}', {id}, 'read')"
        ),
    )
    .await;
}

async fn deletion_takes_the_rows_and_nobody_elses(db: &Db, kind: &str) {
    let (targets, entries) = support::targets(db, PurgeRegistry::stand_ins());
    let owner = support::account(db, &format!("owner-{kind}"), "USER").await;
    let actor = actor();
    let (doomed, survivor) = if kind == "repository" {
        let doomed = targets
            .create_repository(
                &changes(&format!("https://gitlab.example.org/team/doomed-{kind}")),
                &Visibility::Everything,
                &actor,
            )
            .await
            .unwrap();
        let survivor = targets
            .create_repository(
                &changes(&format!("https://gitlab.example.org/team/survivor-{kind}")),
                &Visibility::Everything,
                &actor,
            )
            .await
            .unwrap();
        (doomed.id, survivor.id)
    } else {
        let image = |name: &str| vectispire_cp_targets::containers::Changes {
            image_name: Some(name.to_owned()),
            tag: Some("1.0".to_owned()),
            ..Default::default()
        };
        (
            targets.create_container(&image("team/doomed"), &actor).await.unwrap().id,
            targets.create_container(&image("team/survivor"), &actor).await.unwrap().id,
        )
    };
    populate(db, kind, doomed, owner, &format!("{kind}-doomed")).await;
    populate(db, kind, survivor, owner, &format!("{kind}-survivor")).await;
    let before = support::rows_naming(db, kind, survivor).await;
    assert!(
        support::rows_naming(db, kind, doomed).await.iter().all(|(_, rows)| *rows > 0),
        "the fixture wrote a row everywhere"
    );
    entries.taken();

    if kind == "repository" {
        targets.delete_repository(doomed, &Visibility::Everything, &actor).await.unwrap();
    } else {
        targets.delete_container(doomed, &Visibility::Everything, &actor).await.unwrap();
    }

    for (table, rows) in support::rows_naming(db, kind, doomed).await {
        assert_eq!(rows, 0, "{table}: nothing naming the deleted {kind} remains");
    }
    assert_eq!(support::rows_naming(db, kind, survivor).await, before, "the other {kind} keeps every row");
    let table = if kind == "repository" { "t_repository" } else { "t_container" };
    assert_eq!(count(db, &format!("select count(*) from {table} where id = {doomed}")).await, 0);

    // The deletion's entry says what went with it and signals the access change; one entry per key, under its id.
    let recorded = entries.taken();
    assert_eq!(recorded.len(), 2, "{recorded:#?}");
    let what = if kind == "repository" {
        "Repository deleted: https://gitlab.example.org/team/doomed-repository"
    } else {
        "Image deleted: team/doomed:1.0"
    };
    assert_eq!(
        recorded[0].description.as_deref(),
        Some(format!("{what} (1 grant(s) and 1 API key(s) revoked)").as_str())
    );
    assert_eq!(recorded[0].signal.map(|signal| signal.0), Some("ACCESS_GRANT_CHANGED"));
    assert_eq!(recorded[1].operation, AuditOperation::ApiKeyDeleted);
    let noun = if kind == "repository" { "repository" } else { "image" };
    assert_eq!(
        recorded[1].description.as_deref(),
        Some(
            format!("API key revoked with its target: pipeline-{kind}-doomed (restricted to {noun} {doomed}, deleted)")
                .as_str()
        )
    );

    // Absent and hidden refused alike.
    let refusal = if kind == "repository" {
        targets.delete_repository(doomed, &Visibility::Everything, &actor).await
    } else {
        targets.delete_container(doomed, &Visibility::Everything, &actor).await
    };
    let hidden = if kind == "repository" {
        targets.delete_repository(survivor, &Visibility::only([]), &actor).await
    } else {
        targets.delete_container(survivor, &Visibility::only([]), &actor).await
    };
    let message = if kind == "repository" { "Repository not found." } else { "Image not found." };
    assert!(matches!(refusal, Err(TargetError::NotFound(ref m)) if m == message), "{refusal:?}");
    assert!(matches!(hidden, Err(TargetError::NotFound(ref m)) if m == message), "{hidden:?}");
}

/// What a listener saw: its name, and whether the grants and the target's row were still there.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    listener: &'static str,
    grants: i64,
    target_rows: i64,
}

struct Probe {
    name: &'static str,
    phase: Phase,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl PurgeListener for Probe {
    fn name(&self) -> ListenerName {
        ListenerName { module: "test", listener: self.name }
    }

    fn phase(&self) -> Phase {
        self.phase
    }

    fn purge<'a>(&'a self, tx: &'a mut Tx, purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async move {
            let TargetPurge::Deleted(ScanTarget::Repository(id)) = purge else {
                return Ok(());
            };
            // Read in the deletion's transaction: what the purge has done so far.
            let grants = in_tx(
                tx,
                &format!("select count(*) from t_user_target where target_kind = 'repository' and target_id = {id}"),
            )
            .await;
            let target_rows = in_tx(tx, &format!("select count(*) from t_repository where id = {id}")).await;
            self.seen.lock().unwrap().push(Seen { listener: self.name, grants, target_rows });
            Ok(())
        })
    }
}

async fn in_tx(tx: &mut Tx, sql: &str) -> i64 {
    let statement = sqlx::AssertSqlSafe(sql.to_owned());
    match tx {
        Tx::MySql(tx) => sqlx::query_scalar::<_, i64>(statement).fetch_one(&mut **tx).await.unwrap(),
        Tx::PostgreSql(tx) => sqlx::query_scalar::<_, i64>(statement).fetch_one(&mut **tx).await.unwrap(),
    }
}

/// `TargetPurgeOrderTest`: the listeners run phase by phase whatever order they were registered in; the grants are
/// revoked before the first; the target's own row goes after the last.
async fn the_purge_runs_children_before_parents(db: &Db) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let probe = |name, phase| Arc::new(Probe { name, phase, seen: seen.clone() }) as Arc<dyn PurgeListener>;
    let registry = PurgeRegistry::stand_ins().with(vec![
        probe("scans", Phase::Scans),
        probe("issue-children", Phase::IssueChildren),
        probe("references", Phase::References),
        probe("scan-children", Phase::ScanChildren),
        probe("issues", Phase::Issues),
        probe("findings", Phase::Findings),
    ]);
    let order: Vec<Phase> = registry.names().into_iter().map(|(_, phase)| phase).collect();
    assert!(order.windows(2).all(|pair| pair[0] <= pair[1]), "sorted by phase: {order:?}");
    let (targets, _) = support::targets(db, registry);
    let owner = support::account(db, "order-owner", "USER").await;
    let doomed = targets
        .create_repository(&changes("https://gitlab.example.org/team/ordered"), &Visibility::Everything, &actor())
        .await
        .unwrap()
        .id;
    populate(db, "repository", doomed, owner, "ordered").await;

    targets.delete_repository(doomed, &Visibility::Everything, &actor()).await.unwrap();

    let seen = seen.lock().unwrap().clone();
    let names: Vec<&str> = seen.iter().map(|probe| probe.listener).collect();
    assert_eq!(names, ["references", "issue-children", "findings", "issues", "scan-children", "scans"]);
    assert!(seen.iter().all(|probe| probe.grants == 0), "the grants went before the first phase: {seen:?}");
    assert!(seen.iter().all(|probe| probe.target_rows == 1), "the target goes after the last listener: {seen:?}");
    assert_eq!(count(db, &format!("select count(*) from t_repository where id = {doomed}")).await, 0);
}

struct Failing;

#[derive(Debug, thiserror::Error)]
#[error("this listener refuses")]
struct Refused;

impl PurgeListener for Failing {
    fn name(&self) -> ListenerName {
        ListenerName { module: "test", listener: "Failing.purge" }
    }

    fn phase(&self) -> Phase {
        Phase::Issues
    }

    fn purge<'a>(&'a self, _tx: &'a mut Tx, _purge: &'a TargetPurge) -> BoxFuture<'a, Result<(), PurgeError>> {
        Box::pin(async { Err(Box::new(Refused) as PurgeError) })
    }
}

/// The purge and the deletion commit together or not at all: grants revoked for a deletion that then failed would be
/// access lost for nothing (`TargetDeletionTest.purgeNeedsTheDeletingTransaction`; a listener outside a transaction
/// does not compile here, since it is handed the deletion's).
async fn a_listener_that_fails_rolls_the_deletion_back(db: &Db) {
    let (targets, entries) = support::targets(db, PurgeRegistry::stand_ins().with(vec![Arc::new(Failing)]));
    let owner = support::account(db, "rollback-owner", "USER").await;
    let kept = targets
        .create_repository(&changes("https://gitlab.example.org/team/kept"), &Visibility::Everything, &actor())
        .await
        .unwrap()
        .id;
    populate(db, "repository", kept, owner, "kept").await;
    let before = support::rows_naming(db, "repository", kept).await;
    entries.taken();
    let refused = targets.delete_repository(kept, &Visibility::Everything, &actor()).await;
    assert!(matches!(refused, Err(TargetError::Unexpected(_))), "{refused:?}");
    assert_eq!(support::rows_naming(db, "repository", kept).await, before, "nothing went: grants and keys included");
    assert_eq!(count(db, &format!("select count(*) from t_repository where id = {kept}")).await, 1);
    assert!(entries.taken().is_empty(), "no entry describes a deletion that did not happen");
}

/// Past the PostgreSQL driver's 65,535 bind parameters: seventy thousand issues, every one taken.
async fn issues_past_the_bind_limit_all_go(db: &Db) {
    let (targets, _) = support::targets(db, PurgeRegistry::stand_ins());
    let id = targets
        .create_repository(&changes("https://gitlab.example.org/team/large"), &Visibility::Everything, &actor())
        .await
        .unwrap()
        .id;
    for from in (0..70_000).step_by(1_000) {
        let values: Vec<String> = (from..from + 1_000)
            .map(|index| {
                format!(
                    "({id}, 'large-{id}-{index}', 'vulnerability', 'high', 'open', 'under_review', {}, 'UNKNOWN', \
                     '2026-09-01 10:00:00', '2026-09-01 10:00:00', 1)",
                    bool_literal(db, false)
                )
            })
            .collect();
        exec(
            db,
            &format!(
                "insert into t_issue (repo_id, fingerprint, type, severity, state, triage_status, is_kev, reachability, \
                 first_seen_at, last_seen_at, times_seen) values {}",
                values.join(", ")
            ),
        )
        .await;
    }
    assert_eq!(count(db, &format!("select count(*) from t_issue where repo_id = {id}")).await, 70_000);
    targets.delete_repository(id, &Visibility::Everything, &actor()).await.unwrap();
    assert_eq!(count(db, &format!("select count(*) from t_issue where repo_id = {id}")).await, 0);
}

/// Two creations racing: the second waits on the first's guard, and once the first commits it is refused as the twin
/// it is, naming the winner — read from the committed row, not from the failed statement.
async fn one_twin_wins_the_other_is_told(database: &Migrated, db: &Db) {
    exec(db, "delete from t_repository").await;
    let (targets, _) = support::targets(db, PurgeRegistry::stand_ins());
    let importer = actor();
    let mut batch = targets.import_batch(&importer).await.unwrap();
    let first = batch
        .repository(&changes("https://gitlab.example.org/team/raced.git"), None, OffsetDateTime::now_utc(), "")
        .await
        .unwrap();
    let racer = targets.clone();
    let second = tokio::spawn(async move {
        racer.create_repository(&changes("git@gitlab.example.org:Team/Raced"), &Visibility::Everything, &actor()).await
    });
    let waiting = match database.engine {
        Engine::PostgreSql => "select count(*) from pg_stat_activity where wait_event_type = 'Lock'",
        Engine::MySql => "select count(*) from performance_schema.data_lock_waits",
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if database.sql_as_admin(waiting).trim().parse::<i64>().unwrap_or(0) > 0 {
            break;
        }
        assert!(!second.is_finished(), "the second creation ended without ever waiting on the first");
        assert!(Instant::now() < deadline, "the second creation never waited on the first one's key");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    batch.commit().await.unwrap();
    match second.await.unwrap() {
        Err(TargetError::Conflict { cause, members, .. }) => {
            assert_eq!(cause, Some("target-already-registered"));
            assert_eq!(members, vec![("existingRepositoryId", serde_json::Value::from(first.id))]);
        }
        other => panic!("the twin was not refused: {other:?}"),
    }
    assert_eq!(count(db, "select count(*) from t_repository").await, 1, "one row, the first one's");
}

/// Rows filed twice before the rule: the engine keeps both, the oldest takes the guard, and the pair is listed.
async fn twins_found_by_the_upgrade_keep_their_rows(db: &Db) {
    exec(db, "delete from t_repository").await;
    let (targets, _) = support::targets(db, PurgeRegistry::stand_ins());
    for url in [
        "https://gitlab.example.org/team/legacy.git",
        "git@gitlab.example.org:team/legacy.git",
        "ssh://git@gitlab.example.org/team/legacy",
    ] {
        exec(
            db,
            &format!(
                "insert into t_repository (url, branch, tier) values ('{url}', 'main', 'TIER_2_BUSINESS_OPERATIONAL')"
            ),
        )
        .await;
    }
    let older = count(db, "select min(id) from t_repository").await;
    let keyed = targets.key_unkeyed().await.unwrap();
    assert_eq!((keyed.keyed, keyed.twins), (1, 2));
    assert!(text(db, &format!("select identity_guard from t_repository where id = {older}")).await.is_some());
    assert_eq!(count(db, "select count(*) from t_repository where identity_guard is null").await, 2);
    assert_eq!(
        count(db, "select count(*) from t_repository where url_identity = 'gitlab.example.org/team/legacy'").await,
        3
    );
    // A second turn finds nothing to do — and the task is that turn.
    RepositoryIdentityTask(targets.clone()).run().await.unwrap();
    assert_eq!(count(db, "select count(*) from t_repository where identity_guard is not null").await, 1);
    let groups = targets.duplicates(&Visibility::Everything).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].identity.repository, "gitlab.example.org/team/legacy");
    assert_eq!(groups[0].targets.len(), 3);
    assert_eq!(groups[0].targets[0].repository.id, older, "oldest first");
    // A reader who sees none of them is shown no group.
    assert!(targets.duplicates(&Visibility::only([])).await.unwrap().is_empty());
    // An edit making another row the twin is refused; renaming a twin filed before the rule is not.
    let younger = count(db, &format!("select min(id) from t_repository where id > {older}")).await;
    let rename = Changes { name: Some("Renamed".to_owned()), ..Changes::default() };
    targets.update_repository(younger, &rename, &Visibility::Everything, &actor()).await.unwrap();
}

/// A token and a key stored encrypted, bound to their rows; their listings never carry the secret.
async fn credentials_are_stored_encrypted_under_their_contexts(db: &Db) {
    let (targets, entries) = support::targets(db, PurgeRegistry::stand_ins());
    let token = targets
        .add_git_token(Some(" Forge "), Some("GitLab.Example.Org."), Some("bot"), Some("glpat-secret-value"), &actor())
        .await
        .unwrap();
    assert_eq!((token.host.as_str(), token.encryption_state.as_str()), ("gitlab.example.org", "current"));
    let stored = text(db, &format!("select token from t_git_token where id = '{}'", token.id)).await.unwrap();
    assert!(!stored.contains("glpat-secret-value"), "the token is stored encrypted");
    let read = support::encryption().inspect(&stored, &git_token_context(&token.id.to_string())).await;
    assert_eq!(read.plain_text(), "glpat-secret-value");
    let elsewhere = support::encryption().inspect(&stored, &git_token_context(&uuid::Uuid::new_v4().to_string())).await;
    assert_eq!(elsewhere.plain_text(), "", "bound to its row: copied elsewhere it reads as nothing");

    let key = targets
        .add_ssh_key(
            Some("deploy"),
            Some("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"),
            Some("ssh-ed25519 AAAA"),
            &actor(),
        )
        .await
        .unwrap();
    let stored = text(db, &format!("select private_key from t_ssh_key where id = '{}'", key.id)).await.unwrap();
    assert!(!stored.contains("PRIVATE KEY"));
    assert!(
        support::encryption()
            .inspect(&stored, &private_key_context(&key.id.to_string()))
            .await
            .plain_text()
            .starts_with("-----BEGIN")
    );

    // Used by a repository, neither can be deleted; the refusal says how many.
    let https = Changes {
        url: Some("https://gitlab.example.org/team/private".to_owned()),
        https_token_id: Some(token.id.to_string()),
        ..Changes::default()
    };
    targets.create_repository(&https, &Visibility::Everything, &actor()).await.unwrap();
    let refused = targets.remove_git_token(token.id, &actor()).await;
    assert!(
        matches!(refused, Err(TargetError::Invalid(ref m)) if m == "This token is used by 1 repository(ies). Detach it from them first."),
        "{refused:?}"
    );
    let listed = targets.git_tokens().await.unwrap();
    assert_eq!(listed.iter().find(|view| view.id == token.id).map(|view| view.used_by_repositories), Some(1));

    // Unreadable once its ciphertext is not what this key wrote.
    exec(db, &format!("update t_ssh_key set private_key = 'v2:AAAA' where id = '{}'", key.id)).await;
    let keys = targets.ssh_keys().await.unwrap();
    assert_eq!(
        keys.iter().find(|view| view.id == key.id).map(|view| view.encryption_state.as_str()),
        Some("unreadable")
    );
    targets.remove_ssh_key(key.id, &actor()).await.unwrap();
    let recorded: Vec<String> = entries.taken().into_iter().filter_map(|entry| entry.description).collect();
    assert!(recorded.contains(&"HTTPS token added: Forge (gitlab.example.org)".to_owned()), "{recorded:?}");
    assert!(recorded.contains(&"SSH key deleted: deploy".to_owned()), "{recorded:?}");
    assert!(recorded.iter().all(|line| !line.contains("glpat-secret-value")), "no entry carries a secret");
}
