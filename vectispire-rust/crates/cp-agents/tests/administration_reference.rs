//! The agents' administration held to Java's answers: `reference/agents/administration.json`, written by
//! `AgentAdministrationReferenceSetTest` over the real `AgentAdministrationService`.
//!
//! Each case puts Java's prior row in a real database, calls this crate's service with Java's input, and compares the
//! three things Java recorded: the refusal (status and message), the audit entries in the order they were written, and
//! the row as it was saved. An audit sentence is read back from `t_audit_log`, so it is compared as `AuditLogService`
//! stores it — cut to its column by `vectispire_cp_audit::text::truncate`, whose parity its own reference set holds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::too_many_lines)]

mod support;

use serde_json::{Value, json};
use uuid::Uuid;
use vectispire_cp_agents::{AgentError, Change, Declaration};
use vectispire_cp_audit::RequestActor;
use vectispire_cp_audit::text::{TEXT_COLUMN, truncate};
use vectispire_cp_db::Db;
use vectispire_cp_http::Problem;

use support::{Migrated, clean, compose, exec, system_clock};

/// Java's fixed agent id: the case's prior row is written under it, and every operation but a declaration names it.
const ID: &str = "0b9a3c52-6f1e-4d1a-9c55-2f0e7a4b8d10";

fn reference() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/agents/administration.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("the reference set is committed"))
        .expect("the reference set is JSON")
}

#[tokio::test]
async fn the_administration_answers_what_java_answers() {
    for engine in vectispire_cp_db::testing::engines() {
        if !vectispire_cp_db::testing::runs_on(*engine) {
            continue;
        }
        let migrated = Migrated::start(*engine).await;
        let db = migrated.connect().await;
        let reference = reference();
        let key = reference["key"].as_str().unwrap().to_owned();
        let cases = reference["cases"].as_array().unwrap();
        assert!(cases.len() > 60, "the reference set holds every case");
        let mut differences = Vec::new();
        for case in cases {
            if let Some(difference) = run(&db, &key, case).await {
                differences.push(difference);
            }
        }
        db.close().await;
        assert!(
            differences.is_empty(),
            "{engine:?}: {} of {} cases differ:\n{}",
            differences.len(),
            cases.len(),
            differences.join("\n")
        );
    }
}

async fn run(db: &Db, key: &str, case: &Value) -> Option<String> {
    let name = case["name"].as_str().unwrap();
    clean(db).await;
    exec(db, "delete from t_api_key").await;
    let id = Uuid::parse_str(ID).unwrap();
    if !case["prior"].is_null() {
        prior(db, id, &case["prior"], key).await;
    }
    if let Some(running) = case.get("running").and_then(Value::as_i64) {
        for _ in 0..running {
            exec(
                db,
                &format!(
                    "insert into t_scan (branch, status, created_at, attempts, findings_count, new_issues_count, resolved_issues_count, claimed_by) values ('main', 'scanning', '2026-01-01 00:00:00', 1, 0, 0, 0, '{ID}')"
                ),
            )
            .await;
        }
    }

    let composed = compose(db, system_clock());
    let admin = composed.agents.admin.clone();
    let actor = RequestActor {
        username: Some("admin".to_owned()),
        ip_address: Some("203.0.113.7".to_owned()),
        user_agent: Some("reference".to_owned()),
    };
    let input = &case["input"];
    let text = |field: &str| input[field].as_str().map(str::to_owned);
    let int = |field: &str| input[field].as_i64().map(|value| i32::try_from(value).unwrap());

    let (answer, row_id): (Result<Value, AgentError>, Uuid) = match case["operation"].as_str().unwrap() {
        "declare" => {
            let declared = admin
                .declare(
                    Declaration {
                        name: text("name").unwrap_or_default(),
                        description: text("description"),
                        credentials_mode: text("credentialsMode"),
                        labels: text("labels"),
                        max_concurrent: int("maxConcurrent"),
                    },
                    &actor,
                )
                .await;
            match declared {
                Ok(declared) => (Ok(json!({ "secretIssued": !declared.secret.trim().is_empty() })), declared.id),
                Err(refused) => (Err(refused), id),
            }
        }
        "change" => {
            let change = Change {
                enabled: input["enabled"].as_bool(),
                labels: text("labels"),
                max_concurrent: int("maxConcurrent"),
            };
            let changed = admin.change(id, change, &actor).await;
            (changed.map(|changed| json!({ "enabled": changed.enabled, "labels": changed.labels })), id)
        }
        "pin" => {
            let pinned = admin.pin_signing_key(id, text("publicKey").as_deref(), &actor).await;
            (
                pinned.map(|pinned| {
                    json!({ "signsResults": pinned.signs_results, "privateKeyReturned": pinned.private_key.is_some() })
                }),
                id,
            )
        }
        "reset" => (admin.reset_sealing_key(id, &actor).await.map(|()| json!({})), id),
        "remove" => (admin.remove(id, &actor).await.map(|()| json!({})), id),
        other => panic!("{name}: no operation {other}"),
    };

    let mut outcome = serde_json::Map::new();
    match answer {
        Ok(answer) => {
            outcome.insert("answer".to_owned(), answer);
        }
        Err(refused) => {
            let problem = Problem::from(refused);
            outcome.insert(
                "refused".to_owned(),
                json!({ "status": problem.status().as_u16(), "detail": problem.detail() }),
            );
        }
    }
    outcome.insert("audit".to_owned(), Value::Array(audit(db).await));
    let expected = &case["outcome"];
    if expected.get("stored").is_some() {
        outcome.insert("stored".to_owned(), stored(db, row_id).await);
    }
    let mut expected = expected.clone();
    for entry in expected["audit"].as_array_mut().unwrap() {
        let description = entry["description"].as_str().unwrap().to_owned();
        entry["description"] = Value::String(truncate(&description, TEXT_COLUMN).to_owned());
        // A declaration's id is the insert's, mocked on the Java side to the fixed one: here it is the row's.
        if entry["resourceId"] == ID {
            entry["resourceId"] = Value::String(row_id.as_hyphenated().to_string());
        }
    }

    let actual = Value::Object(outcome);
    (actual != expected).then(|| format!("  {name}:\n    java: {expected}\n    rust: {actual}"))
}

/// The key a declaration issued stops opening anything when the agent is removed: Java revokes it in the removal's
/// transaction, since a key left behind is a door to the protocol with no agent behind it.
#[tokio::test]
async fn a_removed_agent_takes_its_key_with_it() {
    for engine in vectispire_cp_db::testing::engines() {
        if !vectispire_cp_db::testing::runs_on(*engine) {
            continue;
        }
        let migrated = Migrated::start(*engine).await;
        let db = migrated.connect().await;
        clean(&db).await;
        let admin = compose(&db, system_clock()).agents.admin.clone();
        let actor = RequestActor { username: Some("admin".to_owned()), ip_address: None, user_agent: None };
        let declaration = Declaration {
            name: "leaving".to_owned(),
            description: None,
            credentials_mode: None,
            labels: None,
            max_concurrent: None,
        };
        let declared = admin.declare(declaration, &actor).await.expect("declared");
        let keys = || support::count(&db, "select count(*) from t_api_key where name = 'Agent leaving'");
        assert_eq!(keys().await, 1, "{engine:?}: the declaration issued its key");
        admin.remove(declared.id, &actor).await.expect("removed");
        assert_eq!(keys().await, 0, "{engine:?}: and the removal revoked it");
        db.close().await;
    }
}

/// Java's prior row, as `AgentEntity` held it: remote, local credentials, a pinned signing key.
async fn prior(db: &Db, id: Uuid, prior: &Value, key: &str) {
    let name = prior["name"].as_str().unwrap();
    let labels = prior["labels"].as_str();
    let enabled = prior["enabled"].as_bool().unwrap();
    let max = prior["maxConcurrent"].as_i64().map(|value| i32::try_from(value).unwrap());
    let id = id.as_hyphenated().to_string();
    let inserted = match db {
        Db::MySql(pool) => {
            sqlx::query(
                "insert into t_agent (id, name, kind, credentials_mode, labels, enabled, max_concurrent, signing_public_key, created_at) values (?, ?, 'remote', 'local', ?, ?, ?, ?, '2026-01-01 00:00:00')",
            )
            .bind(&id)
            .bind(name)
            .bind(labels)
            .bind(enabled)
            .bind(max)
            .bind(key)
            .execute(pool)
            .await
            .map(drop)
        }
        Db::PostgreSql(pool) => {
            sqlx::query(
                "insert into t_agent (id, name, kind, credentials_mode, labels, enabled, max_concurrent, signing_public_key, created_at) values ($1::uuid, $2, 'remote', 'local', $3, $4, $5, $6, '2026-01-01 00:00:00')",
            )
            .bind(&id)
            .bind(name)
            .bind(labels)
            .bind(enabled)
            .bind(max)
            .bind(key)
            .execute(pool)
            .await
            .map(drop)
        }
    };
    inserted.expect("the prior row is written");
}

/// The entries the case wrote, oldest first, as Java's reference names them.
async fn audit(db: &Db) -> Vec<Value> {
    let sql = "select operation_type, resource_id, description, user_id from t_audit_log order by timestamp";
    let rows: Vec<(String, String, String, Option<String>)> = match db {
        Db::MySql(pool) => sqlx::query_as(sql).fetch_all(pool).await,
        Db::PostgreSql(pool) => sqlx::query_as(sql).fetch_all(pool).await,
    }
    .expect("the audit log is read");
    rows.into_iter()
        .map(|(operation, resource_id, description, user_id)| {
            json!({ "operation": operation, "resourceId": resource_id, "description": description, "userId": user_id })
        })
        .collect()
}

/// Name, description, credentials mode, labels, enabled, limit, and whether a signing key is pinned.
type StoredRow = (String, Option<String>, String, Option<String>, bool, Option<i32>, bool);

/// The row as saved, in the fields Java's reference records.
async fn stored(db: &Db, id: Uuid) -> Value {
    let id = id.as_hyphenated().to_string();
    let row: Option<StoredRow> = match db {
        Db::MySql(pool) => {
            sqlx::query_as(
                "select name, description, credentials_mode, labels, enabled, max_concurrent, signing_public_key is not null from t_agent where id = ?",
            )
            .bind(&id)
            .fetch_optional(pool)
            .await
        }
        Db::PostgreSql(pool) => {
            sqlx::query_as(
                "select name, description, credentials_mode, labels, enabled, max_concurrent, signing_public_key is not null from t_agent where id = $1::uuid",
            )
            .bind(&id)
            .fetch_optional(pool)
            .await
        }
    }
    .expect("the agent is read");
    let Some((name, description, mode, labels, enabled, max, signs)) = row else { return Value::Null };
    json!({
        "name": name,
        "description": description,
        "credentialsMode": mode,
        "labels": labels,
        "enabled": enabled,
        "maxConcurrent": max,
        "signsResults": signs,
    })
}
