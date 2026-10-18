//! The three scan routes through the real chain, on MySQL 9.4 and PostgreSQL 17.
//!
//! **The authorization coverage, enumerated from the router**, in `cp-targets/tests/routes.rs`'s shape: every route
//! naming a scan is sent, by each restricted caller, the identifier of a scan that exists and is hidden from them and
//! one that does not exist — the same bytes, never a success, 404 where the route admits the caller (a refusal must
//! read like an absence, or it confirms the scan exists). The callers: an account of the role `USER` with no grant in
//! `assigned` mode, and an administrator's key restricted to another repository. The history is held to the same
//! callers: a hidden scan is never listed, and narrowing to a hidden target lists nothing.
//!
//! Then the answers themselves, for one scenario.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines, clippy::print_stdout)]

mod support;

use serde_json::Value;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::credentials::StaticCredentials;
use vectispire_cp_http::routes::Visibility as Declared;
use vectispire_cp_http::{Restriction, Role};
use vectispire_domain::ScanTarget;

use support::{Migrated, count, exec, literal, send};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_both_engines() {
    for engine in [Engine::MySql, Engine::PostgreSql] {
        let database = Migrated::start(engine).await;
        let db = database.connect().await;
        every_route_naming_a_scan_refuses_a_caller_who_cannot_see_it(&db).await;
        println!("{engine}: the routes' suite passed");
        db.close().await;
    }
}

const ABSENT: i64 = 987_654_321;

fn table() -> Vec<vectispire_cp_http::routes::RouteDecl> {
    let db = support::unreachable();
    let composed = support::compose(&db, support::system_clock(), Default::default());
    vectispire_cp_scanning::routes(composed.scanning).iter().map(|entry| entry.decl().clone()).collect()
}

async fn every_route_naming_a_scan_refuses_a_caller_who_cannot_see_it(db: &Db) {
    let composed = support::compose(db, support::system_clock(), Default::default());
    let admin = support::account(db, "coverage-admin", "ADMIN").await;
    let reader = support::account(db, "coverage-reader", "USER").await;
    let hidden_repo = support::repository(db, "hidden").await;
    let allowed_repo = support::repository(db, "allowed").await;
    let image = support::container(db, "team/hidden").await;
    let at = support::literal(time::OffsetDateTime::from_unix_timestamp(1_786_615_200).unwrap());
    exec(db, &format!(
        "insert into t_scan (repo_id, branch, status, created_at, sbom, attempts, findings_count, new_issues_count, resolved_issues_count) values ({hidden_repo}, 'main', 'completed', {at}, '{{\"artifacts\":[]}}', 1, 1, 1, 0)"
    )).await;
    let hidden = count(db, "select max(id) from t_scan").await;
    exec(db, &format!(
        "insert into t_scan (container_id, branch, status, created_at, attempts, findings_count, new_issues_count, resolved_issues_count) values ({image}, 'n/a', 'failed', {at}, 1, 0, 0, 0)"
    )).await;
    exec(db, &format!(
        "insert into t_scan (repo_id, branch, status, created_at, sbom, attempts, findings_count, new_issues_count, resolved_issues_count, plugin_steps, examined_types) values ({allowed_repo}, 'main', 'completed', {at}, '{{\"artifacts\":[1]}}', 1, 1, 1, 0, '[{{\"pluginId\":\"acme\",\"state\":\"absent\",\"reason\":\"crashed\"}}]', 'sast,secret')"
    )).await;
    let allowed = count(db, "select max(id) from t_scan").await;
    exec(db, &format!(
        "insert into t_finding (scan_id, type, severity, identifier, source, is_kev, created_at, reachability, line) values ({allowed}, 'secret', 'high', 'aws-key', 'gitleaks', {}, {}, 'UNKNOWN', 7)",
        if matches!(db, Db::MySql(_)) { "0" } else { "false" },
        literal(time::OffsetDateTime::now_utc())
    )).await;

    let credentials = StaticCredentials::default()
        .session("tok-reader", support::principal("coverage-reader", reader, Role::User, Restriction::None, false))
        .session("tok-admin", support::principal("coverage-admin", admin, Role::Admin, Restriction::None, false))
        .key(
            "zsk_image",
            support::principal(
                "coverage-admin",
                admin,
                Role::Admin,
                Restriction::Target(ScanTarget::Container(image)),
                true,
            ),
        )
        .key(
            "zsk_restricted",
            support::principal(
                "coverage-admin",
                admin,
                Role::Admin,
                Restriction::Target(ScanTarget::Repository(allowed_repo)),
                true,
            ),
        );
    let router = support::router(db, composed.scanning.clone(), credentials, "assigned");

    let mut covered = 0;
    for route in table() {
        if !route.path.contains("{id}") {
            continue;
        }
        assert_eq!(
            route.visibility,
            Declared::Scoped,
            "{} {} names a scan and must be .scoped()",
            route.method,
            route.path
        );
        for token in ["tok-reader", "zsk_restricted"] {
            let hidden_path = route.path.replace("{id}", &hidden.to_string());
            let absent_path = route.path.replace("{id}", &ABSENT.to_string());
            let existing = send(&router, &route.method, &hidden_path, Some(token), None).await;
            let absent = send(&router, &route.method, &absent_path, Some(token), None).await;
            let name = format!("{} {} as {token}", route.method, route.path);
            assert_eq!(existing.0, 404, "{name}: {existing:?}");
            assert_eq!(
                (existing.0, existing.1.replace(&hidden_path, "PATH")),
                (absent.0, absent.1.replace(&absent_path, "PATH")),
                "{name}: a hidden scan answers unlike an absent one"
            );
            assert!(existing.1.contains("Scan not found."), "{name}: {}", existing.1);
            covered += 1;
        }
    }
    assert_eq!(covered, 4, "the detail and the SBOM, by each caller");

    // The history: the reader sees nothing, the key its own repository's scan alone, whatever it narrows to.
    let (status, body) = send(&router, "GET", "/api/v1/scans", Some("tok-reader"), None).await;
    assert_eq!((status, body.as_str()), (200, "[]"));
    let (_, body) = send(&router, "GET", "/api/v1/scans", Some("zsk_restricted"), None).await;
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        listed.as_array().unwrap().iter().map(|scan| scan["id"].as_i64().unwrap()).collect::<Vec<_>>(),
        vec![allowed]
    );
    let (_, body) =
        send(&router, "GET", &format!("/api/v1/scans?repo_id={hidden_repo}"), Some("zsk_restricted"), None).await;
    assert_eq!(body, "[]");

    // The answers, as Java writes them.
    let (status, body) = send(&router, "GET", &format!("/api/v1/scans/{allowed}"), Some("zsk_restricted"), None).await;
    assert_eq!(status, 200, "{body}");
    let detail: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(detail["scan"]["targetKind"], "repository");
    assert_eq!(detail["scan"]["targetName"], "allowed");
    assert_eq!(detail["hasSbom"], true);
    assert_eq!(detail["findingsTotal"], 1);
    assert_eq!(detail["findingsTruncated"], false);
    assert_eq!(detail["findings"][0]["type"], "secret");
    assert_eq!(detail["findings"][0]["line"], 7);
    assert_eq!(detail["examinedTypes"], serde_json::json!(["sast", "secret"]));
    assert_eq!(detail["plugins"][0]["state"], "absent");
    assert_eq!(detail["plugins"][0]["manifestDigest"], Value::Null);
    let (status, body) = send(&router, "GET", &format!("/api/v1/scans/{allowed}/sbom"), Some("tok-admin"), None).await;
    assert_eq!((status, body.as_str()), (200, "{\"artifacts\":[1]}"));
    let image_scan = count(db, &format!("select id from t_scan where container_id = {image}")).await;
    let (status, body) =
        send(&router, "GET", &format!("/api/v1/scans/{image_scan}/sbom"), Some("tok-admin"), None).await;
    assert_eq!(status, 404);
    assert!(body.contains("This scan produced no SBOM."), "{body}");
    let (status, body) = send(&router, "GET", "/api/v1/scans/x", Some("tok-admin"), None).await;
    assert_eq!(status, 400);
    assert!(body.contains("Failed to convert 'id' with value: 'x'"), "{body}");
    let (status, body) = send(&router, "GET", "/api/v1/scans?limit=2&offset=1", Some("tok-admin"), None).await;
    assert_eq!(status, 400, "{body}");
    let (status, body) = send(&router, "GET", "/api/v1/scans?limit=1&offset=1", Some("tok-admin"), None).await;
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap().as_array().unwrap().len(), 1);
    // An image's scan, to a key restricted to the image.
    let (status, body) = send(&router, "GET", &format!("/api/v1/scans/{image_scan}"), Some("zsk_image"), None).await;
    assert_eq!(status, 200, "{body}");
    // A restricted reader's pages are cut from what it sees.
    exec(db, &format!(
        "insert into t_scan (repo_id, branch, status, created_at, attempts, findings_count, new_issues_count, resolved_issues_count) values ({allowed_repo}, 'main', 'completed', {}, 1, 0, 0, 0)",
        support::literal(time::OffsetDateTime::from_unix_timestamp(1_786_615_100).unwrap())
    )).await;
    let older = count(db, "select max(id) from t_scan").await;
    let (_, first) = send(&router, "GET", "/api/v1/scans?limit=1&offset=0", Some("zsk_restricted"), None).await;
    let (_, second) = send(&router, "GET", "/api/v1/scans?limit=1&offset=1", Some("zsk_restricted"), None).await;
    let id_of = |body: &str| serde_json::from_str::<Value>(body).unwrap()[0]["id"].as_i64();
    assert_eq!((id_of(&first), id_of(&second)), (Some(allowed), Some(older)));
    // A visibility that cannot be resolved is a failure, never everything.
    let failing = support::router_with(
        db,
        composed.scanning.clone(),
        StaticCredentials::default()
            .session("tok-reader", support::principal("coverage-reader", reader, Role::User, Restriction::None, false)),
        std::sync::Arc::new(support::Unanswering),
    );
    let (status, body) = send(&failing, "GET", "/api/v1/scans", Some("tok-reader"), None).await;
    assert_eq!(status, 500, "{body}");
    let (status, _) = send(&router, "GET", "/api/v1/scans", None, None).await;
    assert_eq!(status, 401);
    exec(db, "delete from t_finding").await;
}
