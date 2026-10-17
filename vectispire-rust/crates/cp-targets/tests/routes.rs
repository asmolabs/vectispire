//! The twenty-nine routes through the real chain, on MySQL 9.4 and PostgreSQL 17.
//!
//! **The authorization coverage, enumerated from the router** (`AuthorizationCoverageTest` and `VisibilityRoutesTest`
//! in one): every route the module registers is read from its table, and every one whose path names a target, a
//! project or a solution is sent, by each restricted caller, the identifier of one that exists and is hidden from them
//! and the identifier of one that does not exist. The two answers must be the same bytes and never a success, and a
//! caller the route admits must be answered 404 — so a route added tomorrow is covered without anybody remembering to
//! list it, and one that forgets its visibility fails here. The callers:
//!
//! - an account of the role `USER` with no grant, the installation in `assigned` mode;
//! - an administrator's integration key restricted to another repository — the case the role cannot express, which
//!   is why a key needs an allowance where a role marker would otherwise do.
//!
//! The list routes are held to the same callers: a hidden target is never listed.
//!
//! Then the answers themselves, member for member as Java writes them, for one scenario through every route.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::too_many_lines)]

mod support;

use serde_json::Value;
use vectispire_cp_db::{Db, Engine};
use vectispire_cp_http::access::Access;
use vectispire_cp_http::credentials::StaticCredentials;
use vectispire_cp_http::routes::Visibility as Declared;
use vectispire_cp_http::{Restriction, Role};
use vectispire_cp_targets::deletion::PurgeRegistry;
use vectispire_domain::ScanTarget;

use support::{Migrated, count, exec, send};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_both_engines() {
    for engine in [Engine::MySql, Engine::PostgreSql] {
        let database = Migrated::start(engine).await;
        let db = database.connect().await;
        every_route_naming_a_target_refuses_a_caller_who_cannot_see_it(&db).await;
        exec(&db, "delete from t_repository").await;
        exec(&db, "delete from t_container").await;
        exec(&db, "delete from t_project").await;
        exec(&db, "delete from t_solution").await;
        the_answers_are_javas(&db).await;
        println!("{engine}: the routes' suite passed");
        db.close().await;
    }
}

const HIDDEN_URL: &str = "https://gitlab.example.org/team/hidden";
const ABSENT: i64 = 987_654_321;

/// The table, as the module registers it.
fn table() -> Vec<vectispire_cp_http::routes::RouteDecl> {
    // The table does not run a handler: a pool that never connects is enough to build it.
    let db = support::unreachable();
    let (targets, _) = support::targets(&db, PurgeRegistry::stand_ins());
    vectispire_cp_targets::routes(targets).iter().map(|entry| entry.decl().clone()).collect()
}

/// Fills a route's path with `id` for every parameter naming what the route is about, and with the visible
/// project for a project the route files into.
fn concrete(path: &str, subject: i64, project: i64) -> String {
    path.replace("{repositoryId}", &subject.to_string()).replace("{containerId}", &subject.to_string()).replace(
        "{id}",
        &if path.contains("{repositoryId}") || path.contains("{containerId}") { project } else { subject }.to_string(),
    )
}

async fn every_route_naming_a_target_refuses_a_caller_who_cannot_see_it(db: &Db) {
    let (targets, _) = support::targets(db, PurgeRegistry::stand_ins());
    let admin = support::account(db, "coverage-admin", "ADMIN").await;
    let reader = support::account(db, "coverage-reader", "USER").await;
    // Hidden from both callers: a repository and an image, filed in a project of a solution. Visible to the key's
    // restriction only: one other repository, unfiled.
    exec(db, "insert into t_solution (name, created_at) values ('Hidden solution', '2026-01-01 00:00:00')").await;
    let solution = count(db, "select max(id) from t_solution").await;
    exec(db, &format!("insert into t_project (solution_id, name, created_at) values ({solution}, 'Hidden project', '2026-01-01 00:00:00')")).await;
    let project = count(db, "select max(id) from t_project").await;
    exec(db, &format!("insert into t_repository (url, branch, tier, project_id) values ('{HIDDEN_URL}', 'main', 'TIER_2_BUSINESS_OPERATIONAL', {project})")).await;
    let repository = count(db, "select max(id) from t_repository").await;
    exec(db, &format!("insert into t_container (image_name, tag, tier, project_id) values ('team/hidden', '1.0', 'TIER_2_BUSINESS_OPERATIONAL', {project})")).await;
    let container = count(db, "select max(id) from t_container").await;
    exec(db, "insert into t_repository (url, branch, tier) values ('https://gitlab.example.org/team/allowed', 'main', 'TIER_2_BUSINESS_OPERATIONAL')").await;
    let allowed = count(db, "select max(id) from t_repository").await;

    let credentials = StaticCredentials::default()
        .session("tok-reader", support::principal("coverage-reader", reader, Role::User, Restriction::None, false))
        .key(
            "zsk_restricted",
            support::principal(
                "coverage-admin",
                admin,
                Role::Admin,
                Restriction::Target(ScanTarget::Repository(allowed)),
                true,
            ),
        );
    let router = support::router(db, targets, credentials, "assigned");

    let mut covered = 0;
    let mut reached = 0;
    for route in table() {
        let names = ["/repositories/{id}", "/containers/{id}", "/projects/{id}", "/solutions/{id}"]
            .iter()
            .find(|prefix| route.path.contains(*prefix));
        let Some(names) = names else {
            continue;
        };
        assert_eq!(
            route.visibility,
            Declared::Scoped,
            "{} {} names a target and must be .scoped()",
            route.method,
            route.path
        );
        let hidden = match *names {
            "/repositories/{id}" => repository,
            "/containers/{id}" => container,
            "/projects/{id}" if route.path.contains("{repositoryId}") => repository,
            "/projects/{id}" if route.path.contains("{containerId}") => container,
            "/projects/{id}" => project,
            "/solutions/{id}" => solution,
            other => panic!("{other}: a target parameter this test does not know how to fill"),
        };
        for token in ["tok-reader", "zsk_restricted"] {
            let body = (route.method != "GET" && route.method != "DELETE").then_some("{}");
            let (hidden_path, absent_path) =
                (concrete(&route.path, hidden, project), concrete(&route.path, ABSENT, ABSENT));
            let existing = send(&router, &route.method, &hidden_path, Some(token), body).await;
            let absent = send(&router, &route.method, &absent_path, Some(token), body).await;
            let route_name = format!("{} {} as {token}", route.method, route.path);
            assert!(!(200..300).contains(&existing.0), "{route_name}: a hidden target was served: {existing:?}");
            // `instance` names the path, which differs by the identifier; everything else must be the same bytes.
            assert_eq!(
                (existing.0, existing.1.replace(&hidden_path, "PATH")),
                (absent.0, absent.1.replace(&absent_path, "PATH")),
                "{route_name}: a hidden target answers unlike an absent one"
            );
            let admits = match token {
                "tok-reader" => route.access == Access::Account,
                _ => route.accepts_api_key.is_some(),
            };
            if admits {
                assert_eq!(existing.0, 404, "{route_name}: admitted, and so refused as an absence: {existing:?}");
                reached += 1;
            }
            covered += 1;
        }
    }
    // Sixteen routes name a target, a project or a solution; each was asked by both callers. A route added with a
    // target parameter raises this, which is the point: the count is the table's, not a list kept beside it.
    assert_eq!(covered, 2 * 16, "the table was read: {covered} probes");
    assert!(reached >= 3, "the scan routes and the project read are reached by a restricted caller: {reached}");

    // The lists show neither caller a hidden target.
    for (token, expected) in [("tok-reader", Vec::<i64>::new()), ("zsk_restricted", vec![allowed])] {
        let (status, body) = send(&router, "GET", "/api/v1/repositories", Some(token), None).await;
        assert_eq!(status, 200, "{body}");
        let ids: Vec<i64> = serde_json::from_str::<Value>(&body)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, expected, "{token}");
        let (status, body) = send(&router, "GET", "/api/v1/containers", Some(token), None).await;
        assert_eq!((status, body.as_str()), (200, "[]"), "{token}");
        let (status, body) = send(&router, "GET", "/api/v1/solutions", Some(token), None).await;
        assert_eq!(status, 200, "{body}");
        let tree: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(tree["solutions"], serde_json::json!([]), "{token}: no hidden solution or project in the tree");
        assert!(!body.contains("Hidden"), "{token}: {body}");
    }
}

/// The answers, member for member as the Java control plane writes them, through every route once.
async fn the_answers_are_javas(db: &Db) {
    let (targets, _) = support::targets(db, PurgeRegistry::stand_ins());
    let admin = support::account(db, "answers-admin", "ADMIN").await;
    let credentials = StaticCredentials::default()
        .session("tok-admin", support::principal("answers-admin", admin, Role::Admin, Restriction::None, false));
    let router = support::router(db, targets, credentials, "everyone");
    let admin = Some("tok-admin");

    // A repository: the URL redacted is refused when it carries a credential, accepted otherwise.
    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/repositories",
        admin,
        Some(r#"{"url":"https://user:tok@gitlab.example.org/team/api.git"}"#),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(
        body,
        r#"{"detail":"The URL carries a credential. Remove it from the URL and attach an HTTPS token instead: it is stored encrypted and sent only to its own host.","instance":"/api/v1/repositories","status":400,"title":"Bad Request"}"#
    );
    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/repositories",
        admin,
        Some(r#"{"url":"https://gitlab.example.org/team/api.git","scanIntervalMinutes":"60","required_agent_label":" GPU ","tier":"tier_1_mission_critical"}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let id = serde_json::from_str::<Value>(&body).unwrap()["id"].as_i64().unwrap();
    assert_eq!(
        body,
        format!(
            r#"{{"id":{id},"url":"https://gitlab.example.org/team/api.git","branch":"main","name":null,"subPath":null,"displayName":"team/api","scanIntervalMinutes":60,"scanCron":null,"scanManualOnly":false,"schedule":{{"mode":"interval","intervalMinutes":60}},"requiredAgentLabel":"gpu","sshKeyId":null,"httpsTokenId":null,"lastScheduledScanAt":null,"lastScan":null,"openIssues":0,"tier":"TIER_1_MISSION_CRITICAL","projectId":null,"projectName":null,"detectedLanguages":null}}"#
        )
    );
    // Its twin, over SSH: 409, typed, naming the target to a caller who sees it.
    let (status, body) =
        send(&router, "POST", "/api/v1/repositories", admin, Some(r#"{"url":"git@gitlab.example.org:Team/API"}"#))
            .await;
    assert_eq!(status, 409);
    assert_eq!(
        body,
        format!(
            r#"{{"detail":"This repository is already registered as \"team/api\" (id {id}), on branch main, at its root. Edit that target, or choose another branch or sub-path.","instance":"/api/v1/repositories","status":409,"title":"Conflict","type":"urn:vectispire:problem:target-already-registered","existingRepositoryId":{id}}}"#
        )
    );
    // Manual only beside an interval is refused; manual only alone clears the interval.
    let (status, body) = send(
        &router,
        "PATCH",
        &format!("/api/v1/repositories/{id}"),
        admin,
        Some(r#"{"scanManualOnly":true,"scanIntervalMinutes":5}"#),
    )
    .await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (400, "A target set to manual only takes no interval and no cron expression: choose one or the other.")
    );
    let (status, body) = send(
        &router,
        "PATCH",
        &format!("/api/v1/repositories/{id}"),
        admin,
        Some(r#"{"scanManualOnly":true,"name":"  The API "}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let patched: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (patched["scanIntervalMinutes"].clone(), patched["schedule"].clone(), patched["name"].clone()),
        (Value::Null, serde_json::json!({"mode":"manual","intervalMinutes":null}), Value::from("The API"))
    );
    // A malformed identifier, in Spring's words; an absent one, as an absence.
    let (status, body) = send(&router, "PATCH", "/api/v1/repositories/abc", admin, Some("{}")).await;
    assert_eq!(
        (status, body.as_str()),
        (
            400,
            r#"{"detail":"Failed to convert 'id' with value: 'abc'","instance":"/api/v1/repositories/abc","status":400,"title":"Bad Request"}"#
        )
    );
    let (status, body) = send(&router, "PATCH", &format!("/api/v1/repositories/{ABSENT}"), admin, Some("{}")).await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (404, "Target not found.")
    );
    // The duplicates: none.
    assert_eq!(send(&router, "GET", "/api/v1/repositories/duplicates", admin, None).await, (200, "[]".to_owned()));
    // "Scan now" fails as the stand-in says until the queue (2.7) is composed: a 500 quoting a reference.
    let (status, body) = send(&router, "POST", &format!("/api/v1/repositories/{id}/scan"), admin, None).await;
    assert_eq!(status, 500);
    assert!(
        body.starts_with(r#"{"detail":"An unexpected error occurred. Quote reference "#)
            && body.contains(r#""correlationId":""#),
        "{body}"
    );

    // An image.
    let (status, body) = send(&router, "POST", "/api/v1/containers", admin, Some(r#"{"registry":"registry.example.org:5000","image_name":"team/api","tag":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#)).await;
    assert_eq!(status, 200, "{body}");
    let image: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        image["reference"],
        "registry.example.org:5000/team/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        image["schedule"],
        serde_json::json!({"mode":"default","intervalMinutes":10080}),
        "the default interval, seven days"
    );
    let image_id = image["id"].as_i64().unwrap();
    let (status, body) =
        send(&router, "PATCH", &format!("/api/v1/containers/{image_id}"), admin, Some(r#"{"image_name":"Team/API"}"#))
            .await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (400, r#"Invalid image name "Team/API". Lower case, digits, ". _ -" and "/"."#)
    );

    // A solution, a project, the repository and the image filed into it.
    let (status, body) =
        send(&router, "POST", "/api/v1/solutions", admin, Some(r#"{"name":"Payments","description":"Money"}"#)).await;
    assert_eq!(status, 201, "{body}");
    let solution: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(solution.as_object().unwrap().keys().collect::<Vec<_>>(), ["id", "name", "description", "createdAt"]);
    let solution_id = solution["id"].as_i64().unwrap();
    let (status, body) = send(&router, "POST", "/api/v1/solutions", admin, Some(r#"{"name":"PAYMENTS"}"#)).await;
    assert_eq!(
        (status, body.as_str()),
        (
            409,
            r#"{"detail":"A solution named \"PAYMENTS\" already exists.","instance":"/api/v1/solutions","status":409,"title":"Conflict","type":"urn:vectispire:problem:solution-name-taken"}"#
        )
    );
    let (status, body) =
        send(&router, "POST", &format!("/api/v1/solutions/{solution_id}/projects"), admin, Some(r#"{"name":"API"}"#))
            .await;
    assert_eq!(status, 201, "{body}");
    let project_id = serde_json::from_str::<Value>(&body).unwrap()["id"].as_i64().unwrap();
    assert_eq!(
        send(&router, "PUT", &format!("/api/v1/projects/{project_id}/repositories/{id}"), admin, None).await.0,
        204
    );
    assert_eq!(
        send(&router, "PUT", &format!("/api/v1/projects/{project_id}/containers/{image_id}"), admin, None).await.0,
        204
    );
    let (status, body) = send(&router, "GET", &format!("/api/v1/projects/{project_id}"), admin, None).await;
    assert_eq!(status, 200, "{body}");
    let detail: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        detail.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "id",
            "solutionId",
            "solution",
            "name",
            "description",
            "createdAt",
            "partial",
            "checklistsVisible",
            "repositoryCount",
            "openIssues",
            "repositories",
            "detectedLanguages",
            "languagesUnknownFor",
            "containerCount",
            "containers"
        ]
    );
    assert_eq!(detail["solution"], serde_json::json!({"id": solution_id, "name": "Payments"}));
    assert_eq!(detail["repositories"], serde_json::json!([{"id": id, "name": "The API"}]));
    assert_eq!(detail["languagesUnknownFor"], serde_json::json!([id]), "no scan yet: unknown, never none");
    assert_eq!(
        detail["openIssues"],
        serde_json::json!({"critical":0,"high":0,"medium":0,"low":0,"negligible":0,"unknown":0,"total":0})
    );
    let (status, body) = send(&router, "GET", "/api/v1/solutions", admin, None).await;
    assert_eq!(status, 200, "{body}");
    let tree: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        tree["solutions"][0]["projects"][0]["containers"],
        serde_json::json!([{"id": image_id, "name": "team/api:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}])
    );
    assert_eq!(tree["unfiled"]["repositoryCount"], 0);
    // A solution still holding a project is not deleted; the listing names the project.
    let (status, body) = send(&router, "DELETE", &format!("/api/v1/solutions/{solution_id}"), admin, None).await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (409, "The solution Payments still holds 1 project(s). Move them to another solution or delete them first.")
    );
    let (status, body) = send(&router, "GET", "/api/v1/repositories", admin, None).await;
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()[0]["projectName"], "Payments / API");
    assert_eq!(
        send(&router, "DELETE", &format!("/api/v1/projects/{project_id}/repositories/{id}"), admin, None).await.0,
        204
    );
    let (status, body) =
        send(&router, "DELETE", &format!("/api/v1/projects/{project_id}/repositories/{id}"), admin, None).await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (404, "This repository is not in that project.")
    );
    assert_eq!(send(&router, "DELETE", &format!("/api/v1/projects/{project_id}"), admin, None).await.0, 204);
    assert_eq!(
        count(db, &format!("select count(*) from t_container where id = {image_id} and project_id is null")).await,
        1,
        "the image returned to no project"
    );
    assert_eq!(send(&router, "DELETE", &format!("/api/v1/solutions/{solution_id}"), admin, None).await.0, 204);

    // The clone credentials: the token never comes back.
    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/git-tokens",
        admin,
        Some(r#"{"name":"Forge","host":"gitlab.example.org","token":"glpat-123"}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("glpat-123"), "{body}");
    let token: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        token.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["id", "name", "host", "username", "createdAt", "encryptionState", "usedByRepositories"]
    );
    assert_eq!(
        (token["encryptionState"].clone(), token["usedByRepositories"].clone()),
        (Value::from("current"), Value::from(0))
    );
    let (status, body) = send(
        &router,
        "POST",
        "/api/v1/git-tokens",
        admin,
        Some(r#"{"name":"Forge","host":"gitlab.example.org","token":"Bearer glpat"}"#),
    )
    .await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (400, "The token contains spaces or line breaks: paste the token alone.")
    );
    let (status, _) =
        send(&router, "DELETE", &format!("/api/v1/git-tokens/{}", token["id"].as_str().unwrap()), admin, None).await;
    assert_eq!(status, 204);
    let (status, body) = send(&router, "DELETE", "/api/v1/git-tokens/not-a-uuid", admin, None).await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (400, "Failed to convert 'id' with value: 'not-a-uuid'")
    );
    let (status, body) =
        send(&router, "POST", "/api/v1/ssh-keys", admin, Some(r#"{"name":"deploy","private_key":"not a key"}"#)).await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (400, "This does not look like a private key: expected a \"-----BEGIN … PRIVATE KEY-----\" block.")
    );
    assert_eq!(send(&router, "GET", "/api/v1/ssh-keys", admin, None).await, (200, "[]".to_owned()));
    // A body that is not an object is refused in Java's sentence; `null` included.
    let (status, body) = send(&router, "POST", "/api/v1/solutions", admin, Some("null")).await;
    assert_eq!(
        (status, serde_json::from_str::<Value>(&body).unwrap()["detail"].as_str().unwrap()),
        (400, "The request body could not be read: it is not JSON, or not the shape this route expects.")
    );

    // And the repository goes, with nothing left.
    assert_eq!(send(&router, "DELETE", &format!("/api/v1/repositories/{id}"), admin, None).await.0, 204);
    let (status, body) = send(&router, "DELETE", &format!("/api/v1/repositories/{id}"), admin, None).await;
    assert_eq!(
        (status, body),
        (
            404,
            format!(
                r#"{{"detail":"Repository not found.","instance":"/api/v1/repositories/{id}","status":404,"title":"Not Found"}}"#
            )
        )
    );
}
